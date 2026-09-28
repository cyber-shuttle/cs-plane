// Session run history tests cover bounded redaction, remote collection, usage samples, and durable runs.
// Remote log reads stay sequence-scoped and below the SSH output ceiling.
// Sample windows remain bounded.
// Terminal runs retain owned history while delayed Slurm accounting remains independently bounded.
package session

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

const (
	sessionLogIDOne = "s-111111111111"
	sessionLogIDTwo = "s-222222222222"
)

func sessionLogText(t *testing.T, logs *sessionLogs, sessionID string) string {
	t.Helper()
	tail, ok := logs.tail(sessionID)
	if !ok {
		t.Fatal("session produced no log tail")
	}
	texts := make([]string, 0, len(tail.Lines))
	for _, line := range tail.Lines {
		texts = append(texts, line.Text)
	}
	return strings.Join(texts, "\n")
}

func sameLogLine(line SessionLogLine, stream, text string) bool {
	return line.Stream == stream && line.Text == text && !line.At.IsZero()
}

func remoteSessionLogTail(t *testing.T, home, id string, seq int) string {
	t.Helper()
	cmd := exec.Command("sh", "-s", "--", "cs-session-log-tail", id, strconv.Itoa(seq))
	cmd.Stdin = strings.NewReader(sessionLogTailScript)
	cmd.Env = append(os.Environ(), "HOME="+home)
	output, err := cmd.Output()
	testutil.Check(t, err)
	parsed, err := ssh.Sections(string(output), sessionLogMarkerPrefix, []string{sessionLogMarker(id, "stdout"), sessionLogMarker(id, "stderr")})
	testutil.Check(t, err)
	stdout, err := decodeSessionLogTail(parsed[sessionLogMarker(id, "stdout")])
	testutil.Check(t, err)
	return stdout
}

func TestSessionLogsSanitizeAndSplit(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "CR LF and CRLF", input: "one\rtwo\nthree\r\nfour\n", want: []string{"one", "two", "three", "four"}},
		{name: "interior blank", input: "one\n\ntwo", want: []string{"one", "", "two"}},
		{name: "ANSI CSI and OSC", input: "\x1b[31mred\x1b[0m \x1b]0;secret\x07plain", want: []string{"red plain"}},
		{name: "ESC designation and intermediates", input: "a\x1b(Bb\x1b%Gc\x1b#8d", want: []string{"abcd"}},
		{name: "7-bit string controls", input: "a\x1bPprivate-dcs\x1b\\b\x1b_hidden-apc\x1b\\c\x1b^hidden-pm\x1b\\d\x1bXhidden-sos\x1b\\e", want: []string{"abcde"}},
		{name: "C1 CSI and string controls", input: "a\u009b31mred\u009b0m b\u009dprivate-osc\u0007c\u0090private-dcs\u009cd\u009fprivate-apc\u009ce\u009eprivate-pm\u009cf\u0098private-sos\u009cg", want: []string{"ared bcdefg"}},
		{name: "OSC BEL and ST terminators", input: "a\x1b]private\x07b\x1b]private\x1b\\c\u009dprivate\u009cd", want: []string{"abcd"}},
		{name: "7-bit OSC ends at BEL across lines", input: "before\x1b]hidden\rhidden\nhidden\x07after", want: []string{"beforeafter"}},
		{name: "7-bit DCS ignores BEL through ESC ST", input: "before\x1bPhidden\rhidden\nhidden\x07must-not-leak\x1b\\after", want: []string{"beforeafter"}},
		{name: "incomplete CSI drops parameters", input: "safe\x1b[31", want: []string{"safe"}},
		{name: "malformed CSI drops payload", input: "safe\x1b[31\x00private", want: []string{"safe"}},
		{name: "incomplete ESC intermediates drop payload", input: "safe\x1b(", want: []string{"safe"}},
		{name: "UTF-8 around controls", input: "α\x1b(B界\u009b31mβ\u009b0m", want: []string{"α界β"}},
		{name: "split-looking literals are ordinary text", input: `literal \\x1b[31m and \\u009b31m`, want: []string{`literal \\x1b[31m and \\u009b31m`}},
		{name: "controls", input: "a\x00b\tc\x7fd\u0085e", want: []string{"abcde"}},
		{name: "invalid UTF-8", input: "a\xffb", want: []string{"a�b"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			logs := newSessionLogs()
			logs.append(sessionLogIDOne, test.input, time.Now())
			tail, ok := logs.tail(sessionLogIDOne)
			if !ok || len(tail.Lines) != len(test.want) {
				t.Fatalf("tail = %#v, want %q", tail, test.want)
			}
			for i, want := range test.want {
				if !sameLogLine(tail.Lines[i], "status", want) {
					t.Fatalf("line %d = %#v, want %q", i, tail.Lines[i], want)
				}
			}
		})
	}
}

func TestSessionLogsEnforceLineAndByteLimits(t *testing.T) {
	t.Run("line limit", func(t *testing.T) {
		logs := newSessionLogs()
		for i := 0; i < maxSessionLogLines+25; i++ {
			logs.append(sessionLogIDOne, fmt.Sprintf("line-%03d", i), time.Now())
		}
		tail, _ := logs.tail(sessionLogIDOne)
		if len(tail.Lines) != maxSessionLogLines || tail.Lines[0].Text != "line-025" || tail.Lines[len(tail.Lines)-1].Text != "line-124" {
			t.Fatalf("line eviction tail = first=%q last=%q count=%d", tail.Lines[0].Text, tail.Lines[len(tail.Lines)-1].Text, len(tail.Lines))
		}
	})

	t.Run("byte limit", func(t *testing.T) {
		logs := newSessionLogs()
		for i := 0; i < 100; i++ {
			line := fmt.Sprintf("%04d", i) + strings.Repeat("x", 996)
			logs.append(sessionLogIDOne, line, time.Now())
		}
		tail, _ := logs.tail(sessionLogIDOne)
		bytes := 0
		for _, line := range tail.Lines {
			bytes += len(line.Text)
		}
		if len(tail.Lines) != 65 || bytes != 65000 || tail.Lines[0].Text[:4] != "0035" {
			t.Fatalf("byte eviction = count %d bytes %d first %q", len(tail.Lines), bytes, tail.Lines[0].Text[:4])
		}
	})
}

func TestSessionLogsRedactsSessionAndCredentialSecrets(t *testing.T) {
	logs := newSessionLogs()
	logs.setSessionSensitive(sessionLogIDOne,
		"/home/sentinel-user/.cybershuttle/sessions/"+sessionLogIDOne,
		"/scratch/sentinel-user/workspace",
		"/opt/private/linkspan-sentinel",
	)
	input := strings.Join([]string{
		"benign startup message",
		"workspace /scratch/sentinel-user/workspace/file.ipynb",
		"executable /opt/private/linkspan-sentinel",
		"authorization Bearer abcdefghijklmnopqrstuvwxyz012345",
		"token=token-shaped-secret-value-123456",
		"jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJzZW50aW5lbCJ9.signature-value",
		"standalone generated tokens 0123456789abcdef0123456789abcdef and 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		"tokenization for sentinel-user preserves 0123abcd and build 0123456789abcdefABCDEF_-0123456789abcdef",
	}, "\n")
	logs.append(sessionLogIDOne, input, time.Now())
	joined := sessionLogText(t, logs, sessionLogIDOne)
	for _, secret := range []string{".cybershuttle/sessions", "linkspan-sentinel", "abcdefghijklmnopqrstuvwxyz012345", "token-shaped-secret-value-123456", "eyJhbGciOiJIUzI1NiJ9", "0123456789abcdef0123456789abcdef"} {
		if strings.Contains(joined, secret) {
			t.Errorf("secret %q leaked in:\n%s", secret, joined)
		}
	}
	for _, benign := range []string{"benign startup message", "tokenization", "sentinel-user", "0123abcd", "0123456789abcdefABCDEF_-0123456789abcdef"} {
		if !strings.Contains(joined, benign) {
			t.Errorf("benign value %q was over-redacted in:\n%s", benign, joined)
		}
	}
	if !strings.Contains(joined, "[redacted]") {
		t.Fatalf("redaction omitted marker:\n%s", joined)
	}
}

func TestSessionLogTailScriptIsScopedBySeq(t *testing.T) {
	home := t.TempDir()
	logDir := filepath.Join(home, ".cybershuttle", "logs")
	testutil.Check(t, os.MkdirAll(logDir, 0o700))
	id, oldSeq, newSeq := "s-abcdefabcdef", 1, 2
	testutil.Check(t, os.WriteFile(filepath.Join(logDir, id+"-"+strconv.Itoa(oldSeq)+".out"), []byte("finished run output\n"), 0o600))

	if got := remoteSessionLogTail(t, home, id, newSeq); got != "" {
		t.Fatalf("the next run read the finished run's log: %q", got)
	}

	testutil.Check(t, os.WriteFile(filepath.Join(logDir, id+"-"+strconv.Itoa(newSeq)+".out"), []byte("new run output\n"), 0o600))
	if got := remoteSessionLogTail(t, home, id, newSeq); got != "new run output\n" {
		t.Fatalf("next run log = %q", got)
	}
}

func TestSessionLogTailScriptWorstCaseStaysUnderTheRemoteOutputCap(t *testing.T) {
	const sshMaxOutput = 1 << 20
	home := t.TempDir()
	logDir := filepath.Join(home, ".cybershuttle", "logs")
	testutil.Check(t, os.MkdirAll(logDir, 0o700))
	huge := bytes.Repeat([]byte("x"), sshMaxOutput)
	args := []string{"cs-session-log-tail"}
	for i := 0; i < maxSessionLogCollections; i++ {
		id := fmt.Sprintf("s-%012x", i)
		seq := i + 1
		for _, suffix := range []string{"out", "err"} {
			path := filepath.Join(logDir, id+"-"+strconv.Itoa(seq)+"."+suffix)
			testutil.Check(t, os.WriteFile(path, huge, 0o600))
		}
		args = append(args, id, strconv.Itoa(seq))
	}
	cmd := exec.Command("sh", append([]string{"-s", "--"}, args...)...)
	cmd.Stdin = strings.NewReader(sessionLogTailScript)
	cmd.Env = append(os.Environ(), "HOME="+home)
	output, err := cmd.Output()
	testutil.Check(t, err)
	if len(output) >= sshMaxOutput {
		t.Fatalf("a full chunk of maximal tails produced %d bytes, at or over the SSH output cap of %d", len(output), sshMaxOutput)
	}
}

func TestSampleWindowIsBoundedAndNewestLast(t *testing.T) {
	usage := newSessionUsage()
	for index := 0; index < maxUsageSamples+5; index++ {
		used := int64(index)
		usage.append("s-111111111111", UsageSample{At: time.Unix(int64(index), 0), MemBytes: &used})
	}
	series := usage.samples("s-111111111111")
	testutil.Equal(t, len(series), maxUsageSamples, "window sample count")
	if *series[len(series)-1].MemBytes != int64(maxUsageSamples+4) {
		t.Fatalf("the newest sample is not last: %+v", series[len(series)-1])
	}
	usage.forget("s-111111111111")
	if got := usage.samples("s-111111111111"); len(got) != 0 {
		t.Fatalf("a forgotten session kept %d samples", len(got))
	}
}

const sacctRows = `12345|4|8192000K|3600|14400|||
12345.batch|4|8192000K|3600|14400|4096000K|02:00:00
12345.extern|4|8192000K|3600|14400|4K|00:00:00`

func runsIn(t *testing.T, service Service) []Run {
	t.Helper()
	runs, err := service.Runs(testPrincipal)
	testutil.Check(t, err)
	return runs
}

func TestARunOutlivesTheSessionThatEnded(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	putSessions(t, service, session)
	used := int64(4096)
	service.usage.append(session.ID, UsageSample{At: time.Now(), MemBytes: &used})

	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|node1|"+session.JobName+"|3600")
	testutil.Check(t, service.reconcileAll(context.Background()))
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].FinalState != "STOPPED" || runs[0].SessionID != session.ID {
		t.Fatalf("a finished session left no usable record: %+v", runs)
	}
	if len(runs[0].Samples) != 1 || *runs[0].Samples[0].MemBytes != used {
		t.Fatalf("the sample window did not travel with the run: %+v", runs[0].Samples)
	}
	if got := service.usage.samples(session.ID); len(got) != 0 {
		t.Fatalf("a finished session kept its live window: %+v", got)
	}
	endedAt := runs[0].EndedAt

	testutil.Check(t, service.reconcileAll(context.Background()))
	if runs := runsIn(t, service); len(runs) != 1 {
		t.Fatalf("the same run was recorded %d times", len(runs))
	} else if !runs[0].EndedAt.Equal(endedAt) {
		t.Fatalf("a later reconcile moved EndedAt from %s to %s, the terminal transition's own time", endedAt, runs[0].EndedAt)
	}
}

func TestEachSeqIsItsOwnRun(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "STOPPED"
	setTestSessionMetadata(&session)
	testutil.Check(t, service.freezeRun(&session))
	second := session
	second.Seq = 2
	second.Resources.Cores = 8
	testutil.Check(t, service.freezeRun(&second))
	runs := runsIn(t, service)
	if len(runs) != 2 {
		t.Fatalf("the next run overwrote the previous run: %+v", runs)
	}
	if runs[0].Seq != second.Seq || runs[0].Resources.Cores != 8 {
		t.Fatalf("the newest run is not first, or lost its own session: %+v", runs[0])
	}
	testutil.Check(t, service.freezeRun(&second))
	if runs := runsIn(t, service); len(runs) != 2 {
		t.Fatalf("recording the same run twice kept %d runs", len(runs))
	}
}

func TestRunHistoryIsFilteredToItsOwner(t *testing.T) {
	service, _, _ := reconciliationService(t)
	mine := pendingSession("s-111111111111", "alpha", "101")
	mine.State = "STOPPED"
	setTestSessionMetadata(&mine)
	theirs := pendingSession("s-222222222222", "alpha", "102")
	theirs.State = "STOPPED"
	setTestSessionMetadata(&theirs)
	theirs.Owner.Subject = "someone-else"
	for _, session := range []*Session{&mine, &theirs} {
		testutil.Check(t, service.freezeRun(session))
	}
	runs := runsIn(t, service)
	if len(runs) != 1 || runs[0].SessionID != mine.ID {
		t.Fatalf("the history is not the caller's own: %+v", runs)
	}
}

func TestRunHistoryIsBounded(t *testing.T) {
	current := &state{Sessions: map[string]*Session{}}
	for index := 0; index < maxRunRecords+10; index++ {
		recordRun(current, runRecord{Run: Run{
			SessionID: "s-111111111111", Seq: index + 1,
		}})
	}
	testutil.Equal(t, len(current.Runs), maxRunRecords, "run history length")
}

func TestCompleteRunStatsGivesEachPendingRunItsOwnTimeout(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	sleepOnce := filepath.Join(t.TempDir(), "sacct-slept-once")
	t.Setenv("FAKE_RUN_STATS_SLEEP_ONCE", sleepOnce)
	t.Setenv("FAKE_RUN_STATS_SLEEP_SECONDS", "2")
	t.Setenv("FAKE_RUN_STATS_OUTPUT", sacctRows)
	service := newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: time.Second}, testSessionStore(t))
	slow := runRecord{Run: Run{SessionID: "s-111111111111", Seq: 1, Alias: "delta", EndedAt: service.utcNow()}, Owner: testPrincipal}
	fast := runRecord{Run: Run{SessionID: "s-222222222222", Seq: 2, Alias: "delta", EndedAt: service.utcNow()}, Owner: testPrincipal}
	testutil.Check(t, service.Store.locked(func(current *state) error {
		current.Runs = []runRecord{slow, fast}
		return service.Store.save(current)
	}))

	service.completeRunStats(context.Background())

	runs := runsIn(t, service)
	var gotFast bool
	for _, run := range runs {
		if run.Seq == fast.Seq {
			gotFast = run.Stats != nil
		}
	}
	if !gotFast {
		t.Fatal("a slow run starved the timeout of the pending run behind it")
	}
}
