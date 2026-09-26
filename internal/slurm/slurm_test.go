// These tests cover the framed Slurm boundary: discovery, submission outcomes, scheduler observations,
// and accounting. Session policy and state transitions are tested by the sessions package.
package slurm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestDiscoveryParsesOneFramedSnapshot(t *testing.T) {
	output := strings.Join([]string{
		"SSH banner", markerUser, "alice", markerAccounts, "Account|", "project-b|", "project-a|", markerPartitions,
		"cpu*|64|256000|gpu:a100:4(IDX:0-3),license:1", markerHome, "/home/alice", markerDone, "",
	}, "\n")
	got, err := parseDiscovery(output)
	testutil.Check(t, err)
	if got.User != "alice" || got.Home != "/home/alice" || strings.Join(got.Accounts, ",") != "project-a,project-b" {
		t.Fatalf("discovery identity = %+v", got)
	}
	if len(got.Partitions) != 1 || got.Partitions[0].Name != "cpu" || got.Partitions[0].CPUCount != 64 || got.Partitions[0].MemoryMB != 256000 || len(got.Partitions[0].GRES) != 2 {
		t.Fatalf("discovery partitions = %+v", got.Partitions)
	}
	for marker, operation := range map[string]string{
		markerErrorUser: "identify remote user", markerErrorAccounts: "query the accounts", markerErrorPartitions: "query Slurm partitions", markerErrorHome: "read remote home",
	} {
		_, err := parseDiscovery(marker + "\n")
		if failure, ok := errors.AsType[*DiscoveryError](err); !ok || !strings.Contains(failure.Operation, operation) {
			t.Fatalf("marker %q error = %v", marker, err)
		}
	}
}

func TestSubmissionClassifiesOutcomesAndRedactsEnvironment(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "ssh")
	script := `#!/bin/sh
if [ "$1" = "-G" ]; then
  printf 'hostname fake.example\nuser alice\n'
  exit 0
fi
for command; do :; done
printf '%s\n' "$command" >> "$FAKE_ARGV"
case "$FAKE_SLURM_MODE" in
  check) printf 'job would run\n' ;;
  submit) eval "set -- $command"; PATH="$FAKE_BIN:$PATH" exec "$@" ;;
  fail) printf '%s\n' "$command" >&2; exit 255 ;;
  reject) printf '%s\n' "$command" >&2; exit 1 ;;
esac
`
	testutil.WriteScript(t, bin, script)
	testutil.WriteScript(t, filepath.Join(filepath.Dir(bin), "sbatch"), `#!/bin/sh
{ printf '%s|%s\n' "$*" "$TOKEN"; cat; } > "$FAKE_SBATCH_LOG"
printf '8123;cluster\n'
`)
	sbatchLog, argv := filepath.Join(t.TempDir(), "sbatch"), filepath.Join(t.TempDir(), "argv")
	t.Setenv("FAKE_BIN", filepath.Dir(bin))
	t.Setenv("FAKE_SBATCH_LOG", sbatchLog)
	t.Setenv("FAKE_ARGV", argv)
	runner := ssh.Runner{SSHBin: bin, Timeout: time.Second}
	const secret = "it's top-secret"
	read := func(path string) string { data, _ := os.ReadFile(path); return string(data) }

	t.Setenv("FAKE_SLURM_MODE", "check")
	checked, err := Check(context.Background(), runner, "delta", "#!/bin/sh\ntrue\n")
	if err != nil || !checked.Passed || strings.TrimSpace(checked.Stdout) != "job would run" {
		t.Fatalf("check = %+v, %v", checked, err)
	}

	t.Setenv("FAKE_SLURM_MODE", "submit")
	jobID, err := Submit(context.Background(), runner, "delta", SubmitRequest{JobName: "cs-session", Script: "#!/bin/sh\ntrue\n", Environment: map[string]string{"TOKEN": secret, "PORT": "20000"}})
	if err != nil || jobID != "8123" {
		t.Fatalf("submit = %q, %v", jobID, err)
	}
	if got, want := read(sbatchLog), "--job-name=cs-session --export=ALL --parsable|"+secret+"\n#!/bin/sh\ntrue\n"; got != want {
		t.Fatalf("sbatch saw %q, want %q", got, want)
	}

	t.Setenv("FAKE_SLURM_MODE", "fail")
	_, err = Submit(context.Background(), runner, "delta", SubmitRequest{JobName: "cs-session", Script: "#!/bin/sh\ntrue\n", Environment: map[string]string{"TOKEN": secret}})
	if !AmbiguousSubmission(err) || strings.Contains(err.Error(), secret) {
		t.Fatalf("ambiguous submit error leaked its environment: %v", err)
	}

	t.Setenv("FAKE_SLURM_MODE", "reject")
	_, err = Submit(context.Background(), runner, "delta", SubmitRequest{JobName: "cs-session", Script: "#!/bin/sh\ntrue\n", Environment: map[string]string{"TOKEN": secret}})
	if err == nil || AmbiguousSubmission(err) || strings.Contains(err.Error(), secret) {
		t.Fatalf("conclusive submit error = %v", err)
	}
	if strings.Contains(read(argv), "top-secret") {
		t.Fatalf("a submission put its environment on the command line:\n%s", read(argv))
	}
}

func TestStatusParsesCancellationQueueAndAccounting(t *testing.T) {
	jobs := []Job{
		{ID: "101", Name: "cs-one", Cancel: true},
		{Name: "cs-two", Cancel: true},
		{ID: "303", Name: "cs-three"},
	}
	output := strings.Join([]string{
		"banner", statusMarkerCancel, "name:cs-two|not found", statusMarkerQueue,
		"101|RUNNING|node-a|cs-one|0", statusMarkerAccounting,
		"101|RUNNING|node-a|cs-one|42", "303|TIMEOUT|(null)|cs-three|90", "",
	}, "\n")
	statuses, err := parseStatuses(output, jobs)
	testutil.Check(t, err)
	if !statuses[0].Found || statuses[0].Observation.State != Active || statuses[0].Observation.ElapsedSeconds != 42 {
		t.Fatalf("queued observation = %+v", statuses[0])
	}
	if statuses[1].Found || statuses[1].CancelError != "not found" {
		t.Fatalf("name cancellation = %+v", statuses[1])
	}
	if !statuses[2].Found || statuses[2].Observation.State != Expired {
		t.Fatalf("accounting observation = %+v", statuses[2])
	}
}

func TestAccountingSelectsTheJobAndBatchStepStats(t *testing.T) {
	got := parseStats("8123|4|8192K|120|480|0K|00:00:00\n8123.batch|4|8192K|120|480|4096K|00:04:00\n")
	if got.Cores != 4 || got.RequestedMemory != "8.0 MB" || got.ElapsedSeconds != 120 || got.MaxRSS != "4.0 MB" || got.CPUEfficiencyPct != 50 || got.MemoryEfficiencyPct != 50 {
		t.Fatalf("stats = %+v", got)
	}
}
