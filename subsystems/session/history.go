// Session run history owns bounded process-local logs and usage samples, remote collection, and the durable runs.
// Logs are sanitized before storage, while usage and Slurm accounting remain principal-scoped remote operations.
// A run freezes when its session ends; accounting may arrive after termination.
// Incomplete runs are retried for a bounded window without changing run identity or blocking samples.
package session

import (
	"cmp"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/slurm"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

const (
	maxSessionLogLines     = 100
	maxSessionLogBytes     = 64 << 10
	maxSessionLogLineBytes = 4 << 10
)

var sessionCredentialPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}`),
	regexp.MustCompile(`(?i)\b(token|secret|password|api[_-]?key)\s*[:=]\s*[^\s,;]+`),
	regexp.MustCompile(`\beyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`),
	regexp.MustCompile(`\b(?:[a-f0-9]{64}|[a-f0-9]{32})\b`),
	regexp.MustCompile(`/[^\s'\"]*\.cybershuttle/sessions/s-[a-f0-9]{12}(?:/[^\s'\"]*)?`),
}

type sessionLogBuffer struct {
	statusBytes int
	status      []SessionLogLine
	remote      []SessionLogLine
}

type sessionLogs struct {
	mu        sync.RWMutex
	tails     map[string]*sessionLogBuffer
	sensitive map[string][]string
}

const (
	maxSessionLogCollections = 4
	sessionLogMarkerPrefix   = "__CS_SESSION_LOG__"
)

const sessionLogTailScript = `set -eu
[ "$#" -ge 3 ]
[ "$1" = cs-session-log-tail ]
shift
[ "$#" -le 8 ]
[ $(( $# % 2 )) -eq 0 ]
while [ "$#" -gt 0 ]; do
  cs_session_id=$1
  cs_seq=$2
  shift 2
  case "$cs_session_id" in
    s-????????????) ;;
    *) exit 64 ;;
  esac
  case "${cs_session_id#s-}" in
    *[!a-f0-9]*) exit 64 ;;
  esac
  case "$cs_seq" in
    ''|*[!0-9]*) exit 64 ;;
  esac
  [ "$cs_seq" -ge 1 ] || exit 64
  for cs_stream in stdout stderr; do
    case "$cs_stream" in
      stdout) cs_suffix=out ;;
      stderr) cs_suffix=err ;;
    esac
    cs_log_path=$HOME/.cybershuttle/logs/$cs_session_id-$cs_seq.$cs_suffix
    printf '` + sessionLogMarkerPrefix + `|%s|%s\n' "$cs_session_id" "$cs_stream"
    if [ -f "$cs_log_path" ] && [ ! -L "$cs_log_path" ]; then
      tail -n 100 -- "$cs_log_path" | tail -c 16384 | od -An -v -tx1 | tr -d ' \n'
    fi
    printf '\n'
  done
done
`

type remoteSessionTail struct {
	stdout string
	stderr string
}

type sessionLogTarget struct {
	id  string
	seq int
}

var (
	terminalSequences = regexp.MustCompile(`(?s)(?:\x1b\[|\x9b)[0-?]*[ -/]*[@-~]|(?:\x1b\[|\x9b).*` +
		`|(?:\x1b\]|\x9d).*?(?:\x07|\x1b\\|\x9c)|(?:\x1b\]|\x9d).*` +
		`|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*?(?:\x1b\\|\x9c)|(?:\x1b[PX^_]|[\x90\x98\x9e\x9f]).*` +
		`|\x1b[ -/]*[0-~]|\x1b[ -/]*`)
	terminalControls = regexp.MustCompile(`[\x00-\x09\x0b\x0c\x0e-\x1f\x7f-\x9f]`)
)

func redactSessionLogLine(value string, sensitive []string) string {
	trimmed := strings.TrimSpace(value)
	for _, prefix := range []string{"#!", "#SBATCH"} {
		if strings.HasPrefix(trimmed, prefix) {
			return "[redacted]"
		}
	}
	for _, secret := range sensitive {
		value = strings.ReplaceAll(value, secret, "[redacted]")
	}
	for _, pattern := range sessionCredentialPatterns {
		value = pattern.ReplaceAllString(value, "[redacted]")
	}
	return value
}

func sanitizedSessionLogLines(value string, sensitive []string) []string {
	if value == "" {
		return nil
	}
	value = strings.ToValidUTF8(value, "�")
	value = terminalControls.ReplaceAllString(terminalSequences.ReplaceAllString(value, ""), "")
	value = strings.ReplaceAll(value, "\r\n", "\n")
	value = strings.ReplaceAll(value, "\r", "\n")
	parts := strings.Split(strings.TrimSuffix(value, "\n"), "\n")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		part = redactSessionLogLine(part, sensitive)
		result = append(result, security.TruncateUTF8(part, maxSessionLogLineBytes))
	}
	return result
}

func sessionLogMarker(sessionID, stream string) string {
	return sessionLogMarkerPrefix + "|" + sessionID + "|" + stream
}

func decodeSessionLogTail(section string) (string, error) {
	data, err := hex.DecodeString(strings.TrimSpace(section))
	if err != nil || len(data) > maxSessionLogBytes {
		return "", errors.New("invalid session log tail encoding")
	}
	return string(data), nil
}

func (l *sessionLogs) forget(sessionID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.tails, sessionID)
	delete(l.sensitive, sessionID)
}

func (l *sessionLogs) sensitiveFor(sessionID string) []string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return slices.Clone(l.sensitive[sessionID])
}

func (l *sessionLogs) append(sessionID, text string, now time.Time) {
	if !idPattern.MatchString(sessionID) {
		return
	}
	lines := sanitizedSessionLogLines(text, l.sensitiveFor(sessionID))
	if len(lines) == 0 {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(sessionID)
	for _, line := range lines {
		entry := SessionLogLine{Stream: "status", Text: line, At: now}
		if last := len(buffer.status) - 1; last >= 0 && buffer.status[last].Stream == entry.Stream && buffer.status[last].Text == entry.Text {
			continue
		}
		buffer.status = append(buffer.status, entry)
		buffer.statusBytes += len(entry.Text)
		for len(buffer.status) > maxSessionLogLines || buffer.statusBytes > maxSessionLogBytes {
			buffer.statusBytes -= len(buffer.status[0].Text)
			buffer.status = buffer.status[1:]
		}
	}
}

func (l *sessionLogs) mergeRemote(sessionID, stdout, stderr string, now time.Time) bool {
	if !idPattern.MatchString(sessionID) {
		return false
	}
	sensitive := l.sensitiveFor(sessionID)
	remote := make([]SessionLogLine, 0, maxSessionLogLines)
	for _, source := range []struct{ stream, text string }{{"stdout", stdout}, {"stderr", stderr}} {
		for _, line := range sanitizedSessionLogLines(source.text, sensitive) {
			remote = append(remote, SessionLogLine{Stream: source.stream, Text: line})
		}
	}
	if len(remote) > maxSessionLogLines {
		remote = remote[len(remote)-maxSessionLogLines:]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	buffer := l.bufferLocked(sessionID)
	for i := range remote {
		remote[i].At = now
		if i < len(buffer.remote) && buffer.remote[i].Stream == remote[i].Stream && buffer.remote[i].Text == remote[i].Text {
			remote[i].At = buffer.remote[i].At
		}
	}
	buffer.remote = remote
	return len(buffer.remote) > 0
}

func (l *sessionLogs) bufferLocked(sessionID string) *sessionLogBuffer {
	buffer := l.tails[sessionID]
	if buffer == nil {
		buffer = &sessionLogBuffer{}
		l.tails[sessionID] = buffer
	}
	return buffer
}

func (l *sessionLogs) tail(sessionID string) (SessionLogTail, bool) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	buffer := l.tails[sessionID]
	if buffer == nil {
		return SessionLogTail{}, false
	}
	lines := slices.Concat(buffer.status, buffer.remote)
	if len(lines) == 0 {
		return SessionLogTail{}, false
	}
	return SessionLogTail{SessionID: sessionID, Lines: lines}, true
}

func (l *sessionLogs) setSessionSensitive(sessionID string, values ...string) {
	if !idPattern.MatchString(sessionID) {
		return
	}
	clean := slices.Compact(slices.Sorted(slices.Values(slices.DeleteFunc(slices.Clone(values), func(value string) bool { return len(value) < 3 }))))
	slices.SortFunc(clean, func(a, b string) int { return len(b) - len(a) })
	l.mu.Lock()
	l.sensitive[sessionID] = clean
	l.mu.Unlock()
}

func newSessionLogs() *sessionLogs {
	return &sessionLogs{tails: make(map[string]*sessionLogBuffer), sensitive: make(map[string][]string)}
}

func (s Service) sessionStatus(sessionID, text string) {
	s.logs.append(sessionID, text, s.utcNow())
}

func (s Service) readRemoteSessionTails(ctx context.Context, alias string, targets []sessionLogTarget) (map[string]remoteSessionTail, error) {
	if len(targets) == 0 || len(targets) > maxSessionLogCollections {
		return nil, errors.New("session log tail request must contain one to four IDs")
	}
	args := []string{"sh", "-s", "--", "cs-session-log-tail"}
	requested := make(map[string]bool, len(targets))
	for _, target := range targets {
		if !idPattern.MatchString(target.id) || target.seq < 1 || requested[target.id] {
			return nil, errors.New("session log tail ID is invalid")
		}
		requested[target.id] = true
		args = append(args, target.id, strconv.Itoa(target.seq))
	}
	output, err := s.runner.Run(ctx, alias, strings.NewReader(sessionLogTailScript), args...)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, 2*len(targets))
	for _, target := range targets {
		names = append(names, sessionLogMarker(target.id, "stdout"), sessionLogMarker(target.id, "stderr"))
	}
	parsed, err := ssh.Sections(output, sessionLogMarkerPrefix, names)
	if err != nil {
		return nil, err
	}
	result := make(map[string]remoteSessionTail, len(targets))
	for _, target := range targets {
		stdout, err := decodeSessionLogTail(parsed[sessionLogMarker(target.id, "stdout")])
		if err != nil {
			return nil, err
		}
		stderr, err := decodeSessionLogTail(parsed[sessionLogMarker(target.id, "stderr")])
		if err != nil {
			return nil, err
		}
		result[target.id] = remoteSessionTail{stdout: stdout, stderr: stderr}
	}
	return result, nil
}

func (s Service) collectStartingSessionLogs(ctx context.Context, sessions []Session) map[string]struct{} {
	started := make(map[string]struct{})
	if ctx.Err() != nil {
		return started
	}
	starting := make([]Session, 0, len(sessions))
	for _, session := range sessions {
		if session.State == stateStarting && idPattern.MatchString(session.ID) &&
			session.Seq >= 1 && ssh.ValidAlias(session.Alias) {
			starting = append(starting, session)
		}
	}
	slices.SortFunc(starting, func(a, b Session) int {
		return cmp.Or(strings.Compare(a.Alias, b.Alias), strings.Compare(a.ID, b.ID))
	})
	for _, session := range starting {
		s.logs.setSessionSensitive(session.ID, session.PrivateRoot, session.RootFolderPath, s.LinkspanPath)
	}
	byScope := groupByScope(starting, func(session Session) schedulerScope {
		return schedulerScope{owner: session.Owner, alias: session.Alias}
	})
	scopes := slices.SortedFunc(maps.Keys(byScope), func(a, b schedulerScope) int {
		return cmp.Or(strings.Compare(a.alias, b.alias), strings.Compare(a.owner.Subject, b.owner.Subject))
	})
	for _, scope := range scopes {
		targets := make([]sessionLogTarget, len(byScope[scope]))
		for i, session := range byScope[scope] {
			targets[i] = sessionLogTarget{id: session.ID, seq: session.Seq}
		}
		for chunk := range slices.Chunk(targets, maxSessionLogCollections) {
			if ctx.Err() != nil {
				return started
			}
			tails, err := s.forPrincipal(scope.owner).readRemoteSessionTails(ctx, scope.alias, chunk)
			if err != nil || ctx.Err() != nil {
				continue
			}
			for _, target := range chunk {
				if s.logs.mergeRemote(target.id, tails[target.id].stdout, tails[target.id].stderr, s.utcNow()) {
					started[target.id] = struct{}{}
				}
			}
		}
	}
	return started
}

const (
	maxUsageSamples     = 20
	usageSampleInterval = 5 * time.Second
)

type sessionUsage struct {
	mu     sync.RWMutex
	series map[string][]UsageSample
}

func (m *sessionUsage) append(sessionID string, sample UsageSample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.series[sessionID] = append(m.series[sessionID], sample)
	if kept := m.series[sessionID]; len(kept) > maxUsageSamples {
		m.series[sessionID] = kept[len(kept)-maxUsageSamples:]
	}
}

func (m *sessionUsage) samples(sessionID string) []UsageSample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return slices.Clone(m.series[sessionID])
}

func (m *sessionUsage) forget(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.series, sessionID)
}

const maxUsageBodyBytes = 64 << 10

const devtunnelAuthorizationHeader = "X-Tunnel-Authorization"

func (s Service) sampleAndAccount(ctx context.Context) {
	s.sampleOnce(ctx)
	if s.runtime.statsInFlight.CompareAndSwap(false, true) && !s.runtime.start(func(ctx context.Context) {
		defer s.runtime.statsInFlight.Store(false)
		s.completeRunStats(ctx)
	}) {
		s.runtime.statsInFlight.Store(false)
	}
}

func (s Service) sampleOnce(parent context.Context) {
	sessions, err := s.loadSessions()
	if err != nil {
		return
	}
	ctx, cancel := context.WithTimeout(parent, usageSampleInterval)
	defer cancel()
	var group sync.WaitGroup
	for _, record := range sessions {
		if record.State != stateReady {
			continue
		}
		group.Add(1)
		go func(record Session) {
			defer group.Done()
			sample, err := s.sampleSession(ctx, record)
			if err == nil {
				s.usage.append(record.ID, sample)
			}
		}(record)
	}
	group.Wait()
}

func newSessionUsage() *sessionUsage {
	return &sessionUsage{series: make(map[string][]UsageSample)}
}

func (s Service) sampleSession(ctx context.Context, session Session) (UsageSample, error) {
	body, status, err := s.linkspan(ctx, session, http.MethodGet, "/api/v1/usage", nil, maxUsageBodyBytes)
	if err != nil {
		return UsageSample{}, err
	}
	if status != http.StatusOK {
		return UsageSample{}, errors.New("the job's Linkspan did not answer with a sample")
	}
	var sample UsageSample
	if err := json.Unmarshal(body, &sample); err != nil {
		return UsageSample{}, errors.New("the job's Linkspan returned no sample")
	}
	sample.At = s.utcNow()
	return sample, nil
}

const maxRunRecords = 200

type runRecord struct {
	Run
	Owner security.Principal `json:"owner"`
}

const runStatsWindow = 10 * time.Minute

func (s RunStats) complete() bool { return s.MaxRSS != "" }

func recordRun(current *state, record runRecord) bool {
	if record.Seq == 0 || slices.ContainsFunc(current.Runs, func(existing runRecord) bool {
		return existing.SessionID == record.SessionID && existing.Seq == record.Seq
	}) {
		return false
	}
	current.Runs = append([]runRecord{record}, current.Runs...)
	if len(current.Runs) > maxRunRecords {
		current.Runs = current.Runs[:maxRunRecords]
	}
	return true
}

func (s Service) runOf(session *Session) runRecord {
	logTail, _ := s.logs.tail(session.ID)
	return runRecord{
		Run: Run{
			SessionID: session.ID, Seq: session.Seq, Platform: session.Platform, Alias: session.Alias,
			Account: session.Account, Partition: session.Partition, RootFolder: session.RootFolder,
			Resources: session.Resources, TunnelModes: session.TunnelModes,
			FinalState: session.State, Error: session.Error, StartedAt: session.StartedAt,
			EndedAt: session.UpdatedAt, Samples: s.usage.samples(session.ID),
			Logs: logTail.Lines,
		},
		Owner: session.Owner,
	}
}

func (s Service) freezeRun(session *Session) error {
	return s.Store.locked(func(current *state) error {
		changed, err := s.freezeIfTerminal(current, session)
		if !changed {
			return err
		}
		if saveErr := s.Store.save(current); saveErr != nil {
			return saveErr
		}
		return err
	})
}

func (s Service) freezeIfTerminal(current *state, session *Session) (bool, error) {
	if !terminalSession(session.State) {
		return false, nil
	}
	if err := deleteRunTokens(s.TokenDir, session.ID, session.Seq); err != nil {
		session.State, session.Error = stateStopping, "session cleanup pending: "+boundedSessionError(err)
		return true, err
	}
	if !recordRun(current, s.runOf(session)) {
		return false, nil
	}
	s.forgetSessionBuffers(session.ID)
	return true, nil
}

func (s Service) attachRunStats(sessionID string, seq int, stats RunStats) error {
	return s.Store.locked(func(current *state) error {
		for index := range current.Runs {
			run := &current.Runs[index]
			if run.SessionID != sessionID || run.Seq != seq || run.Stats != nil {
				continue
			}
			run.Stats = &stats
			return s.Store.save(current)
		}
		return nil
	})
}

func (s Service) pendingRunStats() ([]runRecord, error) {
	cutoff := s.utcNow().Add(-runStatsWindow)
	rows, err := s.Store.queries().ListRuns(background)
	if err != nil {
		return nil, err
	}
	var due []runRecord
	for _, row := range rows {
		run, err := decodeRun(row.SessionID, row.Seq, row.Payload)
		if err != nil {
			return nil, err
		}
		if run.Stats == nil && !clientLaunched(run.Platform) && !run.EndedAt.Before(cutoff) {
			due = append(due, run)
		}
	}
	return due, nil
}

func (s Service) completeRunStats(parent context.Context) {
	due, err := s.pendingRunStats()
	if err != nil {
		return
	}
	for _, run := range due {
		ctx, cancel := context.WithTimeout(parent, s.runner.EffectiveTimeout())
		stats, err := slurm.Account(ctx, s.forPrincipal(run.Owner).runner, run.Alias, jobName(run.SessionID, run.Seq), run.StartedAt, s.utcNow())
		cancel()
		if err != nil || !RunStats(stats).complete() {
			continue
		}
		_ = s.attachRunStats(run.SessionID, run.Seq, RunStats(stats))
	}
}
