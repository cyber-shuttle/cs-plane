// Package slurm runs the fixed Slurm programs used by sessions and parses their bounded output.
// Discovery, submission, status, cancellation, and accounting are neutral protocol operations;
// principal policy, session transitions, HTTP errors, narration, and persistence remain with sessions.
// Every multi-command program frames its fields so SSH banners cannot become scheduler data.
package slurm

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

const (
	discoveryMarkerPrefix = "__CS_DSC_6f1c9a7e4b2d8053_"
	markerUser            = discoveryMarkerPrefix + "USER__"
	markerAccounts        = discoveryMarkerPrefix + "ACCOUNTS__"
	markerPartitions      = discoveryMarkerPrefix + "PARTITIONS__"
	markerHome            = discoveryMarkerPrefix + "HOME__"
	markerDone            = discoveryMarkerPrefix + "DONE__"
	markerErrorUser       = discoveryMarkerPrefix + "ERROR_USER__"
	markerErrorAccounts   = discoveryMarkerPrefix + "ERROR_ACCOUNTS__"
	markerErrorPartitions = discoveryMarkerPrefix + "ERROR_PARTITIONS__"
	markerErrorHome       = discoveryMarkerPrefix + "ERROR_HOME__"
	submitScriptEnd       = "CS_JOB_SCRIPT_END"

	statusMarkerPrefix     = "__CS_S"
	statusMarkerCancel     = statusMarkerPrefix + "CANCEL__"
	statusMarkerQueue      = statusMarkerPrefix + "QUEUE__"
	statusMarkerAccounting = statusMarkerPrefix + "ACCT__"

	accountingFormat = "JobID,AllocCPUs,ReqMem,ElapsedRaw,CPUTimeRAW,MaxRSS,TotalCPU"
)

const discoveryScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
printf '%s\n' '` + markerUser + `'
if cs_user=$(id -un); then :; else
  printf '%s\n' '` + markerErrorUser + `'
  exit 71
fi
case "$cs_user" in
  ''|*[!A-Za-z0-9_.-]*) printf '%s\n' '` + markerErrorUser + `'; exit 72 ;;
esac
[ "${#cs_user}" -le 64 ] || { printf '%s\n' '` + markerErrorUser + `'; exit 72; }
printf '%s\n' "$cs_user"
printf '%s\n' '` + markerAccounts + `'
sacctmgr show associations where "user=$cs_user" format=Account -p || {
  printf '%s\n' '` + markerErrorAccounts + `'
  exit 73
}
printf '%s\n' '` + markerPartitions + `'
sinfo -h -o '%P|%c|%m|%G' || {
  printf '%s\n' '` + markerErrorPartitions + `'
  exit 74
}
printf '%s\n' '` + markerHome + `'
printenv HOME || {
  printf '%s\n' '` + markerErrorHome + `'
  exit 75
}
printf '%s\n' '` + markerDone + `'
`

var (
	leadingDigits = regexp.MustCompile(`[0-9]+`)
	gresEntry     = regexp.MustCompile(`^(.+):([0-9]+)(?:\([^)]*\))?$`)
	jobIDPattern  = regexp.MustCompile(`^[0-9]+$`)
	absolutePath  = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
)

type GRES struct {
	Name  string
	Count int
}

type Partition struct {
	Name     string
	CPUCount int
	MemoryMB int
	GRES     []GRES
}

type Discovery struct {
	User       string
	Accounts   []string
	Partitions []Partition
	Home       string
}

type DiscoveryError struct{ Operation string }

func (e *DiscoveryError) Error() string { return "remote discovery failed to " + e.Operation }

type CheckResult struct {
	Stdout string
	Stderr string
	Passed bool
}

type SubmitRequest struct {
	JobName     string
	Script      string
	Environment map[string]string
}

type submissionError struct {
	cause     error
	ambiguous bool
}

func (e *submissionError) Error() string { return e.cause.Error() }
func (e *submissionError) Unwrap() error { return e.cause }

func AmbiguousSubmission(err error) bool {
	submit, ok := errors.AsType[*submissionError](err)
	return ok && submit.ambiguous
}

type State uint8

const (
	Unknown State = iota
	Pending
	Active
	Stopped
	Expired
	Failed
)

type Job struct {
	ID        string
	Name      string
	Cancel    bool
	CreatedAt time.Time
}

type Observation struct {
	JobID          string
	State          State
	Node           string
	ElapsedSeconds int64
}

type JobStatus struct {
	Found       bool
	Observation Observation
	CancelError string
}

type Stats struct {
	Cores               int
	RequestedMemory     string
	ElapsedSeconds      int64
	MaxRSS              string
	CPUEfficiencyPct    float64
	MemoryEfficiencyPct float64
}

func parseAccounts(output string) []string {
	accounts := []string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		account, _, _ := strings.Cut(line, "|")
		if account = strings.TrimSpace(account); !strings.EqualFold(account, "Account") && security.SafeName(account, 64) {
			accounts = append(accounts, account)
		}
	}
	slices.Sort(accounts)
	return slices.Compact(accounts)
}

// parseGRES skips entries it cannot count, such as tmpdisk:100G.
func parseGRES(value string) []GRES {
	if value == "" || value == "(null)" {
		return []GRES{}
	}
	var entries []string
	start, depth := 0, 0
	for index, char := range value {
		switch char {
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				entries = append(entries, strings.TrimSpace(value[start:index]))
				start = index + 1
			}
		}
	}
	entries = append(entries, strings.TrimSpace(value[start:]))
	result := make([]GRES, 0, len(entries))
	for _, entry := range entries {
		match := gresEntry.FindStringSubmatch(entry)
		if match == nil {
			continue
		}
		count, _ := strconv.Atoi(match[2])
		result = append(result, GRES{Name: match[1], Count: count})
	}
	return result
}

func parsePartitions(output string) ([]Partition, error) {
	partitions := []Partition{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) != 4 {
			return nil, fmt.Errorf("invalid sinfo line: %q", line)
		}
		cpus, cpuErr := strconv.Atoi(leadingDigits.FindString(parts[1]))
		memory, memoryErr := strconv.Atoi(leadingDigits.FindString(parts[2]))
		if cpuErr != nil || memoryErr != nil {
			return nil, fmt.Errorf("invalid capacity in sinfo line: %q", line)
		}
		partitions = append(partitions, Partition{
			Name: strings.TrimSuffix(strings.TrimSpace(parts[0]), "*"), CPUCount: cpus, MemoryMB: memory, GRES: parseGRES(strings.TrimSpace(parts[3])),
		})
	}
	return partitions, nil
}

func parseDiscovery(output string) (Discovery, error) {
	for _, failure := range []struct{ marker, operation string }{
		{markerErrorUser, "identify remote user"},
		{markerErrorAccounts, "query the accounts the remote user is associated with"},
		{markerErrorPartitions, "query Slurm partitions"},
		{markerErrorHome, "read remote home directory"},
	} {
		if strings.Contains(output, failure.marker+"\n") {
			return Discovery{}, &DiscoveryError{Operation: failure.operation}
		}
	}
	parsed, err := ssh.Sections(output, discoveryMarkerPrefix, []string{markerUser, markerAccounts, markerPartitions, markerHome, markerDone})
	if err != nil {
		return Discovery{}, err
	}
	if strings.TrimSpace(parsed[markerDone]) != "" {
		return Discovery{}, errors.New("discovery output continued past its final marker")
	}
	user := strings.TrimSpace(parsed[markerUser])
	if !security.SafeName(user, 64) {
		return Discovery{}, errors.New("remote username is unsafe")
	}
	home := strings.TrimSpace(parsed[markerHome])
	if !absolutePath.MatchString(home) || path.Clean(home) != home || home == "/" {
		return Discovery{}, errors.New("remote HOME is unsafe")
	}
	partitions, err := parsePartitions(parsed[markerPartitions])
	if err != nil {
		return Discovery{}, err
	}
	return Discovery{User: user, Accounts: parseAccounts(parsed[markerAccounts]), Partitions: partitions, Home: home}, nil
}

func Discover(ctx context.Context, runner ssh.Runner, alias string) (Discovery, error) {
	ctx, cancel := context.WithTimeout(ctx, runner.EffectiveTimeout())
	defer cancel()
	stdout, stderr, runErr := runner.RunOutput(ctx, alias, strings.NewReader(discoveryScript), "sh", "-s")
	if runErr != nil && (errors.Is(runErr, context.DeadlineExceeded) || ssh.AuthenticationFailure(stderr)) {
		return Discovery{}, ssh.ClassifyFailure(alias, stderr, runErr)
	}
	discovered, parseErr := parseDiscovery(stdout)
	switch {
	case runErr != nil && parseErr != nil:
		if classified := security.For(runErr); classified.Code != "internal_error" {
			return Discovery{}, runErr
		}
		return Discovery{}, fmt.Errorf("%w: %s", parseErr, ssh.FailureMessage(stderr, runErr))
	case runErr != nil:
		return Discovery{}, ssh.ClassifyFailure(alias, stderr, runErr)
	default:
		return discovered, parseErr
	}
}

func Check(ctx context.Context, runner ssh.Runner, alias, script string) (CheckResult, error) {
	ctx, cancel := context.WithTimeout(ctx, runner.EffectiveTimeout())
	defer cancel()
	stdout, stderr, err := runner.RunOutput(ctx, alias, strings.NewReader(script), "sbatch", "--test-only")
	if !ssh.AmbiguousExit(err) {
		return CheckResult{Stdout: stdout, Stderr: stderr, Passed: err == nil}, nil
	}
	return CheckResult{}, ssh.ClassifyFailure(alias, stderr, err)
}

// submitProgram exports the environment and feeds the script to sbatch from stdin, so no value reaches an argv
// on the shared SSH host, where any user can list processes.
func submitProgram(request SubmitRequest) (string, error) {
	if !strings.HasSuffix(request.Script, "\n") || strings.Contains(request.Script, "\n"+submitScriptEnd+"\n") {
		return "", errors.New("submission script is not newline-terminated or contains its terminator")
	}
	var program strings.Builder
	for _, key := range slices.Sorted(maps.Keys(request.Environment)) {
		program.WriteString("export " + key + "=" + ssh.ShellQuote(request.Environment[key]) + "\n")
	}
	program.WriteString(`exec sbatch --job-name="$2" --export=ALL --parsable <<'` + submitScriptEnd + "'\n" + request.Script + submitScriptEnd + "\n")
	return program.String(), nil
}

func Submit(ctx context.Context, runner ssh.Runner, alias string, request SubmitRequest) (string, error) {
	program, err := submitProgram(request)
	if err != nil {
		return "", err
	}
	secrets := slices.Collect(maps.Values(request.Environment))
	ctx, cancel := context.WithTimeout(ctx, runner.EffectiveTimeout())
	defer cancel()
	stdout, stderr, runErr := runner.RunOutput(ctx, alias, strings.NewReader(program),
		"sh", "-s", "--", "cs-submit", request.JobName)
	if runErr != nil {
		cause := security.Redact(fmt.Sprintf("submit %s failed", request.JobName), errors.New(ssh.FailureMessage(stderr, runErr)), secrets...)
		return "", &submissionError{cause: cause, ambiguous: ssh.AmbiguousExit(runErr)}
	}
	jobID := strings.SplitN(strings.TrimSpace(stdout), ";", 2)[0]
	if !jobIDPattern.MatchString(jobID) {
		return "", &submissionError{cause: fmt.Errorf("submit outcome pending reconciliation for %s: invalid job ID", request.JobName), ambiguous: true}
	}
	return jobID, nil
}

func normalizeState(raw string) State {
	fields := strings.Fields(raw)
	if len(fields) == 0 {
		return Unknown
	}
	switch strings.TrimSuffix(strings.ToUpper(fields[0]), "+") {
	case "PENDING", "REQUEUED", "REQUEUE_FED", "REQUEUE_HOLD", "SUSPENDED", "STOPPED": // SUSPENDED and STOPPED keep their nodes
		return Pending
	case "RUNNING", "CONFIGURING", "COMPLETING", "RESIZING", "SIGNALING", "STAGE_OUT":
		return Active
	case "COMPLETED", "CANCELLED":
		return Stopped
	case "TIMEOUT":
		return Expired
	case "BOOT_FAIL", "DEADLINE", "FAILED", "NODE_FAIL", "OUT_OF_MEMORY", "PREEMPTED", "REVOKED", "SPECIAL_EXIT":
		return Failed
	default:
		return Unknown
	}
}

func lookback(oldest, now time.Time) string {
	window := min(now.Sub(oldest)+time.Hour, 30*24*time.Hour)
	return "now-" + strconv.FormatInt(int64(window.Seconds()), 10) + "seconds"
}

func statusScript(jobs []Job, now time.Time) string {
	var script strings.Builder
	marker := func(name string) { fmt.Fprintf(&script, "printf '%%s\\n' %s\n", ssh.ShellQuote(name)) }
	script.WriteString("set -u\n")
	marker(statusMarkerCancel)
	for _, job := range jobs {
		if !job.Cancel {
			continue
		}
		key, flag, value := "id:"+job.ID, "", job.ID
		if job.ID == "" {
			key, flag, value = "name:"+job.Name, "--name=", job.Name
		}
		fmt.Fprintf(&script, "cs_cancel=$(scancel %s%s 2>&1) || printf '%%s|%%s\\n' %s \"$(printf '%%s' \"$cs_cancel\" | tr '\\n|' '  ')\"\n",
			flag, ssh.ShellQuote(value), ssh.ShellQuote(key))
	}
	marker(statusMarkerQueue)
	script.WriteString("squeue --me --noheader --format='%i|%T|%N|%j'\n")
	names := make([]string, 0, len(jobs))
	oldest := now
	for _, job := range jobs {
		names = append(names, job.Name)
		if !job.CreatedAt.IsZero() && job.CreatedAt.Before(oldest) {
			oldest = job.CreatedAt
		}
	}
	slices.Sort(names)
	marker(statusMarkerAccounting)
	fmt.Fprintf(&script, "sacct --noheader -X --starttime=%s --name=%s --format=JobIDRaw,State,NodeList,JobName,ElapsedRaw --parsable2\n",
		ssh.ShellQuote(lookback(oldest, now)), ssh.ShellQuote(strings.Join(names, ",")))
	return script.String()
}

func Observe(ctx context.Context, runner ssh.Runner, alias string, jobs []Job, now time.Time) ([]JobStatus, error) {
	output, err := runner.Run(ctx, alias, strings.NewReader(statusScript(jobs, now)), "sh", "-s", "--", "cs-session-status")
	if err != nil {
		return nil, err
	}
	return parseStatuses(output, jobs)
}

func parseStatuses(output string, jobs []Job) ([]JobStatus, error) {
	parsed, err := ssh.Sections(output, statusMarkerPrefix, []string{statusMarkerCancel, statusMarkerQueue, statusMarkerAccounting})
	if err != nil {
		return nil, err
	}
	cancelByKey := map[string]string{}
	for _, line := range strings.Split(parsed[statusMarkerCancel], "\n") {
		if key, message, ok := strings.Cut(line, "|"); ok {
			cancelByKey[key] = strings.TrimSpace(message)
		}
	}
	byID, byName := map[string]Observation{}, map[string]Observation{}
	for _, marker := range []string{statusMarkerAccounting, statusMarkerQueue} {
		queue := marker == statusMarkerQueue
		for _, line := range strings.Split(parsed[marker], "\n") {
			parts := strings.Split(strings.TrimSpace(line), "|")
			if len(parts) < 4 || !jobIDPattern.MatchString(strings.TrimSpace(parts[0])) {
				continue
			}
			observation := Observation{JobID: strings.TrimSpace(parts[0]), State: normalizeState(parts[1]), Node: strings.TrimSpace(parts[2])}
			if len(parts) > 4 {
				if seconds, parseErr := strconv.ParseInt(strings.TrimSpace(parts[4]), 10, 64); parseErr == nil && seconds >= 0 {
					observation.ElapsedSeconds = seconds
				}
			}
			name := strings.TrimSpace(parts[3])
			if queue || byID[observation.JobID].JobID == "" {
				if observation.ElapsedSeconds == 0 {
					observation.ElapsedSeconds = byID[observation.JobID].ElapsedSeconds
				}
				byID[observation.JobID], byName[name] = observation, observation
			}
		}
	}
	result := make([]JobStatus, len(jobs))
	for index, job := range jobs {
		key := "name:" + job.Name
		observation, found := byName[job.Name]
		if job.ID != "" {
			key = "id:" + job.ID
			observation, found = byID[job.ID]
		}
		result[index] = JobStatus{Found: found, Observation: observation}
		if job.Cancel {
			result[index].CancelError = cancelByKey[key]
		}
	}
	return result, nil
}

func field(row []string, index int) string {
	if index >= len(row) {
		return ""
	}
	return row[index]
}

// parseKiB reads the leading number of a sacct memory field such as "8192K" or "4096Kn".
func parseKiB(value string) (float64, bool) {
	number, err := strconv.ParseFloat(strings.TrimRightFunc(strings.TrimSpace(value), func(r rune) bool { return r < '0' || r > '9' }), 64)
	return number, err == nil
}

func humanKiB(kib float64) string {
	switch {
	case kib >= 1024*1024:
		return fmt.Sprintf("%.1f GB", kib/(1024*1024))
	case kib >= 1024:
		return fmt.Sprintf("%.1f MB", kib/1024)
	default:
		return fmt.Sprintf("%.0f KB", kib)
	}
}

func hmsSeconds(value string) float64 {
	text := strings.TrimSpace(value)
	if text == "" {
		return 0
	}
	days, rest := "0", text
	if before, after, found := strings.Cut(text, "-"); found {
		days, rest = before, after
	}
	parts := strings.Split(rest, ":")
	if len(parts) < 2 {
		return 0
	}
	seconds := 0.0
	for _, part := range parts {
		value, err := strconv.ParseFloat(strings.TrimSpace(part), 64)
		if err != nil {
			return 0
		}
		seconds = seconds*60 + value
	}
	dayCount, err := strconv.ParseFloat(strings.TrimSpace(days), 64)
	if err != nil {
		return 0
	}
	return dayCount*86400 + seconds
}

func parseStats(output string) Stats {
	var rows [][]string
	for _, line := range strings.Split(output, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			rows = append(rows, strings.Split(trimmed, "|"))
		}
	}
	if len(rows) == 0 {
		return Stats{}
	}
	alloc, used := rows[0], rows[0]
	for _, row := range rows {
		if !strings.Contains(row[0], ".") {
			alloc = row
			break
		}
	}
	for _, row := range rows {
		if strings.HasSuffix(row[0], ".batch") {
			used = row
			break
		}
	}
	stats := Stats{}
	if cores, err := strconv.Atoi(strings.TrimSpace(field(alloc, 1))); err == nil && cores > 0 {
		stats.Cores = cores
	}
	if elapsed, err := strconv.ParseInt(strings.TrimSpace(field(alloc, 3)), 10, 64); err == nil {
		stats.ElapsedSeconds = elapsed
	}
	requestedKiB, hasRequested := parseKiB(field(alloc, 2))
	allocatedCPUSeconds, _ := strconv.ParseFloat(strings.TrimSpace(field(alloc, 4)), 64)
	maxRSSKiB, hasMaxRSS := parseKiB(field(used, 5))
	usedCPUSeconds := hmsSeconds(field(used, 6))
	if hasRequested {
		stats.RequestedMemory = humanKiB(requestedKiB)
	}
	if hasMaxRSS {
		stats.MaxRSS = humanKiB(maxRSSKiB)
	}
	if usedCPUSeconds > 0 && allocatedCPUSeconds > 0 {
		stats.CPUEfficiencyPct = usedCPUSeconds / allocatedCPUSeconds * 100
	}
	if hasMaxRSS && hasRequested && requestedKiB > 0 {
		stats.MemoryEfficiencyPct = maxRSSKiB / requestedKiB * 100
	}
	return stats
}

func Account(ctx context.Context, runner ssh.Runner, alias, name string, startedAt, now time.Time) (Stats, error) {
	output, err := runner.Run(ctx, alias, nil, "sacct", "-P", "-n", "--units=K", "--starttime="+lookback(startedAt, now), "--name="+name, "--format="+accountingFormat)
	if err != nil {
		return Stats{}, err
	}
	return parseStats(strings.TrimSpace(output)), nil
}
