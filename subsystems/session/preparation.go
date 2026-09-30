// Session preparation validates public requests against discovered Slurm resources and resolves the root folder.
// It builds the Linkspan workflow and job script, then performs bounded provisioning and submission operations.
// Validate narrates into a throwaway log so a dry run never writes into a session's visible log tail.
// Slurm framing and parsing live in internal/slurm; session policy and API error mapping remain here.
// Secrets are composed only at the final submission boundary.
package session

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	pathpkg "path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/slurm"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

type sessionPlan struct {
	session  Session
	script   string
	home     string
	linkspan string
}

func (s Service) Validate(ctx context.Context, principal security.Principal, request CreateRequest) (*ValidationResult, error) {
	s = s.forPrincipal(principal)
	s.logs = newSessionLogs()
	request, err := assignSessionID(request, principal)
	if err != nil {
		return nil, err
	}
	if _, err := s.devtunnelCredential(ctx, principal, request.TunnelModes); err != nil {
		return nil, err
	}
	plan, err := s.planSession(ctx, request)
	if err != nil {
		return nil, err
	}
	result, err := slurm.Check(ctx, s.runner, plan.session.Alias, plan.script)
	if err != nil {
		return nil, err
	}
	status := "FAILED"
	if result.Passed {
		status = "PASSED"
	}
	return &ValidationResult{
		SessionID: plan.session.ID,
		Script:    plan.script,
		Status:    status,
		Message:   validationMessage(result),
		Stdout:    strings.TrimSpace(result.Stdout),
		Stderr:    strings.TrimSpace(result.Stderr),
	}, nil
}

func invalidRootFolder(message string) error {
	return security.New("invalid_root_folder", message, http.StatusBadRequest)
}

func resourcesFit(resources Resources, partition Partition) bool {
	return resources.Cores <= partition.CPUCount && resources.MemoryMB <= partition.MemoryMB
}

func hasGPU(partition Partition) bool {
	return slices.ContainsFunc(partition.GRES, func(g Gres) bool { return g.Name == "gpu" || strings.HasPrefix(g.Name, "gpu:") })
}

func gpuSupports(partition Partition, gpuType string, gpuCount int) bool {
	return slices.ContainsFunc(partition.GRES, func(g Gres) bool {
		return g.Count >= gpuCount && (g.Name == "gpu" || strings.TrimPrefix(g.Name, "gpu:") == gpuType)
	})
}

func safeRemotePath(value string) bool {
	return remotePathPattern.MatchString(value) && pathpkg.Clean(value) == value && value != "/"
}

func homeRootExpression(value string) bool {
	return value == "." || value == "~" || value == "$HOME" || value == "${HOME}"
}

func resolveRemoteExecutable(value, home string) string {
	rest, anchored := strings.CutPrefix(value, "$HOME/")
	if !anchored {
		return value
	}
	return pathpkg.Join(home, rest)
}

func safeRootFolderSuffix(value string) bool {
	if value == "" || pathpkg.Clean(value) != value || strings.HasPrefix(value, "/") {
		return false
	}
	for _, part := range strings.Split(value, "/") {
		if part == "" || part == "." || part == ".." || !rootFolderSegment.MatchString(part) {
			return false
		}
	}
	return true
}

func validatePartitionResources(values []Partition, name string, resources Resources) error {
	matches := slices.DeleteFunc(slices.Clone(values), func(p Partition) bool { return p.Name != name })
	if len(matches) == 0 {
		return security.New("invalid_partition", "Slurm partition was not discovered for this SSH host", http.StatusBadRequest)
	}
	fits := func(p Partition) bool { return resourcesFit(resources, p) }
	gpuRequested := resources.GPUCount != 0 || resources.GPUType != ""
	if gpuRequested && (resources.GPUCount < 1 || !security.SafeName(resources.GPUType, 64)) {
		return security.New("invalid_gpu", "gpuType and positive gpuCount must be supplied together", http.StatusBadRequest)
	}
	if !gpuRequested {
		if slices.ContainsFunc(matches, func(p Partition) bool { return !hasGPU(p) && fits(p) }) {
			return nil
		}
		return security.New("invalid_resource", "no CPU variant of the selected partition supports the requested resources", http.StatusBadRequest)
	}
	supported := slices.DeleteFunc(matches, func(p Partition) bool { return !gpuSupports(p, resources.GPUType, resources.GPUCount) })
	switch {
	case slices.ContainsFunc(supported, fits):
		return nil
	case len(supported) != 0:
		return security.New("invalid_resource", "requested CPU or memory exceeds the matching GPU partition capacity", http.StatusBadRequest)
	}
	return security.New("invalid_gpu", "requested GPU is not available in the selected partition", http.StatusBadRequest)
}

func oneRemotePath(output string) (string, error) {
	value := strings.TrimSuffix(output, "\n")
	if value == "" || strings.ContainsAny(value, "\r\n") || !safeRemotePath(value) {
		return "", errors.New("not one safe absolute path")
	}
	return value, nil
}

func safeRemoteExecutable(value string) bool {
	if rest, anchored := strings.CutPrefix(value, "$HOME/"); anchored {
		return safeRemotePath("/" + rest)
	}
	return safeRemotePath(value) && strings.HasPrefix(value, "/")
}

func validRootFolderExpression(value string) bool {
	if value == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	if homeRootExpression(value) {
		return true
	}
	if strings.HasPrefix(value, "/") {
		return safeRemotePath(value)
	}
	if strings.HasPrefix(value, "~/") {
		return safeRootFolderSuffix(strings.TrimPrefix(value, "~/"))
	}
	if match := rootFolderVar.FindStringSubmatch(value); match != nil {
		return !strings.HasSuffix(value, "/") && len(cmp.Or(match[1], match[2])) <= 64 && (match[3] == "" || safeRootFolderSuffix(match[3]))
	}
	return safeRootFolderSuffix(value)
}

func canonicalTunnelModes(transports []string) ([]string, error) {
	transports = slices.Sorted(slices.Values(transports))
	if len(transports) == 0 || len(slices.Compact(slices.Clone(transports))) != len(transports) || slices.ContainsFunc(transports, func(transport string) bool { return linkspanTransportFlags[transport] == "" }) {
		return nil, security.New("invalid_tunnel_modes", "tunnelModes must be distinct values from link and devtunnel", http.StatusBadRequest)
	}
	return transports, nil
}

func validateCreate(request *CreateRequest) (err error) {
	if request.ID == "" && request.IdempotencyKey == "" {
		return security.New("invalid_idempotency_key", "idempotencyKey is required", http.StatusBadRequest)
	}
	if !ssh.ValidAlias(request.Alias) {
		return ssh.ErrInvalidAlias
	}
	if !security.SafeName(request.Partition, 64) {
		return security.New("invalid_partition", "invalid partition", http.StatusBadRequest)
	}
	if request.Account != "" && !security.SafeName(request.Account, 64) {
		return security.New("invalid_account", "invalid account", http.StatusBadRequest)
	}
	if !validRootFolderExpression(request.RootFolder) {
		return invalidRootFolder("rootFolder must be a safe POSIX path: absolute, relative to the home, or under $HOME or $VAR")
	}
	if request.Resources.Cores < minCores || request.Resources.Cores > 4096 {
		return security.New("invalid_resources", "cores must be between 2 and 4096", http.StatusBadRequest)
	}
	if request.Resources.MemoryMB < minMemoryMB || request.Resources.MemoryMB > 100_000_000 {
		return security.New("invalid_resources", "memoryMb is out of range", http.StatusBadRequest)
	}
	if request.Resources.WallMinutes < 1 || request.Resources.WallMinutes > 525600 {
		return security.New("invalid_resources", "wallMinutes is out of range", http.StatusBadRequest)
	}
	if request.IdempotencyKey != "" && (len(request.IdempotencyKey) > 128 || strings.ContainsAny(request.IdempotencyKey, "\x00\r\n")) {
		return security.New("invalid_idempotency_key", "invalid idempotency key", http.StatusBadRequest)
	}
	if request.TunnelModes == nil {
		request.TunnelModes = []string{transportLink}
	}
	request.TunnelModes, err = canonicalTunnelModes(request.TunnelModes)
	return err
}

func validateRootFolderPrivateLayout(home, rootFolder, privateRoot, sessionID, expression string) error {
	if rootFolder == privateRoot || strings.HasPrefix(rootFolder, privateRoot+"/") {
		return invalidRootFolder("root folder resolves inside the private session directory")
	}
	if !strings.HasPrefix(privateRoot, rootFolder+"/") {
		return nil
	}
	expected := pathpkg.Join(home, defaultSessionBase, sessionID)
	if rootFolder == home && homeRootExpression(expression) && privateRoot == expected {
		return nil
	}
	return invalidRootFolder("root folder may contain private session state only at $HOME/.cybershuttle/sessions/{sessionId}")
}

func (s Service) discover(ctx context.Context, alias string) (Resource, error) {
	discovered, err := slurm.Discover(ctx, s.runner, alias)
	if failure, ok := errors.AsType[*slurm.DiscoveryError](err); ok {
		return Resource{}, security.New("slurm_discovery_failed", failure.Error(), http.StatusBadGateway)
	}
	if err != nil {
		return Resource{}, err
	}
	partitions := make([]Partition, len(discovered.Partitions))
	for index, discovered := range discovered.Partitions {
		values := make([]Gres, len(discovered.GRES))
		for resourceIndex, value := range discovered.GRES {
			values[resourceIndex] = Gres{Name: value.Name, Count: value.Count}
		}
		partitions[index] = Partition{Name: discovered.Name, CPUCount: discovered.CPUCount, MemoryMB: discovered.MemoryMB, GRES: values}
	}
	return Resource{Alias: alias, Accounts: discovered.Accounts, Partitions: partitions, HomeDir: discovered.Home}, nil
}

const provisionTimeout = 5 * time.Minute

const provisionScript = `set -u
LC_ALL=C
LANG=C
export LC_ALL LANG
[ "$#" -eq 5 ] && [ "$1" = cs-provision ] || { printf '%s\n' 'error=arguments'; exit 70; }
shift
home=$1
linkspan=$2
workflow=$3
document=$4
case "$home" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac
case "$linkspan" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac
case "$workflow" in /*) ;; *) printf '%s\n' 'error=arguments'; exit 70 ;; esac

# Newest wins, and a tie goes to the release: a build made by hand carries a
# version above the published one and is left alone, while a release that has
# caught up (same tag or higher) replaces it. Both installers follow this rule,
# so neither can undo the other.
installed=""
[ -x "$linkspan" ] && installed=$("$linkspan" --version 2>/dev/null | head -1 | tr -d 'v \r')
latest=$(curl -fsSLI -o /dev/null -w '%{url_effective}' \
  https://github.com/cyber-shuttle/linkspan/releases/latest 2>/dev/null | sed 's#.*/##' | tr -d 'v \r')
# What is installed is X.Y.Z for a release or X.Y.Z.<commit> for a build ahead
# of one; anything else -- an unversioned build above all else -- sorts above
# every release under sort -V, so it does not count as a version at all. What is
# published is always a release, so equal numbers mean the release has caught up
# and takes over, whether what is installed is a build or the same release.
installed=$(printf '%s' "$installed" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+(\.[0-9a-f]{7,40})?$')
numbers=$(printf '%s' "$installed" | cut -d. -f1-3)
latest=$(printf '%s' "$latest" | grep -Eo '^[0-9]+\.[0-9]+\.[0-9]+$')
keep=0
if [ -n "$installed" ]; then
  if [ -z "$latest" ]; then
    # No published release to compare against; a working binary beats a guess.
    keep=1
  elif [ "$numbers" != "$latest" ]; then
    [ "$(printf '%s\n%s\n' "$numbers" "$latest" | sort -V | tail -1)" = "$numbers" ] && keep=1
  elif [ "$installed" = "$numbers" ]; then
    # The published release is already the one installed: nothing to fetch. A
    # build ahead of it carries the commit that says so, and yields to it.
    keep=1
  fi
fi
if [ "$keep" = 1 ]; then
  printf '%s\n' 'linkspan=present'
else
  bin_dir=$(dirname "$linkspan")
  install -d -m 700 "$bin_dir" 2>/dev/null || { printf '%s\n' 'error=linkspan-directory'; exit 77; }
  arch=$(uname -m)
  case "$arch" in
    x86_64) arch=x86_64 ;;
    aarch64|arm64) arch=arm64 ;;
    *) printf '%s\n' 'error=architecture'; exit 78 ;;
  esac
  staged="$bin_dir/.linkspan.$$"
  # Staged and moved, so a partial download never becomes the binary a job execs.
  curl -fsSL "https://github.com/cyber-shuttle/linkspan/releases/latest/download/linkspan_Linux_${arch}.tar.gz" 2>/dev/null |
    tar -xzO linkspan > "$staged" 2>/dev/null || {
      rm -f "$staged"; printf '%s\n' 'error=linkspan-download'; exit 79; }
  [ -s "$staged" ] || { rm -f "$staged"; printf '%s\n' 'error=linkspan-download'; exit 79; }
  chmod 700 "$staged" && mv -f "$staged" "$linkspan" || {
    rm -f "$staged"; printf '%s\n' 'error=linkspan-install'; exit 80; }
  printf '%s\n' 'linkspan=installed'
fi
# A Linkspan below the floor refuses the session's flags or document and takes
# the session with it, so it is refused here instead.
floor=` + linkspanFloor + `
version=$("$linkspan" --version 2>/dev/null | head -1 | tr -d 'v \r')
[ "$(printf '%s\n%s\n' "$floor" "$version" | sort -V | head -1)" = "$floor" ] || {
  printf '%s\n' 'error=linkspan-unsupported'; exit 81; }

# What the session is for travels with it, staged and moved so a partial
# write never becomes the document Linkspan reads.
umask 077
staged="$workflow.staged"
install -d -m 700 "$(dirname "$workflow")" 2>/dev/null &&
  printf '%s' "$document" | base64 -d > "$staged" 2>/dev/null &&
  [ -s "$staged" ] && mv -f "$staged" "$workflow" || {
    rm -f "$staged"; printf '%s\n' 'error=workflow'; exit 82; }
printf '%s\n' 'provision=complete'
`

var provisionFailures = map[string]string{
	"arguments":            "the SSH host was given paths it could not use",
	"linkspan-directory":   "could not create the directory the Linkspan binary belongs in",
	"architecture":         "the SSH host reports an architecture Linkspan is not released for",
	"linkspan-download":    "could not download the Linkspan release",
	"linkspan-install":     "could not install the downloaded Linkspan binary",
	"linkspan-unsupported": "the Linkspan on this SSH host is older than " + linkspanFloor + ", so it cannot link this session to cs-plane",
	"workflow":             "could not write the workflow the session runs",
}

func sessionWorkflowPath(session Session) string {
	return strings.TrimSuffix(session.PrivateRoot, "/") + "/workflow.yaml"
}

func minutesToWalltime(minutes int) string {
	days, rest := minutes/(24*60), minutes%(24*60)
	hours, mins := rest/60, rest%60
	if days > 0 {
		return fmt.Sprintf("%d-%02d:%02d:00", days, hours, mins)
	}
	return fmt.Sprintf("%02d:%02d:00", hours, mins)
}

func validationMessage(result slurm.CheckResult) string {
	if result.Passed {
		if message := strings.TrimSpace(result.Stdout); message != "" {
			return message
		}
		return "Slurm accepted the job script."
	}
	if message := strings.TrimSpace(result.Stderr); message != "" {
		return message
	}
	if message := strings.TrimSpace(result.Stdout); message != "" {
		return message
	}
	return "Slurm rejected the job script."
}

func buildScript(session Session, linkspan string) string {
	walltime := minutesToWalltime(session.Resources.WallMinutes)
	lines := []string{"#!/bin/bash", "#SBATCH --nodes=1", "#SBATCH --ntasks=1", "#SBATCH --cpus-per-task=" + strconv.Itoa(session.Resources.Cores), "#SBATCH --mem=" + strconv.Itoa(session.Resources.MemoryMB) + "M", "#SBATCH --time=" + walltime, "#SBATCH --partition=" + session.Partition}
	if session.Account != "" {
		lines = append(lines, "#SBATCH --account="+session.Account)
	}
	if session.Resources.GPUCount > 0 {
		gres := "#SBATCH --gres=gpu:"
		if session.Resources.GPUType != "gpu" {
			gres += session.Resources.GPUType + ":"
		}
		lines = append(lines, gres+strconv.Itoa(session.Resources.GPUCount))
	}
	logBase := session.ID + "-" + strconv.Itoa(session.Seq)
	lines = append(lines,
		"set -eu", "umask 077", `LOG_DIR="$HOME/.cybershuttle/logs"`, `install -d -m 700 "$LOG_DIR"`, `exec >"$LOG_DIR/`+logBase+`.out" 2>"$LOG_DIR/`+logBase+`.err"`, "unset XDG_RUNTIME_DIR TMPDIR",
		"LINKSPAN_BIN="+ssh.ShellQuote(linkspan),
		`exec "$LINKSPAN_BIN" --port "$CS_CONTROL_PORT" `+linkspanTransportArgs(session.TunnelModes)+` --workflow `+ssh.ShellQuote(sessionWorkflowPath(session)),
		"")
	return strings.Join(lines, "\n")
}

func sessionWorkflow(session Session) string {
	port := strconv.Itoa(int(ports(session.ID, session.Seq).Jupyter))
	return strings.Join([]string{
		"name: cs-session",
		"tasks:",
		"  - on: start",
		"    steps:",
		"      - name: Start Jupyter Server",
		"        action: jupyter.sessions.start",
		"        params:",
		"          root_dir: " + fmt.Sprintf("%q", session.RootFolderPath),
		"          addr: " + fmt.Sprintf("%q", "127.0.0.1:"+port),
		"",
	}, "\n")
}

func provisionOutcome(output string) map[string]string {
	report := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		if key, value, found := strings.Cut(strings.TrimSpace(line), "="); found {
			report[key] = value
		}
	}
	return report
}

func provisionMessage(alias, failure, stderr string) string {
	if reason, known := provisionFailures[failure]; known {
		return fmt.Sprintf("Preparing the session environment on %s failed: %s.", alias, reason)
	}
	if detail := strings.TrimSpace(stderr); detail != "" {
		return fmt.Sprintf("Preparing the session environment on %s failed: %s", alias, detail)
	}
	return "Preparing the session environment on " + alias + " failed."
}

func (s Service) linkURL(id string) string {
	return "ws" + strings.TrimPrefix(s.PublicURL, "http") + "/api/v1/sessions/" + id + "/link"
}

func (s Service) submitSessionScript(ctx context.Context, session Session, script string, tokens runTokens, hostToken string) (string, error) {
	environment := linkspanEnvironment(session.TunnelModes, s.linkURL(session.ID), tokens.LinkToken, session.Devtunnel, hostToken)
	environment["JUPYTER_TOKEN"], environment["CS_CONTROL_PORT"] = tokens.JupyterToken, strconv.Itoa(int(ports(session.ID, session.Seq).Control))
	return slurm.Submit(ctx, s.runner, session.Alias, slurm.SubmitRequest{JobName: session.JobName, Script: script, Environment: environment})
}

func (s Service) provisionSession(ctx context.Context, session Session, home, linkspan string) error {
	alias := session.Alias
	key := s.runner.ConfigPath + "\x00" + alias
	if _, busy := s.hostPreparations.LoadOrStore(key, true); busy {
		return security.New("session_provisioning_in_progress",
			"The session environment on "+alias+" is still being prepared. Try again in a moment.", http.StatusConflict)
	}
	defer s.hostPreparations.Delete(key)
	ctx, cancel := context.WithTimeout(ctx, provisionTimeout)
	defer cancel()
	s.sessionStatus(session.ID, "Preparing the session environment")
	document := base64.StdEncoding.EncodeToString([]byte(sessionWorkflow(session)))
	outText, errText, runErr := s.runner.RunOutput(ctx, alias, strings.NewReader(provisionScript),
		"sh", "-s", "--", "cs-provision", home, linkspan, sessionWorkflowPath(session), document)
	report := provisionOutcome(outText)
	if runErr != nil {
		if ctx.Err() != nil {
			return security.New("session_provisioning_failed", "Preparing the session environment on "+alias+" timed out.", http.StatusGatewayTimeout)
		}
		if ssh.AuthenticationFailure(errText) {
			return ssh.ClassifyFailure(alias, errText, runErr)
		}
		return security.New("session_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	if report["provision"] != "complete" {
		return security.New("session_provisioning_failed", provisionMessage(alias, report["error"], errText), http.StatusBadGateway)
	}
	if report["linkspan"] == "installed" {
		s.sessionStatus(session.ID, "Installed Linkspan")
	}
	s.sessionStatus(session.ID, "Session environment ready")
	return nil
}

func (s Service) planSession(ctx context.Context, request CreateRequest) (_ *sessionPlan, resultErr error) {
	s.sessionStatus(request.ID, "Preparing session")
	defer func() {
		if resultErr != nil {
			status := "Session preparation failed"
			if security.For(resultErr).Code == "ssh_authentication_required" {
				status = "Interactive SSH authentication required"
			}
			s.sessionStatus(request.ID, status)
		}
	}()
	resource, err := s.discover(ctx, request.Alias)
	if err != nil {
		return nil, fmt.Errorf("discover session resource: %w", err)
	}
	if request.Account != "" && !slices.Contains(resource.Accounts, request.Account) {
		return nil, security.New("invalid_account", "Slurm account was not discovered for this SSH host", http.StatusBadRequest)
	}
	if err := validatePartitionResources(resource.Partitions, request.Partition, request.Resources); err != nil {
		return nil, err
	}
	privateRoot := pathpkg.Join(resource.HomeDir, defaultSessionBase, request.ID)
	if !safeRemotePath(privateRoot) {
		return nil, errors.New("resolved private session path is unsafe")
	}
	rootFolderPath, err := s.resolveRootFolder(ctx, request.Alias, resource.HomeDir, request.RootFolder)
	if err != nil {
		return nil, err
	}
	if err := validateRootFolderPrivateLayout(resource.HomeDir, rootFolderPath, privateRoot, request.ID, request.RootFolder); err != nil {
		return nil, err
	}
	session := Session{
		SessionResponse: SessionResponse{ID: request.ID, Alias: request.Alias, Account: request.Account, Partition: request.Partition, RootFolder: request.RootFolder, Resources: request.Resources, TunnelModes: request.TunnelModes},
		PrivateRoot:     privateRoot, RootFolderPath: rootFolderPath,
	}
	s.sessionStatus(request.ID, "Session preparation complete")
	linkspan := resolveRemoteExecutable(s.LinkspanPath, resource.HomeDir)
	return &sessionPlan{session: session, script: buildScript(session, linkspan), home: resource.HomeDir, linkspan: linkspan}, nil
}

func (s Service) resolveRootFolder(ctx context.Context, alias, home, expression string) (string, error) {
	if !validRootFolderExpression(expression) || !safeRemotePath(home) {
		return "", invalidRootFolder("root folder expression is invalid")
	}
	base, suffix := home, ""
	switch {
	case homeRootExpression(expression):
	case strings.HasPrefix(expression, "/"):
		base = expression
	case strings.HasPrefix(expression, "~/"):
		suffix = strings.TrimPrefix(expression, "~/")
	case rootFolderVar.MatchString(expression):
		match := rootFolderVar.FindStringSubmatch(expression)
		name := cmp.Or(match[1], match[2])
		suffix = match[3]
		if name != "HOME" {
			output, err := s.runner.Run(ctx, alias, nil, "printenv", name)
			if err != nil {
				return "", invalidRootFolder("root folder environment variable " + name + " is unavailable")
			}
			base, err = oneRemotePath(output)
			if err != nil {
				return "", invalidRootFolder("root folder environment variable " + name + " must contain one absolute safe path")
			}
		}
	default:
		suffix = expression
	}
	resolved := base
	if suffix != "" {
		resolved = pathpkg.Join(base, suffix)
	}
	if !safeRemotePath(resolved) {
		return "", invalidRootFolder("root folder resolves to an unsafe path")
	}
	return resolved, nil
}
