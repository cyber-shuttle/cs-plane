// Session lifecycle tests cover durable transitions, compensation, and concurrency.
// One fake SSH boundary drives complete define, start, stop and delete flows.
// Races assert that persisted intent wins over delayed remote work.
// Detached work survives request cancellation and stops with the service.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func fakeSSH(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	status := filepath.Join(dir, "status")
	scriptLog := filepath.Join(dir, "script")
	validationScriptLog := filepath.Join(dir, "validation-script")
	commandLog := filepath.Join(dir, "commands")
	statusScriptLog := filepath.Join(dir, "status-script")
	discoveryScriptLog := filepath.Join(dir, "discovery-script")
	acceptedJobName := filepath.Join(dir, "accepted-job-name")
	schedulerQueryCount := filepath.Join(dir, "scheduler-query-count")
	acceptedJobID := filepath.Join(dir, "accepted-job-id")
	testutil.Check(t, os.WriteFile(status, []byte("RUNNING\n"), 0o600))
	path := filepath.Join(dir, "ssh")
	script := `#!/bin/sh
set -eu
if [ "$1" = "-G" ]; then
  shift
  while [ "$1" = "-o" ] || [ "$1" = "-F" ]; do shift 2; done
  printf 'host %s\nhostname %s.example\nuser tester\nport 22\n' "$1" "$1"
  exit 0
fi
while [ "$1" = "-o" ] || [ "$1" = "-F" ]; do shift 2; done
alias=$1; shift
[ "$#" -eq 1 ] || { echo "expected one OpenSSH remote command argument" >&2; exit 2; }
wire_command=$1
printf '%s|%s\n' "$alias" "$wire_command" >> "$FAKE_COMMAND_LOG"
if printf '%s' "$wire_command" | grep -q 'cs-session-log-tail'; then
  cat > /dev/null
  eval "set -- $wire_command"
  shift 4
  while [ "$#" -gt 0 ]; do
    session_id=$1; shift 2
    printf '__CS_SESSION_LOG__|%s|stdout\n' "$session_id"
    printf '%s' "${FAKE_SESSION_STDOUT:-}" | od -An -v -tx1 | tr -d ' \n'
    printf '\n__CS_SESSION_LOG__|%s|stderr\n' "$session_id"
    printf '\n'
  done
  exit 0
fi
if [ "$wire_command" = "'sh' '-s' '--' 'cs-session-status'" ]; then
  payload=$(cat)
  printf '%s\n__CS_SCRIPT_END__\n' "$payload" >> "$FAKE_STATUS_SCRIPT_LOG"
  query_count=0; [ ! -f "$FAKE_SCHEDULER_QUERY_COUNT" ] || query_count=$(cat "$FAKE_SCHEDULER_QUERY_COUNT")
  query_count=$((query_count + 1)); printf '%s\n' "$query_count" > "$FAKE_SCHEDULER_QUERY_COUNT"
  job_id=12345; [ ! -f "$FAKE_ACCEPTED_JOB_ID" ] || job_id=$(cat "$FAKE_ACCEPTED_JOB_ID")
  if printf '%s' "$payload" | grep -q 'scancel '; then
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s' "$payload" | grep -o 'scancel [^)]*' | sed 's/ 2>&1$//' | tr -d "'" | sed 's/^/batch /' >> "$FAKE_SCANCEL_LOG"
    if [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ]; then printf 'CANCELLED\n' > "$FAKE_STATUS"; fi
  fi
  [ -z "${FAKE_STATUS_STARTED:-}" ] || : > "$FAKE_STATUS_STARTED"
  while [ -n "${FAKE_STATUS_RELEASE:-}" ] && [ ! -e "$FAKE_STATUS_RELEASE" ]; do sleep .02; done
  [ "${FAKE_STATUS_FAIL:-0}" = 0 ] || { printf 'scheduler unavailable\n' >&2; exit 1; }
  printf '__CS_SCANCEL__\n'
  [ -z "${FAKE_CANCEL_ERRORS:-}" ] || printf '%b\n' "$FAKE_CANCEL_ERRORS"
  if [ -n "${FAKE_STATUS_LINES+x}" ]; then
    printf '__CS_SQUEUE__\n%b\n__CS_SACCT__\n%b\n' "${FAKE_QUEUE_LINES-$FAKE_STATUS_LINES}" "$FAKE_STATUS_LINES"
    exit 0
  fi
  state=$(cat "$FAKE_STATUS")
  accepted_name=; [ ! -f "$FAKE_ACCEPTED_JOB_NAME" ] || accepted_name=$(cat "$FAKE_ACCEPTED_JOB_NAME")
  printf '__CS_SQUEUE__\n'
  if [ -n "$accepted_name" ] && { [ -z "${FAKE_SUBMIT_RELEASE:-}" ] || [ -e "$FAKE_SUBMIT_RELEASE" ]; }; then
    case "$state" in RUNNING|PENDING|CONFIGURING) printf '%s|%s|cn001|%s\n' "$job_id" "$state" "$accepted_name";; esac
  fi
  printf '__CS_SACCT__\n'
  if [ -n "$accepted_name" ] && { [ -z "${FAKE_SUBMIT_RELEASE:-}" ] || [ -e "$FAKE_SUBMIT_RELEASE" ]; }; then
    printf '%s|%s|cn001|%s|\n' "$job_id" "$state" "$accepted_name"
  fi
  exit 0
fi
if [ "$wire_command" = "'sh' '-s'" ]; then
  cat > "$FAKE_DISCOVERY_SCRIPT_LOG"
  if [ -n "${FAKE_DISCOVERY_BLOCK_ALIAS:-}" ] && [ "$alias" = "$FAKE_DISCOVERY_BLOCK_ALIAS" ]; then
    [ -z "${FAKE_DISCOVERY_STARTED:-}" ] || printf '1' > "$FAKE_DISCOVERY_STARTED"
    while [ -n "${FAKE_DISCOVERY_RELEASE:-}" ] && [ ! -e "$FAKE_DISCOVERY_RELEASE" ]; do sleep .01; done
  fi
  printf 'REMOTE SSH BANNER\n' >&2
  user=${FAKE_REMOTE_USER:-tester}
  printf '%s\n' "$DISC_USER"
  case "$user" in ''|*[!A-Za-z0-9_.-]*) printf '%s\n' "$DISC_ERROR_USER"; exit 72;; esac
  printf '%s\n%s\n' "$user" "$DISC_ACCOUNTS"
  printf 'Account|\nproject-a|\nproject-a|\n'
  if [ -n "${FAKE_DISCOVERY_PARTITIONS_FAIL:-}" ]; then printf '%s\n' "$DISC_ERROR_PARTITIONS"; exit 74; fi
  printf '%s\n' "$DISC_PARTITIONS"
  printf 'cpu*|24+|191000+|(null)\ngpu|64|515000|gpu:a100:2(S:2,5)\n%s\n' "$DISC_HOME"
  printf '/home/tester\n%s\n' "$DISC_DONE"
  exit 0
fi
eval "set -- $wire_command"
command="$*"
case "$command" in
  "sbatch --test-only")
    cat > "$FAKE_VALIDATION_SCRIPT_LOG"
    [ -z "${FAKE_VALIDATION_STDOUT:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDOUT"
    [ -z "${FAKE_VALIDATION_STDERR:-}" ] || printf '%s\n' "$FAKE_VALIDATION_STDERR" >&2
    [ "${FAKE_VALIDATION_FAIL:-0}" = 0 ] || exit "${FAKE_VALIDATION_FAIL}"
    ;;
  "sh -s -- cs-submit "*)
    PATH="$FAKE_BIN:$PATH" exec "$@"
    ;;
  "scancel "*)
    [ -z "${FAKE_SCANCEL_LOG:-}" ] || printf '%s\n' "$command" >> "$FAKE_SCANCEL_LOG"
    [ -z "${FAKE_SCANCEL_STARTED:-}" ] || : > "$FAKE_SCANCEL_STARTED"
    while [ -n "${FAKE_SCANCEL_RELEASE:-}" ] && [ ! -e "$FAKE_SCANCEL_RELEASE" ]; do sleep .01; done
    [ "${FAKE_SCANCEL_FAIL:-0}" = 0 ] || { echo 'scheduler temporarily unavailable' >&2; exit 1; }
    printf 'CANCELLED\n' > "$FAKE_STATUS"
    ;;
  "sh -s -- cs-provision "*)
    cat > /dev/null
    [ -z "${FAKE_PROVISION_STARTED:-}" ] || : > "$FAKE_PROVISION_STARTED"
    while [ -n "${FAKE_PROVISION_RELEASE:-}" ] && [ ! -e "$FAKE_PROVISION_RELEASE" ]; do sleep .01; done
    printf 'linkspan=present\n'
    printf 'provision=complete\n'
    ;;
  "printenv WORKSPACE") printf '/scratch/tester\n';;
  "printenv EMPTY") exit 1;;
  "printenv RELATIVE") printf 'relative/path\n';;
  "printenv MULTILINE") printf '/scratch/one\n/scratch/two\n';;
  "sacct -P -n --units=K --starttime="*)
    if [ -n "${FAKE_RUN_STATS_SLEEP_ONCE:-}" ] && [ ! -e "$FAKE_RUN_STATS_SLEEP_ONCE" ]; then
      : > "$FAKE_RUN_STATS_SLEEP_ONCE"
      sleep "${FAKE_RUN_STATS_SLEEP_SECONDS:-0}"
    fi
    printf '%s\n' "${FAKE_RUN_STATS_OUTPUT:-}"
    ;;
  *) echo "unexpected command: $command" >&2; exit 2;;
esac
`
	testutil.WriteScript(t, path, script)
	testutil.Check(t, os.Mkdir(filepath.Join(dir, "bin"), 0o700))
	testutil.WriteScript(t, filepath.Join(dir, "bin", "sbatch"), `#!/bin/sh
cat > "$FAKE_SCRIPT_LOG"
env | grep -E '^(CS_|LINKSPAN_|JUPYTER_)' | sort > "$FAKE_SUBMIT_ENV"
[ -z "${FAKE_SUBMIT_STARTED:-}" ] || : > "$FAKE_SUBMIT_STARTED"
while [ -n "${FAKE_SUBMIT_RELEASE:-}" ] && [ ! -e "$FAKE_SUBMIT_RELEASE" ]; do sleep .01; done
printf '%s\n' "${1#--job-name=}" > "$FAKE_ACCEPTED_JOB_NAME"
printf '%s\n' "${FAKE_JOB_ID:-12345}" > "$FAKE_ACCEPTED_JOB_ID"
printf '%s;cluster\n' "${FAKE_JOB_ID:-12345}"
`)
	t.Setenv("FAKE_BIN", filepath.Join(dir, "bin"))
	t.Setenv("FAKE_SUBMIT_ENV", filepath.Join(dir, "submit-env"))
	t.Setenv("FAKE_STATUS", status)
	t.Setenv("FAKE_SCRIPT_LOG", scriptLog)
	t.Setenv("FAKE_VALIDATION_SCRIPT_LOG", validationScriptLog)
	t.Setenv("FAKE_VALIDATION_STDOUT", "Job script accepted")
	t.Setenv("FAKE_VALIDATION_FAIL", "0")
	t.Setenv("FAKE_COMMAND_LOG", commandLog)
	t.Setenv("FAKE_STATUS_SCRIPT_LOG", statusScriptLog)
	t.Setenv("FAKE_DISCOVERY_SCRIPT_LOG", discoveryScriptLog)
	t.Setenv("FAKE_ACCEPTED_JOB_NAME", acceptedJobName)
	t.Setenv("FAKE_ACCEPTED_JOB_ID", acceptedJobID)
	t.Setenv("FAKE_SCHEDULER_QUERY_COUNT", schedulerQueryCount)
	const discoveryMarker = "__CS_DSC_6f1c9a7e4b2d8053_"
	t.Setenv("DISC_USER", discoveryMarker+"USER__")
	t.Setenv("DISC_ACCOUNTS", discoveryMarker+"ACCOUNTS__")
	t.Setenv("DISC_PARTITIONS", discoveryMarker+"PARTITIONS__")
	t.Setenv("DISC_HOME", discoveryMarker+"HOME__")
	t.Setenv("DISC_DONE", discoveryMarker+"DONE__")
	t.Setenv("DISC_ERROR_USER", discoveryMarker+"ERROR_USER__")
	t.Setenv("DISC_ERROR_PARTITIONS", discoveryMarker+"ERROR_PARTITIONS__")
	return path, scriptLog, commandLog
}

// newTestService is NewService without the background reconciler and sampler; tests drive those directly.
func newTestService(t *testing.T, runner ssh.Runner, store Store) Service {
	t.Helper()
	service := Service{
		Config: Config{
			Runners: testRunnerProvider{runner: runner}, Store: store, LinkspanPath: "/opt/cybershuttle/linkspan",
			UpstreamTimeout: runner.EffectiveTimeout(), PublicURL: "https://plane.example.edu",
		},
		runner: runner, logs: newSessionLogs(), usage: newSessionUsage(),
		hostPreparations: &sync.Map{}, now: time.Now, runtime: newSessionRuntime(), links: &sync.Map{},
	}
	t.Cleanup(service.Close)
	return service
}

func fakeSSHService(t *testing.T, sshBin string) Service {
	t.Helper()
	return newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: 5 * time.Second}, testSessionStore(t))
}

func testService(t *testing.T) Service {
	t.Helper()
	sshBin, _, _ := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	service.now = func() time.Time { return time.Unix(1, 0).UTC() }
	configureTestDevtunnel(t, &service)
	return service
}

func newTestCreateRequest() CreateRequest {
	return CreateRequest{ID: "s-012345abcdef", IdempotencyKey: "request-one", Alias: "delta", Account: "project-a", Partition: "cpu", RootFolder: "projects/example", Resources: Resources{Cores: 4, MemoryMB: 4096, WallMinutes: 60}, TunnelModes: []string{transportDevtunnel, transportLink}}
}

func TestSessionLifecycleUsesManagedLinkspanAndSeparateRoots(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	cancellations := filepath.Join(t.TempDir(), "cancellations")
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := fakeSSHService(t, sshBin)
	configureTestDevtunnel(t, &service)
	session, err := defineAndStart(context.Background(), service, newTestCreateRequest())
	testutil.Check(t, err)
	if session.State != "QUEUED" || session.PrivateRoot != "/home/tester/.cybershuttle/sessions/s-012345abcdef" || session.RootFolderPath != "/home/tester/projects/example" {
		t.Fatalf("unexpected session: %#v", session)
	}
	t.Setenv("FAKE_SESSION_STDOUT", "Linkspan started\n")
	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if len(listed) != 1 || listed[0].State != "READY" || listed[0].Node != "cn001" {
		t.Fatalf("unexpected list: %#v", listed)
	}
	stopped, err := service.Stop(testPrincipal, session.ID)
	if err != nil || stopped.State != "STOPPED" {
		t.Fatalf("unexpected stop: %#v %v", stopped, err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "scancel 12345") {
		t.Fatalf("known job was not cancelled: %q %v", data, err)
	}
	runs, err := service.Runs(testPrincipal)
	if err != nil || len(runs) != 1 || runs[0].SessionID != session.ID {
		t.Fatalf("stop did not freeze a run: %#v %v", runs, err)
	}
	if _, ok := service.logs.tail(session.ID); ok {
		t.Fatal("stop left the live log tail behind")
	}
}

func TestConcurrentStartsLaunchOneRun(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	started := filepath.Join(t.TempDir(), "discovery-started")
	release := filepath.Join(t.TempDir(), "discovery-release")
	t.Setenv("FAKE_DISCOVERY_BLOCK_ALIAS", "delta")
	t.Setenv("FAKE_DISCOVERY_STARTED", started)
	t.Setenv("FAKE_DISCOVERY_RELEASE", release)
	service := fakeSSHService(t, sshBin)
	configureTestDevtunnel(t, &service)

	session, _, err := service.Define(testPrincipal, newTestCreateRequest())
	testutil.Check(t, err)
	start := func() chan error {
		result := make(chan error, 1)
		go func() {
			_, err := service.Start(context.Background(), testPrincipal, session.ID)
			result <- err
		}()
		return result
	}
	first := start()
	testutil.WaitForFile(t, started)
	second := start()
	testutil.RemainsBlocked(t, second, "a competing start bypassed the in-flight launch")
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-first)
	if err := <-second; security.For(err).Code != "session_running" {
		t.Fatalf("a start racing an in-flight launch answered %v, not session_running", err)
	}
}

func TestOnlyTheDevtunnelTransportMakesADevTunnelAndItNeedsAnAccount(t *testing.T) {
	sshBin, _, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	manager := configureTestDevtunnel(t, &service)
	request := newTestCreateRequest()
	request.TunnelModes = []string{transportLink}
	session, err := defineAndStart(context.Background(), service, request)
	testutil.Check(t, err)
	if session.State != "QUEUED" || session.Devtunnel.ID != "" || len(manager.creates) != 0 {
		t.Fatalf("a link session made a Dev Tunnel: %#v, %d creates", session, len(manager.creates))
	}
	submitted := string(mustRead(t, os.Getenv("FAKE_SUBMIT_ENV")))
	for _, want := range []string{"CS_LINK_URL=wss://plane.example.edu/api/v1/sessions/" + session.ID + "/link", "LINKSPAN_LINK_TOKEN="} {
		if !strings.Contains(submitted, want) {
			t.Fatalf("submission is missing %q:\n%s", want, submitted)
		}
	}
	if strings.Contains(submitted, "CS_DEVTUNNEL_ID=") {
		t.Fatalf("submission named a Dev Tunnel it does not have:\n%s", submitted)
	}
	if commands := string(mustRead(t, commandLog)); strings.Contains(commands, "TOKEN=") {
		t.Fatalf("submission put a token on the command line:\n%s", commands)
	}

	service.DevtunnelCredentials = &testDevtunnelsAccounts{}
	handler := serviceHandler(t, &service)
	request.IdempotencyKey, request.TunnelModes = "request-two", []string{transportDevtunnel}
	body, err := json.Marshal(request)
	testutil.Check(t, err)
	defined := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/sessions", body))
	var created SessionResponse
	_ = json.Unmarshal(defined.Body.Bytes(), &created)
	for path, body := range map[string][]byte{"/api/v1/sessions/validate": body, "/api/v1/sessions/" + created.ID + "/start": nil} {
		if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, path, body)); response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"code":"devtunnels_account_required"`) {
			t.Fatalf("%s without a Dev Tunnels account = %d %s", path, response.Code, response.Body.String())
		}
	}
}

func TestServiceCloseWaitsForAStop(t *testing.T) {
	service := testService(t)
	manager := service.DevtunnelManager.(*testDevtunnelManager)
	manager.operationStarted, manager.operationBlock = make(chan struct{}), make(chan struct{})
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	session.State = "READY"
	session.Account = "project-a"
	session.RootFolder = "projects/example"
	session.RootFolderPath = "/home/tester/projects/example"
	session.PrivateRoot = "/home/tester/.cybershuttle/sessions/" + session.ID
	putSessions(t, service, session)

	var stopped *Session
	var stopErr error
	done := make(chan error, 1)
	go func() {
		stopped, stopErr = service.Stop(testPrincipal, session.ID)
		done <- stopErr
	}()
	<-manager.operationStarted
	closed := make(chan error, 1)
	go func() { service.Close(); closed <- nil }()
	testutil.RemainsBlocked(t, closed, "service closed while a stop was still running")
	close(manager.operationBlock)
	testutil.Within(t, closed, time.Second, "service did not close after stop completed")
	testutil.Within(t, done, time.Second, "stop did not complete")
	if stopped.State != "STOPPING" {
		t.Fatalf("stop = %#v", stopped)
	}
}

func TestDeleteClearsATerminalSessionAndItsCredential(t *testing.T) {
	service := testService(t)
	session := pendingSession(sessionLogIDOne, "delta", "12345")
	setTestSessionMetadata(&session)
	session.State = "FAILED"
	putSessions(t, service, session)
	testutil.Check(t, putCapability(service.CapabilityDir, session.ID, session.Seq, defaultSessionCapability()))
	service.logs.append(session.ID, "starting", service.utcNow())

	deleted, err := service.Delete(testPrincipal, session.ID)
	if err != nil || deleted.ID != session.ID {
		t.Fatalf("delete failed: %#v %v", deleted, err)
	}
	sessions, err := service.loadSessions()
	testutil.Check(t, err)
	for _, remaining := range sessions {
		if remaining.ID == session.ID {
			t.Fatalf("deleted session is still listed: %#v", remaining)
		}
	}
	if _, err := getCapability(service.CapabilityDir, session.ID, session.Seq); err == nil {
		t.Fatal("delete left the run's capability on disk")
	}
	if _, ok := service.logs.tail(session.ID); ok {
		t.Fatal("delete left the session log tail in memory")
	}
	if _, err := service.Delete(testPrincipal, session.ID); err == nil {
		t.Fatal("deleting an absent session should not succeed")
	}
}

func TestStopAndDeleteSurviveADevTunnelsReleaseFailure(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	manager := configureTestDevtunnel(t, &service)
	created, err := defineAndStart(context.Background(), service, newTestCreateRequest())
	testutil.Check(t, err)
	manager.deleteErr = errors.New("Dev Tunnels outage")

	stopped, err := service.Stop(testPrincipal, created.ID)
	testutil.Check(t, err)
	if stopped.State != "STOPPED" {
		t.Fatalf("unexpected state after stop: %#v", stopped)
	}
	if !strings.Contains(stopped.Error, "Dev Tunnels outage") {
		t.Fatalf("the release failure was not recorded on the session: %#v", stopped)
	}

	deleted, err := service.Delete(testPrincipal, created.ID)
	testutil.Check(t, err)
	if deleted.ID != created.ID {
		t.Fatalf("unexpected deleted session: %#v", deleted)
	}
}

func TestStartSerializesAcrossProcessesWithoutHoldingStoreLockDuringDevtunnelCreate(t *testing.T) {
	service := testService(t)
	manager := service.DevtunnelManager.(*testDevtunnelManager)
	manager.operationStarted = make(chan struct{})
	manager.operationBlock = make(chan struct{})
	request := newTestCreateRequest()
	sum := sha256.Sum256([]byte(request.ID))
	lockPath := filepath.Join(service.Store.Dir, fmt.Sprintf(".session-create-%02x.lock", int(sum[0])%len(createLocks)))
	processLock, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	testutil.Check(t, err)
	defer func() { _ = processLock.Close() }()
	testutil.Check(t, syscall.Flock(int(processLock.Fd()), syscall.LOCK_EX))

	done := make(chan error, 1)
	go func() {
		_, err := defineAndStart(context.Background(), service, request)
		done <- err
	}()
	testutil.RemainsBlocked(t, manager.operationStarted, "create bypassed the cross-process session lock")
	testutil.Check(t, syscall.Flock(int(processLock.Fd()), syscall.LOCK_UN))

	select {
	case <-manager.operationStarted:
	case <-time.After(time.Second):
		t.Fatal("Dev Tunnel create was never reached")
	}
	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.Store.locked(func(*state) error { return nil }) }()
	testutil.Within(t, lockAvailable, 300*time.Millisecond, "state lock was held during blocked Dev Tunnel create")

	close(manager.operationBlock)
	testutil.Check(t, <-done)
}

const testConnectToken = "test-connect-token"

const testHostToken = "test-host-token"

const testJupyterToken = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

var testPrincipal = security.Principal{Subject: "test-owner", Tenant: "test-tenant"}

var otherTestPrincipal = security.Principal{Subject: "other-owner", Tenant: "test-tenant"}

type testDevtunnelsAccounts struct {
	mu       sync.Mutex
	accounts map[security.Principal]devtunnel.Credential
}

func newTestDevtunnelsAccounts() *testDevtunnelsAccounts {
	return &testDevtunnelsAccounts{accounts: map[security.Principal]devtunnel.Credential{testPrincipal: {Scheme: "Bearer", Token: "test-devtunnels-account-token"}}}
}

func (b *testDevtunnelsAccounts) Credential(_ context.Context, principal security.Principal) (devtunnel.Credential, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.accounts[principal], nil
}

func reconciledList(ctx context.Context, service Service) ([]Session, error) {
	if err := service.reconcileAll(ctx); err != nil {
		return nil, err
	}
	return service.loadSessions()
}

type testDevtunnelManager struct {
	mu               sync.Mutex
	creates          []devtunnel.CreateRequest
	deletes          []devtunnel.DeleteRequest
	createErr        error
	deleteErr        error
	operationStarted chan struct{}
	operationBlock   chan struct{}
}

func (m *testDevtunnelManager) Create(_ context.Context, request devtunnel.CreateRequest) (devtunnel.Record, error) {
	if m.operationStarted != nil {
		close(m.operationStarted)
	}
	if m.operationBlock != nil {
		<-m.operationBlock
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.creates = append(m.creates, request)
	if m.createErr != nil {
		return devtunnel.Record{}, m.createErr
	}
	return devtunnel.Record{ID: request.TunnelID, ClusterID: "use", ConnectToken: testConnectToken, HostToken: testHostToken, ExpiresAt: time.Now().UTC().Add(time.Duration(request.DurationSeconds) * time.Second)}, nil
}

func (m *testDevtunnelManager) Get(context.Context, devtunnel.GetRequest) (devtunnel.Record, error) {
	return devtunnel.Record{}, nil
}

func (m *testDevtunnelManager) Delete(_ context.Context, request devtunnel.DeleteRequest) error {
	if m.operationStarted != nil {
		close(m.operationStarted)
	}
	if m.operationBlock != nil {
		<-m.operationBlock
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.deletes = append(m.deletes, request)
	return m.deleteErr
}

type testRunnerProvider struct{ runner ssh.Runner }

func (h testRunnerProvider) Runner(security.Principal) ssh.Runner { return h.runner }

func configureTestDevtunnel(t *testing.T, service *Service) *testDevtunnelManager {
	t.Helper()
	testutil.Check(t, security.EnsurePrivateDir(service.Store.Dir))
	manager := &testDevtunnelManager{}
	service.DevtunnelManager = manager
	service.DevtunnelCredentials = newTestDevtunnelsAccounts()
	service.CapabilityDir = t.TempDir() + "/session-capabilities"
	return manager
}

func setTestSessionMetadata(session *Session) {
	if session.Seq == 0 {
		session.Seq = 1
		session.Owner = testPrincipal
		session.Devtunnel = devtunnelMetadata{ID: session.ID + "-" + strconv.Itoa(session.Seq), ClusterID: "use", ExpiresAt: time.Now().Add(time.Hour)}
	}
}

func putSessions(t *testing.T, service Service, sessions ...Session) {
	t.Helper()
	testutil.Check(t, service.Store.locked(func(current *state) error {
		for i := range sessions {
			copy := sessions[i]
			setTestSessionMetadata(&copy)
			current.Sessions[copy.ID] = &copy
		}
		return service.Store.save(current)
	}))
}

func pendingSession(id, alias, jobID string) Session {
	now := time.Unix(1, 0).UTC()
	return Session{
		SessionResponse: SessionResponse{ID: id, State: "QUEUED", Alias: alias, Partition: "cpu", RootFolder: ".", Resources: Resources{Cores: 1, MemoryMB: 1024, WallMinutes: 60}, CreatedAt: now, UpdatedAt: now},
		JobID:           jobID, JobName: jobName(id, 1), PrivateRoot: "/home/test/.cybershuttle/sessions/" + id, RootFolderPath: "/home/test", Owner: testPrincipal,
	}
}

func createStopRaceService(t *testing.T) (Service, string, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "submit-started")
	release := filepath.Join(dir, "submit-release")
	cancellations := filepath.Join(dir, "cancellations")
	t.Setenv("FAKE_SUBMIT_STARTED", started)
	t.Setenv("FAKE_SUBMIT_RELEASE", release)
	t.Setenv("FAKE_SCANCEL_LOG", cancellations)
	service := testService(t)
	return service, started, release, cancellations
}

// waitFor waits for the fake SSH marker file at path while create is still running.
func waitFor(t *testing.T, errs <-chan error, what, path string) {
	t.Helper()
	testutil.Eventually(t, 5*time.Second, what, func() bool {
		select {
		case err := <-errs:
			t.Fatalf("Create finished before %s: %v", what, err)
		default:
		}
		_, err := os.Stat(path)
		return err == nil
	})
}

func TestStartCancelsJobWhenStopWinsBeforeSbatchReturns(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := defineAndStart(context.Background(), service, newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)

	stopped, err := service.Stop(testPrincipal, newTestCreateRequest().ID)
	if err != nil || stopped.State != "STOPPING" || stopped.JobID != "" {
		t.Fatalf("stop did not persist intent while sbatch was blocked: %#v %v", stopped, err)
	}
	testutil.Check(t, os.WriteFile(release, nil, 0o600))

	testutil.Within(t, errs, 5*time.Second, "Create did not finish after sbatch was released")
	created := <-result
	if created.State != "STOPPING" || created.JobID != "12345" || created.Error != "" {
		t.Fatalf("Create overwrote stop intent: %#v", created)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || strings.Count(string(data), "scancel 12345") != 1 {
		t.Fatalf("submitted job was not immediately cancelled exactly once: %q %v", data, err)
	}
	cached, err := service.loadSession(created.ID)
	if err != nil || cached.State != "STOPPING" || cached.JobID != "12345" {
		t.Fatalf("stored state lost stop/job identity: %#v %v", cached, err)
	}
}

func TestStartPersistsCancelFailureAndLaterBatchRetries(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	t.Setenv("FAKE_SCANCEL_FAIL", "1")
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	go func() {
		session, err := defineAndStart(context.Background(), service, newTestCreateRequest())
		result <- session
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)
	_, err := service.Stop(testPrincipal, newTestCreateRequest().ID)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	created := <-result
	if created.State != "STOPPING" || !strings.Contains(created.Error, "scheduler temporarily unavailable") {
		t.Fatalf("cancel failure was not persisted: %#v", created)
	}

	t.Setenv("FAKE_SCANCEL_FAIL", "0")
	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if len(listed) != 1 || listed[0].State != "STOPPED" || listed[0].Error != "" {
		t.Fatalf("later reconciliation did not retry cancellation: %#v", listed)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "batch scancel") {
		t.Fatalf("later batch did not retry cancellation: %q %v", data, err)
	}
}

func TestStartCancelsUnsavedJobEvenWithACancelledRequestContext(t *testing.T) {
	service, started, release, cancellations := createStopRaceService(t)
	cancelStarted := filepath.Join(t.TempDir(), "scancel-started")
	cancelRelease := filepath.Join(t.TempDir(), "scancel-release")
	t.Setenv("FAKE_SCANCEL_STARTED", cancelStarted)
	t.Setenv("FAKE_SCANCEL_RELEASE", cancelRelease)
	ctx, cancel := context.WithCancel(context.Background())
	request := newTestCreateRequest()
	errs := make(chan error, 1)
	go func() {
		_, err := defineAndStart(ctx, service, request)
		errs <- err
	}()
	waitFor(t, errs, "sbatch started", started)
	testutil.Check(t, service.Store.Database.Close())
	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	waitFor(t, errs, "compensation scancel started", cancelStarted)
	cancel()
	testutil.Check(t, os.WriteFile(cancelRelease, nil, 0o600))

	err := <-errs
	if err == nil || !strings.Contains(err.Error(), "job was cancelled") {
		t.Fatalf("compensation did not report a successful cancel with a cancelled request context: %v", err)
	}
	data, err := os.ReadFile(cancellations)
	if err != nil || !strings.Contains(string(data), "12345") {
		t.Fatalf("submitted job was not cancelled: %q %v", data, err)
	}
}

func retire(t *testing.T, service Service, id string) Session {
	t.Helper()
	var terminal Session
	testutil.Check(t, service.Store.locked(func(current *state) error {
		session := current.Sessions[id]
		session.State, session.Node = "STOPPED", "cn001"
		session.CreatedAt, session.UpdatedAt = time.Unix(0, 0).UTC(), time.Unix(0, 0).UTC()
		terminal = *session
		return service.Store.save(current)
	}))
	return terminal
}

func TestStartRunsTheFinishedSessionOnTheSameSession(t *testing.T) {
	service := testService(t)
	devtunnels := configureTestDevtunnel(t, &service)
	created, err := defineAndStart(context.Background(), service, newTestCreateRequest())
	testutil.Check(t, err)
	terminal := retire(t, service, created.ID)

	started, err := service.Start(context.Background(), testPrincipal, created.ID)
	testutil.Check(t, err)
	if started.State != "QUEUED" || started.Seq == terminal.Seq || started.Node != "" {
		t.Fatalf("unexpected next run: %#v", started)
	}
	if !started.CreatedAt.Equal(terminal.CreatedAt) || !started.UpdatedAt.After(terminal.UpdatedAt) {
		t.Fatalf("the next run must keep the session's creation time and move it forward: %#v", started.SessionResponse)
	}
	if len(devtunnels.deletes) != 1 || devtunnels.deletes[0].TunnelID != created.ID+"-"+strconv.Itoa(terminal.Seq) {
		t.Fatalf("the finished run's Dev Tunnel was not released: %#v", devtunnels.deletes)
	}
}

func TestStartRefusesSessionsItMayNotRun(t *testing.T) {
	service := testService(t)
	created, err := defineAndStart(context.Background(), service, newTestCreateRequest())
	testutil.Check(t, err)
	if _, err := service.Start(context.Background(), testPrincipal, created.ID); err == nil || security.For(err).Code != "session_running" {
		t.Fatalf("a live session was started again: %v", err)
	}
	retire(t, service, created.ID)

	stranger := security.Principal{Subject: "other-owner", Tenant: "test-tenant"}
	if _, err := service.Start(context.Background(), stranger, created.ID); err == nil || security.For(err).Code != "session_owner_mismatch" {
		t.Fatalf("another principal ran this session: %v", err)
	}
	if _, err := service.Start(context.Background(), testPrincipal, "s-999999999999"); err == nil || security.For(err).Code != "session_not_found" {
		t.Fatalf("an unknown session was run: %v", err)
	}
}

func nextRunRaceService(t *testing.T) (Service, *atomic.Int64, string, string) {
	t.Helper()
	dir := t.TempDir()
	started := filepath.Join(dir, "provision-started")
	release := filepath.Join(dir, "provision-release")
	t.Setenv("FAKE_PROVISION_STARTED", started)
	clock := &atomic.Int64{}
	clock.Store(time.Date(2026, 8, 28, 10, 0, 0, 0, time.UTC).UnixNano())
	service := testService(t)
	service.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	return service, clock, started, release
}

func TestPostIntentWorkOutlivesRequestAndStopsWithService(t *testing.T) {
	sshBin, _, _ := fakeSSH(t)
	dir := t.TempDir()
	provisionStarted, provisionRelease := filepath.Join(dir, "provision-started"), filepath.Join(dir, "provision-release")
	submitStarted := filepath.Join(dir, "submit-started")
	t.Setenv("FAKE_PROVISION_STARTED", provisionStarted)
	t.Setenv("FAKE_PROVISION_RELEASE", provisionRelease)
	t.Setenv("FAKE_SUBMIT_STARTED", submitStarted)
	t.Setenv("FAKE_SUBMIT_RELEASE", filepath.Join(dir, "never-released"))
	service := fakeSSHService(t, sshBin)
	configureTestDevtunnel(t, &service)
	ctx, cancel := context.WithCancel(context.Background())
	created := make(chan error, 1)
	go func() { _, err := defineAndStart(ctx, service, newTestCreateRequest()); created <- err }()
	waitFor(t, created, "provisioning started", provisionStarted)
	cancel()
	testutil.Check(t, os.WriteFile(provisionRelease, nil, 0o600))
	waitFor(t, created, "submission started", submitStarted)

	closed := make(chan error, 1)
	go func() { service.Close(); closed <- nil }()
	testutil.Within(t, closed, time.Second, "Close did not cancel and wait for submission")
	if err := <-created; err == nil {
		t.Fatal("cancelled submission succeeded")
	}
	if _, _, ok := service.runtime.begin(); ok {
		t.Fatal("closed runtime accepted new work")
	}
}

func TestTheNextRunSurvivesAReconciliationAgainstTheFinishedRun(t *testing.T) {
	service, clock, started, release := nextRunRaceService(t)
	ctx := context.Background()
	created, err := defineAndStart(ctx, service, newTestCreateRequest())
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(os.Getenv("FAKE_STATUS"), []byte("TIMEOUT\n"), 0o600))
	finished := retire(t, service, created.ID)

	clock.Store(finished.CreatedAt.Add(time.Hour).UnixNano())
	t.Setenv("FAKE_PROVISION_RELEASE", release)
	t.Setenv("FAKE_JOB_ID", "67890")
	testutil.Check(t, os.Remove(started))
	result := make(chan *Session, 1)
	errs := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		session, err := service.Start(ctx, testPrincipal, created.ID)
		result <- session
		errs <- err
	}()
	t.Cleanup(func() {
		_ = os.WriteFile(release, nil, 0o600)
		<-done
	})
	waitFor(t, errs, "sbatch started", started)

	testutil.Check(t, service.reconcileAll(ctx))
	during, err := service.loadSession(created.ID)
	testutil.Check(t, err)
	if during.State != "SUBMITTING" {
		t.Fatalf("the finished run retired the next run: %s (job %q, node %q)", during.State, during.JobID, during.Node)
	}
	if during.JobID == finished.JobID || during.Node == finished.Node {
		t.Fatalf("the next run adopted the finished run's job: %#v", during)
	}

	testutil.Check(t, os.WriteFile(release, nil, 0o600))
	testutil.Check(t, <-errs)
	next := <-result
	if next.State != "QUEUED" || next.JobID != "67890" {
		t.Fatalf("the submitted next run was not queued: %#v (job %q)", next.SessionResponse, next.JobID)
	}
}

func defineAndStart(ctx context.Context, service Service, request CreateRequest) (*Session, error) {
	session, _, err := service.Define(testPrincipal, request)
	if err != nil {
		return nil, err
	}
	return service.Start(ctx, testPrincipal, session.ID)
}

type refusingCredentials struct{ t *testing.T }

func (r refusingCredentials) Credential(context.Context, security.Principal) (devtunnel.Credential, error) {
	r.t.Error("a link-only session read the Dev Tunnels credential")
	return devtunnel.Credential{}, nil
}

func TestAttachAdmitsAClientLaunchedRunThatNeverReachesTheSchedulerOrDevTunnels(t *testing.T) {
	sshBin, _, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	manager := configureTestDevtunnel(t, &service)
	service.DevtunnelCredentials = refusingCredentials{t}
	session, _, err := service.Define(testPrincipal, newTestCreateRequest())
	testutil.Check(t, err)
	response := testutil.Serve(serviceHandler(t, &service), requestAs(testPrincipal, http.MethodPost, "/api/v1/sessions/"+session.ID+"/attach", []byte(`{"tunnelModes":["link"]}`)))
	var attached AttachResponse
	_ = json.Unmarshal(response.Body.Bytes(), &attached)
	if response.Code != http.StatusOK || attached.Session.State != "QUEUED" || attached.Session.Platform != platformVSCode || attached.Session.Seq != 1 || attached.Link == nil || attached.Devtunnel != nil || !slices.Equal(attached.Session.TunnelModes, []string{transportLink}) || attached.Port != ports(session.ID, 1).Control {
		t.Fatalf("attach = %d %#v, port %d", response.Code, attached.Session, attached.Port)
	}
	if _, err := service.dial(context.Background(), Session{SessionResponse: attached.Session}, 1); !errors.Is(err, errNoRoute) {
		t.Fatalf("a session with no link and no Dev Tunnel dialed something: %v", err)
	}
	capability, err := getCapability(service.CapabilityDir, session.ID, 1)
	if err != nil || attached.Link.Token != capability.LinkToken || attached.Link.URL != "wss://plane.example.edu/api/v1/sessions/"+session.ID+"/link" {
		t.Fatalf("link = %#v, capability %v", attached.Link, err)
	}
	if len(manager.creates) != 0 || capability.ConnectToken != "" {
		t.Fatalf("attach made a Dev Tunnel: %d creates", len(manager.creates))
	}
	if _, err := service.Attach(context.Background(), testPrincipal, session.ID, nil); !errors.Is(err, errSessionRunning) {
		t.Fatalf("attach on a running session = %v", err)
	}
	service.now = func() time.Time { return time.Now().Add(time.Hour) }
	listed, err := reconciledList(context.Background(), service)
	if err != nil || listed[0].State != "QUEUED" {
		t.Fatalf("reconciliation retired a client-launched run: %#v %v", listed, err)
	}
	stopped, err := service.Stop(testPrincipal, session.ID)
	if err != nil || stopped.State != "STOPPED" {
		t.Fatalf("stop = %#v %v", stopped, err)
	}
	runs, err := service.Runs(testPrincipal)
	if err != nil || len(runs) != 1 || runs[0].Seq != 1 || runs[0].Platform != platformVSCode || runs[0].FinalState != "STOPPED" || !slices.Equal(runs[0].TunnelModes, []string{transportLink}) {
		t.Fatalf("stop did not freeze the run: %#v %v", runs, err)
	}
	if _, err := os.Stat(commandLog); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a client-launched run reached the scheduler:\n%s", mustRead(t, commandLog))
	}
}
