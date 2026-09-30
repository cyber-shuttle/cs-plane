// Session reconciliation tests cover scheduler policy, stale snapshots, and batching.
// Missing observations respect submission propagation and running-session walltime.
// Cancellation may target a known job ID or an unresolved submission name.
// Remote work never holds the state lock or overwrites a newer local transition.
package session

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func reconciliationService(t *testing.T) (Service, string, string) {
	t.Helper()
	service := testService(t)
	service.now = time.Now
	return service, os.Getenv("FAKE_COMMAND_LOG"), filepath.Join(service.Store.Dir, "release")
}

func stoppingSession(id, alias, jobID string) Session {
	session := pendingSession(id, alias, jobID)
	session.State = "STOPPING"
	return session
}

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	testutil.Check(t, err)
	return data
}

func assertOneSchedulerRound(t *testing.T, log, alias string) {
	t.Helper()
	data := string(mustRead(t, log))
	if strings.Count(data, alias+"|'sh' '-s' '--' 'cs-session-status'") != 1 {
		t.Fatalf("scheduler calls were not one round for %s: %s", alias, data)
	}
}

func runningSession(startedAt time.Time) Session {
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	session.StartedAt = startedAt
	session.Resources.WallMinutes = 60
	return session
}

func TestReconcileUsesOneRoundPerMixedHostAndNoneForTerminal(t *testing.T) {
	service, log, _ := reconciliationService(t)
	one := pendingSession("s-111111111111", "alpha", "101")
	two := pendingSession("s-222222222222", "beta", "202")
	terminal := pendingSession("s-333333333333", "gamma", "303")
	terminal.State = "FAILED"
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+one.JobName+"\\n202|PENDING||"+two.JobName)
	putSessions(t, service, one, two, terminal)
	_, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	data, _ := os.ReadFile(log)
	if got := strings.Count(string(data), "cs-session-status"); got != 2 || strings.Contains(string(data), "gamma|") {
		t.Fatalf("unexpected scheduler rounds: %s", data)
	}
}

func TestStoppingFailedCancelKeepsActiveStateAndDiagnostic(t *testing.T) {
	service, log, _ := reconciliationService(t)
	stopping := stoppingSession("s-111111111111", "alpha", "101")
	unrelated := pendingSession("s-222222222222", "alpha", "202")
	t.Setenv("FAKE_CANCEL_ERRORS", "id:101|scheduler temporarily unavailable")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+stopping.JobName+"\\n202|PENDING|cn002|"+unrelated.JobName)
	putSessions(t, service, stopping, unrelated)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	byID := map[string]Session{}
	for _, session := range listed {
		byID[session.ID] = session
	}
	if got := byID[stopping.ID]; got.State != "STOPPING" || got.Error != "scheduler temporarily unavailable" {
		t.Fatalf("active stopping session lost cancellation diagnostic: %#v", got)
	}
	if got := byID[unrelated.ID]; got.State != "QUEUED" || got.Error != "" || got.Node != "cn002" {
		t.Fatalf("unrelated session did not reconcile: %#v", got)
	}
	assertOneSchedulerRound(t, log, "alpha")
}

func TestStoppingUnknownSubmissionUsesJobNameAndObservesState(t *testing.T) {
	service, log, _ := reconciliationService(t)
	session := stoppingSession("s-111111111111", "alpha", "")
	t.Setenv("FAKE_CANCEL_ERRORS", "name:"+session.JobName+"|submission cancellation pending")
	t.Setenv("FAKE_STATUS_LINES", "777|PENDING||"+session.JobName)
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].JobID != "777" || listed[0].State != "STOPPING" || listed[0].Error != "submission cancellation pending" {
		t.Fatalf("unknown stopping submission was not reconciled: %#v", listed[0])
	}
	assertOneSchedulerRound(t, log, "alpha")
	script := string(mustRead(t, os.Getenv("FAKE_STATUS_SCRIPT_LOG")))
	if !strings.Contains(script, "scancel --name='"+session.JobName+"'") {
		t.Fatalf("unknown submission was not cancelled by unique job name:\n%s", script)
	}
}

func TestReconcileDoesNotHoldStoreLockDuringSSHAndDoesNotOverwriteStop(t *testing.T) {
	service, log, release := reconciliationService(t)
	started := filepath.Join(t.TempDir(), "started")
	t.Setenv("FAKE_STATUS_STARTED", started)
	t.Setenv("FAKE_STATUS_RELEASE", release)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|PENDING||"+session.JobName)
	putSessions(t, service, session)
	done := make(chan error, 1)
	go func() { _, err := reconciledList(context.Background(), service); done <- err }()
	testutil.WaitForFile(t, log)

	lockAvailable := make(chan error, 1)
	go func() { lockAvailable <- service.Store.locked(func(*state) error { return nil }) }()
	testutil.Within(t, lockAvailable, 300*time.Millisecond, "state lock was held during blocked SSH")
	_, err := service.Stop(testPrincipal, session.ID)
	testutil.Check(t, err)
	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	testutil.Check(t, <-done)
	testutil.Check(t, service.reconcileAll(context.Background()))
	got, err := service.loadSession(session.ID)
	testutil.Check(t, err)
	if got.State != "STOPPING" && got.State != "STOPPED" {
		t.Fatalf("stale list overwrote stop intent: %#v", got)
	}
}

func TestSchedulerThatDoesNotKnowTheJobRetiresTheSession(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "STOPPED" {
		t.Fatalf("a session the scheduler has no record of stayed %s, want STOPPED", got[0].State)
	}
}

func TestSubmittingSessionWithNoJobIDSurvivesThePropagationWindow(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "")
	session.State = "SUBMITTING"
	session.UpdatedAt = time.Now().Add(-provisionTimeout / 2).UTC()
	t.Setenv("FAKE_STATUS_LINES", "")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "SUBMITTING" {
		t.Fatalf("a submitting session with no job ID was retired as %s, want SUBMITTING", got[0].State)
	}

	session.UpdatedAt = time.Now().Add(-provisionTimeout - time.Minute).UTC()
	putSessions(t, service, session)
	got, _ = service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "STOPPED" {
		t.Fatalf("a submitting session with no job ID past provisionTimeout stayed %s, want STOPPED", got[0].State)
	}
}

func TestWalltimeExpiryWithNoObservationDeletesTheCredential(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := runningSession(time.Now().Add(-4 * time.Hour))
	setTestSessionMetadata(&session)
	testutil.Check(t, putRunTokens(service.TokenDir, session.ID, session.Seq, defaultRunTokens()))
	putSessions(t, service, session)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	testutil.Check(t, service.reconcileAll(context.Background()))
	if _, err := getRunTokens(service.TokenDir, session.ID, session.Seq); err == nil {
		t.Fatal("a session retired past its walltime with no observation kept its run's tokens")
	}
}

func TestUnreachableSchedulerKeepsASessionInsideItsWalltime(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := runningSession(time.Now().Add(-5 * time.Minute))
	putSessions(t, service, session)
	t.Setenv("FAKE_STATUS_FAIL", "1")
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if got[0].State != "READY" {
		t.Fatalf("a session inside its walltime was retired as %s by an unreachable scheduler", got[0].State)
	}
	if got[0].Error == "" {
		t.Fatal("an unreachable scheduler left no diagnostic on the session")
	}
}

func TestQueueRowDoesNotResetTheAccountingElapsedAnchor(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_QUEUE_LINES", "101|RUNNING|node1|"+session.JobName)
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|node1|"+session.JobName+"|7200")
	putSessions(t, service, session)
	got, _ := service.reconcileSnapshots(context.Background(), []Session{session})
	if elapsed := time.Since(got[0].StartedAt); elapsed < 2*time.Hour-time.Minute {
		t.Fatalf("a two-hour-old job was anchored %s ago: the queue row reset it", elapsed)
	}
}

func TestRunningSessionStaysStartingUntilItsTailHasContent(t *testing.T) {
	service, _, _ := reconciliationService(t)
	session := pendingSession("s-111111111111", "alpha", "101")
	t.Setenv("FAKE_STATUS_LINES", "101|RUNNING|cn001|"+session.JobName)
	putSessions(t, service, session)

	listed, err := reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State != "STARTING" {
		t.Fatalf("a running job with an empty tail was promoted early: %#v", listed[0])
	}

	t.Setenv("FAKE_SESSION_STDOUT", "Jupyter Server started\n")
	listed, err = reconciledList(context.Background(), service)
	testutil.Check(t, err)
	if listed[0].State != "READY" {
		t.Fatalf("a running job with a non-empty tail was not promoted: %#v", listed[0])
	}
}

func TestStaleReconciliationRoundDoesNotNarrateASessionStartedAgain(t *testing.T) {
	service, commandLog, release := reconciliationService(t)
	t.Setenv("FAKE_STATUS_RELEASE", release)
	session := pendingSession("s-111111111111", "alpha", "101")
	session.State = "READY"
	t.Setenv("FAKE_STATUS_LINES", "101|COMPLETED|cn001|"+session.JobName)
	putSessions(t, service, session)

	done := make(chan error, 1)
	go func() { done <- service.reconcileAll(context.Background()) }()
	testutil.WaitForFile(t, commandLog)

	service.logs.forget(session.ID)
	next := session
	next.State, next.JobID, next.UpdatedAt = "SUBMITTING", "", time.Now().UTC()
	putSessions(t, service, next)

	testutil.Check(t, os.WriteFile(release, []byte("ok"), 0o600))
	testutil.Check(t, <-done)
	if tail, ok := service.logs.tail(session.ID); ok {
		t.Fatalf("a superseded round narrated the session started again: %#v", tail.Lines)
	}
}
