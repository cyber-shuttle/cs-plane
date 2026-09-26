// Scheduler reconciliation folds neutral Slurm observations into sessions grouped by principal and SSH host.
// Slurm vocabulary and wire parsing stay in internal/slurm; this file owns session-state and walltime policy.
// Silence is not evidence, so a session with no observation stays put until its propagation window expires.
// Foreground and background refreshes share one serialized, rate-limited service runtime.
// A run is READY once its link connects; a running job's log tail is the READY signal only without a link.
// Client-launched sessions are never observed or accounted; a stop retires them locally, and one with a Dev Tunnel
// is READY once Linkspan answers its health route.
package session

import (
	"cmp"
	"context"
	"log"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/slurm"
)

const (
	schedulerPropagationWindow = 2 * time.Minute
	walltimeGrace              = 10 * time.Minute
	backgroundInterval         = 30 * time.Second
	refreshTimeout             = 60 * time.Second
)

var stateNarration = map[string]string{
	"QUEUED":   "Session is queued",
	"STARTING": "Session is starting",
	"READY":    "Session is running",
	"STOPPED":  "Session stopped",
	"FAILED":   "Session failed",
}

type schedulerScope struct {
	owner security.Principal
	alias string
}

func outlivedWalltime(session Session, now time.Time) bool {
	if (session.State != "STARTING" && session.State != "READY") || session.StartedAt.IsZero() || session.Resources.WallMinutes <= 0 {
		return false
	}
	return now.Sub(session.StartedAt) > time.Duration(session.Resources.WallMinutes)*time.Minute+walltimeGrace
}

func unknownToScheduler(session Session, now time.Time) bool {
	return now.Sub(session.UpdatedAt) > schedulerPropagationWindow
}

func unreachableScheduler(session *Session, err error, now time.Time) []string {
	if outlivedWalltime(*session, now) {
		session.State, session.Error = "STOPPED", ""
		return []string{"Session reached its walltime"}
	}
	session.Error = boundedSessionError(err)
	return []string{"Session status check failed"}
}

func missingFromScheduler(session *Session, cancelError string, now time.Time) []string {
	if session.JobID == "" && now.Sub(session.UpdatedAt) <= provisionTimeout {
		return nil
	}
	if session.State == "STOPPING" && !unknownToScheduler(*session, now) {
		session.Error = cmp.Or(cancelError, "scheduler returned no state")
		return []string{"Session status is temporarily unavailable"}
	}
	if session.JobID != "" && !unknownToScheduler(*session, now) {
		return nil
	}
	session.State, session.Error = "STOPPED", ""
	return []string{"Session is no longer known to the scheduler"}
}

func nextState(current string, state slurm.State) string {
	switch {
	case current == "STOPPING" && (state == slurm.Pending || state == slurm.Active):
		return "STOPPING"
	case state == slurm.Pending:
		return "QUEUED"
	case state == slurm.Active && current == "READY":
		return "READY"
	case state == slurm.Active:
		return "STARTING"
	case state == slurm.Stopped || state == slurm.Expired:
		return "STOPPED"
	}
	return "FAILED"
}

func groupByScope[T any](items []T, scope func(T) schedulerScope) map[schedulerScope][]T {
	byScope := map[schedulerScope][]T{}
	for _, item := range items {
		key := scope(item)
		byScope[key] = append(byScope[key], item)
	}
	return byScope
}

func reconciliationSnapshotCurrent(current, snapshot *Session) bool {
	return current != nil && current.UpdatedAt.Equal(snapshot.UpdatedAt) && current.State == snapshot.State && current.JobID == snapshot.JobID
}

func mergeReconciled(current, snapshot, candidate *Session, now time.Time) bool {
	if !reconciliationSnapshotCurrent(current, snapshot) ||
		(snapshot.State == candidate.State && snapshot.Error == candidate.Error && snapshot.JobID == candidate.JobID && snapshot.Node == candidate.Node && snapshot.StartedAt.Equal(candidate.StartedAt)) {
		return false
	}
	current.State, current.Error, current.JobID, current.Node, current.UpdatedAt = candidate.State, candidate.Error, candidate.JobID, candidate.Node, now
	current.StartedAt = candidate.StartedAt
	return true
}

func (s Service) triggerRefresh() {
	s.runtime.refreshMu.Lock()
	if s.runtime.refreshing || time.Since(s.runtime.refreshCompleted) < time.Second {
		s.runtime.refreshMu.Unlock()
		return
	}
	s.runtime.refreshing = true
	s.runtime.refreshMu.Unlock()
	if s.runtime.start(func(parent context.Context) {
		ctx, cancel := context.WithTimeout(parent, refreshTimeout)
		defer cancel()
		if err := s.reconcileAll(ctx); err != nil && ctx.Err() == nil {
			log.Print("session reconciliation failed")
		}
		s.runtime.refreshMu.Lock()
		s.runtime.refreshing, s.runtime.refreshCompleted = false, time.Now()
		s.runtime.refreshMu.Unlock()
	}) {
		return
	}
	s.runtime.refreshMu.Lock()
	s.runtime.refreshing = false
	s.runtime.refreshMu.Unlock()
}

func (s Service) applyObservation(session *Session, observation slurm.Observation, cancelError string) []string {
	var lines []string
	if session.JobID == "" {
		session.JobID = observation.JobID
	}
	previousNode := session.Node
	node := strings.TrimSpace(observation.Node)
	if node != "" && node != "(null)" && node != "None assigned" && security.SafeName(node, 256) {
		session.Node = node
	}
	if session.Node != "" && session.Node != previousNode {
		lines = append(lines, "Compute node assigned: "+session.Node)
	}
	if observation.State == slurm.Unknown {
		return lines
	}
	if observation.State == slurm.Active && session.StartedAt.IsZero() {
		session.StartedAt = s.utcNow().Add(-time.Duration(observation.ElapsedSeconds) * time.Second)
	}
	previous := session.State
	next := nextState(previous, observation.State)
	if (next == "QUEUED" || next == "STARTING") && s.link(*session) != nil {
		next = "READY"
	}
	session.State = next
	if next != previous {
		line := stateNarration[next]
		if next == "STOPPED" && observation.State == slurm.Expired {
			line = "Session reached its walltime"
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	session.Error = ""
	if previous == "STOPPING" && next == "STOPPING" {
		session.Error = cancelError
	}
	return lines
}

func (s Service) reconcileSnapshots(ctx context.Context, snapshots []Session) ([]Session, [][]string) {
	results := slices.Clone(snapshots)
	narration := make([][]string, len(results))
	var indexes []int
	var wg sync.WaitGroup
	for i := range results {
		switch {
		case results[i].Platform == platformVSCode && results[i].State == "STOPPING":
			results[i].State, results[i].Error = "STOPPED", ""
		case results[i].Platform == platformVSCode && results[i].State == "QUEUED" && results[i].Devtunnel.ID != "":
			wg.Go(func() { narration[i] = s.probeDevtunnel(ctx, &results[i]) })
		case results[i].Platform != platformVSCode && reconcilable(results[i].State):
			indexes = append(indexes, i)
		}
	}
	byScope := groupByScope(indexes, func(i int) schedulerScope {
		return schedulerScope{owner: results[i].Owner, alias: results[i].Alias}
	})
	for scope, indexes := range byScope {
		wg.Add(1)
		go func() {
			defer wg.Done()
			group := make([]Session, len(indexes))
			for position, index := range indexes {
				group[position] = results[index]
			}
			observations, cancelErrors, err := s.forPrincipal(scope.owner).schedulerObservations(ctx, scope.alias, group)
			if err != nil && ctx.Err() != nil {
				return
			}
			for _, index := range indexes {
				session := &results[index]
				switch observation, ok := observations[session.ID]; {
				case err != nil:
					narration[index] = unreachableScheduler(session, err, s.utcNow())
				case !ok:
					narration[index] = missingFromScheduler(session, cancelErrors[session.ID], s.utcNow())
				default:
					narration[index] = s.applyObservation(session, observation, cancelErrors[session.ID])
				}
			}
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}

	started := s.collectStartingSessionLogs(ctx, results)
	if ctx.Err() != nil {
		return snapshots, make([][]string, len(snapshots))
	}
	for index := range results {
		if _, ok := started[results[index].ID]; ok && results[index].State == "STARTING" {
			results[index].State = "READY"
			narration[index] = append(narration[index], "Session is running")
		}
	}
	return results, narration
}

func (s Service) reconcileAll(ctx context.Context) error {
	snapshots, err := s.loadSessions()
	if err != nil {
		return err
	}
	candidates, narration := s.reconcileSnapshots(ctx, snapshots)
	if err := ctx.Err(); err != nil {
		return err
	}
	return s.Store.locked(func(current *state) error {
		changed := false
		for i := range snapshots {
			session := current.Sessions[snapshots[i].ID]
			s.narrateReconciled(session, &snapshots[i], narration[i])
			if !mergeReconciled(session, &snapshots[i], &candidates[i], s.utcNow()) {
				continue
			}
			changed = true
			_, _ = s.freezeIfTerminal(current, session)
		}
		if changed {
			return s.Store.save(current)
		}
		return nil
	})
}

func (s Service) schedulerObservations(ctx context.Context, alias string, sessions []Session) (map[string]slurm.Observation, map[string]string, error) {
	jobs := make([]slurm.Job, len(sessions))
	for index, session := range sessions {
		jobs[index] = slurm.Job{ID: session.JobID, Name: session.JobName, Cancel: session.State == "STOPPING", CreatedAt: session.CreatedAt}
	}
	statuses, err := slurm.Observe(ctx, s.runner, alias, jobs, s.utcNow())
	if err != nil {
		return nil, nil, err
	}
	observations := make(map[string]slurm.Observation, len(sessions))
	cancelErrors := make(map[string]string)
	for index, status := range statuses {
		session := sessions[index]
		if status.Found {
			observations[session.ID] = status.Observation
		}
		if status.CancelError != "" {
			cancelErrors[session.ID] = status.CancelError
		}
	}
	return observations, cancelErrors, nil
}

func (s Service) probeDevtunnel(ctx context.Context, session *Session) []string {
	if _, status, err := s.linkspan(ctx, *session, http.MethodGet, "/api/v1/health", nil, 1<<10); err != nil || status != http.StatusOK {
		return nil
	}
	session.State, session.StartedAt = "READY", cmp.Or(session.StartedAt, s.utcNow())
	return []string{stateNarration["READY"]}
}

func (s Service) narrateReconciled(current, snapshot *Session, lines []string) {
	if !reconciliationSnapshotCurrent(current, snapshot) {
		return
	}
	for _, line := range lines {
		s.sessionStatus(snapshot.ID, line)
	}
}
