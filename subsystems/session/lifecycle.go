// The session state machine. Define records a stopped session under an ID derived from the idempotency key, so a
// replay answers it. Start launches a run through Slurm, serialized across processes before Dev Tunnel side effects,
// and persists intent before provisioning. A conclusive submission failure compensates through abandonSubmitIntent; an
// ambiguous one stays durable. A stop proceeds locally without a usable link, and reads the Dev Tunnels account only
// for a session that has a Dev Tunnel.
// Attach admits a run the client launches itself, which cs-plane never schedules or cancels.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/slurm"
)

func assignSessionID(request CreateRequest, principal security.Principal) (CreateRequest, error) {
	if err := validateCreate(&request); err != nil {
		return request, err
	}
	if request.ID == "" {
		sum := sha256.Sum256([]byte(security.PrincipalDirName(principal) + "\x00" + request.IdempotencyKey))
		request.ID = "s-" + hex.EncodeToString(sum[:6])
	}
	if !idPattern.MatchString(request.ID) {
		return request, security.New("invalid_session_id", "session ID must match s-[a-f0-9]{12}", http.StatusBadRequest)
	}
	return request, nil
}

func sameCreateRequest(session *Session, request CreateRequest) bool {
	return session.Alias == request.Alias && session.Account == request.Account && session.Partition == request.Partition && session.RootFolder == request.RootFolder && session.Resources == request.Resources && slices.Equal(session.TunnelModes, request.TunnelModes)
}

func (s Service) devtunnelCredential(ctx context.Context, principal security.Principal, transports []string) (devtunnel.Credential, error) {
	if !slices.Contains(transports, transportDevtunnel) {
		return devtunnel.Credential{}, nil
	}
	credential, err := s.DevtunnelCredentials.Credential(ctx, principal)
	if err == nil && credential.Token == "" {
		err = errDevtunnelsAccountRequired
	}
	return credential, err
}

func (s Service) launch(ctx context.Context, principal security.Principal, request CreateRequest) (_ *Session, resultErr error) {
	defer func() {
		if resultErr != nil {
			s.forgetUnpersistedBuffers(request.ID)
		}
	}()
	var result *Session
	resultErr = s.serialized(request.ID, func() (err error) {
		result, err = s.launchSerialized(ctx, request, principal)
		return err
	})
	return result, resultErr
}

func (s Service) serialized(id string, fn func() error) error {
	sum := sha256.Sum256([]byte(id))
	slot := int(sum[0]) % len(createLocks)
	lock := &createLocks[slot]
	lock.Lock()
	defer lock.Unlock()
	return security.WithFileLock(filepath.Join(s.Store.Dir, fmt.Sprintf(".session-create-%02x.lock", slot)), fn)
}

func (s Service) launchSerialized(ctx context.Context, request CreateRequest, principal security.Principal) (*Session, error) {
	credential, err := s.devtunnelCredential(ctx, principal, request.TunnelModes)
	if err != nil {
		return nil, err
	}
	plan, err := s.planSession(ctx, request)
	if err != nil {
		return nil, err
	}
	if err := s.validateForCreate(ctx, request, plan.script); err != nil {
		return nil, err
	}

	operationCtx, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()

	intent := plan.session
	intent.State, intent.Platform = stateSubmitting, platformJupyterLab
	intent, hostToken, tokens, err := s.claimRun(operationCtx, principal, credential, intent)
	if err != nil {
		return nil, err
	}
	plan.script = buildScript(intent, plan.linkspan)
	if err := s.provisionSession(operationCtx, intent, plan.home, plan.linkspan); err != nil {
		s.sessionStatus(intent.ID, "Session environment preparation failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(credential, intent))
	}

	s.sessionStatus(intent.ID, "Submitting Slurm job")
	jobID, err := s.submitSessionScript(operationCtx, intent, plan.script, tokens, hostToken)
	if err != nil {
		if slurm.AmbiguousSubmission(err) {
			s.sessionStatus(intent.ID, "Session submission outcome is unresolved")
			return nil, err
		}
		s.sessionStatus(intent.ID, "Session submission failed")
		return nil, errors.Join(err, s.abandonSubmitIntent(credential, intent))
	}
	s.sessionStatus(intent.ID, "Slurm job submitted")
	created, superseded, err := s.recordSubmittedJob(intent.ID, jobID)
	if err != nil {
		s.sessionStatus(intent.ID, "Session submission could not be saved")
		if cancelErr := s.scancelWithOwnTimeout(request.Alias, jobID); cancelErr != nil {
			return nil, fmt.Errorf("%w; compensation scancel failed: %w", err, cancelErr)
		}
		return nil, fmt.Errorf("%w; job was cancelled", err)
	}
	if created.State == stateQueued {
		s.sessionStatus(intent.ID, stateNarration[stateQueued])
	}
	if !superseded {
		return created, nil
	}
	replaced, err := s.cancelSupersededJob(request.Alias, intent.ID, jobID)
	if err != nil {
		return nil, err
	}
	if replaced != nil {
		created = replaced
	}
	return created, nil
}

func (s Service) claimLaunch(id string, principal security.Principal) (previous *Session, err error) {
	err = s.Store.locked(func(current *state) error {
		existing, err := ownedSession(current.Sessions[id], principal)
		if err != nil {
			return err
		}
		if !terminalSession(existing.State) {
			return errSessionRunning
		}
		previous = detached(existing)
		return nil
	})
	return previous, err
}

func (s Service) claimRun(ctx context.Context, principal security.Principal, credential devtunnel.Credential, intent Session) (Session, string, runTokens, error) {
	previous, err := s.claimLaunch(intent.ID, principal)
	if err != nil {
		return intent, "", runTokens{}, err
	}
	intent.CreatedAt, intent.UpdatedAt = previous.CreatedAt, s.utcNow()
	hostToken, tokens, err := s.issueSession(ctx, &intent, principal, credential, previous.Seq+1)
	if err == nil {
		if err = s.persistSubmitIntent(previous, intent); err != nil {
			err = errors.Join(err, s.releaseDevtunnel(credential, intent.ID, intent.Seq, intent.Devtunnel))
		}
	}
	return intent, hostToken, tokens, err
}

func (s Service) persistSubmitIntent(previous *Session, intent Session) error {
	return s.Store.locked(func(current *state) error {
		existing := current.Sessions[intent.ID]
		if existing == nil {
			return errSessionNotFound
		}
		if !existing.UpdatedAt.Equal(previous.UpdatedAt) || existing.State != previous.State || existing.Owner != previous.Owner {
			return errSessionRunning
		}
		current.Sessions[intent.ID] = &intent
		if err := s.Store.save(current); err != nil {
			return fmt.Errorf("persist submit intent: %w", err)
		}
		return nil
	})
}

func (s Service) validateForCreate(ctx context.Context, request CreateRequest, script string) error {
	s.sessionStatus(request.ID, "Validating session with Slurm")
	checked, err := slurm.Check(ctx, s.runner, request.Alias, script)
	if err == nil && !checked.Passed {
		err = security.New("slurm_validation_failed", validationMessage(checked), http.StatusBadRequest)
	}
	if err != nil {
		s.sessionStatus(request.ID, "Slurm validation failed")
		return err
	}
	s.sessionStatus(request.ID, "Slurm validation passed")
	return nil
}

func (s Service) recordSubmittedJob(sessionID, jobID string) (*Session, bool, error) {
	var created *Session
	superseded := false
	err := s.Store.locked(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return errors.New("submitted session disappeared from state")
		}
		session.JobID = jobID
		if session.State == stateSubmitting {
			session.State = stateQueued
		}
		superseded = session.State != stateQueued
		session.UpdatedAt = s.utcNow()
		if err := s.Store.save(current); err != nil {
			return fmt.Errorf("persist submitted job %s: %w", jobID, err)
		}
		created = detached(session)
		return nil
	})
	return created, superseded, err
}

func (s Service) scancelWithOwnTimeout(alias, jobID string) error {
	ctx, cancel := s.ownTimeout()
	defer cancel()
	_, err := s.runner.Run(ctx, alias, nil, "scancel", jobID)
	return err
}

func (s Service) cancelSupersededJob(alias, sessionID, jobID string) (*Session, error) {
	diagnostic := ""
	if cancelErr := s.scancelWithOwnTimeout(alias, jobID); cancelErr != nil {
		diagnostic = boundedSessionError(cancelErr)
	}
	var result *Session
	err := s.Store.locked(func(current *state) error {
		session := current.Sessions[sessionID]
		if session == nil {
			return nil
		}
		if session.JobID == jobID && session.State != stateQueued {
			session.Error, session.UpdatedAt = diagnostic, s.utcNow()
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return nil
	})
	return result, err
}

func (s Service) retireFinished(ctx context.Context, principal security.Principal, id string) (*Session, error) {
	session, err := s.claimLaunch(id, principal)
	if err != nil {
		return nil, err
	}
	if session.Devtunnel.ID != "" {
		credential, err := s.DevtunnelCredentials.Credential(ctx, principal)
		if err != nil {
			return nil, err
		}
		if err := s.releaseDevtunnel(credential, session.ID, session.Seq, session.Devtunnel); err != nil {
			return nil, err
		}
	}
	return session, s.freezeRun(session)
}

func (s Service) Start(ctx context.Context, principal security.Principal, id string) (*Session, error) {
	s = s.forPrincipal(principal)
	session, err := s.retireFinished(ctx, principal, id)
	if err != nil {
		return nil, err
	}
	return s.launch(ctx, principal, CreateRequest{
		ID: id, Alias: session.Alias, Account: session.Account,
		Partition: session.Partition, RootFolder: session.RootFolder, Resources: session.Resources, TunnelModes: session.TunnelModes,
	})
}

func (s Service) Attach(ctx context.Context, principal security.Principal, id string, transports []string) (*AttachResponse, error) {
	previous, err := s.retireFinished(ctx, principal, id)
	if err != nil {
		return nil, err
	}
	intent := *previous
	if transports != nil {
		if intent.TunnelModes, err = canonicalTunnelModes(transports); err != nil {
			return nil, err
		}
	}
	credential, err := s.devtunnelCredential(ctx, principal, intent.TunnelModes)
	if err != nil {
		return nil, err
	}
	operationCtx, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	var hostToken string
	var tokens runTokens
	intent.State, intent.Platform, intent.Error, intent.JobID, intent.Node, intent.StartedAt = stateQueued, platformVSCode, "", "", "", time.Time{}
	if err := s.serialized(id, func() (err error) {
		intent, hostToken, tokens, err = s.claimRun(operationCtx, principal, credential, intent)
		return err
	}); err != nil {
		return nil, err
	}
	s.sessionStatus(id, "Waiting for the client's Linkspan to connect")
	response := &AttachResponse{Session: intent.SessionResponse, Port: ports(id, intent.Seq).Control}
	if slices.Contains(intent.TunnelModes, transportLink) {
		response.Link = &LinkAccess{URL: s.linkURL(id), Token: tokens.LinkToken}
	}
	if slices.Contains(intent.TunnelModes, transportDevtunnel) {
		response.Devtunnel = &DevtunnelAccess{ID: intent.Devtunnel.ID, Cluster: intent.Devtunnel.ClusterID, HostToken: hostToken}
	}
	return response, nil
}

func (s Service) Stop(principal security.Principal, id string) (*Session, error) {
	s = s.forPrincipal(principal)
	operationCtx, done, err := s.beginOperation()
	if err != nil {
		return nil, err
	}
	defer done()
	var snapshot Session
	var alreadyStopped bool
	if err := s.Store.locked(func(current *state) error {
		session, err := ownedSession(current.Sessions[id], principal)
		if err != nil {
			return err
		}
		alreadyStopped = terminalSession(session.State)
		if !alreadyStopped {
			session.State, session.Error, session.UpdatedAt = stateStopping, "", s.utcNow()
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		snapshot = *session
		return nil
	}); err != nil {
		return nil, err
	}
	if !alreadyStopped {
		s.sessionStatus(id, "Stopping session")
	}
	var credential devtunnel.Credential
	if snapshot.Devtunnel.ID != "" {
		credential, _ = s.DevtunnelCredentials.Credential(operationCtx, principal)
	}
	managementErr := s.releaseDevtunnel(credential, snapshot.ID, snapshot.Seq, snapshot.Devtunnel)
	if link, ok := s.links.LoadAndDelete(id); ok {
		_ = link.(*sessionLink).mux.Close()
	}
	candidate := snapshot
	var narration []string
	if reconcilable(snapshot.State) {
		if !clientLaunched(snapshot.Platform) {
			s.sessionStatus(id, "Requesting scheduler cancellation")
		}
		stopCtx, cancel := s.ownTimeout()
		candidates, lines := s.reconcileSnapshots(stopCtx, []Session{snapshot})
		cancel()
		candidate, narration = candidates[0], lines[0]
		if candidate.Error != "" {
			s.sessionStatus(id, "Session stop is pending")
		}
	}
	var result *Session
	err = s.Store.locked(func(current *state) error {
		session, changed := s.commitReconciled(current, &snapshot, &candidate, narration)
		if session == nil {
			return errSessionNotFound
		}
		if session.Seq == snapshot.Seq && session.Devtunnel.ID == snapshot.Devtunnel.ID {
			if managementErr != nil {
				session.Error = boundedSessionError(managementErr)
				session.UpdatedAt = s.utcNow()
				changed = true
			} else if snapshot.Devtunnel.ID != "" {
				session.Devtunnel = devtunnelMetadata{}
				session.UpdatedAt = s.utcNow()
				changed = true
			}
		}
		if session.State == stateStopped && !alreadyStopped {
			s.sessionStatus(id, stateNarration[stateStopped])
		}
		frozen, freezeErr := s.freezeIfTerminal(current, session)
		if frozen {
			changed = true
		}
		if changed {
			if err := s.Store.save(current); err != nil {
				return err
			}
		}
		result = detached(session)
		return freezeErr
	})
	return result, err
}

func (s Service) forgetSessionBuffers(id string) {
	s.logs.forget(id)
	s.usage.forget(id)
}

func (s Service) forgetUnpersistedBuffers(id string) {
	if _, err := s.loadSession(id); errors.Is(err, errSessionNotFound) {
		s.forgetSessionBuffers(id)
	}
}

func (s Service) Delete(principal security.Principal, id string) (*Session, error) {
	var deleted *Session
	if err := s.Store.locked(func(current *state) error {
		session, err := ownedSession(current.Sessions[id], principal)
		if err != nil {
			return err
		}
		if !terminalSession(session.State) {
			return security.New("session_not_stopped", "stop the session before deleting it", http.StatusConflict)
		}
		deleted = detached(session)
		delete(current.Sessions, id)
		return s.Store.save(current)
	}); err != nil {
		return nil, err
	}
	s.forgetSessionBuffers(id)
	return deleted, deleteRunTokens(s.TokenDir, deleted.ID, deleted.Seq)
}

func (s Service) abandonSubmitIntent(credential devtunnel.Credential, intent Session) error {
	compensateErr := s.releaseDevtunnel(credential, intent.ID, intent.Seq, intent.Devtunnel)
	stateErr := s.Store.locked(func(current *state) error {
		currentSession := current.Sessions[intent.ID]
		if currentSession == nil || currentSession.Seq != intent.Seq || currentSession.JobName != intent.JobName || currentSession.JobID != "" {
			return nil
		}
		next := map[string]string{stateSubmitting: stateFailed, stateStopping: stateStopped}[currentSession.State]
		if next == "" {
			return nil
		}
		currentSession.State, currentSession.Devtunnel, currentSession.Error, currentSession.UpdatedAt = next, devtunnelMetadata{}, "", s.utcNow()
		if compensateErr != nil {
			currentSession.Error = boundedSessionError(compensateErr)
		}
		return s.Store.save(current)
	})
	return errors.Join(compensateErr, stateErr)
}

func (s Service) Define(principal security.Principal, request CreateRequest) (*Session, bool, error) {
	request, err := assignSessionID(request, principal)
	if err != nil {
		return nil, false, err
	}
	session := &Session{SessionResponse: SessionResponse{
		ID: request.ID, State: stateStopped, Platform: platformJupyterLab, Alias: request.Alias, Account: request.Account,
		Partition: request.Partition, RootFolder: request.RootFolder, Resources: request.Resources, TunnelModes: request.TunnelModes,
		CreatedAt: s.utcNow(), UpdatedAt: s.utcNow(),
	}, Owner: principal}
	created := false
	err = s.Store.locked(func(current *state) error {
		if existing := current.Sessions[session.ID]; existing != nil {
			if existing.Owner != principal {
				return errOwnerMismatch
			}
			if !sameCreateRequest(existing, request) {
				return errIdempotencyConflict
			}
			session = detached(existing)
			return nil
		}
		current.Sessions[session.ID] = session
		created = true
		session = detached(session)
		return s.Store.save(current)
	})
	return session, created, err
}
