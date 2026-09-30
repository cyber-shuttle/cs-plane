// Package session owns session orchestration and its HTTP surface. RunnerProvider supplies principal-scoped
// SSH execution, while DevtunnelCredentials supplies connected Dev Tunnels accounts; sessions owns the resulting
// state, Dev Tunnel, run history, and run lifecycles. Every exported operation takes the acting principal
// explicitly and checks ownership itself, so it is usable without HTTP; Routes are one-line adapters over those operations.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

const maxSessionError = 4096

var (
	idPattern         = regexp.MustCompile(`^s-[a-f0-9]{12}$`)
	remotePathPattern = regexp.MustCompile(`^/[A-Za-z0-9._/-]+$`)
	rootFolderVar     = regexp.MustCompile(`^\$(?:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\})(?:/(.*))?$`)
	rootFolderSegment = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
	createLocks       [64]sync.Mutex
)

type devtunnelMetadata struct {
	ID        string    `json:"id"`
	ClusterID string    `json:"clusterId"`
	ExpiresAt time.Time `json:"expiresAt"`
}

type Session struct {
	SessionResponse
	Owner          security.Principal `json:"owner"`
	Devtunnel      devtunnelMetadata  `json:"devtunnel"`
	JobID          string             `json:"jobId,omitempty"`
	JobName        string             `json:"jobName"`
	Node           string             `json:"node,omitempty"`
	PrivateRoot    string             `json:"privateRoot"`
	RootFolderPath string             `json:"rootFolderPath"`
}

type state struct {
	Sessions map[string]*Session
	Runs     []runRecord
}

const (
	stateSubmitting = "SUBMITTING"
	stateQueued     = "QUEUED"
	stateStarting   = "STARTING"
	stateReady      = "READY"
	stateStopping   = "STOPPING"
	stateStopped    = "STOPPED"
	stateFailed     = "FAILED"
)

const (
	platformJupyterLab = "jupyterlab"
	platformVSCode     = "vscode"
)

// clientLaunched reports a run the client submits itself, which cs-plane never schedules, observes or accounts.
func clientLaunched(platform string) bool { return platform == platformVSCode }

const DefaultLinkspanPath = "$HOME/.cybershuttle/bin/linkspan"

const defaultSessionBase = ".cybershuttle/sessions"

const (
	minCores    = 2
	minMemoryMB = 4096
)

type RunnerProvider interface {
	Runner(principal security.Principal) ssh.Runner
}

type DevtunnelManager interface {
	Create(context.Context, devtunnel.CreateRequest) (devtunnel.Record, error)
	Get(context.Context, devtunnel.GetRequest) (devtunnel.Record, error)
	Delete(context.Context, devtunnel.DeleteRequest) error
}

type Config struct {
	Runners              RunnerProvider
	Store                Store
	LinkspanPath         string
	DevtunnelManager     DevtunnelManager
	DevtunnelCredentials DevtunnelCredentials
	TokenDir             string
	PublicURL            string
	UpstreamTimeout      time.Duration
	Origins              security.Origins
}

type Service struct {
	Config
	runner           ssh.Runner
	logs             *sessionLogs
	usage            *sessionUsage
	links            *sync.Map
	transport        *http.Transport
	hostPreparations *sync.Map
	now              func() time.Time
	runtime          *sessionRuntime
}

type sessionRuntime struct {
	ctx    context.Context
	cancel context.CancelFunc

	mu      sync.Mutex
	closing bool
	wg      sync.WaitGroup

	refreshMu        sync.Mutex
	refreshing       bool
	refreshCompleted time.Time
	statsInFlight    atomic.Bool
}

func newSessionRuntime() *sessionRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	return &sessionRuntime{ctx: ctx, cancel: cancel}
}

func (r *sessionRuntime) begin() (context.Context, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closing {
		return nil, nil, false
	}
	r.wg.Add(1)
	ctx, cancel := context.WithCancel(r.ctx)
	return ctx, func() { cancel(); r.wg.Done() }, true
}

func (r *sessionRuntime) start(run func(context.Context)) bool {
	ctx, done, ok := r.begin()
	if !ok {
		return false
	}
	go func() {
		defer done()
		run(ctx)
	}()
	return true
}

// every runs fn on interval until ctx ends.
func every(ctx context.Context, interval time.Duration, fn func(context.Context)) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			fn(ctx)
		}
	}
}

func (r *sessionRuntime) close() {
	r.mu.Lock()
	r.closing = true
	r.cancel()
	r.mu.Unlock()
	r.wg.Wait()
}

func (s Service) beginOperation() (context.Context, func(), error) {
	operationCtx, done, ok := s.runtime.begin()
	if !ok {
		return nil, nil, errServiceStopping
	}
	return operationCtx, done, nil
}

func NewService(config Config) *Service {
	if !safeRemoteExecutable(config.LinkspanPath) {
		config.LinkspanPath = DefaultLinkspanPath
	}
	service := &Service{
		Config: config, logs: newSessionLogs(), usage: newSessionUsage(), links: &sync.Map{},
		hostPreparations: &sync.Map{}, now: time.Now, runtime: newSessionRuntime(),
	}
	service.transport = newSessionTransport(service.dialHost)
	service.runtime.start(func(ctx context.Context) {
		every(ctx, backgroundInterval, func(context.Context) { service.triggerRefresh() })
	})
	service.runtime.start(func(ctx context.Context) { every(ctx, usageSampleInterval, service.sampleAndAccount) })
	return service
}

func terminalSession(state string) bool {
	return state == stateStopped || state == stateFailed
}

func reconcilable(state string) bool {
	return state == stateSubmitting || state == stateQueued || state == stateStarting || state == stateReady || state == stateStopping
}

func jobName(id string, seq int) string { return "cs-" + id + "-" + strconv.Itoa(seq) }

func boundedSessionError(err error) string {
	return security.TruncateUTF8(strings.ToValidUTF8(err.Error(), "�"), maxSessionError)
}

func detached(session *Session) *Session {
	value := *session
	return &value
}

func (s Service) forPrincipal(principal security.Principal) Service {
	scoped := s
	scoped.runner = s.Runners.Runner(principal)
	return scoped
}

var (
	errSessionNotFound           = security.New("session_not_found", "session not found", http.StatusNotFound)
	errOwnerMismatch             = security.New("session_owner_mismatch", "session is owned by another principal", http.StatusForbidden)
	errSessionRunning            = security.New("session_running", "session is still running; stop it before starting it again", http.StatusConflict)
	errIdempotencyConflict       = security.New("idempotency_conflict", "idempotency key was already used for another request", http.StatusConflict)
	errServiceStopping           = security.New("service_stopping", "The session service is stopping.", http.StatusServiceUnavailable)
	errDevtunnelsAccountRequired = security.New("devtunnels_account_required", "the devtunnel transport requires a connected Dev Tunnels account", http.StatusConflict)
)

func (s Service) utcNow() time.Time { return s.now().UTC() }

func (s Service) ownTimeout() (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.runtime.ctx, s.runner.EffectiveTimeout())
}

func (s Service) Close() { s.runtime.close() }

func ifNoneMatch(raw, current string) bool {
	for validator := range strings.SplitSeq(raw, ",") {
		validator = strings.TrimSpace(validator)
		if validator == "*" || strings.TrimPrefix(validator, "W/") == current {
			return true
		}
	}
	return false
}

func ownedSession(session *Session, principal security.Principal) (*Session, error) {
	switch {
	case session == nil:
		return nil, errSessionNotFound
	case session.Owner != principal:
		return nil, errOwnerMismatch
	}
	return session, nil
}

func (s Service) Get(principal security.Principal, id string) (*Session, error) {
	session, err := s.loadSession(id)
	if err == nil && session.Owner != principal {
		return nil, errOwnerMismatch
	}
	return session, err
}

func (s Service) List(principal security.Principal) (SessionList, error) {
	sessions, err := s.sessionsOf(principal)
	list := SessionList{Sessions: make([]SessionResponse, 0, len(sessions)), Logs: []SessionLogTail{}}
	for _, session := range sessions {
		list.Sessions = append(list.Sessions, session.SessionResponse)
		if tail, ok := s.logs.tail(session.ID); ok {
			list.Logs = append(list.Logs, tail)
		}
	}
	return list, err
}

func (s Service) Discover(ctx context.Context, principal security.Principal, alias string) (Resource, error) {
	return s.forPrincipal(principal).discover(ctx, alias)
}

func (s Service) Usage(principal security.Principal, id string) (SessionSeries, error) {
	session, err := s.Get(principal, id)
	if err != nil {
		return SessionSeries{}, err
	}
	return SessionSeries{SessionID: session.ID, Samples: s.usage.samples(session.ID)}, nil
}

func view(session *Session, err error) (SessionResponse, error) {
	if err != nil {
		return SessionResponse{}, err
	}
	return session.SessionResponse, nil
}

func decoded[T any](request *http.Request) (T, error) {
	var body T
	return body, security.DecodeJSON(request, &body)
}

func (s Service) defineSession(writer http.ResponseWriter, request *http.Request) {
	principal, err := security.PrincipalFromContext(request.Context())
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	body, err := decoded[CreateRequest](request)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	session, isNew, err := s.Define(principal, body)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	status := http.StatusOK
	if isNew {
		status = http.StatusCreated
		writer.Header().Set("Location", "/api/v1/sessions/"+session.ID)
	}
	security.WriteJSON(writer, status, session.SessionResponse)
}

func (s Service) listSessions(writer http.ResponseWriter, request *http.Request) {
	principal, err := security.PrincipalFromContext(request.Context())
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	list, err := s.List(principal)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	body, err := json.Marshal(list)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	sum := sha256.Sum256(body)
	etag := `"` + hex.EncodeToString(sum[:]) + `"`
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("ETag", etag)
	if ifNoneMatch(request.Header.Get("If-None-Match"), etag) {
		writer.WriteHeader(http.StatusNotModified)
		return
	}
	security.WriteJSONBytes(writer, http.StatusOK, body)
}

func (s Service) Routes() router.Routes {
	id := func(request *http.Request) string { return request.PathValue("id") }
	return router.Routes{
		"/api/v1/hosts/{alias}/slurm": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (Resource, error) {
			return s.Discover(request.Context(), principal, request.PathValue("alias"))
		})},
		"/api/v1/sessions": {http.MethodGet: s.listSessions, http.MethodPost: s.defineSession},
		"/api/v1/sessions/validate": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*ValidationResult, error) {
			body, err := decoded[CreateRequest](request)
			if err != nil {
				return nil, err
			}
			return s.Validate(request.Context(), principal, body)
		})},
		"/api/v1/sessions/{id}": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (SessionResponse, error) {
				return view(s.Get(principal, id(request)))
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, request *http.Request) error {
				_, err := s.Delete(principal, id(request))
				return err
			}),
		},
		"/api/v1/sessions/{id}/start": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (SessionResponse, error) {
			return view(s.Start(request.Context(), principal, id(request)))
		})},
		"/api/v1/sessions/{id}/attach": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*AttachResponse, error) {
			var body struct {
				TunnelModes []string `json:"tunnelModes"`
			}
			if err := security.DecodeStrict(io.LimitReader(request.Body, 1<<10), &body); err != nil && !errors.Is(err, io.EOF) {
				return nil, security.New("invalid_json", "request body is invalid", http.StatusBadRequest)
			}
			return s.Attach(request.Context(), principal, id(request), body.TunnelModes)
		})},
		"/api/v1/sessions/{id}/stop": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (SessionResponse, error) {
			return view(s.Stop(principal, id(request)))
		})},
		"/api/v1/sessions/{id}/access": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*SessionAccessResponse, error) {
			return s.Access(principal, id(request))
		})},
		"/api/v1/sessions/{id}/ssh": {http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (*SSHAccessResponse, error) {
			body, err := decoded[struct {
				PublicKey string `json:"publicKey"`
			}](request)
			if err != nil {
				return nil, err
			}
			return s.StartSSH(request.Context(), principal, id(request), body.PublicKey)
		})},
		"/api/v1/sessions/{id}/usage": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (SessionSeries, error) {
			return s.Usage(principal, id(request))
		})},
		"/api/v1/runs": {http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (RunList, error) {
			runs, err := s.Runs(principal)
			return RunList{Runs: runs}, err
		})},
	}
}
