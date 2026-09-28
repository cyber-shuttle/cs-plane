// Package devtunnels owns connecting a Dev Tunnels account and its HTTP surface. The broker binds device
// authorizations to principals, bounds pending work, and seals the connected Microsoft or GitHub tokens in protected
// principal files. Provider protocol and cryptography remain internal; routes and stored metadata never expose tokens.
package devtunnels

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	maxStoredCredential        = 64 << 10
	accountRefreshWindow       = 2 * time.Minute
	maxPendingAuthorizations   = 256
	authorizationStartInterval = time.Second
	maxPollInterval            = 60 * time.Second
	accountFileName            = "devtunnels-account"
	accountKeyFileName         = "devtunnels-account.key"
)

var handlePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

type accountAuthorizer interface {
	Supports(string) bool
	Start(context.Context, string) (*devtunnel.DeviceAuthorization, error)
	Poll(context.Context, *devtunnel.DeviceAuthorization, time.Duration) (devtunnel.PollResult, error)
	Refresh(context.Context, string, string) (devtunnel.AuthorizationTokens, error)
}

type account struct {
	Provider     string    `json:"provider"`
	Scheme       string    `json:"scheme"`
	AccessToken  string    `json:"accessToken"`
	RefreshToken string    `json:"refreshToken,omitempty"`
	ExpiresAt    time.Time `json:"expiresAt,omitzero"`
	Account      string    `json:"account"`
	ConnectedAt  time.Time `json:"connectedAt"`
}

type pendingAuthorization struct {
	principal     security.Principal
	authorization *devtunnel.DeviceAuthorization
	expiresAt     time.Time
	interval      time.Duration
	nextPoll      time.Time
}

type Service struct {
	mu                 sync.Mutex
	entries            map[string]*pendingAuthorization
	nextPrincipalStart map[security.Principal]time.Time
	stateDir           string
	principalDir       string
	box                *security.SecretBox
	authorizer         accountAuthorizer
	now                func() time.Time
}

func (a account) status() AccountStatus {
	return AccountStatus{Connected: true, Provider: a.Provider, Account: a.Account, ConnectedAt: a.ConnectedAt}
}

func (s *Service) withCredentialLock(principal security.Principal, fn func() error) error {
	path := filepath.Join(s.stateDir, ".devtunnels-account-"+security.PrincipalDirName(principal)+".lock")
	return security.WithFileLock(path, fn)
}

func (s *Service) accountPath(principal security.Principal) string {
	return filepath.Join(s.principalDir, security.PrincipalDirName(principal), accountFileName)
}

func (s *Service) loadAccount(principal security.Principal) (account, bool, error) {
	path := s.accountPath(principal)
	if err := security.PrivateDir(filepath.Dir(path)); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return account{}, false, nil
		}
		return account{}, false, err
	}
	sealed, err := security.ReadPrivateFile(path, maxStoredCredential)
	if errors.Is(err, os.ErrNotExist) {
		return account{}, false, nil
	}
	if err != nil {
		return account{}, false, err
	}
	plaintext, err := s.box.Open(sealed)
	if err != nil {
		return account{}, false, err
	}
	var stored account
	if json.Unmarshal(plaintext, &stored) != nil {
		return account{}, false, errors.New("stored Dev Tunnels account is invalid")
	}
	return stored, true, nil
}

func (s *Service) saveAccount(principal security.Principal, stored account) error {
	path := s.accountPath(principal)
	if err := security.EnsurePrivateDir(filepath.Dir(path)); err != nil {
		return err
	}
	plaintext, err := json.Marshal(stored)
	if err != nil {
		return err
	}
	sealed, err := s.box.Seal(plaintext)
	if err != nil {
		return err
	}
	return security.ReplaceFile(path, sealed)
}

func (s *Service) cleanupLocked(now time.Time) {
	for handle, entry := range s.entries {
		if !now.Before(entry.expiresAt) {
			s.deleteLocked(handle)
		}
	}
	for principal, next := range s.nextPrincipalStart {
		if !now.Before(next) {
			delete(s.nextPrincipalStart, principal)
		}
	}
}

func (s *Service) deleteLocked(handle string) {
	if entry := s.entries[handle]; entry != nil {
		entry.authorization.Clear()
		delete(s.entries, handle)
	}
}

func (s *Service) finishPoll(handle string, remove bool, slowDown time.Duration) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.entries[handle]
	if entry == nil {
		return 0
	}
	if remove {
		s.deleteLocked(handle)
		return 0
	}
	entry.interval = min(entry.interval+slowDown, maxPollInterval)
	entry.nextPoll = s.now().Add(entry.interval)
	return entry.interval
}

func authorizationError(err error) error {
	switch {
	case errors.Is(err, devtunnel.ErrUnknownProvider):
		return security.New("unknown_provider", "sign-in provider is not offered", http.StatusBadRequest)
	case errors.Is(err, devtunnel.ErrAuthorizationDenied):
		return security.New("authorization_denied", "authorization was denied", http.StatusForbidden)
	case errors.Is(err, devtunnel.ErrAuthorizationExpired):
		return security.New("authorization_expired", "authorization expired", http.StatusGone)
	case errors.Is(err, devtunnel.ErrAuthorizationUnavailable):
		return security.New("upstream_unavailable", "authorization service is unavailable", http.StatusBadGateway)
	case errors.Is(err, devtunnel.ErrAuthorizationRejected):
		return security.New("upstream_failure", "authorization service rejected the request", http.StatusBadGateway)
	default:
		return security.New("upstream_invalid", "authorization service returned an invalid response", http.StatusBadGateway)
	}
}

func (s *Service) status(principal security.Principal) (AccountStatus, error) {
	stored, ok, err := s.loadAccount(principal)
	if err != nil || !ok {
		return AccountStatus{}, err
	}
	return stored.status(), nil
}

func (s *Service) start(ctx context.Context, principal security.Principal, providerName string) (AuthorizationStart, error) {
	if !s.authorizer.Supports(providerName) {
		return AuthorizationStart{}, authorizationError(devtunnel.ErrUnknownProvider)
	}
	now := s.now()
	s.mu.Lock()
	s.cleanupLocked(now)
	if now.Before(s.nextPrincipalStart[principal]) {
		s.mu.Unlock()
		return AuthorizationStart{}, security.New("rate_limited", "request rate exceeded", http.StatusTooManyRequests)
	}
	if len(s.entries) >= maxPendingAuthorizations {
		s.mu.Unlock()
		return AuthorizationStart{}, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	s.nextPrincipalStart[principal] = now.Add(authorizationStartInterval)
	s.mu.Unlock()

	authorization, err := s.authorizer.Start(ctx, providerName)
	if err != nil {
		return AuthorizationStart{}, authorizationError(err)
	}
	rawHandle := make([]byte, 32)
	_, _ = rand.Read(rawHandle)
	handle := base64.RawURLEncoding.EncodeToString(rawHandle)
	now = s.now()
	entry := &pendingAuthorization{
		principal: principal, authorization: authorization, expiresAt: now.Add(authorization.ExpiresIn),
		interval: authorization.Interval, nextPoll: now.Add(authorization.Interval),
	}
	s.mu.Lock()
	if len(s.entries) >= maxPendingAuthorizations {
		s.mu.Unlock()
		authorization.Clear()
		return AuthorizationStart{}, security.New("broker_capacity", "authorization service is busy", http.StatusServiceUnavailable)
	}
	s.entries[handle] = entry
	s.mu.Unlock()
	return AuthorizationStart{
		Handle: handle, UserCode: authorization.UserCode, VerificationURI: authorization.VerificationURI,
		ExpiresInSeconds: int64(authorization.ExpiresIn / time.Second), IntervalSeconds: int64(authorization.Interval / time.Second),
	}, nil
}

func (s *Service) poll(ctx context.Context, principal security.Principal, handle string) (result AuthorizationPoll, err error) {
	if !handlePattern.MatchString(handle) {
		return AuthorizationPoll{}, security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	err = s.withCredentialLock(principal, func() error {
		result, err = s.pollCredentialLocked(ctx, principal, handle)
		return err
	})
	return result, err
}

func (s *Service) pollCredentialLocked(ctx context.Context, principal security.Principal, handle string) (AuthorizationPoll, error) {
	now := s.now()
	s.mu.Lock()
	entry, ok := s.entries[handle]
	if !ok || entry.principal != principal {
		s.mu.Unlock()
		return AuthorizationPoll{}, security.New("not_found", "authorization was not found", http.StatusNotFound)
	}
	if !now.Before(entry.expiresAt) {
		s.deleteLocked(handle)
		s.mu.Unlock()
		return AuthorizationPoll{}, security.New("authorization_expired", "authorization expired", http.StatusGone)
	}
	if now.Before(entry.nextPoll) {
		s.mu.Unlock()
		return AuthorizationPoll{}, security.New("rate_limited", "polling too quickly", http.StatusTooManyRequests)
	}
	authorization, remaining := entry.authorization, entry.expiresAt.Sub(now)
	s.mu.Unlock()

	result, err := s.authorizer.Poll(ctx, authorization, remaining)
	if err != nil {
		s.finishPoll(handle, true, 0)
		return AuthorizationPoll{}, authorizationError(err)
	}
	if result.Pending {
		interval := s.finishPoll(handle, false, result.SlowDown)
		return AuthorizationPoll{Status: "pending", IntervalSeconds: int64(interval / time.Second)}, nil
	}
	s.finishPoll(handle, true, 0)
	now = s.now()
	stored := account{
		Provider: result.Tokens.Provider, Scheme: result.Tokens.Scheme, AccessToken: result.Tokens.AccessToken,
		RefreshToken: result.Tokens.RefreshToken, Account: result.Tokens.Account, ConnectedAt: now,
	}
	if result.Tokens.ExpiresIn > 0 {
		stored.ExpiresAt = now.Add(result.Tokens.ExpiresIn)
	}
	if err = s.saveAccount(principal, stored); err != nil {
		return AuthorizationPoll{}, err
	}
	return AuthorizationPoll{Status: "connected", AccountStatus: stored.status()}, nil
}

func (s *Service) Credential(ctx context.Context, principal security.Principal) (result devtunnel.Credential, err error) {
	err = s.withCredentialLock(principal, func() error {
		stored, ok, err := s.loadAccount(principal)
		if err != nil {
			return err
		}
		if !ok {
			return nil
		}
		if stored.RefreshToken != "" && !stored.ExpiresAt.IsZero() && s.now().Add(accountRefreshWindow).After(stored.ExpiresAt) {
			tokens, err := s.authorizer.Refresh(ctx, stored.Provider, stored.RefreshToken)
			if err != nil {
				return security.New("upstream_unavailable", "the Dev Tunnels account could not be refreshed", http.StatusBadGateway)
			}
			stored.AccessToken, stored.RefreshToken, stored.ExpiresAt = tokens.AccessToken, tokens.RefreshToken, s.now().Add(tokens.ExpiresIn)
			if err := s.saveAccount(principal, stored); err != nil {
				return err
			}
		}
		result = devtunnel.Credential{Scheme: stored.Scheme, Token: stored.AccessToken}
		return nil
	})
	return result, err
}

func (s *Service) delete(principal security.Principal) error {
	return s.withCredentialLock(principal, func() error {
		path := s.accountPath(principal)
		if err := security.PrivateDir(filepath.Dir(path)); errors.Is(err, os.ErrNotExist) {
			return nil
		} else if err != nil {
			return err
		}
		return security.RemoveFile(path)
	})
}

func (s *Service) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for handle := range s.entries {
		s.deleteLocked(handle)
	}
	clear(s.nextPrincipalStart)
}

func NewService(stateDir, principalDir string, client *http.Client) (*Service, error) {
	if stateDir == "" || principalDir == "" {
		return nil, errors.New("the Dev Tunnels broker directories are required")
	}
	if err := security.EnsurePrivateDir(stateDir); err != nil {
		return nil, err
	}
	if err := security.EnsurePrivateDir(principalDir); err != nil {
		return nil, err
	}
	box, err := security.LoadOrCreateSecretBox(filepath.Join(stateDir, accountKeyFileName))
	if err != nil {
		return nil, err
	}
	return newService(stateDir, principalDir, box, devtunnel.NewAuthorizer(client)), nil
}

func newService(stateDir, principalDir string, box *security.SecretBox, authorizer accountAuthorizer) *Service {
	return &Service{
		entries: map[string]*pendingAuthorization{}, nextPrincipalStart: map[security.Principal]time.Time{},
		stateDir: stateDir, principalDir: principalDir, box: box, authorizer: authorizer, now: time.Now,
	}
}

func (s *Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/devtunnels": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (AccountStatus, error) {
				return s.status(principal)
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, _ *http.Request) error {
				return s.delete(principal)
			}),
		},
		"/api/v1/devtunnels/authorizations": {
			http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (AuthorizationStart, error) {
				var body AuthorizationRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return AuthorizationStart{}, err
				}
				return s.start(request.Context(), principal, body.Provider)
			}),
		},
		"/api/v1/devtunnels/authorizations/{handle}/poll": {
			http.MethodPost: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (AuthorizationPoll, error) {
				return s.poll(request.Context(), principal, request.PathValue("handle"))
			}),
		},
	}
}
