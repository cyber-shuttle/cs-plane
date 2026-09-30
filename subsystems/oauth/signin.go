// The sign-in routes finish CILogon grants while keeping the client secret server-side: the browser's
// authorization-code flow with PKCE, and the device grant for a client that cannot receive a redirect. Only config and
// exchange serve browsers alone and require an Origin; device, its poll and refresh also serve native clients. A
// device poll answers pending as a status, not an error. Upstream failures are classified without provider details.
package oauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/identity"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const signInScope = "openid email profile offline_access"

type Service struct {
	oidc         *identity.OIDC
	clientID     string
	clientSecret string
	origins      security.Origins
	// validator is s.validate in production; tests substitute a fake.
	validator func(context.Context, string) (security.Principal, error)
}

func redirectOriginAllowed(redirectURI string, origins security.Origins) bool {
	parsed, err := url.Parse(redirectURI)
	return err == nil && parsed.Scheme != "" && parsed.Host != "" && parsed.User == nil && origins.Allowed(parsed.Scheme+"://"+parsed.Host)
}

func (s *Service) handleConfig(writer http.ResponseWriter, request *http.Request) {
	metadata, err := s.oidc.Discovery(request.Context())
	if err != nil {
		security.WriteError(writer, security.New("upstream_unavailable", "the identity provider is unavailable", http.StatusBadGateway))
		return
	}
	security.WriteJSON(writer, http.StatusOK, OAuthConfigResponse{Issuer: metadata.Issuer, AuthorizationEndpoint: metadata.AuthorizationEndpoint, ClientID: s.clientID, Scope: signInScope})
}

func (s *Service) handleExchange(writer http.ResponseWriter, request *http.Request) {
	var body ExchangeRequest
	if err := security.DecodeJSON(request, &body); err != nil {
		security.WriteError(writer, err)
		return
	}
	if body.Code == "" || body.CodeVerifier == "" || !redirectOriginAllowed(body.RedirectURI, s.origins) {
		security.WriteError(writer, security.New("invalid_grant", "the request is invalid", http.StatusBadRequest))
		return
	}
	tokens, err := s.oidc.Exchange(request.Context(), s.clientSecret, body.Code, body.CodeVerifier, body.RedirectURI)
	s.writeTokens(writer, tokens, err)
}

func (s *Service) handleRefresh(writer http.ResponseWriter, request *http.Request) {
	var body RefreshRequest
	if err := security.DecodeJSON(request, &body); err != nil {
		security.WriteError(writer, err)
		return
	}
	if body.RefreshToken == "" {
		security.WriteError(writer, security.New("invalid_json", "request body is invalid", http.StatusBadRequest))
		return
	}
	tokens, err := s.oidc.Refresh(request.Context(), s.clientSecret, body.RefreshToken)
	s.writeTokens(writer, tokens, err)
}

func tokenError(err error) error {
	switch {
	case errors.Is(err, identity.ErrGrantRejected):
		return security.New("invalid_grant", "the authorization code or refresh token was rejected", http.StatusBadRequest)
	case errors.Is(err, identity.ErrTokenInvalid):
		return security.New("upstream_invalid", "the identity provider returned an invalid response", http.StatusBadGateway)
	}
	return security.New("upstream_unavailable", "the identity provider is unavailable", http.StatusBadGateway)
}

func tokenBody(tokens identity.Tokens) *TokenResponse {
	return &TokenResponse{IDToken: tokens.IDToken, RefreshToken: tokens.RefreshToken, ExpiresInSeconds: tokens.ExpiresIn}
}

func (s *Service) writeTokens(writer http.ResponseWriter, tokens identity.Tokens, err error) {
	if err != nil {
		security.WriteError(writer, tokenError(err))
		return
	}
	security.WriteJSON(writer, http.StatusOK, tokenBody(tokens))
}

func (s *Service) handleDevice(writer http.ResponseWriter, request *http.Request) {
	device, err := s.oidc.DeviceAuthorize(request.Context(), s.clientSecret, signInScope)
	if err != nil {
		security.WriteError(writer, tokenError(err))
		return
	}
	security.WriteJSON(writer, http.StatusOK, DeviceResponse{DeviceCode: device.DeviceCode, UserCode: device.UserCode, CompleteURI: device.CompleteURI, IntervalSeconds: device.Interval})
}

func (s *Service) handleDevicePoll(writer http.ResponseWriter, request *http.Request) {
	var body DevicePollRequest
	if err := security.DecodeJSON(request, &body); err != nil || body.DeviceCode == "" {
		security.WriteError(writer, security.New("invalid_json", "request body is invalid", http.StatusBadRequest))
		return
	}
	tokens, err := s.oidc.RedeemDevice(request.Context(), s.clientSecret, body.DeviceCode)
	switch {
	case errors.Is(err, identity.ErrAuthorizationPending):
		security.WriteJSON(writer, http.StatusOK, DevicePoll{Status: "pending", IntervalSeconds: identity.MinDeviceInterval})
	case err != nil:
		security.WriteError(writer, tokenError(err))
	default:
		security.WriteJSON(writer, http.StatusOK, DevicePoll{Status: "complete", TokenResponse: tokenBody(tokens)})
	}
}

func NewService(issuer, clientID, clientSecret string, origins security.Origins, client *http.Client) (*Service, error) {
	if strings.TrimSpace(clientSecret) == "" || len(origins) == 0 {
		return nil, errors.New("auth service dependencies are required")
	}
	oidc, err := identity.NewOIDC(issuer, clientID, client)
	if err != nil {
		return nil, err
	}
	service := &Service{oidc: oidc, clientID: clientID, clientSecret: clientSecret, origins: origins}
	service.validator = service.validate
	return service, nil
}

func (s *Service) Routes() router.Routes {
	return router.Routes{
		"/api/v1/oauth/config":      {http.MethodGet: s.handleConfig},
		"/api/v1/oauth/exchange":    {http.MethodPost: s.handleExchange},
		"/api/v1/oauth/refresh":     {http.MethodPost: s.handleRefresh},
		"/api/v1/oauth/device":      {http.MethodPost: s.handleDevice},
		"/api/v1/oauth/device/poll": {http.MethodPost: s.handleDevicePoll},
	}
}

// Protect wraps the registry so that only this service's own routes are public; a WebSocket upgrade subprotocolAuth
// admits carries its bearer as a subprotocol.
func (s *Service) Protect(next *router.Registry, subprotocolAuth func(*http.Request) bool) http.Handler {
	public := map[string]struct{}{}
	for path := range s.Routes() {
		public[path] = struct{}{}
	}
	browser := map[string]struct{}{"/api/v1/oauth/config": {}, "/api/v1/oauth/exchange": {}}
	return &oauthBoundary{next: next, subprotocolAuth: subprotocolAuth, validate: s.validator, origins: s.origins, publicPaths: public, browserPaths: browser}
}
