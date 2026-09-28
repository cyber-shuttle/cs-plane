// Dev Tunnels authorization exchanges Microsoft or GitHub device codes for credentials accepted by the
// management service. It owns provider protocol details and validates bounded upstream responses, while callers
// own principal binding, admission, polling cadence, persistence, and public errors. DeviceAuthorization keeps
// the device code opaque and clears it when authorization reaches a terminal outcome.
package devtunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	maxAuthorizationResponse = 64 << 10
	authorizationTimeout     = 15 * time.Second
	microsoftScheme          = "Bearer"
	deviceGrantType          = "urn:ietf:params:oauth:grant-type:device_code"
	maxTokenLifetime         = 24 * time.Hour
	microsoftClientID        = "c0df98ca-23b4-4bce-bb9f-72039b28d3a5"
	githubClientID           = "Iv1.e7b89e013f801f03"
	deviceScope              = "openid profile offline_access 46da2f7e-b5ef-422a-88d4-2a7f9de6a0b2/.default"
	githubDeviceEndpoint     = "https://github.com/login/device/code"
	githubOAuthEndpoint      = "https://github.com/login/oauth/access_token"
	githubUserEndpoint       = "https://api.github.com/user"
	microsoftDeviceEndpoint  = "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
	microsoftOAuthEndpoint   = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
)

var (
	ErrUnknownProvider          = errors.New("unknown Dev Tunnels authorization provider")
	ErrAuthorizationDenied      = errors.New("authorization for Dev Tunnels was denied")
	ErrAuthorizationExpired     = errors.New("authorization for Dev Tunnels expired")
	ErrAuthorizationUnavailable = errors.New("authorization for Dev Tunnels is unavailable")
	ErrAuthorizationInvalid     = errors.New("invalid Dev Tunnels authorization response")
	ErrAuthorizationRejected    = errors.New("authorization for Dev Tunnels was rejected")
)

type authorizationProvider struct {
	name, scheme, deviceEndpoint, tokenEndpoint, userEndpoint, clientID, scope string
}

type DeviceAuthorization struct {
	UserCode        string
	VerificationURI string
	ExpiresIn       time.Duration
	Interval        time.Duration

	mu         sync.Mutex
	provider   authorizationProvider
	deviceCode []byte
}

type AuthorizationTokens struct {
	Provider     string
	Scheme       string
	AccessToken  string
	RefreshToken string
	Account      string
	ExpiresIn    time.Duration
}

type PollResult struct {
	Pending  bool
	SlowDown time.Duration
	Tokens   AuthorizationTokens
}

type Authorizer struct {
	providers map[string]authorizationProvider
	client    *http.Client
}

func NewAuthorizer(client *http.Client) *Authorizer {
	return &Authorizer{
		providers: map[string]authorizationProvider{
			"microsoft": {
				name: "microsoft", scheme: microsoftScheme, deviceEndpoint: microsoftDeviceEndpoint,
				tokenEndpoint: microsoftOAuthEndpoint, clientID: microsoftClientID, scope: deviceScope,
			},
			"github": {
				name: "github", scheme: "github", deviceEndpoint: githubDeviceEndpoint,
				tokenEndpoint: githubOAuthEndpoint, userEndpoint: githubUserEndpoint, clientID: githubClientID,
			},
		},
		client: security.GuardedClient(client, authorizationTimeout),
	}
}

func (a *Authorizer) Supports(provider string) bool {
	_, ok := a.providers[provider]
	return ok
}

// postForm posts the provider's client_id and scope with form to endpoint; any network or non-2xx failure is
// ErrAuthorizationUnavailable.
func (a *Authorizer) postForm(ctx context.Context, provider authorizationProvider, endpoint string, form url.Values) ([]byte, error) {
	form.Set("client_id", provider.clientID)
	if provider.scope != "" {
		form.Set("scope", provider.scope)
	}
	body, status, err := security.PostForm(ctx, a.client, endpoint, form, authorizationTimeout, maxAuthorizationResponse)
	if err != nil || status < 200 || status >= 300 {
		return nil, ErrAuthorizationUnavailable
	}
	return body, nil
}

func (a *DeviceAuthorization) Clear() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.deviceCode)
	a.deviceCode = nil
}

func (a *Authorizer) Start(ctx context.Context, providerName string) (*DeviceAuthorization, error) {
	provider, ok := a.providers[providerName]
	if !ok {
		return nil, ErrUnknownProvider
	}
	body, err := a.postForm(ctx, provider, provider.deviceEndpoint, url.Values{})
	if err != nil {
		return nil, err
	}
	var response struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int64  `json:"expires_in"`
		Interval        int64  `json:"interval"`
	}
	if json.Unmarshal(body, &response) != nil {
		return nil, ErrAuthorizationInvalid
	}
	verificationURI, parseErr := url.Parse(response.VerificationURI)
	if !security.ValidCredential(response.DeviceCode) || len(response.DeviceCode) > 4096 || !security.ValidCredential(response.UserCode) || len(response.UserCode) > 128 ||
		response.ExpiresIn <= 0 || response.ExpiresIn > 3600 || response.Interval < 0 || response.Interval > 60 || parseErr != nil ||
		verificationURI.Scheme != "https" || verificationURI.Host == "" || verificationURI.User != nil || verificationURI.Fragment != "" || len(response.VerificationURI) > 2048 {
		return nil, ErrAuthorizationInvalid
	}
	if response.Interval == 0 {
		response.Interval = 5
	}
	return &DeviceAuthorization{
		UserCode: response.UserCode, VerificationURI: response.VerificationURI,
		ExpiresIn: time.Duration(response.ExpiresIn) * time.Second, Interval: time.Duration(response.Interval) * time.Second,
		provider: provider, deviceCode: []byte(response.DeviceCode),
	}, nil
}

func (a *Authorizer) Poll(ctx context.Context, authorization *DeviceAuthorization, timeout time.Duration) (PollResult, error) {
	if authorization == nil {
		return PollResult{}, ErrAuthorizationInvalid
	}
	authorization.mu.Lock()
	provider, deviceCode := authorization.provider, string(authorization.deviceCode)
	authorization.mu.Unlock()
	if deviceCode == "" {
		return PollResult{}, ErrAuthorizationInvalid
	}
	if timeout <= 0 || timeout > authorizationTimeout {
		timeout = authorizationTimeout
	}
	body, status, err := security.PostForm(ctx, a.client, provider.tokenEndpoint, url.Values{
		"grant_type": {deviceGrantType}, "client_id": {provider.clientID}, "device_code": {deviceCode},
	}, timeout, maxAuthorizationResponse)
	if err != nil {
		authorization.Clear()
		return PollResult{}, ErrAuthorizationUnavailable
	}
	var oauthError struct {
		Error string `json:"error"`
	}
	_ = json.Unmarshal(body, &oauthError)
	if status < 200 || status >= 300 || oauthError.Error != "" {
		switch oauthError.Error {
		case "authorization_pending":
			return PollResult{Pending: true}, nil
		case "slow_down":
			return PollResult{Pending: true, SlowDown: 5 * time.Second}, nil
		case "access_denied":
			authorization.Clear()
			return PollResult{}, ErrAuthorizationDenied
		case "expired_token":
			authorization.Clear()
			return PollResult{}, ErrAuthorizationExpired
		default:
			authorization.Clear()
			return PollResult{}, ErrAuthorizationRejected
		}
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &response) != nil || !security.ValidCredential(response.AccessToken) ||
		response.RefreshToken != "" && !security.ValidCredential(response.RefreshToken) || response.ExpiresIn < 0 ||
		response.ExpiresIn == 0 && provider.name != "github" || response.ExpiresIn > int64(maxTokenLifetime/time.Second) {
		authorization.Clear()
		return PollResult{}, ErrAuthorizationInvalid
	}
	account := preferredUsername(response.IDToken)
	if provider.name == "github" {
		var user struct {
			Login string `json:"login"`
		}
		if err := security.GetJSON(ctx, a.client, provider.userEndpoint, microsoftScheme+" "+response.AccessToken, maxAuthorizationResponse, &user); err != nil {
			authorization.Clear()
			return PollResult{}, ErrAuthorizationInvalid
		}
		account = user.Login
	}
	if !security.ValidIdentityValue(account) {
		authorization.Clear()
		return PollResult{}, ErrAuthorizationInvalid
	}
	authorization.Clear()
	return PollResult{Tokens: AuthorizationTokens{
		Provider: provider.name, Scheme: provider.scheme, AccessToken: response.AccessToken,
		RefreshToken: response.RefreshToken, Account: account, ExpiresIn: time.Duration(response.ExpiresIn) * time.Second,
	}}, nil
}

func (a *Authorizer) Refresh(ctx context.Context, providerName, refreshToken string) (AuthorizationTokens, error) {
	provider, ok := a.providers[providerName]
	if !ok {
		return AuthorizationTokens{}, ErrUnknownProvider
	}
	if !security.ValidCredential(refreshToken) {
		return AuthorizationTokens{}, ErrAuthorizationInvalid
	}
	body, err := a.postForm(ctx, provider, provider.tokenEndpoint, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
	if err != nil {
		return AuthorizationTokens{}, err
	}
	var response struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &response) != nil || !security.ValidCredential(response.AccessToken) ||
		response.RefreshToken != "" && !security.ValidCredential(response.RefreshToken) || response.ExpiresIn <= 0 ||
		response.ExpiresIn > int64(maxTokenLifetime/time.Second) {
		return AuthorizationTokens{}, ErrAuthorizationInvalid
	}
	if response.RefreshToken == "" {
		response.RefreshToken = refreshToken
	}
	return AuthorizationTokens{
		Provider: provider.name, Scheme: provider.scheme, AccessToken: response.AccessToken,
		RefreshToken: response.RefreshToken, ExpiresIn: time.Duration(response.ExpiresIn) * time.Second,
	}, nil
}

func preferredUsername(idToken string) string {
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 || !security.ValidCredential(idToken) || len(parts[1]) > security.MaxCredentialBytes {
		return ""
	}
	decoded, ok := security.DecodeBase64URL(parts[1])
	if !ok {
		return ""
	}
	var claims struct {
		PreferredUsername string `json:"preferred_username"`
	}
	if json.Unmarshal(decoded, &claims) != nil {
		return ""
	}
	return claims.PreferredUsername
}
