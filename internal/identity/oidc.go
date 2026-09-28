// Package identity implements the OIDC protocol client that establishes a caller's identity from a CILogon ID token.
// OIDC discovery and JWKS share one cache; only an unknown key inside its cooldown triggers refresh. Token grants
// use the discovered endpoint and expose classified protocol outcomes without HTTP policy. Callers compose this
// client into principals and public routes.
package identity

import (
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	maxOAuthResponse       = 64 << 10
	maxOIDCResponse        = 256 << 10
	oauthRequestTimeout    = 15 * time.Second
	oidcCacheTTL           = 5 * time.Minute
	oidcUnknownKIDCooldown = 30 * time.Second
)

const MinDeviceInterval = 5

var (
	ErrAuthorizationPending = errors.New("OIDC device authorization is pending")
	ErrGrantRejected        = errors.New("OIDC grant was rejected")
	ErrTokenUnavailable     = errors.New("OIDC token service is unavailable")
	ErrTokenInvalid         = errors.New("OIDC token response is invalid")
)

type Metadata struct {
	Issuer                string `json:"issuer"`
	JWKSURI               string `json:"jwks_uri"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	DeviceEndpoint        string `json:"device_authorization_endpoint"`
}

type oidcKeySet struct {
	Keys []struct {
		Kty string `json:"kty"`
		Use string `json:"use"`
		Alg string `json:"alg"`
		Kid string `json:"kid"`
		N   string `json:"n"`
		E   string `json:"e"`
	} `json:"keys"`
}

type cachedOIDCKeys struct {
	metadata Metadata
	keys     map[string]*rsa.PublicKey
	expires  time.Time
}

type oidcRefreshCall struct {
	done chan struct{}
	err  error
}

type OIDC struct {
	authority          *url.URL
	clientID           string
	client             *http.Client
	now                func() time.Time
	mu                 sync.Mutex
	cache              cachedOIDCKeys
	refresh            *oidcRefreshCall
	nextUnknownRefresh time.Time
}

type idTokenHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type idTokenClaims struct {
	Issuer    string `json:"iss"`
	Audience  string `json:"aud"`
	Expires   *int64 `json:"exp"`
	NotBefore *int64 `json:"nbf"`
	Subject   string `json:"sub"`
}

func NewOIDC(issuer, clientID string, client *http.Client) (*OIDC, error) {
	parsed, err := url.Parse(issuer)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("OIDC issuer must be an HTTPS URL")
	}
	if !security.ValidIdentityValue(clientID) {
		return nil, errors.New("OIDC client ID is invalid")
	}
	return &OIDC{
		authority: parsed, clientID: clientID,
		client: security.GuardedClient(client, oauthRequestTimeout), now: time.Now,
	}, nil
}

func parseSignedIDToken(token string) (idTokenHeader, idTokenClaims, string, []byte, error) {
	var header idTokenHeader
	var claims idTokenClaims
	parts := strings.Split(token, ".")
	if len(parts) != 3 || !security.ValidCredential(token) || len(parts[0]) > security.MaxCredentialBytes || len(parts[1]) > security.MaxCredentialBytes || len(parts[2]) > security.MaxCredentialBytes {
		return header, claims, "", nil, errors.New("token format")
	}
	decodeJSON := func(encoded string, destination any) error {
		decoded, ok := security.DecodeBase64URL(encoded)
		if !ok {
			return errors.New("token encoding")
		}
		if json.Unmarshal(decoded, destination) != nil {
			return errors.New("token JSON")
		}
		return nil
	}
	if err := decodeJSON(parts[0], &header); err != nil || header.Alg != "RS256" || !security.ValidIdentityValue(header.Kid) || header.Typ != "" && header.Typ != "JWT" {
		return header, claims, "", nil, errors.New("token header")
	}
	if err := decodeJSON(parts[1], &claims); err != nil {
		return header, claims, "", nil, err
	}
	signature, ok := security.DecodeBase64URL(parts[2])
	if !ok || len(signature) == 0 {
		return header, claims, "", nil, errors.New("token signature")
	}
	return header, claims, parts[0] + "." + parts[1], signature, nil
}

// Validate verifies the ID token and answers its subject.
func (v *OIDC) Validate(ctx context.Context, token string) (string, error) {
	header, claims, signingInput, signature, err := parseSignedIDToken(token)
	if err != nil {
		return "", errors.New("ID token is invalid")
	}
	cache, err := v.keys(ctx, "")
	if err != nil {
		return "", err
	}
	key := cache.keys[header.Kid]
	if key == nil {
		cache, err = v.keys(ctx, header.Kid)
		if err != nil {
			return "", err
		}
		key = cache.keys[header.Kid]
		if key == nil {
			return "", errors.New("ID token signing key is unknown")
		}
	}
	digest := sha256.Sum256([]byte(signingInput))
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature) != nil {
		return "", errors.New("ID token signature is invalid")
	}
	if err := v.validateClaims(claims, cache.metadata.Issuer); err != nil {
		return "", err
	}
	return claims.Subject, nil
}

func (v *OIDC) validateClaims(claims idTokenClaims, configuredIssuer string) error {
	if claims.Issuer != configuredIssuer || claims.Audience != v.clientID || claims.Expires == nil || !security.ValidIdentityValue(claims.Subject) {
		return errors.New("ID token claims are invalid")
	}
	now := v.now().Unix()
	if *claims.Expires <= now {
		return errors.New("ID token is outside its validity period")
	}
	if claims.NotBefore != nil && *claims.NotBefore > now {
		return errors.New("ID token is outside its validity period")
	}
	return nil
}

// keys answers the cached discovery and JWKS, refreshing when the cache expired or when unknownKID is not in it
// and its cooldown has passed. Concurrent callers share one refresh, which outlives the request that started it.
func (v *OIDC) keys(ctx context.Context, unknownKID string) (cachedOIDCKeys, error) {
	v.mu.Lock()
	now := v.now()
	cached := v.cache.keys != nil && now.Before(v.cache.expires)
	if unknownKID != "" {
		cached = v.cache.keys[unknownKID] != nil || v.refresh == nil && now.Before(v.nextUnknownRefresh)
	}
	if cached {
		cache := v.cache
		v.mu.Unlock()
		return cache, nil
	}
	call := v.refresh
	if call == nil {
		call = &oidcRefreshCall{done: make(chan struct{})}
		v.refresh = call
		if unknownKID != "" {
			v.nextUnknownRefresh = now.Add(oidcUnknownKIDCooldown)
		}
		go v.runRefresh(context.WithoutCancel(ctx), call)
	}
	v.mu.Unlock()
	select {
	case <-ctx.Done():
		return cachedOIDCKeys{}, ctx.Err()
	case <-call.done:
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if call.err != nil {
		return cachedOIDCKeys{}, call.err
	}
	return v.cache, nil
}

func (v *OIDC) runRefresh(ctx context.Context, call *oidcRefreshCall) {
	metadata, err := v.fetchMetadata(ctx)
	var keys map[string]*rsa.PublicKey
	if err == nil {
		keys, err = v.fetchKeys(ctx, metadata.JWKSURI)
	}
	v.mu.Lock()
	if err == nil {
		v.cache = cachedOIDCKeys{metadata: metadata, keys: keys, expires: v.now().Add(oidcCacheTTL)}
	}
	call.err = err
	if v.refresh == call {
		v.refresh = nil
	}
	close(call.done)
	v.mu.Unlock()
}

func (v *OIDC) fetchMetadata(ctx context.Context) (Metadata, error) {
	endpoint := *v.authority
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/.well-known/openid-configuration"
	var metadata Metadata
	if err := security.GetJSON(ctx, v.client, endpoint.String(), "", maxOIDCResponse, &metadata); err != nil {
		return metadata, errors.New("fetch OIDC discovery metadata")
	}
	endpoints := []string{metadata.Issuer, metadata.JWKSURI, metadata.AuthorizationEndpoint, metadata.TokenEndpoint}
	if metadata.DeviceEndpoint != "" {
		endpoints = append(endpoints, metadata.DeviceEndpoint)
	}
	parsed := make([]*url.URL, len(endpoints))
	for i, raw := range endpoints {
		u, err := url.Parse(raw)
		if err != nil || raw == "" || u.User != nil {
			return metadata, errors.New("OIDC discovery metadata is invalid")
		}
		parsed[i] = u
	}
	if metadata.Issuer != v.authority.String() {
		return metadata, errors.New("OIDC discovery issuer does not match the configured issuer")
	}
	for _, u := range parsed {
		if u.Scheme != v.authority.Scheme || u.Host != v.authority.Host {
			return metadata, errors.New("OIDC discovery endpoints do not match the configured issuer")
		}
	}
	return metadata, nil
}

func (v *OIDC) fetchKeys(ctx context.Context, endpoint string) (map[string]*rsa.PublicKey, error) {
	var set oidcKeySet
	if err := security.GetJSON(ctx, v.client, endpoint, "", maxOIDCResponse, &set); err != nil {
		return nil, errors.New("fetch OIDC signing keys")
	}
	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, jwk := range set.Keys {
		if jwk.Kty != "RSA" || (jwk.Use != "" && jwk.Use != "sig") || (jwk.Alg != "" && jwk.Alg != "RS256") {
			continue
		}
		if !security.ValidIdentityValue(jwk.Kid) || keys[jwk.Kid] != nil {
			return nil, errors.New("OIDC signing key is invalid")
		}
		n, errN := base64.RawURLEncoding.Strict().DecodeString(jwk.N)
		e, errE := base64.RawURLEncoding.Strict().DecodeString(jwk.E)
		if errN != nil || errE != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
			return nil, errors.New("OIDC RSA key is invalid")
		}
		exponent := 0
		for _, value := range e {
			exponent = exponent<<8 | int(value)
		}
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || exponent < 3 || exponent%2 == 0 {
			return nil, errors.New("OIDC RSA key is invalid")
		}
		keys[jwk.Kid] = &rsa.PublicKey{N: modulus, E: exponent}
	}
	if len(keys) == 0 {
		return nil, errors.New("OIDC signing keys are empty")
	}
	return keys, nil
}

func (v *OIDC) Discovery(ctx context.Context) (Metadata, error) {
	cache, err := v.keys(ctx, "")
	return cache.metadata, err
}

type Tokens struct {
	IDToken      string
	RefreshToken string
	ExpiresIn    int64
}

func (v *OIDC) Exchange(ctx context.Context, clientSecret, code, verifier, redirectURI string) (Tokens, error) {
	return v.redeem(ctx, clientSecret, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURI}, "code_verifier": {verifier},
	})
}

func (v *OIDC) Refresh(ctx context.Context, clientSecret, refreshToken string) (Tokens, error) {
	return v.redeem(ctx, clientSecret, url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshToken}})
}

type DeviceAuthorization struct {
	DeviceCode  string `json:"device_code"`
	UserCode    string `json:"user_code"`
	CompleteURI string `json:"verification_uri_complete"`
	ExpiresIn   int64  `json:"expires_in"`
	Interval    int64  `json:"interval"`
}

// DeviceAuthorize starts the device grant for a client with no redirect URI. The device code is safe to hand out:
// redeeming it needs the client secret only the daemon holds.
func (v *OIDC) DeviceAuthorize(ctx context.Context, clientSecret, scope string) (DeviceAuthorization, error) {
	var authorization DeviceAuthorization
	metadata, err := v.Discovery(ctx)
	if err != nil {
		return authorization, ErrTokenUnavailable
	}
	form := url.Values{"client_id": {v.clientID}, "client_secret": {clientSecret}, "scope": {scope}}
	body, status, err := security.PostForm(ctx, v.client, metadata.DeviceEndpoint, form, oauthRequestTimeout, maxOAuthResponse)
	if err != nil || status != http.StatusOK || json.Unmarshal(body, &authorization) != nil || authorization.DeviceCode == "" {
		return authorization, ErrTokenUnavailable
	}
	authorization.Interval = max(authorization.Interval, MinDeviceInterval)
	return authorization, nil
}

func (v *OIDC) RedeemDevice(ctx context.Context, clientSecret, deviceCode string) (Tokens, error) {
	return v.redeem(ctx, clientSecret, url.Values{"grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}, "device_code": {deviceCode}})
}

func (v *OIDC) redeem(ctx context.Context, clientSecret string, form url.Values) (Tokens, error) {
	metadata, err := v.Discovery(ctx)
	if err != nil {
		return Tokens{}, ErrTokenUnavailable
	}
	form.Set("client_id", v.clientID)
	form.Set("client_secret", clientSecret)
	body, status, err := security.PostForm(ctx, v.client, metadata.TokenEndpoint, form, oauthRequestTimeout, maxOAuthResponse)
	if err != nil {
		return Tokens{}, fmt.Errorf("%w: %w", ErrTokenUnavailable, err)
	}
	var response struct {
		Error        string `json:"error"`
		IDToken      string `json:"id_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if json.Unmarshal(body, &response) != nil {
		return Tokens{}, ErrTokenInvalid
	}
	switch response.Error {
	case "authorization_pending", "slow_down": // ponytail: slow_down reads as pending; add a backoff if CILogon starts sending it
		return Tokens{}, ErrAuthorizationPending
	case "invalid_grant", "expired_token", "access_denied":
		return Tokens{}, ErrGrantRejected
	}
	if status < 200 || status >= 300 || response.Error != "" {
		return Tokens{}, ErrTokenUnavailable
	}
	if !security.ValidCredential(response.IDToken) || response.ExpiresIn <= 0 || response.ExpiresIn > 86400 || response.RefreshToken != "" && !security.ValidCredential(response.RefreshToken) {
		return Tokens{}, ErrTokenInvalid
	}
	return Tokens{IDToken: response.IDToken, RefreshToken: response.RefreshToken, ExpiresIn: response.ExpiresIn}, nil
}
