// Tests the OIDC validator: signature and claim rejection, key refresh, discovery, and issuer policy.
package identity

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func writeTestJSON(t *testing.T, w http.ResponseWriter, value any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Fatal(fmt.Errorf("write test JSON: %w", err))
	}
}
func testRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	testutil.Check(t, err)
	return key
}

func testJWK(kid string, key *rsa.PublicKey) map[string]string {
	exponent := big.NewInt(int64(key.E)).Bytes()
	return map[string]string{
		"kty": "RSA", "use": "sig", "alg": "RS256", "kid": kid,
		"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()), "e": base64.RawURLEncoding.EncodeToString(exponent),
	}
}

func testJWKS(kid string, key *rsa.PublicKey) map[string]any {
	return map[string]any{"keys": []map[string]string{testJWK(kid, key)}}
}

func signIDToken(t *testing.T, key *rsa.PrivateKey, claims, header map[string]any) string {
	t.Helper()
	encode := func(value any) string {
		encoded, err := json.Marshal(value)
		testutil.Check(t, err)
		return base64.RawURLEncoding.EncodeToString(encoded)
	}
	signingInput := encode(header) + "." + encode(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	testutil.Check(t, err)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func changedClaim(source map[string]any, key string, value any) map[string]any {
	claims := maps.Clone(source)
	claims[key] = value
	return claims
}

func withoutClaim(source map[string]any, key string) map[string]any {
	claims := maps.Clone(source)
	delete(claims, key)
	return claims
}

func oidcServer(t *testing.T, routes map[string]http.HandlerFunc) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handler, ok := routes[r.URL.Path]; ok {
			handler(w, r)
			return
		}
		if r.URL.Path != "/.well-known/openid-configuration" {
			t.Errorf("unexpected OIDC request %s", r.URL)
			return
		}
		base := server.URL
		_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q}`, base, base+"/keys", base+"/authorize", base+"/token")
	}))
	t.Cleanup(server.Close)
	return server
}

func jwksRoute(t *testing.T, kid string, public *rsa.PublicKey) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) { writeTestJSON(t, w, testJWKS(kid, public)) }
}

func testOIDC(t *testing.T, issuer string, client *http.Client) *OIDC {
	t.Helper()
	validator, err := NewOIDC(issuer, "client-id", client)
	testutil.Check(t, err)
	return validator
}

const cilogonSubject = "http://cilogon.org/serverA/users/12345"

func TestOIDCValidatorAcceptsValidIDTokens(t *testing.T) {
	key := testRSAKey(t)
	const kid = "identity-key"
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, kid, &key.PublicKey)})
	validator := testOIDC(t, server.URL, server.Client())
	claims := map[string]any{
		"iss": server.URL, "aud": "client-id", "exp": time.Now().Unix() + 300, "sub": cilogonSubject,
	}
	for _, nbf := range []any{time.Now().Unix() - 1, nil} {
		if nbf != nil {
			claims["nbf"] = nbf
		} else {
			delete(claims, "nbf")
		}
		subject, err := validator.Validate(context.Background(), signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": kid}))
		testutil.Check(t, err)
		testutil.Equal(t, subject, cilogonSubject, "subject")
	}
}

func TestOIDCValidatorRejectsInvalidIdentityTokensWithoutLeaks(t *testing.T) {
	key := testRSAKey(t)
	other := testRSAKey(t)
	const kid = "identity-key"
	server := oidcServer(t, map[string]http.HandlerFunc{"/keys": jwksRoute(t, kid, &key.PublicKey)})
	validator := testOIDC(t, server.URL, server.Client())
	fixed := time.Unix(2_000_000_000, 0)
	validator.now = func() time.Time { return fixed }
	valid := map[string]any{
		"iss": server.URL, "aud": "client-id", "exp": fixed.Unix() + 60, "nbf": fixed.Unix() - 1,
		"sub": "owner-id",
	}
	tests := []struct {
		name   string
		claims map[string]any
		header map[string]any
		key    *rsa.PrivateKey
	}{
		{"issuer", changedClaim(valid, "iss", server.URL+"/other"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"audience", changedClaim(valid, "aud", "other-client"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"expired", changedClaim(valid, "exp", fixed.Unix()), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing expiration", withoutClaim(valid, "exp"), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"not before", changedClaim(valid, "nbf", fixed.Unix()+1), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"missing subject", changedClaim(valid, "sub", ""), map[string]any{"alg": "RS256", "kid": kid}, key},
		{"algorithm", valid, map[string]any{"alg": "RS512", "kid": kid}, key},
		{"unknown kid", valid, map[string]any{"alg": "RS256", "kid": "unknown-key"}, key},
		{"signature", valid, map[string]any{"alg": "RS256", "kid": kid}, other},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			token := signIDToken(t, test.key, test.claims, test.header)
			_, err := validator.Validate(context.Background(), token)
			if err == nil || strings.Contains(err.Error(), token) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestOIDCUnknownKIDFloodCoalescesRefreshWithoutBlockingKnownKey(t *testing.T) {
	key := testRSAKey(t)
	const knownKID = "known-key"
	var metadataRequests, keyRequests int
	var requestMu sync.Mutex
	refreshStarted := make(chan struct{})
	releaseRefresh := make(chan struct{})
	var startOnce sync.Once
	var server *httptest.Server
	server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			requestMu.Lock()
			metadataRequests++
			requestMu.Unlock()
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q}`, server.URL, server.URL+"/keys", server.URL+"/authorize", server.URL+"/token")
		case "/keys":
			requestMu.Lock()
			keyRequests++
			request := keyRequests
			requestMu.Unlock()
			if request == 2 {
				startOnce.Do(func() { close(refreshStarted) })
				<-releaseRefresh
			}
			writeTestJSON(t, w, testJWKS(knownKID, &key.PublicKey))
		}
	}))
	defer server.Close()
	validator := testOIDC(t, server.URL, server.Client())
	now := time.Now().Unix()
	claims := map[string]any{"iss": server.URL, "aud": "client-id", "exp": now + 300, "nbf": now - 1, "sub": "owner"}
	known := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": knownKID})
	_, err := validator.Validate(context.Background(), known)
	testutil.Check(t, err)

	const flood = 512
	start := make(chan struct{})
	errors := make(chan error, flood)
	var workers sync.WaitGroup
	workers.Add(flood)
	for i := 0; i < flood; i++ {
		token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": fmt.Sprintf("random-%d", i)})
		go func() {
			defer workers.Done()
			<-start
			_, err := validator.Validate(context.Background(), token)
			errors <- err
		}()
	}
	close(start)
	select {
	case <-refreshStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("unknown-kid refresh did not start")
	}

	knownDone := make(chan error, 1)
	go func() {
		_, err := validator.Validate(context.Background(), known)
		knownDone <- err
	}()
	testutil.Within(t, knownDone, 200*time.Millisecond, "known-key validation was serialized behind OIDC refresh")
	close(releaseRefresh)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err == nil {
			t.Fatal("random kid was accepted")
		}
	}
	requestMu.Lock()
	if metadataRequests != 2 || keyRequests != 2 {
		t.Fatalf("OIDC requests metadata=%d keys=%d, want one initial load and one coalesced refresh", metadataRequests, keyRequests)
	}
	requestMu.Unlock()

	cooldownToken := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "random-after-flood"})
	if _, err := validator.Validate(context.Background(), cooldownToken); err == nil {
		t.Fatal("unknown kid during cooldown was accepted")
	}
	requestMu.Lock()
	defer requestMu.Unlock()
	if metadataRequests != 2 || keyRequests != 2 {
		t.Fatalf("cooldown triggered network requests metadata=%d keys=%d", metadataRequests, keyRequests)
	}
}

func TestOIDCValidatorRejectsWrongJWKAlgorithmAndEncryptionUse(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]string)
	}{
		{"wrong algorithm", func(jwk map[string]string) { jwk["alg"] = "RS512" }},
		{"encryption use", func(jwk map[string]string) { delete(jwk, "alg"); jwk["use"] = "enc" }},
	} {
		t.Run(test.name, func(t *testing.T) {
			key := testRSAKey(t)
			jwk := testJWK("rejected-key", &key.PublicKey)
			test.mutate(jwk)
			server := oidcServer(t, map[string]http.HandlerFunc{
				"/keys": func(w http.ResponseWriter, _ *http.Request) {
					writeTestJSON(t, w, map[string]any{"keys": []map[string]string{jwk}})
				},
			})
			validator := testOIDC(t, server.URL, server.Client())
			now := time.Now().Unix()
			claims := map[string]any{"iss": server.URL, "aud": "client-id", "exp": now + 300, "nbf": now - 1, "sub": "owner"}
			token := signIDToken(t, key, claims, map[string]any{"alg": "RS256", "kid": "rejected-key"})
			if _, err := validator.Validate(context.Background(), token); err == nil {
				t.Fatalf("invalid JWK was accepted: %#v", jwk)
			}
		})
	}
}

func TestOIDCDiscoveryRejectsASubstitutedIssuer(t *testing.T) {
	var server *httptest.Server
	server = oidcServer(t, map[string]http.HandlerFunc{
		"/.well-known/openid-configuration": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = fmt.Fprintf(w, `{"issuer":%q,"jwks_uri":%q,"authorization_endpoint":%q,"token_endpoint":%q}`, server.URL+"/substituted", server.URL+"/keys", server.URL+"/authorize", server.URL+"/token")
		},
	})
	validator := testOIDC(t, server.URL, server.Client())
	if _, err := validator.Discovery(context.Background()); err == nil {
		t.Fatal("discovery accepted an issuer other than the configured issuer")
	}
}

func TestOIDCIssuerMustBeHTTPS(t *testing.T) {
	for _, issuer := range []string{
		"http://cilogon.org",
		"https://user@cilogon.org",
		"not a url",
		"",
	} {
		if _, err := NewOIDC(issuer, "client-id", nil); err == nil {
			t.Fatalf("issuer accepted: %q", issuer)
		}
	}
	validator, err := NewOIDC("https://cilogon.org", "client-id", nil)
	testutil.Check(t, err)
	if validator.authority.String() != "https://cilogon.org" {
		t.Fatalf("authority = %q", validator.authority)
	}
}
