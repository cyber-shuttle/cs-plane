// Tests the OAuth boundary's origins, its one bearer credential channel over headers and over a subprotocol,
// and its conditional poll headers.
package oauth

import (
	"bytes"
	"context"
	"encoding/base64"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

var testPrincipal = security.Principal{Subject: "test-owner", Tenant: "test-tenant"}

func browserWebSocketProtocols(token string) string {
	return ssh.ControlWebSocketProtocol + ", " + webSocketBearerPrefix + base64.RawURLEncoding.EncodeToString([]byte(token))
}

func testOAuthBoundary(t *testing.T, next http.Handler, validator func(context.Context, string) (security.Principal, error), allowedOrigins []string) http.Handler {
	t.Helper()
	origins, err := security.NewOrigins(allowedOrigins)
	testutil.Check(t, err)
	forward := func(writer http.ResponseWriter, request *http.Request) { next.ServeHTTP(writer, request) }
	registry, err := router.New(router.Routes{
		"/api/v1/sessions":          {http.MethodGet: forward, http.MethodPost: forward},
		"/api/v1/hosts/{alias}/ssh": {http.MethodGet: forward},
	})
	testutil.Check(t, err)
	return (&Service{validator: validator, origins: origins}).Protect(registry)
}

func browserUpgradeRequest(token string) *http.Request {
	request := httptest.NewRequest(http.MethodGet, "http://control.example/api/v1/hosts/delta/ssh", nil)
	for name, value := range map[string]string{
		"Origin":                 "https://workspace.example.edu",
		"Connection":             "Upgrade",
		"Upgrade":                "websocket",
		"Sec-WebSocket-Version":  "13",
		"Sec-WebSocket-Protocol": browserWebSocketProtocols(token),
	} {
		request.Header.Set(name, value)
	}
	return request
}

func TestOAuthBoundaryExactOriginsBearerAndNative(t *testing.T) {
	const token = "delegated-secret-token"
	validator := (func(_ context.Context, got string) (security.Principal, error) {
		if got != token {
			t.Fatalf("credentials were not passed exactly: %q", got)
		}
		return security.Principal{Subject: "owner", Tenant: "tenant"}, nil
	})
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, err := security.PrincipalFromContext(r.Context())
		if err != nil || principal != (security.Principal{Subject: "owner", Tenant: "tenant"}) {
			t.Fatalf("delegated authorization = %#v, %v", principal, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := testOAuthBoundary(t, next, validator, []string{"https://workspace.example.edu", "http://127.0.0.1:8045"})

	for _, origin := range []string{"https://workspace.example.edu", "http://127.0.0.1:8045"} {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/sessions", nil)
		req.Header.Set("Origin", origin)
		req.Header.Set("Authorization", "Bearer "+token)
		rr := testutil.Serve(handler, req)
		if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != origin || rr.Header().Get("Access-Control-Allow-Credentials") != "" {
			t.Fatalf("origin %q: code=%d headers=%v", origin, rr.Code, rr.Header())
		}
	}

	native := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	native.Header.Set("Authorization", "Bearer "+token)
	rr := testutil.Serve(handler, native)
	if rr.Code != http.StatusNoContent || rr.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("native code=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestOAuthBoundaryWebSocketSubprotocolBearer(t *testing.T) {
	const token = "delegated-websocket-token"
	var logs bytes.Buffer
	previousLogOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previousLogOutput)
	validatorCalls := 0
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" {
			t.Fatal("Authorization reached the inner handler of a subprotocol-authenticated WebSocket")
		}
		if got := r.Header.Get("Sec-WebSocket-Protocol"); got != ssh.ControlWebSocketProtocol {
			t.Fatalf("inner protocols = %q", got)
		}
		if strings.Contains(r.URL.String(), token) || strings.Contains(r.URL.String(), base64.RawURLEncoding.EncodeToString([]byte(token))) {
			t.Fatalf("request URL exposed token: %s", r.URL)
		}
		principal, err := security.PrincipalFromContext(r.Context())
		if err != nil || principal != testPrincipal {
			t.Fatalf("context authorization = %#v, %v", principal, err)
		}
		w.WriteHeader(http.StatusNoContent)
	})
	handler := testOAuthBoundary(t, next, (func(_ context.Context, got string) (security.Principal, error) {
		validatorCalls++
		testutil.Equal(t, got, token, "validated token")
		return testPrincipal, nil
	}), []string{"https://workspace.example.edu"})
	request := browserUpgradeRequest(token)
	request.Header.Set("Authorization", "Bearer header-websocket-token")
	response := testutil.Serve(handler, request)
	if response.Code != http.StatusNoContent || validatorCalls != 1 {
		t.Fatalf("websocket OAuth response = %d calls=%d body=%q", response.Code, validatorCalls, response.Body.String())
	}
	for _, secret := range []string{token, base64.RawURLEncoding.EncodeToString([]byte(token))} {
		if strings.Contains(response.Body.String(), secret) || strings.Contains(response.Header().Get("Sec-WebSocket-Protocol"), secret) || strings.Contains(logs.String(), secret) {
			t.Fatalf("boundary exposed %q: headers=%v body=%q logs=%q", secret, response.Header(), response.Body.String(), logs.String())
		}
	}
}

func TestOAuthBoundaryConditionalPollHeaders(t *testing.T) {
	const origin = "https://workspace.example.edu"
	validator := (func(context.Context, string) (security.Principal, error) { return testPrincipal, nil })
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("ETag", `"abc"`)
		w.WriteHeader(http.StatusNotModified)
	})
	handler := testOAuthBoundary(t, next, validator, []string{origin})

	preflight := httptest.NewRequest(http.MethodOptions, "/api/v1/sessions", nil)
	preflight.Header.Set("Origin", origin)
	preflight.Header.Set("Access-Control-Request-Method", http.MethodGet)
	preflight.Header.Set("Access-Control-Request-Headers", "authorization,if-none-match")
	rr := testutil.Serve(handler, preflight)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("preflight code=%d body=%q", rr.Code, rr.Body.String())
	}
	if !strings.Contains(strings.ToLower(rr.Header().Get("Access-Control-Allow-Headers")), "if-none-match") {
		t.Fatalf("Allow-Headers = %q", rr.Header().Get("Access-Control-Allow-Headers"))
	}

	actual := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
	actual.Header.Set("Origin", origin)
	actual.Header.Set("Authorization", "Bearer token-value")
	actual.Header.Set("If-None-Match", `"abc"`)
	rr = testutil.Serve(handler, actual)
	if rr.Code != http.StatusNotModified || rr.Header().Get("Access-Control-Expose-Headers") != "ETag, Location" {
		t.Fatalf("code=%d headers=%v", rr.Code, rr.Header())
	}
}

func TestOAuthBoundaryRejectsMalformedCredentials(t *testing.T) {
	validator := (func(context.Context, string) (security.Principal, error) { return testPrincipal, nil })
	handler := testOAuthBoundary(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}), validator, []string{"https://workspace.example.edu"})

	for name, request := range map[string]*http.Request{
		"no credential": httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil),
		"non-bearer scheme": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Set("Authorization", "Basic some-token")
			return r
		}(),
		"two authorizations": func() *http.Request {
			r := httptest.NewRequest(http.MethodGet, "/api/v1/sessions", nil)
			r.Header.Add("Authorization", "Bearer a")
			r.Header.Add("Authorization", "Bearer b")
			return r
		}(),
		"websocket without bearer": func() *http.Request {
			r := browserUpgradeRequest("t")
			r.Header.Set("Sec-WebSocket-Protocol", ssh.ControlWebSocketProtocol+", other."+base64.RawURLEncoding.EncodeToString([]byte("t")))
			return r
		}(),
		"websocket extra protocol": func() *http.Request {
			r := browserUpgradeRequest("t")
			r.Header.Set("Sec-WebSocket-Protocol", browserWebSocketProtocols("t")+", other."+base64.RawURLEncoding.EncodeToString([]byte("t")))
			return r
		}(),
	} {
		t.Run(name, func(t *testing.T) {
			response := testutil.Serve(handler, request)
			if response.Code != http.StatusUnauthorized && response.Code != http.StatusBadRequest {
				t.Fatalf("code = %d, want 400 or 401", response.Code)
			}
		})
	}
}
