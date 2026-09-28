// Tests that serve validates before it listens, stays behind the OAuth boundary, and parses its flags correctly.
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
	"github.com/cyber-shuttle/cs-plane/subsystems/devtunnels"
	"github.com/cyber-shuttle/cs-plane/subsystems/oauth"
	"github.com/cyber-shuttle/cs-plane/subsystems/session"
	sshapi "github.com/cyber-shuttle/cs-plane/subsystems/ssh"
)

func testServices(t *testing.T, stateDir string) services {
	t.Helper()
	configs := ssh.Configurations{Dir: filepath.Join(stateDir, "hosts")}
	return services{
		Configs: configs, SessionStore: session.Store{Dir: stateDir},
		CapabilityDir: filepath.Join(stateDir, "credentials"),
	}
}

func TestServeValidatesOriginsBeforeListening(t *testing.T) {
	t.Setenv("CS_OIDC_CLIENT_SECRET", "the-client-secret")
	oidcArgs := []string{"--oidc-client-id", "the-client-id", "--public-url", "https://plane.example.edu"}
	for _, args := range [][]string{
		oidcArgs,
		append(append([]string{}, oidcArgs...), "--public-url", "http://plane.example.edu", "--allowed-origin", "https://workspace.example"),
		append(append([]string{}, oidcArgs...), "--allowed-origin", "*"),
		append(append([]string{}, oidcArgs...), "--allowed-origin", "http://workspace.example"),
		append(append([]string{"--listen", "0.0.0.0:8045"}, oidcArgs...), "--allowed-origin", "https://workspace.example"),
	} {
		listened := false
		listen := func(string, string) (net.Listener, error) {
			listened = true
			return nil, errors.New("unexpected listen")
		}
		svcs := testServices(t, t.TempDir())
		if err := runServe(context.Background(), svcs, args, listen); err == nil {
			t.Fatalf("invalid serve configuration accepted: %q", args)
		}
		if listened {
			t.Fatalf("serve listened before validating %q", args)
		}
	}
}

func TestServeRefusesIncompatibleStateBeforeCreatingCredentials(t *testing.T) {
	t.Setenv("CS_OIDC_CLIENT_SECRET", "the-client-secret")
	dsn := testutil.Database(t)
	t.Setenv("CS_DATABASE_URL", dsn)
	stateDir := t.TempDir()
	database, err := db.Open(dsn, stateDir, "")
	testutil.Check(t, err)
	testutil.Check(t, database.Tx(func(tx *sql.Tx) error {
		_, err := tx.Exec(`UPDATE schema_meta SET value = 'other' WHERE key = 'format'`)
		return err
	}))
	testutil.Check(t, database.Close())

	svcs := testServices(t, stateDir)
	args := []string{"--oidc-client-id", "the-client-id", "--public-url", "https://plane.example.edu", "--allowed-origin", "https://workspace.example.edu"}
	listen := func(string, string) (net.Listener, error) {
		t.Fatal("serve listened with an incompatible state database")
		return nil, nil
	}
	if err := runServe(context.Background(), svcs, args, listen); err == nil {
		t.Fatal("an incompatible state database was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(stateDir, "devtunnels-account.key")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("startup refusal created a credential key: %v", statErr)
	}
}

func TestServeComponentsAlwaysApplyOAuthBoundary(t *testing.T) {
	const allowedOrigin = "https://workspace.example.edu"
	svcs := testServices(t, t.TempDir())
	svcs.DatabaseURL = testutil.Database(t)
	origins, err := security.NewOrigins([]string{allowedOrigin})
	testutil.Check(t, err)
	authentication, err := oauth.NewService(defaultOIDCIssuer, "the-client-id", "the-client-secret", origins, nil)
	testutil.Check(t, err)
	components, err := newServeComponents(svcs, authentication)
	testutil.Check(t, err)
	defer components.close()

	upgrade := func(origin, protocols string) int {
		request := httptest.NewRequest(http.MethodGet, "/api/v1/hosts/delta/ssh", nil)
		for name, value := range map[string]string{"Origin": origin, "Connection": "Upgrade", "Upgrade": "websocket", "Sec-WebSocket-Protocol": protocols} {
			request.Header.Set(name, value)
		}
		return testutil.Serve(components.handler, request).Code
	}
	testutil.Equal(t, upgrade(allowedOrigin, "cybershuttle.v1"), http.StatusBadRequest, "production handler without bearer")
	testutil.Equal(t, upgrade("https://evil.example", "cybershuttle.v1"), http.StatusForbidden, "disallowed origin before the subprotocol is read")
	bearer := base64.RawURLEncoding.EncodeToString([]byte("not-a-real-id-token"))
	testutil.Equal(t, upgrade(allowedOrigin, "cybershuttle.v1, bearer."+bearer), http.StatusUnauthorized, "well-formed but bogus bearer subprotocol")
}

func TestCanonicalRouteManifest(t *testing.T) {
	groups := []router.Routes{
		(&oauth.Service{}).Routes(),
		(sshapi.Service{}).Routes(),
		(session.Service{}).Routes(),
		(&devtunnels.Service{}).Routes(),
	}
	if _, err := router.New(groups...); err != nil {
		t.Fatal(err)
	}
	got := make(map[string]string)
	for _, group := range groups {
		for path, handlers := range group {
			got[path] = strings.Join(slices.Sorted(maps.Keys(handlers)), " ")
		}
	}
	want := map[string]string{
		"/api/v1/oauth/config":                            "GET",
		"/api/v1/oauth/exchange":                          "POST",
		"/api/v1/oauth/refresh":                           "POST",
		"/api/v1/oauth/device":                            "POST",
		"/api/v1/oauth/device/poll":                       "POST",
		"/api/v1/hosts":                                   "GET POST",
		"/api/v1/hosts/{alias}":                           "DELETE PUT",
		"/api/v1/hosts/{alias}/health":                    "GET",
		"/api/v1/hosts/{alias}/slurm":                     "GET",
		"/api/v1/hosts/{alias}/ssh":                       "GET",
		"/api/v1/keys/ssh":                                "GET POST",
		"/api/v1/keys/ssh/{id}":                           "DELETE",
		"/api/v1/devtunnels":                              "DELETE GET",
		"/api/v1/devtunnels/authorizations":               "POST",
		"/api/v1/devtunnels/authorizations/{handle}/poll": "POST",
		"/api/v1/sessions":                                "GET POST",
		"/api/v1/sessions/validate":                       "POST",
		"/api/v1/sessions/{id}/ssh":                       "POST",
		"/api/v1/sessions/{id}":                           "DELETE GET",
		"/api/v1/sessions/{id}/start":                     "POST",
		"/api/v1/sessions/{id}/attach":                    "POST",
		"/api/v1/sessions/{id}/stop":                      "POST",
		"/api/v1/sessions/{id}/access":                    "GET",
		"/api/v1/sessions/{id}/usage":                     "GET",
		"/api/v1/runs":                                    "GET",
	}
	if !maps.Equal(got, want) {
		t.Fatalf("route manifest = %v, want %v", got, want)
	}
}
