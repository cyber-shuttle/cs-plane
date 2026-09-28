// Broker tests cover principal-bound authorization, sealed persistence, refresh serialization, and
// route wiring. Provider wire behavior belongs to internal/devtunnel tests.
package devtunnels

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

type fakeAuthorizer struct {
	provider string
	poll     devtunnel.PollResult
	pollFn   func() devtunnel.PollResult
	refresh  devtunnel.AuthorizationTokens
}

func (a *fakeAuthorizer) Supports(provider string) bool { return provider == a.provider }

func (a *fakeAuthorizer) Start(context.Context, string) (*devtunnel.DeviceAuthorization, error) {
	return &devtunnel.DeviceAuthorization{
		UserCode: "ABCD-EFGH", VerificationURI: "https://example.test/device",
		ExpiresIn: 15 * time.Minute, Interval: time.Second,
	}, nil
}

func (a *fakeAuthorizer) Poll(context.Context, *devtunnel.DeviceAuthorization, time.Duration) (devtunnel.PollResult, error) {
	if a.pollFn != nil {
		return a.pollFn(), nil
	}
	return a.poll, nil
}

func (a *fakeAuthorizer) Refresh(context.Context, string, string) (devtunnel.AuthorizationTokens, error) {
	return a.refresh, nil
}

func newTestBroker(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	hostsDir := filepath.Join(dir, "hosts")
	var box security.SecretBox
	copy(box[:], strings.Repeat("k", 32))
	return newService(dir, hostsDir, &box, nil), hostsDir
}

func TestBrokerPollStoresSealedCredential(t *testing.T) {
	broker, hostsDir := newTestBroker(t)
	principal := security.Principal{Subject: "owner", Tenant: "cilogon"}
	now := time.Now()
	broker.now = func() time.Time { return now }
	broker.authorizer = &fakeAuthorizer{
		provider: "github",
		poll: devtunnel.PollResult{Tokens: devtunnel.AuthorizationTokens{
			Provider: "github", Scheme: "github", AccessToken: "gho_the_token", Account: "octocat",
		}},
	}

	start, err := broker.start(context.Background(), principal, "github")
	testutil.Check(t, err)
	testutil.Equal(t, start.UserCode, "ABCD-EFGH", "user code")
	now = now.Add(time.Second)
	poll, err := broker.poll(context.Background(), principal, start.Handle)
	testutil.Check(t, err)
	if encoded, _ := json.Marshal(poll); !strings.HasPrefix(string(encoded), `{"status":"connected","connected":true,"provider":"github","account":"octocat"`) {
		t.Fatalf("poll = %s", encoded)
	}

	path := filepath.Join(hostsDir, security.PrincipalDirName(principal), accountFileName)
	sealed, err := os.ReadFile(path)
	testutil.Check(t, err)
	if strings.Contains(string(sealed), "gho_the_token") {
		t.Fatal("the sealed file holds the OAuth token in the clear")
	}
	status, err := broker.status(principal)
	testutil.Check(t, err)
	if !status.Connected || status.Account != "octocat" {
		t.Fatalf("status = %#v", status)
	}
	testutil.Check(t, broker.delete(principal))
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("sealed file survived Delete: %v", err)
	}
}

func TestBrokerCredentialIsEmptyWithoutAnAccount(t *testing.T) {
	broker, _ := newTestBroker(t)
	credential, err := broker.Credential(context.Background(), security.Principal{Subject: "owner", Tenant: "cilogon"})
	if err != nil || credential != (devtunnel.Credential{}) {
		t.Fatalf("credential = %#v, %v", credential, err)
	}
}

func TestBrokerSerializesPollAndDeleteAcrossBrokers(t *testing.T) {
	broker, _ := newTestBroker(t)
	other := newService(broker.stateDir, broker.principalDir, broker.box, nil)
	principal := security.Principal{Subject: "owner", Tenant: "cilogon"}
	now := time.Now()
	broker.now = func() time.Time { return now }
	started, release := make(chan struct{}), make(chan struct{})
	broker.authorizer = &fakeAuthorizer{provider: "github", pollFn: func() devtunnel.PollResult {
		close(started)
		<-release
		return devtunnel.PollResult{Tokens: devtunnel.AuthorizationTokens{Provider: "github", Scheme: "github", AccessToken: "new-access"}}
	}}
	pending, err := broker.start(context.Background(), principal, "github")
	testutil.Check(t, err)
	now = now.Add(time.Second)
	pollDone := make(chan error, 1)
	go func() { _, err := broker.poll(context.Background(), principal, pending.Handle); pollDone <- err }()
	<-started
	deleteDone := make(chan error, 1)
	go func() { deleteDone <- other.delete(principal) }()
	testutil.RemainsBlocked(t, deleteDone, "Delete completed during poll")
	close(release)
	testutil.Check(t, <-pollDone)
	testutil.Check(t, <-deleteDone)
	if _, found, err := broker.loadAccount(principal); err != nil || found {
		t.Fatalf("account after Delete = found %v, error %v", found, err)
	}
}

func TestBrokerRefreshesExpiringCredential(t *testing.T) {
	broker, _ := newTestBroker(t)
	principal := security.Principal{Subject: "owner", Tenant: "cilogon"}
	fixed := time.Now()
	broker.now = func() time.Time { return fixed }
	broker.authorizer = &fakeAuthorizer{
		provider: "microsoft",
		refresh: devtunnel.AuthorizationTokens{
			Provider: "microsoft", Scheme: "Bearer", AccessToken: "new-access",
			RefreshToken: "new-refresh", ExpiresIn: time.Hour,
		},
	}
	testutil.Check(t, broker.saveAccount(principal, account{
		Provider: "microsoft", Scheme: "Bearer", AccessToken: "old-access", RefreshToken: "old-refresh",
		ExpiresAt: fixed.Add(time.Minute), Account: "someone", ConnectedAt: fixed,
	}))
	credential, err := broker.Credential(context.Background(), principal)
	testutil.Check(t, err)
	testutil.Equal(t, credential, devtunnel.Credential{Scheme: "Bearer", Token: "new-access"}, "credential")
	stored, ok, err := broker.loadAccount(principal)
	testutil.Check(t, err)
	if !ok || stored.RefreshToken != "new-refresh" || !stored.ExpiresAt.Equal(fixed.Add(time.Hour)) {
		t.Fatalf("stored account after refresh = %#v", stored)
	}
}

func TestRoutesAnswerStatusAndPollOverHTTP(t *testing.T) {
	broker, _ := newTestBroker(t)
	handler, err := router.New(broker.Routes())
	testutil.Check(t, err)
	principal := security.Principal{Subject: "owner", Tenant: "cilogon"}
	ctx := security.WithPrincipal(context.Background(), principal)

	status := testutil.Serve(handler, httptest.NewRequest(http.MethodGet, "/api/v1/devtunnels", nil).WithContext(ctx))
	if status.Code != http.StatusOK || !strings.Contains(status.Body.String(), `"connected":false`) {
		t.Fatalf("account status = %d %s", status.Code, status.Body.String())
	}
	poll := testutil.Serve(handler, httptest.NewRequest(http.MethodPost, "/api/v1/devtunnels/authorizations/no-such-handle/poll", nil).WithContext(ctx))
	if poll.Code != http.StatusNotFound {
		t.Fatalf("poll of an unknown handle = %d %s, want 404", poll.Code, poll.Body.String())
	}
}
