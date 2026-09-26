// Exercises the Dev Tunnels client and URL policy against a fake management service.
package devtunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

func realisticTunnelResponse(id, hostToken, connectToken string) string {
	created := time.Now().UTC().Truncate(time.Second)
	expires := created.Add(time.Hour)
	return fmt.Sprintf(`{
		"tunnelId":%q,
		"clusterId":"use",
		"accessTokens":{"host":%q,"connect":%q},
		"created":%q,
		"expiration":%q,
		"customExpiration":3600,
		"endpoints":[{"connectionMode":"TunnelRelay","hostId":"session-host","portUriFormat":"https://{port}.use.devtunnels.ms/","portSshCommandFormat":"ssh tunnel@{port}.use.devtunnels.ms","sshGatewayPublicKey":"ignored additive field"}],
		"ports":[],
		"futureField":"ignored"
	}`, id, hostToken, connectToken, created.Format(time.RFC3339), expires.Format(time.RFC3339))
}

func testClient(t *testing.T, baseURL string, httpClient *http.Client) *client {
	t.Helper()
	base, err := url.Parse(baseURL)
	testutil.Check(t, err)
	return &client{baseURL: base, client: security.GuardedClient(httpClient, devTunnelTimeout)}
}

func TestDevTunnelCreateRequestsScopedTokensAndAcceptsAdditiveFields(t *testing.T) {
	const id = "s-123456789abc-g-0123456789abcdef"
	var body map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.Header.Get("Authorization") != "Bearer oauth" || r.Header.Get("If-None-Match") != "*" {
			t.Fatalf("request = %s headers=%v", r.Method, r.Header)
		}
		if got := r.URL.Query()["tokenScopes"]; len(got) != 2 || got[0] != "host" || got[1] != "connect" {
			t.Fatalf("token scopes = %#v", got)
		}
		testutil.Check(t, json.NewDecoder(r.Body).Decode(&body))
		_, _ = io.WriteString(w, realisticTunnelResponse(id, "host-secret", "connect-secret"))
	}))
	defer server.Close()
	record, err := testClient(t, server.URL, server.Client()).Create(context.Background(), CreateRequest{OAuthToken: "oauth", TunnelID: id, DurationSeconds: 3600})
	testutil.Check(t, err)
	if record.ID != id || record.ClusterID != "use" || record.HostToken != "host-secret" || record.ConnectToken != "connect-secret" || record.ExpiresAt.IsZero() {
		t.Fatalf("record = %#v", record)
	}
	if body["tunnelId"] != id || body["customExpiration"] != float64(3600) {
		t.Fatalf("body = %#v", body)
	}
}

func TestDevTunnelRejectsMalformedUsedFields(t *testing.T) {
	expires := time.Now().UTC().Add(time.Hour).Format(time.RFC3339)
	cases := map[string]string{
		"wrong identity":         `{"tunnelId":"other-tunnel","clusterId":"use","expiration":"` + expires + `"}`,
		"missing expiration":     `{"tunnelId":"tunnel-123","clusterId":"use"}`,
		"duplicate port":         `{"tunnelId":"tunnel-123","clusterId":"use","expiration":"` + expires + `","ports":[{"portNumber":31001,"protocol":"http"},{"portNumber":31001,"protocol":"http"}]}`,
		"invalid forwarding URI": `{"tunnelId":"tunnel-123","clusterId":"use","expiration":"` + expires + `","ports":[{"portNumber":31001,"protocol":"http","description":"cybershuttle-control","portForwardingUris":["https://evil.example/"]}]}`,
	}
	for name, response := range cases {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, response) }))
			defer server.Close()
			if _, err := testClient(t, server.URL, server.Client()).Get(context.Background(), GetRequest{ConnectToken: "connect", TunnelID: "tunnel-123", ClusterID: "use"}); err == nil {
				t.Fatal("malformed response accepted")
			}
		})
	}
}

func TestDevTunnelForwardsAuthorizationOnlyAcrossManagementHosts(t *testing.T) {
	const id = "s-123456789abc-g-0123456789abcdef"
	var redirected bool
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer oauth" {
			t.Fatalf("redirected authorization = %q", r.Header.Get("Authorization"))
		}
		if r.Host == "global.rel.tunnels.api.visualstudio.com" {
			w.Header().Set("Location", "https://use.rel.tunnels.api.visualstudio.com"+r.URL.RequestURI())
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		if r.Host != "use.rel.tunnels.api.visualstudio.com" {
			t.Fatalf("redirect host = %q", r.Host)
		}
		redirected = true
		_, _ = io.WriteString(w, realisticTunnelResponse(id, "host-secret", "connect-secret"))
	}))
	defer server.Close()
	local, err := url.Parse(server.URL)
	testutil.Check(t, err)
	transport := server.Client().Transport
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		clone := request.Clone(request.Context())
		endpoint := *request.URL
		clone.Host = endpoint.Host
		endpoint.Scheme, endpoint.Host = local.Scheme, local.Host
		clone.URL = &endpoint
		return transport.RoundTrip(clone)
	})}
	manager, err := NewClient("https://global.rel.tunnels.api.visualstudio.com", httpClient)
	testutil.Check(t, err)
	if _, err := manager.Create(context.Background(), CreateRequest{OAuthToken: "oauth", TunnelID: id, DurationSeconds: 3600}); err != nil {
		t.Fatal(err)
	}
	if !redirected {
		t.Fatal("management redirect was not followed")
	}
}

func TestRecordHTTPURIRequiresTheExactValidatedHTTPPort(t *testing.T) {
	record := Record{Ports: []PortRecord{
		{PortNumber: 21000, Protocol: "http", PortForwardingURIs: []string{"https://21000.use.devtunnels.ms/"}},
		{PortNumber: 21001, Protocol: "tcp", PortForwardingURIs: []string{"https://21001.use.devtunnels.ms"}},
	}}
	if uri, err := record.HTTPURI(21000); err != nil || uri != "https://21000.use.devtunnels.ms" {
		t.Fatalf("HTTPURI = %q, %v", uri, err)
	}
	for _, port := range []uint16{21001, 21002} {
		if _, err := record.HTTPURI(port); err == nil {
			t.Fatalf("port %d was accepted", port)
		}
	}
	record.Ports[0].PortForwardingURIs = []string{"https://safe.use.devtunnels.ms", "https://other.use.devtunnels.ms"}
	if _, err := record.HTTPURI(21000); err == nil {
		t.Fatal("ambiguous forwarding URIs were accepted")
	}
}

func TestDevTunnelURLAndRedirectValidation(t *testing.T) {
	manager, err := NewClient("https://global.rel.tunnels.api.visualstudio.com/", nil)
	testutil.Check(t, err)
	got, err := url.Parse(manager.tunnelURL("tunnel-123", "use", false, true))
	if err != nil || got.Host != "use.rel.tunnels.api.visualstudio.com" || got.Query().Get("includePorts") != "true" {
		t.Fatalf("URL = %s", got)
	}
	from, _ := url.Parse("https://global.rel.tunnels.api.visualstudio.com/tunnels/x")
	to, _ := url.Parse("https://use.rel.tunnels.api.visualstudio.com/tunnels/x")
	if !safeRedirect(from, to) {
		t.Fatal("safe cluster redirect rejected")
	}
	to, _ = url.Parse("https://evil.example/tunnels/x")
	if safeRedirect(from, to) {
		t.Fatal("hostile redirect accepted")
	}
}
