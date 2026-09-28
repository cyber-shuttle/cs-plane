// SSH service tests protect the canonical route surface, principal isolation, key secrecy, host/key atomicity,
// and health checks that dial only a public first hop. Lower-level OpenSSH execution and credential-file durability
// are tested by their internal packages; these cases exercise only the feature composition.
package ssh

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	internalssh "github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
	cryptossh "golang.org/x/crypto/ssh"
)

var (
	testPrincipal      = security.Principal{Subject: "test-owner", Tenant: "test-tenant"}
	otherTestPrincipal = security.Principal{Subject: "other-owner", Tenant: "test-tenant"}
)

func testKey(t *testing.T, passphrase string) []byte {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	testutil.Check(t, err)
	var block *pem.Block
	if passphrase == "" {
		block, err = cryptossh.MarshalPrivateKey(private, "test")
	} else {
		block, err = cryptossh.MarshalPrivateKeyWithPassphrase(private, "test", []byte(passphrase))
	}
	testutil.Check(t, err)
	return pem.EncodeToMemory(block)
}

func isolatedService(t *testing.T) *Service {
	t.Helper()
	dir := t.TempDir()
	principalDir := filepath.Join(dir, "hosts")
	database, err := db.Open(testutil.Database(t), dir, Schema)
	testutil.Check(t, err)
	service, err := NewService(database, internalssh.Configurations{Dir: principalDir}, internalssh.NewControlManager())
	testutil.Check(t, err)
	t.Cleanup(func() {
		service.Control.Close()
		testutil.Check(t, database.Close())
	})
	return service
}

func serviceHandler(t *testing.T, service *Service) http.Handler {
	t.Helper()
	handler, err := router.New(service.Routes())
	testutil.Check(t, err)
	return handler
}

func requestAs(principal security.Principal, method, path string, body []byte) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewReader(body))
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	return request.WithContext(security.WithPrincipal(request.Context(), principal))
}

func TestSSHResourcesArePrincipalScopedAndNeverReturnPrivateKeys(t *testing.T) {
	service := isolatedService(t)
	handler := serviceHandler(t, service)
	private := testKey(t, "secret")
	keyBody, err := json.Marshal(SSHKeyRequest{Name: "delta-key", PrivateKey: string(private)})
	testutil.Check(t, err)
	createdKey := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/keys/ssh", keyBody))
	if createdKey.Code != http.StatusCreated || strings.Contains(createdKey.Body.String(), "PRIVATE KEY") || !strings.Contains(createdKey.Body.String(), `"fingerprint":"SHA256:`) {
		t.Fatalf("key create = %d %s", createdKey.Code, createdKey.Body.String())
	}
	replacement, err := json.Marshal(SSHKeyRequest{Name: "delta-key", PrivateKey: string(testKey(t, ""))})
	testutil.Check(t, err)
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/keys/ssh", replacement)); response.Code != http.StatusConflict {
		t.Fatalf("key replacement = %d %s", response.Code, response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodGet, "/api/v1/keys/ssh", nil)); strings.Contains(response.Body.String(), "delta-key") {
		t.Fatalf("another principal saw the key: %s", response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodPost, "/api/v1/hosts", []byte(`{"alias":"delta","command":"ssh me@login.example.edu","keyId":"delta-key"}`))); response.Code != http.StatusNotFound {
		t.Fatalf("another principal assigned the key: %d %s", response.Code, response.Body.String())
	}

	createdHost := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPost, "/api/v1/hosts", []byte(`{"alias":"delta","command":"ssh me@login.example.edu","keyId":"delta-key"}`)))
	config, err := os.ReadFile(service.Configs.ConfigPath(testPrincipal))
	testutil.Check(t, err)
	keyPath := service.Store.sshPath(security.PrincipalDirName(testPrincipal), "delta-key")
	if createdHost.Code != http.StatusCreated || !strings.Contains(createdHost.Body.String(), `"managed":true`) || strings.Contains(createdHost.Body.String(), keyPath) || !strings.Contains(string(config), "identityfile "+keyPath) {
		t.Fatalf("host create = %d %s config=%s", createdHost.Code, createdHost.Body.String(), config)
	}
	if response := testutil.Serve(handler, requestAs(otherTestPrincipal, http.MethodGet, "/api/v1/hosts", nil)); strings.Contains(response.Body.String(), "delta") {
		t.Fatalf("another principal saw the host: %s", response.Body.String())
	}
	updated := testutil.Serve(handler, requestAs(testPrincipal, http.MethodPut, "/api/v1/hosts/delta", []byte(`{"command":"ssh -p 2222 me@login2.example.edu","keyId":"delta-key"}`)))
	if updated.Code != http.StatusOK || !strings.Contains(updated.Body.String(), `"hostname":"login2.example.edu"`) || !strings.Contains(updated.Body.String(), `"port":2222`) {
		t.Fatalf("host update = %d %s", updated.Code, updated.Body.String())
	}
	deleted := testutil.Serve(handler, requestAs(testPrincipal, http.MethodDelete, "/api/v1/keys/ssh/delta-key", nil))
	if deleted.Code != http.StatusNoContent || deleted.Body.Len() != 0 {
		t.Fatalf("key delete = %d %s", deleted.Code, deleted.Body.String())
	}
	listed := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/hosts", nil))
	if strings.Contains(listed.Body.String(), "delta-key") {
		t.Fatalf("key deletion left a host reference: %s", listed.Body.String())
	}
	if _, err := os.Stat(service.Store.sshPath(security.PrincipalDirName(testPrincipal), "delta-key")); !os.IsNotExist(err) {
		t.Fatalf("key file survived deletion: %v", err)
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodDelete, "/api/v1/hosts/delta", nil)); response.Code != http.StatusNoContent || response.Body.Len() != 0 {
		t.Fatalf("host delete = %d %s", response.Code, response.Body.String())
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/hosts", nil)); strings.Contains(response.Body.String(), `"alias":"delta"`) {
		t.Fatalf("deleted host remains: %s", response.Body.String())
	}
}

func TestConcurrentHostAssignmentAndKeyDeletionLeaveNoReference(t *testing.T) {
	service := isolatedService(t)
	private := testKey(t, "")
	for index := range 10 {
		name := "key-" + string(rune('a'+index))
		_, err := service.writeSSHKey(testPrincipal, name, private)
		testutil.Check(t, err)
		start := make(chan struct{})
		var assigned HostEntry
		var assignedErr, deletedErr error
		var wait sync.WaitGroup
		wait.Add(2)
		go func() {
			defer wait.Done()
			<-start
			assigned, assignedErr = service.addHost(testPrincipal, AddHostRequest{Alias: name, Command: "ssh login.example.edu", Key: name})
		}()
		go func() {
			defer wait.Done()
			<-start
			deletedErr = service.deleteSSHKey(testPrincipal, name)
		}()
		close(start)
		wait.Wait()
		testutil.Check(t, deletedErr)
		if assignedErr != nil && !errors.Is(assignedErr, errSSHKeyNotFound) {
			t.Fatalf("host assignment = %v", assignedErr)
		}
		if assignedErr == nil && (assigned.Key != "" && assigned.Key != name) {
			t.Fatalf("unexpected assigned host: %+v", assigned)
		}
		hosts, err := service.Store.loadHosts(security.PrincipalDirName(testPrincipal))
		testutil.Check(t, err)
		for _, host := range hosts {
			if host.Alias == name && host.Key != "" {
				t.Fatalf("deleted %s remains assigned: %+v", name, host)
			}
		}
	}
}

func TestSSHAuthAndHealthExposeOnlyCanonicalResponses(t *testing.T) {
	service := isolatedService(t)
	handler := serviceHandler(t, service)
	if response := testutil.Serve(handler, httptest.NewRequest(http.MethodGet, "/api/v1/hosts/delta/ssh", nil)); response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated auth = %d", response.Code)
	}
	if response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/hosts/delta/ssh", nil)); response.Code != http.StatusUpgradeRequired {
		t.Fatalf("non-WebSocket auth = %d", response.Code)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	testutil.Check(t, err)
	defer func() { _ = listener.Close() }()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	configPath := service.Configs.ConfigPath(testPrincipal)
	testutil.Check(t, security.EnsurePrivateDir(filepath.Dir(configPath)))
	testutil.Check(t, os.WriteFile(configPath, []byte("Host delta jumpy\n"), 0o600))
	sshBin := filepath.Join(t.TempDir(), "ssh")
	testutil.WriteScript(t, sshBin, `#!/bin/sh
for last do :; done
case "$last" in
  delta|ssh://alice@bastion:*) printf 'hostname 127.0.0.1\nport `+port+`\nproxyjump none\n' ;;
  jumpy) printf 'hostname internal.example\nport 22\nproxyjump alice@bastion:`+port+`,other\n' ;;
esac
`)
	service.Configs.Template = internalssh.Runner{SSHBin: sshBin, Timeout: time.Second}
	handler = serviceHandler(t, service)
	health := func(alias string) (int, string) {
		response := testutil.Serve(handler, requestAs(testPrincipal, http.MethodGet, "/api/v1/hosts/"+alias+"/health", nil))
		return response.Code, response.Body.String()
	}
	if code, body := health("delta"); code != http.StatusOK || !strings.Contains(body, `"ok":false`) {
		t.Fatalf("a loopback listener was dialed: %d %s", code, body)
	}
	original := dialHealth
	dialHealth = (&net.Dialer{}).DialContext
	t.Cleanup(func() { dialHealth = original })
	for _, alias := range []string{"delta", "jumpy"} {
		if code, body := health(alias); code != http.StatusOK || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, "127.0.0.1:"+port) {
			t.Fatalf("%s health = %d %s", alias, code, body)
		}
	}
	if code, _ := health("absent"); code != http.StatusNotFound {
		t.Fatalf("an unconfigured alias answered %d", code)
	}
}
