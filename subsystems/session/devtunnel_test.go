// Session Dev Tunnel tests protect capability files, secret separation, and compensation.
// Capabilities remain strict private files and reject malformed data or symlink traversal.
// Persisted session payloads never contain connection, host, link or Jupyter tokens.
// An uncertain provider create is deleted without exposing its credential in errors.
package session

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func defaultSessionCapability() sessionCapability {
	return sessionCapability{ConnectToken: testConnectToken, JupyterToken: testJupyterToken, LinkToken: testLinkToken}
}

func TestSessionCapabilityStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "session-capabilities")
	const sessionID, seq = "s-123456789abc", 1
	first := sessionCapability{ConnectToken: "first-connect-token", JupyterToken: strings.Repeat("A", 43), LinkToken: testLinkToken}
	testutil.Check(t, putCapability(dir, sessionID, seq, first))
	if got, err := getCapability(dir, sessionID, seq); err != nil || got != first {
		t.Fatalf("getCapability = %#v, %v", got, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, %v", info.Mode(), err)
	}
	path, _ := capabilityPath(dir, sessionID, seq)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, %v", info.Mode(), err)
	}
	replacement := sessionCapability{JupyterToken: strings.Repeat("B", 42) + "A", LinkToken: testLinkToken}
	testutil.Check(t, putCapability(dir, sessionID, seq, replacement))
	if got, err := getCapability(dir, sessionID, seq); err != nil || got != replacement {
		t.Fatalf("replacement = %#v, %v", got, err)
	}
	testutil.Check(t, deleteCapability(dir, sessionID, seq))
	if _, err := getCapability(dir, sessionID, seq); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after delete = %v", err)
	}
}

func TestSessionCapabilityRefusesInvalidRecordsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "session-capabilities")
	const sessionID, seq = "s-123456789abc", 1
	if err := putCapability(dir, sessionID, seq, sessionCapability{ConnectToken: "connect"}); err == nil {
		t.Fatal("invalid capability accepted")
	}
	testutil.Check(t, os.Mkdir(dir, 0o700))
	path, _ := capabilityPath(dir, sessionID, seq)
	capability := defaultSessionCapability()
	valid, _ := json.Marshal(capability)
	missingLink, _ := json.Marshal(map[string]string{"connectToken": capability.ConnectToken, "jupyterToken": capability.JupyterToken})
	for _, raw := range []string{
		strings.TrimSuffix(string(valid), "}") + `,"extra":true}`,
		string(valid) + "{}",
		string(missingLink),
	} {
		testutil.Check(t, os.WriteFile(path, []byte(raw), 0o600))
		if _, err := getCapability(dir, sessionID, seq); err == nil {
			t.Fatalf("invalid record accepted: %s", raw)
		}
	}
	foreign := filepath.Join(root, "foreign.token")
	testutil.Check(t, os.WriteFile(foreign, valid, 0o600))
	testutil.Check(t, os.Remove(path))
	testutil.Check(t, os.Symlink(foreign, path))
	if _, err := getCapability(dir, sessionID, seq); err == nil {
		t.Fatal("capability read followed a symlink")
	}

	linkedDir, target := filepath.Join(root, "linked"), filepath.Join(root, "target")
	testutil.Check(t, os.Mkdir(target, 0o755))
	testutil.Check(t, os.Symlink(target, linkedDir))
	if err := putCapability(linkedDir, sessionID, seq, defaultSessionCapability()); err == nil {
		t.Fatal("capability write followed a directory symlink")
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target entries = %#v, %v", entries, err)
	}
}

func accessTestService(t *testing.T, manager DevtunnelManager) Service {
	t.Helper()
	service := newTestService(t, ssh.Runner{}, testSessionStore(t))
	service.DevtunnelManager, service.CapabilityDir = manager, t.TempDir()+"/credentials"
	return service
}

func TestCreateSessionDevtunnelPersistsCapabilityOnlyInPrivateCredential(t *testing.T) {
	manager := &testDevtunnelManager{}
	service := accessTestService(t, manager)
	session := pendingSession("s-012345abcdef", "delta", "")
	hostToken, capability, err := service.issueSession(context.Background(), &session, testPrincipal, devtunnel.Credential{Scheme: "Bearer", Token: "oauth-token"}, 1)
	testutil.Check(t, err)
	stored, err := getCapability(service.CapabilityDir, session.ID, session.Seq)
	if err != nil || stored != capability || capability.JupyterToken == capability.LinkToken || capability.ConnectToken == "" || hostToken == "" || session.Devtunnel.ID == "" {
		t.Fatalf("private capability = %#v, host token %q, Dev Tunnel %q: %v", stored, hostToken, session.Devtunnel.ID, err)
	}
	persistedSession, err := json.Marshal(session)
	testutil.Check(t, err)
	for _, secret := range []string{stored.JupyterToken, stored.LinkToken, stored.ConnectToken, hostToken} {
		if strings.Contains(string(persistedSession), secret) {
			t.Fatalf("session state contains a run secret: %s", persistedSession)
		}
	}
}

func TestCreateSessionDevtunnelCompensatesUncertainCreateError(t *testing.T) {
	const oauth = "oauth-token-must-not-leak"
	manager := &testDevtunnelManager{
		createErr: errors.New("create response was ambiguous"),
		deleteErr: errors.New("delete failed with " + oauth),
	}
	session := pendingSession("s-012345abcdef", "delta", "")
	before := session
	credentialDir := t.TempDir()
	testutil.Check(t, os.Chmod(credentialDir, 0o700))
	service := accessTestService(t, manager)
	service.CapabilityDir = credentialDir
	_, _, err := service.issueSession(context.Background(), &session, security.Principal{Subject: "owner", Tenant: "tenant"}, devtunnel.Credential{Scheme: "Bearer", Token: oauth}, 1)
	if err == nil || strings.Contains(err.Error(), oauth) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("create/cleanup error = %v", err)
	}
	if !reflect.DeepEqual(session, before) {
		t.Fatalf("session mutated after uncertain create: before=%#v after=%#v", before, session)
	}
	if len(manager.deletes) != 1 || manager.deletes[0].TunnelID != manager.creates[0].TunnelID || manager.deletes[0].ClusterID != "" || manager.deletes[0].OAuthToken != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.creates)
	}
	entries, readErr := os.ReadDir(credentialDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("capability directory after uncertain create = %#v, %v", entries, readErr)
	}
}
