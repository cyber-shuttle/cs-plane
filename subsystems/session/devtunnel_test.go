// Session Dev Tunnel tests protect run token files, secret separation, and compensation.
// Run tokens remain strict private files and reject malformed data or symlink traversal.
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

func defaultRunTokens() runTokens {
	return runTokens{ConnectToken: testConnectToken, JupyterToken: testJupyterToken, LinkToken: testLinkToken}
}

func TestRunTokenStorage(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run-tokens")
	const sessionID, seq = "s-123456789abc", 1
	first := runTokens{ConnectToken: "first-connect-token", JupyterToken: strings.Repeat("A", 43), LinkToken: testLinkToken}
	testutil.Check(t, putRunTokens(dir, sessionID, seq, first))
	if got, err := getRunTokens(dir, sessionID, seq); err != nil || got != first {
		t.Fatalf("getRunTokens = %#v, %v", got, err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("directory mode = %v, %v", info.Mode(), err)
	}
	path, _ := runTokensPath(dir, sessionID, seq)
	if info, err := os.Stat(path); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Fatalf("file mode = %v, %v", info.Mode(), err)
	}
	replacement := runTokens{JupyterToken: strings.Repeat("B", 42) + "A", LinkToken: testLinkToken}
	testutil.Check(t, putRunTokens(dir, sessionID, seq, replacement))
	if got, err := getRunTokens(dir, sessionID, seq); err != nil || got != replacement {
		t.Fatalf("replacement = %#v, %v", got, err)
	}
	testutil.Check(t, deleteRunTokens(dir, sessionID, seq))
	if _, err := getRunTokens(dir, sessionID, seq); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("after delete = %v", err)
	}
}

func TestRunTokensRefuseInvalidRecordsAndSymlinks(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "run-tokens")
	const sessionID, seq = "s-123456789abc", 1
	if err := putRunTokens(dir, sessionID, seq, runTokens{ConnectToken: "connect"}); err == nil {
		t.Fatal("invalid run tokens accepted")
	}
	testutil.Check(t, os.Mkdir(dir, 0o700))
	path, _ := runTokensPath(dir, sessionID, seq)
	tokens := defaultRunTokens()
	valid, _ := json.Marshal(tokens)
	missingLink, _ := json.Marshal(map[string]string{"connectToken": tokens.ConnectToken, "jupyterToken": tokens.JupyterToken})
	for _, raw := range []string{
		strings.TrimSuffix(string(valid), "}") + `,"extra":true}`,
		string(valid) + "{}",
		string(missingLink),
	} {
		testutil.Check(t, os.WriteFile(path, []byte(raw), 0o600))
		if _, err := getRunTokens(dir, sessionID, seq); err == nil {
			t.Fatalf("invalid record accepted: %s", raw)
		}
	}
	foreign := filepath.Join(root, "foreign.token")
	testutil.Check(t, os.WriteFile(foreign, valid, 0o600))
	testutil.Check(t, os.Remove(path))
	testutil.Check(t, os.Symlink(foreign, path))
	if _, err := getRunTokens(dir, sessionID, seq); err == nil {
		t.Fatal("run token read followed a symlink")
	}

	linkedDir, target := filepath.Join(root, "linked"), filepath.Join(root, "target")
	testutil.Check(t, os.Mkdir(target, 0o755))
	testutil.Check(t, os.Symlink(target, linkedDir))
	if err := putRunTokens(linkedDir, sessionID, seq, defaultRunTokens()); err == nil {
		t.Fatal("run token write followed a directory symlink")
	}
	if entries, err := os.ReadDir(target); err != nil || len(entries) != 0 {
		t.Fatalf("symlink target entries = %#v, %v", entries, err)
	}
}

func accessTestService(t *testing.T, manager DevtunnelManager) Service {
	t.Helper()
	service := newTestService(t, ssh.Runner{}, testSessionStore(t))
	service.DevtunnelManager, service.TokenDir = manager, t.TempDir()+"/credentials"
	return service
}

func TestCreateSessionDevtunnelPersistsTokensOnlyInPrivateFile(t *testing.T) {
	manager := &testDevtunnelManager{}
	service := accessTestService(t, manager)
	session := pendingSession("s-012345abcdef", "delta", "")
	hostToken, tokens, err := service.issueSession(context.Background(), &session, testPrincipal, devtunnel.Credential{Scheme: "Bearer", Token: "oauth-token"}, 1)
	testutil.Check(t, err)
	stored, err := getRunTokens(service.TokenDir, session.ID, session.Seq)
	if err != nil || stored != tokens || tokens.JupyterToken == tokens.LinkToken || tokens.ConnectToken == "" || hostToken == "" || session.Devtunnel.ID == "" {
		t.Fatalf("private run tokens = %#v, host token %q, Dev Tunnel %q: %v", stored, hostToken, session.Devtunnel.ID, err)
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
	service.TokenDir = credentialDir
	_, _, err := service.issueSession(context.Background(), &session, security.Principal{Subject: "owner", Tenant: "tenant"}, devtunnel.Credential{Scheme: "Bearer", Token: oauth}, 1)
	if err == nil || strings.Contains(err.Error(), oauth) || !strings.Contains(err.Error(), "[redacted]") {
		t.Fatalf("create/cleanup error = %v", err)
	}
	if !reflect.DeepEqual(session, before) {
		t.Fatalf("session mutated after uncertain create: before=%#v after=%#v", before, session)
	}
	if len(manager.deletes) != 1 || manager.deletes[0].ID != manager.creates[0].ID || manager.deletes[0].ClusterID != "" || manager.deletes[0].Token != oauth {
		t.Fatalf("uncertain create compensation = %#v, create=%#v", manager.deletes, manager.creates)
	}
	entries, readErr := os.ReadDir(credentialDir)
	if readErr != nil || len(entries) != 0 {
		t.Fatalf("run token directory after uncertain create = %#v, %v", entries, readErr)
	}
}
