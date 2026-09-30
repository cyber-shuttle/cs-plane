// Store tests protect principal isolation, deterministic private config rendering, and the compensated
// key-deletion transaction. They exercise database, rendered-file, and staged-key effects together.
package ssh

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func newHostRecord(alias string) HostEntry {
	return HostEntry{Alias: alias, Hostname: alias + ".example.edu", User: "alice", Port: 22, ExtraDirectives: []string{}, Managed: true}
}

func TestSSHHostsArePrincipalIsolatedAndRenderPrivateConfigs(t *testing.T) {
	service := isolatedService(t)
	mine, theirs := security.PrincipalDirName(testPrincipal), security.PrincipalDirName(otherTestPrincipal)
	configPath := service.Configs.ConfigPath(testPrincipal)
	if err := service.Store.addHost(mine, configPath, newHostRecord("delta")); err != nil {
		t.Fatal(err)
	}
	if err := service.Store.addHost(mine, configPath, newHostRecord("DELTA")); err == nil || !strings.Contains(err.Error(), "already configured") {
		t.Fatalf("case-insensitive duplicate was accepted: %v", err)
	}
	if hosts, err := service.Store.loadHosts(theirs); err != nil || len(hosts) != 0 {
		t.Fatalf("another principal saw hosts: %+v %v", hosts, err)
	}
	hosts, err := service.Store.loadHosts(mine)
	testutil.Check(t, err)
	if len(hosts) != 1 || hosts[0].Alias != "delta" || hosts[0].Hostname != "delta.example.edu" {
		t.Fatalf("stored host did not round-trip: %+v", hosts)
	}
	config, err := os.ReadFile(configPath)
	testutil.Check(t, err)
	if string(config) != string(service.Store.renderConfig(mine, hosts)) {
		t.Fatalf("rendered config differs from stored hosts:\n%s", config)
	}
	if info, err := os.Stat(configPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("rendered config is not private: %v %v", info, err)
	}
	if err := service.Store.deleteHost(mine, configPath, "DELTA"); err == nil {
		t.Fatal("differently cased alias selected the stored host")
	}
}

func TestReconcileRestoresStoredConfigsAndEmptiesOrphans(t *testing.T) {
	service := isolatedService(t)
	_, err := service.addHost(testPrincipal, AddHostRequest{Alias: "delta", Command: "ssh alice@login.example.edu"})
	testutil.Check(t, err)
	path := service.Configs.ConfigPath(testPrincipal)
	testutil.Check(t, os.WriteFile(path, []byte("stale"), 0o600))
	orphanDir := filepath.Join(service.Configs.Dir, "orphan")
	testutil.Check(t, os.MkdirAll(orphanDir, 0o700))
	testutil.Check(t, os.WriteFile(filepath.Join(orphanDir, "config"), []byte("stale"), 0o600))
	testutil.Check(t, service.Store.reconcileConfigs())
	hosts, err := service.Store.loadHosts(security.PrincipalDirName(testPrincipal))
	testutil.Check(t, err)
	config, err := os.ReadFile(path)
	testutil.Check(t, err)
	if string(config) != string(service.Store.renderConfig(security.PrincipalDirName(testPrincipal), hosts)) {
		t.Fatalf("reconciliation did not restore committed hosts:\n%s", config)
	}
	orphan, err := os.ReadFile(filepath.Join(orphanDir, "config"))
	if err != nil || len(orphan) != 0 {
		t.Fatalf("orphan config was not emptied: %q %v", orphan, err)
	}
}

func TestKeyDeletionRollsBackMetadataReferencesAndFileWhenConfigWriteFails(t *testing.T) {
	service := isolatedService(t)
	_, err := service.writeSSHKey(testPrincipal, "delta-key", testKey(t, ""))
	testutil.Check(t, err)
	_, err = service.addHost(testPrincipal, AddHostRequest{Alias: "delta", Command: "ssh login.example.edu", Key: "delta-key"})
	testutil.Check(t, err)

	target := t.TempDir()
	linkedParent := filepath.Join(t.TempDir(), "linked")
	testutil.Check(t, os.Symlink(target, linkedParent))
	mine := security.PrincipalDirName(testPrincipal)
	if err := service.Store.deleteSSHKey(mine, filepath.Join(linkedParent, "config"), "delta-key"); err == nil {
		t.Fatal("key deletion succeeded through a symlinked config directory")
	}
	keys, err := service.Store.listSSHKeys(mine)
	if err != nil || len(keys) != 1 || keys[0].Name != "delta-key" {
		t.Fatalf("key metadata was not rolled back: keys=%v err=%v", keys, err)
	}
	if _, err := os.Stat(service.Store.keyPath(mine, "delta-key")); err != nil {
		t.Fatalf("staged key file was not restored: %v", err)
	}
	hosts, err := service.Store.loadHosts(mine)
	testutil.Check(t, err)
	if len(hosts) != 1 || hosts[0].Key != "delta-key" {
		t.Fatalf("host reference was not rolled back: %+v", hosts)
	}
}
