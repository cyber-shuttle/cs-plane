// Executor tests cover principal-scoped configuration, bounded remote output, control-socket ownership, and
// cancellation. Interactive control-master lifecycle is exercised end to end in control_test.
package ssh

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestConfigurationsScopeRunnersAndFailClosed(t *testing.T) {
	principal := security.Principal{Subject: "owner", Tenant: "tenant"}
	other := security.Principal{Subject: "other", Tenant: "tenant"}
	configs := Configurations{Dir: t.TempDir(), Template: Runner{Timeout: time.Second}}
	path := configs.ConfigPath(principal)
	if path != filepath.Join(configs.Dir, security.PrincipalDirName(principal), "config") || configs.Runner(principal).ConfigPath != path || configs.ConfigPath(other) == path || strings.Contains(path, principal.Subject) {
		t.Fatalf("principal configuration was not isolated: %q", path)
	}
	closed := (Configurations{}).Runner(principal)
	if _, _, err := closed.RunOutput(context.Background(), "delta", nil, "true"); closed.ConfigPath != os.DevNull || security.For(err).Code != "ssh_host_not_found" {
		t.Fatalf("unconfigured runner did not fail closed: %q, %v", closed.ConfigPath, err)
	}
	testutil.Check(t, os.MkdirAll(filepath.Dir(path), 0o700))
	testutil.Check(t, os.WriteFile(path+".target", []byte("Host delta\n"), 0o600))
	testutil.Check(t, os.Symlink(path+".target", path))
	if _, err := configs.Runner(principal).identity(context.Background(), "delta"); err == nil {
		t.Fatal("runner followed a symlinked principal configuration")
	}
}

func TestRunOutputBoundsCombinedOutputAndPreservesUTF8Locale(t *testing.T) {
	dir := t.TempDir()
	sshBin, localeLog := filepath.Join(dir, "ssh"), filepath.Join(dir, "locale")
	t.Setenv("LC_ALL", "en_US.UTF-8")
	t.Setenv("LOCALE_LOG", localeLog)
	testutil.WriteScript(t, sshBin, `#!/bin/sh
printf '%s' "$LC_ALL" > "$LOCALE_LOG"
if [ "$1" = "-G" ]; then
  printf 'hostname delta\n'
  exit 0
fi
dd if=/dev/zero bs=1048576 count=1 2>/dev/null
printf x >&2
`)
	runner := Runner{SSHBin: sshBin, Timeout: 5 * time.Second}
	_, _, err := runner.RunOutput(context.Background(), "delta", nil, "true")
	if err == nil || !strings.Contains(err.Error(), "output exceeded limit") {
		t.Fatalf("oversized combined remote output error = %v", err)
	}
	if locale, err := os.ReadFile(localeLog); err != nil || string(locale) != "en_US.UTF-8" {
		t.Fatalf("child locale = %q, %v", locale, err)
	}
	t.Setenv("LC_ALL", "C")
	t.Setenv("LC_CTYPE", "")
	t.Setenv("LANG", "en_US.UTF-8")
	if environment := childEnv(); !slices.Contains(environment, "LC_ALL="+utf8Locale) {
		t.Fatalf("non-UTF-8 effective locale was preserved: %q", environment)
	}
}

func TestMasterHealthyRequiresAPrivateOwnedSocket(t *testing.T) {
	dir := t.TempDir()
	sshBin := filepath.Join(dir, "ssh")
	testutil.WriteScript(t, sshBin, "#!/bin/sh\nexit 0\n")
	runner := Runner{SSHBin: sshBin}
	regular := filepath.Join(dir, "regular")
	testutil.Check(t, os.WriteFile(regular, nil, 0o600))
	link := filepath.Join(dir, "link")
	testutil.Check(t, os.Symlink(regular, link))
	sockets, err := os.MkdirTemp("", "cs")
	testutil.Check(t, err)
	defer func() { _ = os.RemoveAll(sockets) }()
	private, shared := filepath.Join(sockets, "private"), filepath.Join(sockets, "shared")
	privateListener, err := net.Listen("unix", private)
	testutil.Check(t, err)
	defer func() { _ = privateListener.Close() }()
	sharedListener, err := net.Listen("unix", shared)
	testutil.Check(t, err)
	defer func() { _ = sharedListener.Close() }()
	testutil.Check(t, os.Chmod(private, 0o600))
	testutil.Check(t, os.Chmod(shared, 0o777))
	for name, path := range map[string]string{"regular file": regular, "symlink": link, "world-accessible socket": shared} {
		if runner.masterHealthy(context.Background(), "delta", path) {
			t.Fatalf("%s was accepted as a control socket", name)
		}
	}
	if !runner.masterHealthy(context.Background(), "delta", private) {
		t.Fatal("a private socket this user owns was refused")
	}
}

func TestMasterHealthProbeStopsWithItsCaller(t *testing.T) {
	dir := t.TempDir()
	started := filepath.Join(dir, "started")
	sshBin := filepath.Join(dir, "ssh")
	t.Setenv("HEALTH_STARTED", started)
	testutil.WriteScript(t, sshBin, "#!/bin/sh\nprintf started > \"$HEALTH_STARTED\"\nexec sleep 30\n")
	sockets, err := os.MkdirTemp("", "cs")
	testutil.Check(t, err)
	defer func() { _ = os.RemoveAll(sockets) }()
	socket := filepath.Join(sockets, "control")
	listener, err := net.Listen("unix", socket)
	testutil.Check(t, err)
	defer func() { _ = listener.Close() }()
	testutil.Check(t, os.Chmod(socket, 0o600))

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan bool, 1)
	go func() { result <- (Runner{SSHBin: sshBin, Timeout: time.Minute}).masterHealthy(ctx, "delta", socket) }()
	testutil.WaitForFile(t, started)
	cancel()
	select {
	case healthy := <-result:
		if healthy {
			t.Fatal("a canceled health probe reported a healthy master")
		}
	case <-time.After(time.Second):
		t.Fatal("health probe ignored caller cancellation")
	}
}
