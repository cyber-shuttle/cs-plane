// Session preparation tests defend request, path, resource, script, and side-effect boundaries.
// Remote identity and root folder expressions cannot escape their validated forms.
// The generated job script carries identity but never embeds credentials.
// Failed validation leaves the database, Dev Tunnels, run tokens, and Slurm submission untouched.
package session

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
)

func TestDiscoverRejectsUnsafeRemoteUsernameBeforeSacctmgr(t *testing.T) {
	sshBin, _, commandLog := fakeSSH(t)
	t.Setenv("FAKE_REMOTE_USER", "bad;touch")
	service := newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: 5 * time.Second}, Store{})
	if _, err := service.discover(context.Background(), "delta"); err == nil || !strings.Contains(err.Error(), "identify remote user") {
		t.Fatalf("expected unsafe username rejection, got %v", err)
	}
	wire := string(mustRead(t, commandLog))
	if strings.Count(wire, "delta|'sh' '-s'") != 1 {
		t.Fatalf("unsafe username discovery used unexpected remote executions:\n%s", wire)
	}
}

func TestRootFolderExpressionsRejectUnsafeOrUnavailableValues(t *testing.T) {
	service := testService(t)
	for _, expression := range []string{"", " ", "/", "../x", "a/../b", "./x", "~/../x", "$HOME/../x", "${HOME}/../x", "$HOME/$USER", "$HOME/", "${WORKSPACE}/", "prefix/$HOME", "$(id)", "`id`", "$BAD-NAME/x", "${BAD-NAME}/x", "path\\x", "path\nother", "$EMPTY", "$RELATIVE", "$MULTILINE"} {
		t.Run(fmt.Sprintf("%q", expression), func(t *testing.T) {
			if _, err := service.resolveRootFolder(context.Background(), "delta", "/home/tester", expression); err == nil {
				t.Fatalf("accepted unsafe root folder expression %q", expression)
			}
		})
	}
}

func TestStartRejectsRootFolderInsidePrivateSession(t *testing.T) {
	request := newTestCreateRequest()
	request.RootFolder = "/home/tester/.cybershuttle/sessions/s-012345abcdef/workspace"
	service := testService(t)
	if _, err := defineAndStart(context.Background(), service, request); err == nil || security.For(err).Code != "invalid_root_folder" {
		t.Fatalf("private session overlap was not rejected: %v", err)
	}
}

func TestDefineRejectsSessionsBelowTheFloor(t *testing.T) {
	service := testService(t)
	request := newTestCreateRequest()
	for _, below := range []Resources{
		{Cores: minCores - 1, MemoryMB: minMemoryMB, WallMinutes: 60},
		{Cores: minCores, MemoryMB: minMemoryMB - 1, WallMinutes: 60},
	} {
		request.Resources = below
		if _, _, err := service.Define(testPrincipal, request); err == nil || security.For(err).Code != "invalid_resources" {
			t.Fatalf("%d cores / %d MB was not rejected: %v", below.Cores, below.MemoryMB, err)
		}
	}
	request.Resources = Resources{Cores: minCores, MemoryMB: minMemoryMB, WallMinutes: 60}
	if _, _, err := service.Define(testPrincipal, request); err != nil {
		t.Fatalf("the floor itself was rejected: %v", err)
	}
}

func runProvisionScript(t *testing.T, arguments ...string) (string, error) {
	t.Helper()
	stubs := t.TempDir()
	testutil.WriteScript(t, filepath.Join(stubs, "curl"), "#!/bin/sh\nexit 1\n")
	command := exec.Command("/bin/sh", append([]string{"-s", "--"}, arguments...)...)
	command.Stdin = strings.NewReader(provisionScript)
	command.Env = append(os.Environ(), "PATH="+stubs+":"+os.Getenv("PATH"))
	output, err := command.CombinedOutput()
	return string(output), err
}

func TestSessionScriptExecsLinkspanWithExactlyTheSelectedTransports(t *testing.T) {
	const jupyterToken, hostToken, linkToken = "jupyter-secret", "host-secret", "link-secret"
	const devtunnelID, devtunnelCluster, linkURL = "s-012345abcdef-g-0123456789abcdef", "usw3", "wss://plane.example.edu/api/v1/sessions/s-012345abcdef/link"
	linkArgs := "--tunnel-link-args\n--url " + linkURL + "\n"
	devtunnelArgs := "--tunnel-devtunnel-args\n--id " + devtunnelID + " --cluster " + devtunnelCluster + "\n"
	for _, test := range []struct {
		transports          []string
		args, env, exported string
	}{
		{[]string{transportLink}, "--tunnel-mode\nlink\n" + linkArgs, jupyterToken + "\n" + linkToken + "\n\n", "CS_LINK_URL LINKSPAN_LINK_TOKEN"},
		{[]string{transportDevtunnel}, "--tunnel-mode\ndevtunnel\n" + devtunnelArgs, jupyterToken + "\n\n" + hostToken + "\n", "CS_DEVTUNNEL_CLUSTER CS_DEVTUNNEL_ID LINKSPAN_TUNNEL_HOST_TOKEN"},
		{[]string{transportDevtunnel, transportLink}, "--tunnel-mode\ndevtunnel,link\n" + devtunnelArgs + linkArgs, jupyterToken + "\n" + linkToken + "\n" + hostToken + "\n", "CS_DEVTUNNEL_CLUSTER CS_DEVTUNNEL_ID CS_LINK_URL LINKSPAN_LINK_TOKEN LINKSPAN_TUNNEL_HOST_TOKEN"},
	} {
		dir := t.TempDir()
		linkspan := filepath.Join(dir, "linkspan")
		argsLog := filepath.Join(dir, "args")
		testutil.WriteScript(t, linkspan, `#!/bin/sh
printf '%s\n' "$@" > "$ARGS_LOG"
printf '%s\n' "$JUPYTER_TOKEN" "$LINKSPAN_LINK_TOKEN" "$LINKSPAN_TUNNEL_HOST_TOKEN" > "$ENV_LOG"
exit 7
`)
		session := Session{
			SessionResponse: SessionResponse{ID: "s-012345abcdef", Seq: 1, Partition: "cpu", Resources: Resources{Cores: 1, MemoryMB: 128, WallMinutes: 1}, TunnelModes: test.transports},
			JobName:         jobName("s-012345abcdef", 1), PrivateRoot: dir + "/private", RootFolderPath: dir,
		}
		script := buildScript(session, linkspan)
		for _, secret := range []string{jupyterToken, hostToken, linkToken} {
			if strings.Contains(script, secret) {
				t.Fatalf("session script contains a secret literal:\n%s", script)
			}
		}
		environment := linkspanEnvironment(test.transports, linkURL, linkToken, devtunnelMetadata{ID: devtunnelID, ClusterID: devtunnelCluster}, hostToken)
		if got := strings.Join(slices.Sorted(maps.Keys(environment)), " "); got != test.exported {
			t.Fatalf("%v exports %q", test.transports, got)
		}
		environment["JUPYTER_TOKEN"], environment["CS_CONTROL_PORT"] = jupyterToken, strconv.Itoa(int(ports(session.ID, session.Seq).Control))
		command := exec.Command("bash")
		command.Stdin, command.Env = strings.NewReader(script), append(os.Environ(), "HOME="+dir, "ARGS_LOG="+argsLog, "ENV_LOG="+filepath.Join(dir, "env"))
		for name, value := range environment {
			command.Env = append(command.Env, name+"="+value)
		}
		err := command.Run()
		if exitErr, ok := errors.AsType[*exec.ExitError](err); !ok || exitErr.ExitCode() != 7 {
			t.Fatalf("script did not exec Linkspan or preserve status 7: %v", err)
		}
		args := string(mustRead(t, argsLog))
		if want := "--port\n" + environment["CS_CONTROL_PORT"] + "\n--tunnel-enable\n" + test.args + "--workflow\n" + sessionWorkflowPath(session) + "\n"; args != want {
			t.Fatalf("%v argv = %q, want %q", test.transports, args, want)
		}
		if got := string(mustRead(t, filepath.Join(dir, "env"))); got != test.env {
			t.Fatalf("%v Linkspan inherited %q", test.transports, got)
		}
	}
}

func TestTunnelModesAreValidatedAndCanonical(t *testing.T) {
	request := newTestCreateRequest()
	request.TunnelModes = nil
	testutil.Check(t, validateCreate(&request))
	if !slices.Equal(request.TunnelModes, []string{transportLink}) {
		t.Fatalf("omitted transports default to %v", request.TunnelModes)
	}
	request.TunnelModes = []string{transportLink, transportDevtunnel}
	if testutil.Check(t, validateCreate(&request)); !slices.Equal(request.TunnelModes, []string{transportDevtunnel, transportLink}) {
		t.Fatalf("transports stored as %v", request.TunnelModes)
	}
	for _, transports := range [][]string{{}, {"ssh"}, {transportLink, transportLink}, {"Link"}} {
		request.TunnelModes = transports
		if err := validateCreate(&request); security.For(err).Code != "invalid_tunnel_modes" {
			t.Fatalf("transports %q answered %v", transports, err)
		}
	}
}

func TestProvisionScriptGuardsItsArgumentVector(t *testing.T) {
	home := t.TempDir()
	testutil.Check(t, os.MkdirAll(filepath.Join(home, ".local", "bin"), 0o700))
	linkspan := filepath.Join(home, ".local", "bin", "linkspan")
	testutil.WriteScript(t, linkspan, "#!/bin/sh\ncase \"$1\" in --version) echo v9.9.9;; esac\n")
	workflow := filepath.Join(home, ".cybershuttle", "sessions", "s-012345abcdef", "workflow.yaml")
	document := base64.StdEncoding.EncodeToString([]byte("workflow: yes\n"))

	output, err := runProvisionScript(t, "cs-provision", home, linkspan, workflow, document)
	if err != nil || !strings.Contains(output, "provision=complete") {
		t.Fatalf("the vector provisionSession sends was refused: %v\n%s", err, output)
	}

	for _, wrong := range [][]string{
		{"cs-provision", home, linkspan, workflow},
		{"not-cs-provision", home, linkspan, workflow, document},
	} {
		output, err := runProvisionScript(t, wrong...)
		if err == nil || provisionOutcome(output)["error"] != "arguments" {
			t.Fatalf("wrong vector %v was not refused: %v\n%s", wrong, err, output)
		}
	}
}

func TestStartRevalidatesExactScriptBeforeSubmit(t *testing.T) {
	sshBin, scriptLog, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	configureTestDevtunnel(t, &service)
	request := newTestCreateRequest()
	request.ID = ""
	validatedResult, err := service.Validate(context.Background(), testPrincipal, request)
	testutil.Check(t, err)
	created, err := defineAndStart(context.Background(), service, request)
	testutil.Check(t, err)
	testutil.Equal(t, created.ID, validatedResult.SessionID, "created session ID")
	submitted, err := os.ReadFile(scriptLog)
	testutil.Check(t, err)
	validated, err := os.ReadFile(filepath.Join(filepath.Dir(scriptLog), "validation-script"))
	if err != nil || string(validated) != validatedResult.Script {
		t.Fatalf("create revalidation differs from the original validation: %v", err)
	}
	submittedBasename := created.ID + "-" + strconv.Itoa(created.Seq)
	validatedBasename := created.ID + "-0"
	if !strings.Contains(string(submitted), submittedBasename) {
		t.Fatalf("submitted script does not redirect to the created run's log:\n%s", submitted)
	}
	if !strings.Contains(string(validated), validatedBasename) {
		t.Fatalf("validation script does not use the placeholder log path:\n%s", validated)
	}
	if strings.ReplaceAll(string(submitted), submittedBasename, "placeholder") != strings.ReplaceAll(string(validated), validatedBasename, "placeholder") {
		t.Fatalf("submitted and validated scripts differ beyond the log path:\nsubmitted:\n%s\nvalidated:\n%s", submitted, validated)
	}
	commands, _ := os.ReadFile(commandLog)
	if strings.Count(string(commands), "'sbatch' '--test-only'") != 2 || strings.Count(string(commands), "'cs-submit'") != 1 {
		t.Fatalf("expected validation, create revalidation, then one submit:\n%s", commands)
	}
	before, _ := service.logs.tail(created.ID)
	_, err = service.Validate(context.Background(), testPrincipal, request)
	testutil.Check(t, err)
	if after, _ := service.logs.tail(created.ID); len(after.Lines) != len(before.Lines) {
		t.Fatalf("validating a persisted session narrated into its log tail: %v", after.Lines[len(before.Lines):])
	}
}

func TestStartValidationFailureLeavesTheSessionUnlaunched(t *testing.T) {
	sshBin, _, commandLog := fakeSSH(t)
	service := fakeSSHService(t, sshBin)
	store := service.Store
	manager := configureTestDevtunnel(t, &service)
	t.Setenv("FAKE_VALIDATION_FAIL", "1")
	t.Setenv("FAKE_VALIDATION_STDERR", "sbatch: error: rejected")
	_, err := defineAndStart(context.Background(), service, newTestCreateRequest())
	if security.For(err).Code != "slurm_validation_failed" {
		t.Fatalf("unexpected start error: %v", err)
	}
	testutil.Check(t, store.locked(func(current *state) error {
		session := current.Sessions[newTestCreateRequest().ID]
		if len(current.Sessions) != 1 || session.State != "STOPPED" || session.Seq != 0 || len(current.Runs) != 0 {
			t.Fatalf("failed validation launched the session: %#v", current)
		}
		return nil
	}))
	commands, _ := os.ReadFile(commandLog)
	if strings.Contains(string(commands), "cs-submit") {
		t.Fatalf("failed validation submitted a job:\n%s", commands)
	}
	if len(manager.creates) != 0 {
		t.Fatalf("failed validation created a Dev Tunnel: %#v", manager.creates)
	}
	if entries, err := os.ReadDir(service.TokenDir); err == nil && len(entries) != 0 {
		t.Fatalf("failed validation wrote run tokens: %#v", entries)
	} else if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
}

func TestProvisionReportsExpiredSSHAuthenticationAsRequired(t *testing.T) {
	sshBin := filepath.Join(t.TempDir(), "ssh")
	testutil.Check(t, os.WriteFile(sshBin, []byte("#!/bin/sh\n[ \"$1\" = -G ] && echo 'hostname delta' && exit 0\necho 'Permission denied (publickey,password).' >&2\nexit 255\n"), 0o700))
	service := newTestService(t, ssh.Runner{SSHBin: sshBin, Timeout: 5 * time.Second}, Store{})
	if code := security.For(service.provisionSession(context.Background(), Session{SessionResponse: SessionResponse{ID: "s-000000000001", Alias: "delta"}}, "/home/u", "/home/u/.cybershuttle/bin/linkspan")).Code; code != "ssh_authentication_required" {
		t.Fatalf("expired SSH authentication provisioned as %q, want ssh_authentication_required", code)
	}
}
