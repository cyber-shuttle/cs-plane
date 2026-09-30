// Package ssh runs bounded remote commands and foreground OpenSSH control masters against per-principal configs.
// Every operation resolves the alias first; that output also identifies its control socket. Interactive masters
// disable ControlPersist because persistence backgrounds authentication. Exit status 255 belongs to ssh itself and
// cannot establish whether a remote command ran; aliases trust literal Host lines in process-owned configs. FirstHop
// follows each ProxyJump entry as the ssh:// URI it is, so `ssh -G` resolves its user, host and port.
package ssh

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	cryptossh "golang.org/x/crypto/ssh"
)

const (
	maxOutput                   = 1 << 20
	maxConfigBytes              = 64 << 20
	maxControlSocketPath        = 100
	openSSHControlSuffixReserve = 18
	controlSocketHashBytes      = 10
	utf8Locale                  = "C.UTF-8"
)

var ErrInvalidAlias = security.New("invalid_ssh_alias", "invalid SSH alias", http.StatusBadRequest)

func ValidAlias(value string) bool { return security.SafeName(value, 128) }

type Runner struct {
	SSHBin           string
	Timeout          time.Duration
	ControlNamespace string
	ConfigPath       string
}

type Configurations struct {
	Dir      string
	Template Runner
}

type PrivateKeyMetadata struct {
	Type        string
	Fingerprint string
}

func InspectPrivateKey(private []byte) (PrivateKeyMetadata, error) {
	signer, err := cryptossh.ParsePrivateKey(private)
	if err != nil {
		locked, ok := errors.AsType[*cryptossh.PassphraseMissingError](err)
		if !ok || locked.PublicKey == nil {
			return PrivateKeyMetadata{}, err
		}
		return PrivateKeyMetadata{Type: locked.PublicKey.Type(), Fingerprint: cryptossh.FingerprintSHA256(locked.PublicKey)}, nil
	}
	public := signer.PublicKey()
	return PrivateKeyMetadata{Type: public.Type(), Fingerprint: cryptossh.FingerprintSHA256(public)}, nil
}

func (c Configurations) ConfigPath(principal security.Principal) string {
	if c.Dir == "" {
		return os.DevNull
	}
	return filepath.Join(c.Dir, security.PrincipalDirName(principal), "config")
}

func (c Configurations) Runner(principal security.Principal) Runner {
	runner := c.Template
	runner.ConfigPath = c.ConfigPath(principal)
	return runner
}

type capture struct {
	mu        sync.Mutex
	remaining int
	stdout    captureStream
	stderr    captureStream
}

type captureStream struct {
	capture *capture
	buf     bytes.Buffer
}

var authenticationMarkers = []string{
	"permission denied", "host key verification failed", "no supported authentication methods",
	"authentication failed", "keyboard-interactive", "too many authentication failures",
}

const sshTerminateGrace = 500 * time.Millisecond

func newCapture() *capture {
	c := &capture{remaining: maxOutput}
	c.stdout.capture, c.stderr.capture = c, c
	return c
}

func (s *captureStream) Write(data []byte) (int, error) {
	s.capture.mu.Lock()
	defer s.capture.mu.Unlock()
	if len(data) > s.capture.remaining {
		return len(data), errors.New("command output exceeded limit")
	}
	s.capture.remaining -= len(data)
	return s.buf.Write(data)
}

// kill signals the process group, falling back to the process alone when it never became a group leader.
func kill(cmd *exec.Cmd) {
	if syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) != nil {
		_ = cmd.Process.Kill()
	}
}

func killGroup(cmd *exec.Cmd, exited <-chan struct{}) {
	select {
	case <-exited:
		return
	default:
	}
	kill(cmd)
	<-exited
}

func runCommand(ctx context.Context, cmd *exec.Cmd) error {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.WaitDelay = sshTerminateGrace
	if err := cmd.Start(); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { kill(cmd) })
	err := cmd.Wait()
	stop()
	if err != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func (r Runner) bin() string { return cmp.Or(r.SSHBin, "ssh") }

func (r Runner) EffectiveTimeout() time.Duration { return cmp.Or(r.Timeout, 20*time.Second) }

func childEnv() []string {
	environment := os.Environ()
	locale := strings.ToUpper(cmp.Or(os.Getenv("LC_ALL"), os.Getenv("LC_CTYPE"), os.Getenv("LANG")))
	if strings.Contains(locale, "UTF-8") || strings.Contains(locale, "UTF8") {
		return environment
	}
	kept := slices.DeleteFunc(environment, func(entry string) bool { return strings.HasPrefix(entry, "LC_ALL=") })
	return append(kept, "LC_ALL="+utf8Locale)
}

func ShellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'" }

func FailureMessage(stderr string, err error) string {
	if message := strings.TrimSpace(stderr); message != "" {
		return message
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

func AuthenticationFailure(message string) bool {
	value := strings.ToLower(message)
	return slices.ContainsFunc(authenticationMarkers, func(marker string) bool { return strings.Contains(value, marker) })
}

func AmbiguousExit(err error) bool {
	if err == nil {
		return false
	}
	exit, ok := errors.AsType[*exec.ExitError](err)
	return !ok || exit.ExitCode() == 255
}

func ClassifyFailure(alias, stderr string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("ssh command timed out: %w", err)
	}
	message := FailureMessage(stderr, err)
	if AuthenticationFailure(message) {
		return security.New("ssh_authentication_required", "SSH authentication is required for "+alias, http.StatusConflict)
	}
	return fmt.Errorf("ssh command failed: %s", message)
}

func (r Runner) configArgs(args []string) []string {
	if r.ConfigPath == "" {
		return args
	}
	return append(args, "-F", r.ConfigPath)
}

func (r Runner) command(args ...string) *exec.Cmd {
	cmd := exec.Command(r.bin(), args...)
	cmd.Env = childEnv()
	return cmd
}

func (r Runner) identity(ctx context.Context, alias string) (string, error) {
	if !ValidAlias(alias) {
		return "", ErrInvalidAlias
	}
	if r.ConfigPath != "" {
		if r.ConfigPath == os.DevNull {
			return "", security.New("ssh_host_not_found", "SSH host alias is not configured", http.StatusNotFound)
		}
		data, err := security.ReadPrivateFile(r.ConfigPath, maxConfigBytes)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return "", err
		}
		hostLine := func(line string) bool {
			fields := strings.Fields(line)
			return len(fields) >= 2 && strings.EqualFold(fields[0], "Host") && slices.Contains(fields[1:], alias)
		}
		if !slices.ContainsFunc(strings.Split(string(data), "\n"), hostLine) {
			return "", security.New("ssh_host_not_found", "SSH host alias is not configured", http.StatusNotFound)
		}
	}
	return r.resolve(ctx, alias)
}

func (r Runner) resolve(ctx context.Context, destination string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.EffectiveTimeout())
	defer cancel()
	args := r.configArgs([]string{"-G"})
	cmd := r.command(append(args, destination)...)
	captured := newCapture()
	cmd.Stdout, cmd.Stderr = &captured.stdout, &captured.stderr
	if err := runCommand(ctx, cmd); err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("resolve effective SSH configuration: %w", err)
		}
		return "", fmt.Errorf("resolve effective SSH configuration: %s", FailureMessage(captured.stderr.buf.String(), err))
	}
	identity := strings.ReplaceAll(captured.stdout.buf.String(), "\r\n", "\n")
	identity = strings.TrimRight(identity, "\n") + "\n"
	if identity == "\n" {
		return "", errors.New("effective SSH configuration is empty")
	}
	return identity, nil
}

func (r Runner) FirstHop(ctx context.Context, alias string) (string, error) {
	identity, err := r.identity(ctx, alias)
	for range 8 {
		if err != nil {
			return "", err
		}
		option := map[string]string{}
		for line := range strings.SplitSeq(identity, "\n") {
			key, value, _ := strings.Cut(line, " ")
			option[key] = value
		}
		jump, _, _ := strings.Cut(option["proxyjump"], ",")
		if jump == "" || jump == "none" {
			return net.JoinHostPort(option["hostname"], option["port"]), nil
		}
		identity, err = r.resolve(ctx, "ssh://"+strings.TrimPrefix(jump, "ssh://"))
	}
	return "", errors.New("the ProxyJump chain is too long")
}

func (r Runner) privateControlPath(baseName string) (string, error) {
	name := fmt.Sprintf("cs-%d", os.Getuid())
	roots := []string{os.TempDir()}
	if filepath.Clean(roots[0]) != "/tmp" {
		roots = append(roots, "/tmp")
	}
	var tooLong []string
	for _, root := range roots {
		if !filepath.IsAbs(root) {
			continue
		}
		directory := filepath.Join(root, name)
		candidate := filepath.Join(directory, baseName)
		if len(candidate)+openSSHControlSuffixReserve > maxControlSocketPath {
			tooLong = append(tooLong, candidate)
			continue
		}
		if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
			return "", fmt.Errorf("create SSH control directory: %w", err)
		}
		if err := security.PrivateDir(directory); err != nil {
			return "", fmt.Errorf("SSH control directory must be private: %w", err)
		}
		return candidate, nil
	}
	return "", fmt.Errorf("no temporary directory can hold a safe SSH control path: %s", strings.Join(tooLong, ", "))
}

func (r Runner) controlPath(alias, identity string) (string, error) {
	if r.ControlNamespace == "" {
		return "", errors.New("SSH control namespace is not configured")
	}
	if !filepath.IsAbs(r.ControlNamespace) {
		return "", errors.New("SSH control namespace must be absolute")
	}
	hash := sha256.Sum256([]byte(alias + "\x00" + identity + "\x00" + r.ControlNamespace + "\x00" + r.bin() + "\x00" + r.ConfigPath))
	return r.privateControlPath("m-" + hex.EncodeToString(hash[:controlSocketHashBytes]))
}

func (r Runner) sshArgs(alias string, interactive bool, identity string) ([]string, error) {
	batchMode, persist := "yes", "600"
	if interactive {
		batchMode, persist = "no", "no"
	}
	args := []string{
		"-o", "BatchMode=" + batchMode,
		"-o", "ConnectTimeout=10",
		"-o", "ServerAliveInterval=15",
		"-o", "ServerAliveCountMax=3",
	}
	args = r.configArgs(args)
	if r.ControlNamespace != "" {
		path, err := r.controlPath(alias, identity)
		if err != nil {
			return nil, err
		}
		args = append(args, "-o", "ControlMaster=auto", "-o", "ControlPersist="+persist, "-o", "ControlPath="+path)
	}
	return append(args, alias), nil
}

func (r Runner) resolvedControlPath(ctx context.Context, alias string) (string, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return "", err
	}
	return r.controlPath(alias, identity)
}

func (r Runner) RunOutput(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, string, error) {
	if len(remoteArgs) == 0 {
		return "", "", errors.New("remote command is required")
	}
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return "", "", err
	}
	quoted := make([]string, len(remoteArgs))
	for i, argument := range remoteArgs {
		quoted[i] = ShellQuote(argument)
	}
	args, err := r.sshArgs(alias, false, identity)
	if err != nil {
		return "", "", err
	}
	cmd := r.command(append(args, strings.Join(quoted, " "))...)
	cmd.Stdin = stdin
	captured := newCapture()
	cmd.Stdout, cmd.Stderr = &captured.stdout, &captured.stderr
	runErr := runCommand(ctx, cmd)
	return captured.stdout.buf.String(), captured.stderr.buf.String(), runErr
}

func (r Runner) Run(ctx context.Context, alias string, stdin io.Reader, remoteArgs ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, r.EffectiveTimeout())
	defer cancel()
	stdout, stderr, err := r.RunOutput(ctx, alias, stdin, remoteArgs...)
	if err == nil {
		return stdout, nil
	}
	return stdout, ClassifyFailure(alias, stderr, err)
}

func (r Runner) interactiveCommand(ctx context.Context, alias, controlPath string) (*exec.Cmd, error) {
	identity, err := r.identity(ctx, alias)
	if err != nil {
		return nil, err
	}
	currentPath, err := r.controlPath(alias, identity)
	if err != nil {
		return nil, err
	}
	if currentPath != controlPath {
		return nil, errors.New("effective SSH configuration changed during authentication")
	}
	if err := os.Remove(controlPath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	args, err := r.sshArgs(alias, true, identity)
	if err != nil {
		return nil, err
	}
	host := args[len(args)-1]
	args = append(args[:len(args)-1], "-q", "-T", "-N", "-o", "LogLevel=ERROR", host)
	return r.command(args...), nil
}

func (r Runner) masterHealthy(parent context.Context, alias, path string) bool {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || !security.OwnedPrivate(info) {
		return false
	}
	ctx, cancel := context.WithTimeout(parent, r.EffectiveTimeout())
	defer cancel()
	args := r.configArgs([]string{"-S", path, "-O", "check"})
	cmd := exec.CommandContext(ctx, r.bin(), append(args, alias)...)
	cmd.Env = childEnv()
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	return cmd.Run() == nil
}

func (r Runner) acquireControlLock(ctx context.Context, alias, path string) (*os.File, bool, error) {
	lock, err := security.OpenLockFile(path + ".lock")
	if err != nil {
		return nil, false, err
	}
	for {
		if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err == nil {
			return lock, r.masterHealthy(ctx, alias, path), nil
		} else if !errors.Is(err, syscall.EWOULDBLOCK) {
			_ = lock.Close()
			return nil, false, err
		}
		if r.masterHealthy(ctx, alias, path) {
			_ = lock.Close()
			return nil, true, nil
		}
		select {
		case <-ctx.Done():
			_ = lock.Close()
			return nil, false, ctx.Err()
		case <-time.After(25 * time.Millisecond):
		}
	}
}

func unlockControl(lock *os.File) {
	if lock != nil {
		_ = syscall.Flock(int(lock.Fd()), syscall.LOCK_UN)
		_ = lock.Close()
	}
}
