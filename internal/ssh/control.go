// Serves the interactive SSH authentication WebSocket, whose prompt establishes a control master. It runs
// commands only through Runner and has no view of the session domain. The request that first sees the master
// turn healthy owns it, so shutdown reaps that exact process.
package ssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/gorilla/websocket"
)

const (
	maxAuthFrame       = 64 << 10
	maxAuthInput       = 32 << 10
	maxQueuedAuthInput = 64 << 10

	ptyInitialCols = 100
	ptyInitialRows = 30
	ptyMinCols     = 20
	ptyMaxCols     = 500
	ptyMinRows     = 5
	ptyMaxRows     = 200
)

var (
	authWriteTimeout = 5 * time.Second
	authKeepAlive    = 20 * time.Second
)

type authInputOp struct {
	data   []byte
	resize *ClientFrame
}

type authAttempt struct {
	alias       string
	runner      Runner
	controlPath string
	ctx         context.Context
	cancel      context.CancelFunc

	mu       sync.Mutex
	cmd      *exec.Cmd
	master   *os.File
	conn     *websocket.Conn
	waitDone chan struct{}
	waitErr  error
	lock     *os.File
}

type ownedMaster struct {
	alias    string
	lock     *os.File
	cmd      *exec.Cmd
	master   *os.File
	waitDone chan struct{}
}

type ControlManager struct {
	ctx    context.Context
	cancel context.CancelFunc
	mu     sync.Mutex
	closed bool
	active map[string]*authAttempt
	owned  map[string]*ownedMaster
	wg     sync.WaitGroup
}

func exitFrame(code int, message string) ServerFrame {
	return ServerFrame{Type: "exit", Code: &code, Message: message}
}

func pumpPTY(ctx context.Context, master io.Reader, out chan<- []byte, size int) {
	defer close(out)
	buffer := make([]byte, size)
	for {
		n, err := master.Read(buffer)
		if n > 0 {
			select {
			case out <- append([]byte(nil), buffer[:n]...):
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func writeJSON(conn *websocket.Conn, timeout time.Duration, frame any) error {
	_ = conn.SetWriteDeadline(time.Now().Add(timeout))
	return conn.WriteJSON(frame)
}

func stopAndReap(attempt *authAttempt) {
	attempt.mu.Lock()
	cmd, master, waitDone := attempt.cmd, attempt.master, attempt.waitDone
	attempt.mu.Unlock()
	if master != nil {
		_ = master.Close()
	}
	if cmd == nil || cmd.Process == nil || waitDone == nil {
		return
	}
	killGroup(cmd, waitDone)
}

func closeMaster(master *ownedMaster) {
	killGroup(master.cmd, master.waitDone)
	if master.master != nil {
		_ = master.master.Close()
	}
	unlockControl(master.lock)
}

func cleanupFailedAttempt(attempt *authAttempt) {
	attempt.cancel()
	stopAndReap(attempt)
	if attempt.lock != nil {
		unlockControl(attempt.lock)
		attempt.lock = nil
	}
}

func writeReady(conn *websocket.Conn) {
	_ = writeJSON(conn, authWriteTimeout, ServerFrame{Type: "ready"})
	_ = writeJSON(conn, authWriteTimeout, exitFrame(0, ""))
}

func masterExitFrame(err error) ServerFrame {
	if err == nil {
		return exitFrame(1, "SSH control master exited before becoming ready")
	}
	if exit, ok := errors.AsType[*exec.ExitError](err); ok {
		return exitFrame(exit.ExitCode(), "SSH authentication failed")
	}
	return exitFrame(1, "SSH authentication failed")
}

func readClientFrames(attempt *authAttempt, conn *websocket.Conn, input chan<- authInputOp) <-chan struct{} {
	done := make(chan struct{})
	queue := func(operation authInputOp) bool {
		select {
		case input <- operation:
			return true
		case <-attempt.ctx.Done():
		default:
			attempt.cancel()
		}
		return false
	}
	go func() {
		defer close(done)
		for {
			messageType, data, err := conn.ReadMessage()
			if err != nil {
				return
			}
			switch messageType {
			case websocket.BinaryMessage:
				if len(data) > maxAuthInput {
					attempt.cancel()
					return
				}
				if !queue(authInputOp{data: data}) {
					return
				}
			case websocket.TextMessage:
				var frame ClientFrame
				if err := json.Unmarshal(data, &frame); err != nil {
					return
				}
				if frame.Type == "resize" && !queue(authInputOp{resize: &frame}) {
					return
				}
			default:
				attempt.cancel()
				return
			}
		}
	}()
	return done
}

func writeClientInput(attempt *authAttempt, master *os.File, input <-chan authInputOp) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case operation := <-input:
				switch {
				case operation.resize == nil:
					if _, err := master.Write(operation.data); err != nil {
						return
					}
				case operation.resize.Cols >= ptyMinCols && operation.resize.Cols <= ptyMaxCols &&
					operation.resize.Rows >= ptyMinRows && operation.resize.Rows <= ptyMaxRows:
					_ = pty.Setsize(master, &pty.Winsize{Cols: operation.resize.Cols, Rows: operation.resize.Rows})
				}
			case <-attempt.ctx.Done():
				return
			}
		}
	}()
	return done
}

func NewControlManager() *ControlManager {
	ctx, cancel := context.WithCancel(context.Background())
	return &ControlManager{ctx: ctx, cancel: cancel, active: map[string]*authAttempt{}, owned: map[string]*ownedMaster{}}
}

func (m *ControlManager) admit(alias string, runner Runner) (*authAttempt, error) {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return nil, security.New("service_stopping", "SSH authentication service is stopping", http.StatusServiceUnavailable)
	}
	for _, active := range m.active {
		if active.alias == alias && active.runner.ConfigPath == runner.ConfigPath {
			m.mu.Unlock()
			return nil, security.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, http.StatusConflict)
		}
	}
	m.mu.Unlock()

	path, err := runner.resolvedControlPath(m.ctx, alias)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, security.New("service_stopping", "SSH authentication service is stopping", http.StatusServiceUnavailable)
	}
	for _, active := range m.active {
		if active.controlPath == path {
			return nil, security.New("ssh_authentication_in_progress", "SSH authentication is already in progress for "+alias, http.StatusConflict)
		}
	}
	ctx, cancel := context.WithCancel(m.ctx)
	attempt := &authAttempt{alias: alias, runner: runner, controlPath: path, ctx: ctx, cancel: cancel}
	m.active[path] = attempt
	m.wg.Add(1)
	return attempt, nil
}

func (m *ControlManager) finish(attempt *authAttempt, own bool) bool {
	m.mu.Lock()
	attempt.mu.Lock()
	if own && (m.closed || attempt.cmd == nil || attempt.waitDone == nil) {
		attempt.mu.Unlock()
		m.mu.Unlock()
		return false
	}
	if m.active[attempt.controlPath] == attempt {
		delete(m.active, attempt.controlPath)
	}
	if own {
		m.owned[attempt.controlPath] = &ownedMaster{
			alias: attempt.alias, lock: attempt.lock,
			cmd: attempt.cmd, master: attempt.master, waitDone: attempt.waitDone,
		}
		attempt.lock = nil
	}
	attempt.mu.Unlock()
	m.mu.Unlock()
	unlockControl(attempt.lock)
	attempt.lock = nil
	m.wg.Done()
	return own
}

func (m *ControlManager) reclaimExpiredOwned(ctx context.Context, runner Runner, alias, path string) (bool, error) {
	m.mu.Lock()
	master := m.owned[path]
	if master == nil {
		m.mu.Unlock()
		return false, nil
	}
	if master.alias != alias {
		m.mu.Unlock()
		return false, errors.New("SSH control master identity mismatch")
	}
	select {
	case <-master.waitDone:
		delete(m.owned, path)
		m.mu.Unlock()
		if master.master != nil {
			_ = master.master.Close()
		}
		unlockControl(master.lock)
		return false, nil
	default:
	}
	if runner.masterHealthy(ctx, alias, path) {
		m.mu.Unlock()
		return true, nil
	}
	delete(m.owned, path)
	m.mu.Unlock()
	closeMaster(master)
	return false, nil
}

func (m *ControlManager) command(attempt *authAttempt) (*exec.Cmd, bool, error) {
	if healthy, err := m.reclaimExpiredOwned(attempt.ctx, attempt.runner, attempt.alias, attempt.controlPath); err != nil || healthy {
		return nil, healthy, err
	}
	lock, healthy, err := attempt.runner.acquireControlLock(attempt.ctx, attempt.alias, attempt.controlPath)
	if err != nil {
		return nil, false, err
	}
	attempt.lock = lock
	if healthy {
		return nil, true, nil
	}
	cmd, err := attempt.runner.interactiveCommand(attempt.ctx, attempt.alias, attempt.controlPath)
	return cmd, false, err
}

func (m *ControlManager) ServeWebSocket(writer http.ResponseWriter, request *http.Request, alias string, runner Runner) {
	attempt, err := m.admit(alias, runner)
	if err != nil {
		security.WriteError(writer, err)
		return
	}
	finished := false
	defer func() {
		if !finished {
			cleanupFailedAttempt(attempt)
			m.finish(attempt, false)
		}
	}()

	conn, err := security.Upgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	attempt.mu.Lock()
	attempt.conn = conn
	attempt.mu.Unlock()
	defer func() { _ = conn.Close() }()
	conn.SetReadLimit(maxAuthFrame)

	cmd, alreadyReady, err := m.command(attempt)
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to prepare SSH"))
		return
	}
	if alreadyReady {
		writeReady(conn)
		finished = true
		m.finish(attempt, false)
		attempt.cancel()
		return
	}
	master, err := pty.StartWithSize(cmd, &pty.Winsize{Cols: ptyInitialCols, Rows: ptyInitialRows})
	if err != nil {
		_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "failed to start SSH"))
		return
	}
	waitDone := make(chan struct{})
	go func() {
		err := cmd.Wait()
		attempt.mu.Lock()
		attempt.waitErr = err
		attempt.mu.Unlock()
		close(waitDone)
	}()
	attempt.mu.Lock()
	attempt.cmd, attempt.master, attempt.waitDone = cmd, master, waitDone
	attempt.mu.Unlock()

	output := make(chan []byte, 8)
	go pumpPTY(attempt.ctx, master, output, 16<<10)
	input := make(chan authInputOp, maxQueuedAuthInput/maxAuthInput)
	clientGone := readClientFrames(attempt, conn, input)
	inputWriterDone := writeClientInput(attempt, master, input)

	readiness := time.NewTicker(50 * time.Millisecond)
	defer readiness.Stop()
	keepAlive := time.NewTicker(authKeepAlive)
	defer keepAlive.Stop()
	for {
		select {
		case <-keepAlive.C:
			if err := conn.WriteControl(websocket.PingMessage, nil, time.Now().Add(authWriteTimeout)); err != nil {
				return
			}
		case data, ok := <-output:
			if !ok {
				output = nil
				continue
			}
			_ = conn.SetWriteDeadline(time.Now().Add(authWriteTimeout))
			if err := conn.WriteMessage(websocket.BinaryMessage, data); err != nil {
				return
			}
		case <-readiness.C:
			if !attempt.runner.masterHealthy(attempt.ctx, alias, attempt.controlPath) {
				continue
			}
			finished = true
			if !m.finish(attempt, true) {
				cleanupFailedAttempt(attempt)
				m.finish(attempt, false)
				_ = writeJSON(conn, authWriteTimeout, exitFrame(1, "SSH authentication service is stopping"))
				return
			}
			writeReady(conn)
			attempt.cancel()
			if output != nil {
				go func() {
					for range output {
					}
				}()
			}
			return
		case <-waitDone:
			_ = master.Close()
			attempt.mu.Lock()
			err := attempt.waitErr
			attempt.mu.Unlock()
			_ = writeJSON(conn, authWriteTimeout, masterExitFrame(err))
			return
		case <-clientGone:
			return
		case <-inputWriterDone:
			return
		case <-attempt.ctx.Done():
			return
		}
	}
}

func (m *ControlManager) Close() {
	m.cancel()
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	attempts := make([]*authAttempt, 0, len(m.active))
	for _, attempt := range m.active {
		attempt.cancel()
		attempts = append(attempts, attempt)
	}
	m.mu.Unlock()
	for _, attempt := range attempts {
		attempt.mu.Lock()
		conn, master := attempt.conn, attempt.master
		attempt.mu.Unlock()
		if conn != nil {
			_ = conn.Close()
		}
		if master != nil {
			_ = master.Close()
		}
	}
	m.wg.Wait()
	m.mu.Lock()
	masters := make([]*ownedMaster, 0, len(m.owned))
	for _, master := range m.owned {
		masters = append(masters, master)
	}
	m.owned = map[string]*ownedMaster{}
	m.mu.Unlock()
	for _, master := range masters {
		closeMaster(master)
	}
}
