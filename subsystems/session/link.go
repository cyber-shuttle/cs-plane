// Session traffic. A session's Linkspan dials out and holds one WebSocket, authenticated by the per-run link token
// only cs-plane and whoever started the job hold; each stream is a yamux channel on which cs-plane writes the port
// in two bytes and Linkspan answers 1 carried or 0 refused. A Dev Tunnel, through Linkspan's forward route,
// is the fallback. HTTP into a job dials the address <id>.<seq>.session, which pools connections per run. Forward
// and the Jupyter proxy sit outside the bearer boundary under the shared origin policy, opened by the Jupyter token
// compared in constant time; a CORS preflight passes through. A link for the current run makes it READY.
package session

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const (
	linkCapabilityPrefix = "link."
	capabilityPrefix     = "capability."
)

var (
	errNoRoute      = errors.New("the session has no link to cs-plane and no Dev Tunnel")
	errUnauthorized = security.New("unauthorized", "unauthorized", http.StatusUnauthorized)
	linkUpgrader    = websocket.Upgrader{Subprotocols: []string{ssh.ControlWebSocketProtocol}, CheckOrigin: func(*http.Request) bool { return true }}
)

type sessionLink struct {
	seq int
	mux *yamux.Session
}

func (s Service) link(session Session) *yamux.Session {
	if link, ok := s.links.Load(session.ID); ok && link.(*sessionLink).seq == session.Seq {
		return link.(*sessionLink).mux
	}
	return nil
}

func offered(request *http.Request, prefix string) string {
	protocols := websocket.Subprotocols(request)
	if len(protocols) != 2 || protocols[0] != ssh.ControlWebSocketProtocol || !strings.HasPrefix(protocols[1], prefix) {
		return ""
	}
	return strings.TrimPrefix(protocols[1], prefix)
}

func (s Service) linkedSession(request *http.Request) (*Session, bool) {
	session, err := s.loadSession(request.PathValue("id"))
	if err != nil || terminalSession(session.State) {
		return nil, false
	}
	capability, err := getCapability(s.CapabilityDir, session.ID, session.Seq)
	return session, err == nil && subtle.ConstantTimeCompare([]byte(offered(request, linkCapabilityPrefix)), []byte(capability.LinkToken)) == 1
}

func (s Service) authorizedSession(request *http.Request, token string) (*Session, bool) {
	session, err := s.loadSession(request.PathValue("id"))
	if err != nil {
		return nil, false
	}
	capability, err := s.reachable(*session)
	return session, err == nil && (request.Method == http.MethodOptions || subtle.ConstantTimeCompare([]byte(token), []byte(capability.JupyterToken)) == 1)
}

func (s Service) Link(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.linkedSession(request)
	if !ok {
		security.WriteError(writer, errUnauthorized)
		return
	}
	control, err := linkUpgrader.Upgrade(writer, request, nil)
	if err != nil {
		return
	}
	config := yamux.DefaultConfig()
	config.LogOutput = io.Discard
	mux, _ := yamux.Client(streamConn(control), config)
	link := &sessionLink{seq: session.Seq, mux: mux}
	if previous, ok := s.links.Swap(session.ID, link); ok {
		_ = previous.(*sessionLink).mux.Close()
	}
	s.sessionStatus(session.ID, "Linkspan connected to cs-plane")
	_ = s.Store.locked(func(current *state) error {
		linked := current.Sessions[session.ID]
		if linked == nil || linked.Seq != session.Seq || linked.State != "QUEUED" && linked.State != "STARTING" {
			return nil
		}
		linked.State, linked.Error, linked.UpdatedAt = "READY", "", s.utcNow()
		linked.StartedAt = cmp.Or(linked.StartedAt, linked.UpdatedAt)
		s.sessionStatus(session.ID, stateNarration["READY"])
		return s.Store.save(current)
	})
	<-mux.CloseChan()
	s.links.CompareAndDelete(session.ID, link)
}

func (s Service) Forward(writer http.ResponseWriter, request *http.Request) {
	session, ok := s.authorizedSession(request, offered(request, capabilityPrefix))
	if !ok {
		security.WriteError(writer, errUnauthorized)
		return
	}
	port, err := strconv.ParseUint(request.PathValue("port"), 10, 16)
	if err != nil || port == 0 {
		security.WriteError(writer, router.ErrNotFound)
		return
	}
	upstream, err := s.dial(request.Context(), *session, uint16(port))
	if err != nil {
		security.WriteError(writer, security.New("upstream_unavailable", "Linkspan's server could not be reached", http.StatusBadGateway))
		return
	}
	client, err := linkUpgrader.Upgrade(writer, request, nil)
	if err != nil {
		_ = upstream.Close()
		return
	}
	pipe(client, upstream)
}

func (s Service) Jupyter(writer http.ResponseWriter, request *http.Request) {
	token := request.URL.Query().Get("token")
	if scheme, value, found := strings.Cut(request.Header.Get("Authorization"), " "); found && strings.EqualFold(scheme, "token") {
		token = value
	}
	session, ok := s.authorizedSession(request, token)
	if !ok {
		security.WriteError(writer, errUnauthorized)
		return
	}
	port := ports(session.ID, session.Seq).Jupyter
	proxy := &httputil.ReverseProxy{
		Transport: s.transport,
		Rewrite: func(out *httputil.ProxyRequest) {
			out.Out.URL.Scheme, out.Out.URL.Host = "http", sessionHost(*session, port)
			out.Out.Host = "127.0.0.1:" + strconv.Itoa(int(port))
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			security.WriteError(writer, security.New("upstream_unavailable", "the session's Jupyter Server could not be reached", http.StatusBadGateway))
		},
	}
	http.StripPrefix("/api/v1/sessions/"+session.ID+"/jupyter", proxy).ServeHTTP(writer, request)
}

func (s Service) Mount(mux *http.ServeMux) {
	for pattern, handler := range map[string]http.HandlerFunc{
		"GET /api/v1/sessions/{id}/forward/{port}": s.Forward, "/api/v1/sessions/{id}/jupyter/": s.Jupyter, "GET /api/v1/sessions/{id}/link": s.Link,
	} {
		mux.HandleFunc(pattern, func(writer http.ResponseWriter, request *http.Request) {
			if !s.Origins.Admits(request) {
				security.WriteError(writer, security.ErrOriginNotAllowed)
				return
			}
			handler(writer, request)
		})
	}
}

func (s Service) StartSSH(ctx context.Context, principal security.Principal, id, publicKey string) (*SSHAccessResponse, error) {
	session, err := s.Get(principal, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.reachable(*session); err != nil {
		return nil, err
	}
	ref := sha256.Sum256([]byte(publicKey))
	body, _ := json.Marshal(map[string]string{"authorized_key": publicKey, "ref": "ssh-" + hex.EncodeToString(ref[:8])})
	answer, status, err := s.linkspan(ctx, *session, http.MethodPost, "/api/v1/vscode/sessions", bytes.NewReader(body), 4<<10)
	if status == http.StatusBadRequest {
		return nil, security.New("invalid_ssh_key", "Linkspan refused the public key", http.StatusBadRequest)
	}
	var started struct {
		Port int `json:"bind_port"`
	}
	if err != nil || status != http.StatusOK && status != http.StatusCreated || json.Unmarshal(answer, &started) != nil || started.Port < 1 || started.Port > 65535 {
		return nil, security.New("upstream_failure", "Linkspan did not start an SSH server", http.StatusBadGateway)
	}
	return &SSHAccessResponse{Port: started.Port}, nil
}

func (s Service) linkspan(ctx context.Context, session Session, method, path string, body io.Reader, limit int64) ([]byte, int, error) {
	request, err := http.NewRequestWithContext(ctx, method, "http://"+sessionHost(session, ports(session.ID, session.Seq).Control)+path, body)
	if err != nil {
		return nil, 0, err
	}
	request.Header.Set("Content-Type", "application/json")
	return security.Do(&http.Client{Transport: s.transport, Timeout: s.UpstreamTimeout}, request, limit)
}

func dialForward(ctx context.Context, endpoint devtunnelEndpoint, port uint16, timeout time.Duration) (net.Conn, error) {
	dialer := websocket.Dialer{HandshakeTimeout: timeout}
	conn, response, err := dialer.DialContext(ctx, "ws"+strings.TrimPrefix(endpoint.URI, "http")+"/api/v1/forward/"+strconv.Itoa(int(port)),
		http.Header{devtunnelAuthorizationHeader: {"tunnel " + endpoint.ConnectToken}})
	if response != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		return nil, err
	}
	return streamConn(conn), nil
}

func (s Service) dial(ctx context.Context, session Session, port uint16) (net.Conn, error) {
	mux := s.link(session)
	if mux == nil {
		if session.Devtunnel.ID == "" {
			return nil, errNoRoute
		}
		endpoint, err := s.sessionEndpoint(ctx, session, ports(session.ID, session.Seq).Control)
		if err != nil {
			return nil, err
		}
		return dialForward(ctx, endpoint, port, s.UpstreamTimeout)
	}
	stream, err := mux.OpenStream()
	if err != nil {
		return nil, err
	}
	defer context.AfterFunc(ctx, func() { _ = stream.Close() })()
	frame := binary.BigEndian.AppendUint16(nil, port)
	_ = stream.SetDeadline(time.Now().Add(30 * time.Second))
	if _, err = stream.Write(frame); err == nil {
		_, err = io.ReadFull(stream, frame[:1])
	}
	if err == nil && frame[0] != 1 {
		err = errors.New("the job's Linkspan has no server on that port")
	}
	if err != nil {
		_ = stream.Close()
		return nil, err
	}
	_ = stream.SetDeadline(time.Time{})
	return stream, nil
}

func sessionHost(session Session, port uint16) string {
	return session.ID + "." + strconv.Itoa(session.Seq) + ".session:" + strconv.Itoa(int(port))
}

func (s Service) dialHost(ctx context.Context, _, address string) (net.Conn, error) {
	host, rawPort, _ := net.SplitHostPort(address)
	id, _, _ := strings.Cut(host, ".")
	port, err := strconv.ParseUint(rawPort, 10, 16)
	session, loadErr := s.loadSession(id)
	if err != nil || loadErr != nil || sessionHost(*session, uint16(port)) != address {
		return nil, errNoRoute
	}
	return s.dial(ctx, *session, uint16(port))
}

func newSessionTransport(dial func(context.Context, string, string) (net.Conn, error)) *http.Transport {
	return &http.Transport{DialContext: dial, MaxIdleConnsPerHost: 8, IdleConnTimeout: 90 * time.Second, ResponseHeaderTimeout: 5 * time.Minute}
}

func streamConn(ws *websocket.Conn) net.Conn {
	local, remote := net.Pipe()
	go pipe(ws, remote)
	return local
}

func pipe(ws *websocket.Conn, conn net.Conn) {
	defer func() { _ = conn.Close() }()
	go func() {
		defer func() { _ = ws.Close() }()
		buf := make([]byte, 32<<10)
		for {
			n, err := conn.Read(buf)
			if n > 0 && ws.WriteMessage(websocket.BinaryMessage, buf[:n]) != nil || err != nil {
				return
			}
		}
	}()
	for {
		kind, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if kind == websocket.BinaryMessage {
			if _, err := conn.Write(data); err != nil {
				return
			}
		}
	}
}
