// Link tests drive a fake Linkspan that holds a real link against cs-plane's handlers and serves ports from loopback
// servers, so every path a client takes into a job, the Jupyter proxy, the SSH start and forward, and usage, runs
// over the link with no Dev Tunnel; the Dev Tunnel is exercised through Linkspan's forward route.
package session

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/slurm"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/internal/testutil"
	"github.com/gorilla/websocket"
	"github.com/hashicorp/yamux"
)

const testLinkToken = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA"

func planeServer(t *testing.T, service *Service) *httptest.Server {
	t.Helper()
	service.transport = newSessionTransport(service.dialHost)
	mux := http.NewServeMux()
	service.Mount(mux)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return server
}

func wsURL(server *httptest.Server, path string) string {
	return "ws" + strings.TrimPrefix(server.URL, "http") + path
}

func fakeLinkspan(t *testing.T, plane *httptest.Server, service Service, session Session, backends map[int]string) {
	t.Helper()
	capability, err := getCapability(service.CapabilityDir, session.ID, session.Seq)
	testutil.Check(t, err)
	dialer := websocket.Dialer{Subprotocols: []string{ssh.ControlWebSocketProtocol, linkCapabilityPrefix + capability.LinkToken}}
	ws, response, err := dialer.Dial(wsURL(plane, "/api/v1/sessions/"+session.ID+"/link"), nil)
	testutil.Check(t, err)
	_ = response.Body.Close()
	mux, err := yamux.Server(streamConn(ws), nil)
	testutil.Check(t, err)
	t.Cleanup(func() { _ = mux.Close() })
	go func() {
		for {
			stream, err := mux.Accept()
			if err != nil {
				return
			}
			port := make([]byte, 2)
			_, _ = io.ReadFull(stream, port)
			backend, err := net.Dial("tcp", backends[int(binary.BigEndian.Uint16(port))])
			if err != nil {
				_, _ = stream.Write([]byte{0})
				_ = stream.Close()
				continue
			}
			_, _ = stream.Write([]byte{1})
			go func() { _, _ = io.Copy(backend, stream); _ = backend.Close() }()
			go func() { _, _ = io.Copy(stream, backend); _ = stream.Close() }()
		}
	}()
	testutil.Eventually(t, 3*time.Second, "the link to register", func() bool { return service.link(session) != nil })
}

func echoServer(t *testing.T) (string, chan struct{}) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	testutil.Check(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	ended := make(chan struct{}, 8)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(conn, conn); _ = conn.Close(); ended <- struct{}{} }()
		}
	}()
	return listener.Addr().String(), ended
}

func TestTheLinkCarriesJupyterSSHAndUsageOnDemand(t *testing.T) {
	session, service := readyAccessScenario(t)
	numbers := ports(session.ID, session.Seq)
	jupyter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if websocket.IsWebSocketUpgrade(r) {
			conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
			if err == nil {
				kind, data, _ := conn.ReadMessage()
				_ = conn.WriteMessage(kind, data)
				_ = conn.Close()
			}
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"path": r.URL.EscapedPath(), "host": r.Host, "method": r.Method})
	}))
	defer jupyter.Close()
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/usage":
			used := int64(2048)
			_ = json.NewEncoder(w).Encode(UsageSample{MemBytes: &used})
		case "/api/v1/vscode/sessions":
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || body["authorized_key"] != "ssh-ed25519 AAAA" || body["ref"] != "ssh-9de8a23119db6492" {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write([]byte(`{"bind_port":2222}`))
		}
	}))
	defer control.Close()
	plane := planeServer(t, &service)
	sshd, sshdEnded := echoServer(t)
	fakeLinkspan(t, plane, service, session, map[int]string{
		int(numbers.Jupyter): strings.TrimPrefix(jupyter.URL, "http://"), int(numbers.Control): strings.TrimPrefix(control.URL, "http://"), 2222: sshd,
	})

	proxied := plane.URL + "/api/v1/sessions/" + session.ID + "/jupyter"
	get := func(method, path, authorization string) (int, map[string]string) {
		request, err := http.NewRequest(method, proxied+path, nil)
		testutil.Check(t, err)
		if authorization != "" {
			request.Header.Set("Authorization", authorization)
		}
		response, err := http.DefaultClient.Do(request)
		testutil.Check(t, err)
		defer func() { _ = response.Body.Close() }()
		var echoed map[string]string
		_ = json.NewDecoder(response.Body).Decode(&echoed)
		return response.StatusCode, echoed
	}
	if status, echoed := get(http.MethodGet, "/api/contents/a%2Fb.ipynb", "token "+testJupyterToken); status != http.StatusOK || echoed["path"] != "/api/contents/a%2Fb.ipynb" || echoed["host"] != "127.0.0.1:"+strconv.Itoa(int(numbers.Jupyter)) {
		t.Fatalf("proxied request = %d %v", status, echoed)
	}
	if status, _ := get(http.MethodGet, "/api/status", "token wrong"); status != http.StatusUnauthorized {
		t.Fatalf("a wrong Jupyter token answered %d", status)
	}
	if status, echoed := get(http.MethodOptions, "/api/status", ""); status != http.StatusOK || echoed["method"] != http.MethodOptions {
		t.Fatalf("a preflight did not reach the server: %d %v", status, echoed)
	}
	kernel, response, err := websocket.DefaultDialer.Dial(wsURL(plane, "/api/v1/sessions/"+session.ID+"/jupyter/api/kernels/k/channels?token="+testJupyterToken), nil)
	testutil.Check(t, err)
	_ = response.Body.Close()
	testutil.Check(t, kernel.WriteMessage(websocket.TextMessage, []byte("execute")))
	if _, data, err := kernel.ReadMessage(); err != nil || string(data) != "execute" {
		t.Fatalf("kernel socket = %q %v", data, err)
	}
	_ = kernel.Close()

	started, err := service.StartSSH(context.Background(), testPrincipal, session.ID, "ssh-ed25519 AAAA")
	if err != nil || started.Port != 2222 {
		t.Fatalf("ssh start = %#v %v", started, err)
	}
	dialer := websocket.Dialer{Subprotocols: []string{ssh.ControlWebSocketProtocol, capabilityPrefix + testJupyterToken}}
	forward, response, err := dialer.Dial(wsURL(plane, "/api/v1/sessions/"+session.ID+"/forward/2222"), nil)
	testutil.Check(t, err)
	_ = response.Body.Close()
	testutil.Check(t, forward.WriteMessage(websocket.BinaryMessage, []byte("SSH-2.0-client")))
	if _, data, err := forward.ReadMessage(); err != nil || string(data) != "SSH-2.0-client" {
		t.Fatalf("forwarded %q %v", data, err)
	}
	_ = forward.Close()
	select {
	case <-sshdEnded:
	case <-time.After(3 * time.Second):
		t.Fatal("closing the client's forward left the connection to the server open")
	}
	if service.link(session) == nil {
		t.Fatal("a closed stream took the link with it")
	}

	sample, err := service.sampleSession(context.Background(), session)
	if err != nil || sample.MemBytes == nil || *sample.MemBytes != 2048 {
		t.Fatalf("sample = %#v %v", sample, err)
	}
}

func TestTheLinkRefusesAWrongTokenAndAnUnservedPort(t *testing.T) {
	session, service := readyAccessScenario(t)
	plane := planeServer(t, &service)
	refusedWith := func(offer, path string) int {
		dialer := websocket.Dialer{Subprotocols: strings.Split(offer, ", ")}
		_, response, err := dialer.Dial(wsURL(plane, path), nil)
		if err == nil || response == nil {
			t.Fatalf("%s was not refused: %v", path, err)
		}
		_ = response.Body.Close()
		return response.StatusCode
	}
	link, forward := "/api/v1/sessions/"+session.ID+"/link", "/api/v1/sessions/"+session.ID+"/forward/2222"
	for offer, path := range map[string]string{"cybershuttle.v1, link." + testJupyterToken: link, "cybershuttle.v1, capability.wrong": forward, "cybershuttle.v1": forward, "capability." + testJupyterToken: forward} {
		if status := refusedWith(offer, path); status != http.StatusUnauthorized {
			t.Fatalf("%q on %s answered %d", offer, path, status)
		}
	}
	fakeLinkspan(t, plane, service, session, nil)
	if _, err := service.dial(context.Background(), session, 9); err == nil {
		t.Fatalf("a refused port = %v", err)
	}
	capability := "cybershuttle.v1, capability." + testJupyterToken
	for _, port := range []string{"0", "65536", "x", strconv.Itoa(int(ports(session.ID, session.Seq).Control))} {
		if status := refusedWith(capability, "/api/v1/sessions/"+session.ID+"/forward/"+port); status != http.StatusNotFound {
			t.Fatalf("forward to port %s answered %d", port, status)
		}
	}
	foreign := http.Header{"Origin": {"https://evil.example"}}
	_, response, err := (&websocket.Dialer{Subprotocols: strings.Split(capability, ", ")}).Dial(wsURL(plane, forward), foreign)
	if err == nil || response == nil || response.StatusCode != http.StatusForbidden {
		t.Fatalf("a forward from a foreign origin was not refused: %v", err)
	}
	_ = response.Body.Close()
	request, err := http.NewRequest(http.MethodOptions, plane.URL+"/api/v1/sessions/"+session.ID+"/jupyter/api/status", nil)
	testutil.Check(t, err)
	request.Header = foreign
	jupyter, err := http.DefaultClient.Do(request)
	testutil.Check(t, err)
	_ = jupyter.Body.Close()
	if jupyter.StatusCode != http.StatusForbidden {
		t.Fatalf("a Jupyter preflight from a foreign origin answered %d", jupyter.StatusCode)
	}
}

func TestALinkForTheCurrentSeqMakesTheRunReady(t *testing.T) {
	service := testService(t)
	defined, _, err := service.Define(testPrincipal, newTestCreateRequest())
	testutil.Check(t, err)
	attached, err := service.Attach(context.Background(), testPrincipal, defined.ID, nil)
	testutil.Check(t, err)
	session := Session{SessionResponse: attached.Session}
	fakeLinkspan(t, planeServer(t, &service), service, session, nil)
	testutil.Eventually(t, 3*time.Second, "the linked run to become READY", func() bool {
		current, err := service.loadSession(session.ID)
		return err == nil && current.State == "READY" && !current.StartedAt.IsZero()
	})
	if _, err := service.Access(testPrincipal, session.ID); err != nil {
		t.Fatalf("access to a linked READY run = %v", err)
	}
	current, err := service.loadSession(session.ID)
	testutil.Check(t, err)
	service.applyObservation(current, slurm.Observation{State: slurm.Pending}, "")
	if current.State != "READY" {
		t.Fatalf("a scheduler observation demoted a linked run to %s", current.State)
	}
}

func TestADevtunnelOnlyAttachIsReadyAndReachableThroughItsDevTunnel(t *testing.T) {
	service := testService(t)
	defined, _, err := service.Define(testPrincipal, newTestCreateRequest())
	testutil.Check(t, err)
	attached, err := service.Attach(context.Background(), testPrincipal, defined.ID, []string{transportDevtunnel})
	testutil.Check(t, err)
	if attached.Link != nil || attached.Devtunnel == nil || *attached.Devtunnel != (DevtunnelAccess{ID: defined.ID + "-1", Cluster: "use", HostToken: testHostToken}) {
		t.Fatalf("devtunnel attach = %#v %#v", attached.Link, attached.Devtunnel)
	}
	health := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/health" {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer health.Close()
	control := sessionHost(Session{SessionResponse: attached.Session}, ports(defined.ID, 1).Control)
	service.transport = newSessionTransport(func(ctx context.Context, _, address string) (net.Conn, error) {
		if current, err := service.loadSession(defined.ID); err != nil || address != control || service.link(*current) != nil || current.Devtunnel.ID == "" {
			return nil, errNoRoute
		}
		return (&net.Dialer{}).DialContext(ctx, "tcp", health.Listener.Addr().String())
	})
	listed, err := reconciledList(context.Background(), service)
	if err != nil || listed[0].State != "READY" || listed[0].StartedAt.IsZero() {
		t.Fatalf("a devtunnel-only run answering through its Dev Tunnel = %#v %v", listed, err)
	}
	if _, err := service.Access(testPrincipal, defined.ID); err != nil {
		t.Fatalf("access to a devtunnel-only READY run = %v", err)
	}
}

func TestTheDevTunnelCarriesAStreamThroughLinkspansForward(t *testing.T) {
	echo, _ := echoServer(t)
	linkspan := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/forward/2222" || r.Header.Get(devtunnelAuthorizationHeader) != "tunnel "+testConnectToken {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		backend, err := net.Dial("tcp", echo)
		if err != nil {
			return
		}
		conn, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err == nil {
			pipe(conn, backend)
		}
	}))
	defer linkspan.Close()
	conn, err := dialForward(context.Background(), devtunnelEndpoint{URI: linkspan.URL, ConnectToken: testConnectToken}, 2222, time.Second)
	testutil.Check(t, err)
	defer func() { _ = conn.Close() }()
	_, err = conn.Write([]byte("hello"))
	testutil.Check(t, err)
	reply := make([]byte, 5)
	if _, err := io.ReadFull(conn, reply); err != nil || string(reply) != "hello" {
		t.Fatalf("Dev Tunnel stream = %q %v", reply, err)
	}
}
