// Package ssh owns principal-scoped SSH hosts, keys, rendered configuration, live probes, and authentication. The
// database stores SSH host and key metadata while private keys and generated configs remain protected files. SSH
// host and key mutations coordinate database, config, and file effects as compensated flows; OpenSSH execution and
// control-master mechanics remain in internal/ssh. Health only opens a TCP connection to the first hop, and only to
// public addresses, so it cannot probe cs-plane's own network.
package ssh

import (
	"context"
	"errors"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	internalssh "github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/gorilla/websocket"
)

type Service struct {
	Store   Store
	Configs internalssh.Configurations
	Control *internalssh.ControlManager
}

func NewService(database *db.DB, configs internalssh.Configurations, control *internalssh.ControlManager) (*Service, error) {
	if database == nil || configs.Dir == "" || control == nil {
		return nil, errors.New("SSH service dependencies are required")
	}
	if err := security.EnsurePrivateDir(configs.Dir); err != nil {
		return nil, err
	}
	service := &Service{
		Store:   Store{Database: database, PrincipalDir: configs.Dir},
		Configs: configs,
		Control: control,
	}
	if err := service.Store.recoverSSHChanges(); err != nil {
		return nil, err
	}
	if err := service.Store.reconcileConfigs(); err != nil {
		return nil, err
	}
	return service, nil
}

func hostWithKey(alias, command, key string) (HostEntry, error) {
	host, err := parseCommand(alias, command)
	if err != nil {
		return host, err
	}
	host.Key, host.Managed = key, true
	return host, nil
}

func (s Service) addHost(principal security.Principal, request AddHostRequest) (HostEntry, error) {
	host, err := hostWithKey(strings.TrimSpace(request.Alias), request.Command, request.Key)
	if err != nil {
		return HostEntry{}, err
	}
	return host, s.Store.addHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), host)
}

func (s Service) updateHost(principal security.Principal, alias string, request UpdateHostRequest) (HostEntry, error) {
	host, err := hostWithKey(alias, request.Command, request.Key)
	if err != nil {
		return HostEntry{}, err
	}
	return host, s.Store.updateHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), host)
}

func (s Service) deleteHost(principal security.Principal, alias string) error {
	if !internalssh.ValidAlias(alias) {
		return internalssh.ErrInvalidAlias
	}
	return s.Store.deleteHost(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), alias)
}

var dialHealth = (&net.Dialer{Control: func(_, address string, _ syscall.RawConn) error {
	host, _, _ := net.SplitHostPort(address)
	if ip := net.ParseIP(host); ip == nil || ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
		return errors.New("not a public address")
	}
	return nil
}}).DialContext

func (s Service) hostHealth(ctx context.Context, principal security.Principal, alias string) (HostHealth, error) {
	runner := s.Configs.Runner(principal)
	ctx, cancel := context.WithTimeout(ctx, runner.EffectiveTimeout())
	defer cancel()
	address, err := runner.FirstHop(ctx, alias)
	if err != nil {
		return HostHealth{}, err
	}
	conn, err := dialHealth(ctx, "tcp", address)
	if err != nil {
		return HostHealth{Alias: alias, Message: "Nothing accepted a connection at " + address + "."}, nil
	}
	_ = conn.Close()
	return HostHealth{Alias: alias, OK: true, Message: "Listening at " + address + "."}, nil
}

// SubprotocolAuthRoute reports the SSH authentication WebSocket, whose browser client offers its bearer as a subprotocol.
func SubprotocolAuthRoute(request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL.EscapedPath() != request.URL.Path {
		return false
	}
	const prefix = "/api/v1/hosts/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	return len(segments) == 2 && segments[1] == "ssh" && internalssh.ValidAlias(segments[0])
}

func (s Service) sshRoutes() router.Routes {
	return router.Routes{
		"/api/v1/hosts": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (HostList, error) {
				hosts, err := s.Store.loadHosts(security.PrincipalDirName(principal))
				return HostList{Hosts: hosts}, err
			}),
			http.MethodPost: security.CreatedAsPrincipal(func(host HostEntry) string { return "/api/v1/hosts/" + url.PathEscape(host.Alias) }, func(principal security.Principal, request *http.Request) (HostEntry, error) {
				var body AddHostRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return HostEntry{}, err
				}
				return s.addHost(principal, body)
			}),
		},
		"/api/v1/hosts/{alias}": {
			http.MethodPut: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (HostEntry, error) {
				var body UpdateHostRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return HostEntry{}, err
				}
				return s.updateHost(principal, request.PathValue("alias"), body)
			}),
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, request *http.Request) error {
				return s.deleteHost(principal, request.PathValue("alias"))
			}),
		},
		"/api/v1/hosts/{alias}/health": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, request *http.Request) (HostHealth, error) {
				return s.hostHealth(request.Context(), principal, request.PathValue("alias"))
			}),
		},
		"/api/v1/hosts/{alias}/ssh": {
			http.MethodGet: func(writer http.ResponseWriter, request *http.Request) {
				principal, err := security.PrincipalFromContext(request.Context())
				if err != nil {
					security.WriteError(writer, err)
					return
				}
				if !websocket.IsWebSocketUpgrade(request) {
					security.WriteError(writer, security.New("upgrade_required", "SSH authentication requires a WebSocket", http.StatusUpgradeRequired))
					return
				}
				s.Control.ServeWebSocket(writer, request, request.PathValue("alias"), s.Configs.Runner(principal))
			},
		},
	}
}

func (s Service) Routes() router.Routes {
	routes := s.sshRoutes()
	maps.Copy(routes, s.keyRoutes())
	return routes
}
