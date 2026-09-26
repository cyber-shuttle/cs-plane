// Package main is cs-plane's single binary, cs, one service for many users that binds to loopback behind a TLS proxy.
// run dispatches the CLI; serve validates before listening. newServeComponents composes authentication, SSH,
// session, and Dev Tunnels account owners over one state directory and closes them on failure or shutdown.
package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/cyber-shuttle/cs-plane/subsystems/devtunnels"
	"github.com/cyber-shuttle/cs-plane/subsystems/oauth"
	"github.com/cyber-shuttle/cs-plane/subsystems/session"
	sshapi "github.com/cyber-shuttle/cs-plane/subsystems/ssh"
)

const (
	Version                       = "0.3.0"
	defaultDevTunnelManagementURL = "https://global.rel.tunnels.api.visualstudio.com"
	defaultOIDCIssuer             = "https://cilogon.org"
	sshTimeout                    = 20 * time.Second
	serveReadHeaderTimeout        = 10 * time.Second
	serveShutdownTimeout          = 25 * time.Second
)

func init() { security.UserAgent = "cs-plane/" + Version }

func printUsage() {
	fmt.Fprintln(os.Stderr, `Usage:
  cs [global options] serve --oidc-client-id CLIENT_ID --custos-url URL --public-url URL \
      --allowed-origin ORIGIN [--allowed-origin ORIGIN ...]
  cs help
  cs version

Identity (Custos sign-in):
  --oidc-issuer ISSUER (default https://cilogon.org)
  --oidc-client-id CLIENT_ID (required)
  --custos-url URL (required), e.g. https://custos.cybershuttle.org
  --public-url URL (required), the https URL browsers and session jobs reach cs at
  CS_OIDC_CLIENT_SECRET=SECRET (required, for the sign-in token exchange)

State:
  CS_DATABASE_URL=URL (required), a Postgres URL whose search_path names the schema cs owns

Trusted session configuration:
  --linkspan PATH or CS_LINKSPAN=PATH
  --devtunnel-management-url URL or CS_DEVTUNNEL_MANAGEMENT_URL=URL
  Linkspan defaults to `+session.DefaultLinkspanPath+`, which each SSH host resolves
  against its own home and which creating a session installs when missing.`)
}

func usageError() error {
	printUsage()
	return errors.New("invalid command")
}

func defaultStateDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".cs-plane"
	}
	return filepath.Join(home, ".cybershuttle", "control")
}

type services struct {
	DatabaseURL      string
	PublicURL        string
	Configs          ssh.Configurations
	SessionStore     session.Store
	LinkspanPath     string
	DevtunnelManager session.DevtunnelManager
	CapabilityDir    string
	UpstreamTimeout  time.Duration
	Origins          security.Origins
}

type serveComponents struct {
	handler http.Handler
	closers []func()
}

// close releases components in reverse construction order.
func (components *serveComponents) close() {
	for _, closer := range slices.Backward(components.closers) {
		closer()
	}
}

func newServeComponents(svcs services, authentication *oauth.Service) (*serveComponents, error) {
	database, err := db.Open(svcs.DatabaseURL, svcs.SessionStore.Dir, session.Schema+sshapi.Schema)
	if err != nil {
		return nil, err
	}
	components := &serveComponents{closers: []func(){func() { _ = database.Close() }}}
	fail := func(err error) (*serveComponents, error) {
		components.close()
		return nil, err
	}
	svcs.SessionStore.Database = database
	controlManager := ssh.NewControlManager()
	components.closers = append(components.closers, controlManager.Close)
	sshService, err := sshapi.NewService(database, svcs.Configs, controlManager)
	if err != nil {
		return fail(err)
	}
	devtunnelsService, err := devtunnels.NewService(svcs.SessionStore.Dir, svcs.Configs.Dir, nil)
	if err != nil {
		return fail(err)
	}
	components.closers = append(components.closers, devtunnelsService.Close)
	sessionService := session.NewService(session.Config{
		Runners: svcs.Configs, Store: svcs.SessionStore, LinkspanPath: svcs.LinkspanPath, DevtunnelManager: svcs.DevtunnelManager,
		DevtunnelCredentials: devtunnelsService, CapabilityDir: svcs.CapabilityDir, PublicURL: svcs.PublicURL,
		UpstreamTimeout: svcs.UpstreamTimeout, Origins: svcs.Origins,
	})
	components.closers = append(components.closers, sessionService.Close)
	registryRoutes, err := router.New(
		authentication.Routes(),
		sshService.Routes(),
		sessionService.Routes(),
		devtunnelsService.Routes(),
	)
	if err != nil {
		return fail(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/", authentication.Protect(registryRoutes))
	sessionService.Mount(mux)
	components.handler = mux
	return components, nil
}

func validateLoopbackListen(address string) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("invalid listen address: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return errors.New("cs serve only listens on an explicit loopback address")
	}
	return nil
}

func runServe(ctx context.Context, svcs services, args []string, listen func(string, string) (net.Listener, error)) error {
	flags := flag.NewFlagSet("serve", flag.ContinueOnError)
	listenAddress := flags.String("listen", "127.0.0.1:8045", "loopback listen address")
	oidcIssuer := flags.String("oidc-issuer", defaultOIDCIssuer, "OIDC issuer validated against its own discovery document and JWKS")
	oidcClientID := flags.String("oidc-client-id", "", "OIDC client ID pinned as the ID token audience")
	custosURL := flags.String("custos-url", "", "Custos base URL resolving a validated ID token to a user via GET {custos-url}/me")
	publicURL := flags.String("public-url", "", "HTTPS URL clients and session jobs reach cs-plane at, such as https://api.example.edu")
	var allowedOrigins []string
	flags.Func("allowed-origin", "exact browser origin allowed to call the API (repeatable)", func(value string) error {
		allowedOrigins = append(allowedOrigins, value)
		return nil
	})
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if err := validateLoopbackListen(*listenAddress); err != nil {
		return err
	}
	if strings.TrimSpace(*oidcClientID) == "" {
		return errors.New("--oidc-client-id is required")
	}
	if strings.TrimSpace(*custosURL) == "" {
		return errors.New("--custos-url is required")
	}
	if parsed, err := url.Parse(*publicURL); err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errors.New("--public-url must be an https URL without credentials, query or fragment")
	}
	svcs.PublicURL = strings.TrimSuffix(*publicURL, "/")
	oidcClientSecret := os.Getenv("CS_OIDC_CLIENT_SECRET")
	if strings.TrimSpace(oidcClientSecret) == "" {
		return errors.New("CS_OIDC_CLIENT_SECRET is required")
	}
	svcs.DatabaseURL = os.Getenv("CS_DATABASE_URL")
	if strings.TrimSpace(svcs.DatabaseURL) == "" {
		return errors.New("CS_DATABASE_URL is required")
	}
	origins, err := security.NewOrigins(allowedOrigins)
	if err != nil {
		return err
	}
	svcs.Origins = origins
	authentication, err := oauth.NewService(*custosURL, *oidcIssuer, *oidcClientID, oidcClientSecret, origins, nil)
	if err != nil {
		return err
	}
	if err := security.EnsurePrivateDir(svcs.SessionStore.Dir); err != nil {
		return err
	}
	components, err := newServeComponents(svcs, authentication)
	if err != nil {
		return err
	}
	listener, err := listen("tcp", *listenAddress)
	if err != nil {
		components.close()
		return err
	}
	server := &http.Server{
		Handler:           components.handler,
		ReadHeaderTimeout: serveReadHeaderTimeout,
	}
	serveErrors := make(chan error, 1)
	go func() { serveErrors <- server.Serve(listener) }()

	var result error
	select {
	case <-ctx.Done():
	case serveErr := <-serveErrors:
		if !errors.Is(serveErr, http.ErrServerClosed) {
			result = serveErr
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), serveShutdownTimeout)
	shutdownErr := server.Shutdown(shutdownCtx)
	cancel()
	if shutdownErr != nil {
		shutdownErr = errors.Join(shutdownErr, server.Close())
	}
	components.close()
	return errors.Join(result, shutdownErr)
}

func run(ctx context.Context, args []string) error {
	global := flag.NewFlagSet("cs", flag.ContinueOnError)
	global.SetOutput(os.Stderr)
	global.Usage = printUsage
	linkspan := global.String("linkspan", cmp.Or(os.Getenv("CS_LINKSPAN"), session.DefaultLinkspanPath), "remote Linkspan path, absolute or anchored at $HOME/; a missing one is installed there")
	devTunnelManagementURL := global.String("devtunnel-management-url", cmp.Or(os.Getenv("CS_DEVTUNNEL_MANAGEMENT_URL"), defaultDevTunnelManagementURL), "recognized HTTPS Dev Tunnels management endpoint")
	if err := global.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	args = global.Args()
	if len(args) == 0 {
		return usageError()
	}
	switch args[0] {
	case "serve":
		devtunnelManager, err := devtunnel.NewClient(*devTunnelManagementURL, nil)
		if err != nil {
			return err
		}
		stateDir := defaultStateDir()
		credentialDir, err := filepath.Abs(filepath.Join(stateDir, "credentials"))
		if err != nil {
			return fmt.Errorf("resolve credential directory: %w", err)
		}
		principalDir := filepath.Join(stateDir, "hosts")
		configs := ssh.Configurations{
			Dir:      principalDir,
			Template: ssh.Runner{Timeout: sshTimeout, ControlNamespace: stateDir},
		}
		return runServe(ctx, services{
			Configs: configs, SessionStore: session.Store{Dir: stateDir}, LinkspanPath: *linkspan,
			DevtunnelManager: devtunnelManager, CapabilityDir: credentialDir, UpstreamTimeout: sshTimeout,
		}, args[1:], net.Listen)
	case "help", "-h", "--help":
		printUsage()
		return nil
	case "version":
		if len(args) != 1 {
			return usageError()
		}
		fmt.Println(Version)
		return nil
	default:
		return usageError()
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	err := run(ctx, os.Args[1:])
	cancel()
	if err != nil {
		fmt.Fprintln(os.Stderr, "cs:", err)
		os.Exit(1)
	}
}
