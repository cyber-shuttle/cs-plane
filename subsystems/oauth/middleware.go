// OAuth middleware applies the shared exact-origin policy with CORS headers and establishes caller identity from one
// bearer channel; the browser-only sign-in routes also require an Origin. Preflight and dispatch read methods from the
// same route registry. Browser WebSockets carry the same token through the versioned subprotocol because their API
// cannot set Authorization. Any identity failure answers 401 unauthorized.
package oauth

import (
	"context"
	"net/http"
	"slices"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
	"github.com/gorilla/websocket"
)

const (
	webSocketBearerPrefix               = "bearer."
	maxWebSocketCredentialProtocolBytes = (security.MaxCredentialBytes*8 + 5) / 6
)

type oauthBoundary struct {
	next         *router.Registry
	validate     func(context.Context, string) (security.Principal, error)
	origins      security.Origins
	publicPaths  map[string]struct{}
	browserPaths map[string]struct{}
}

func preflightHeadersAllowed(raw string, allowed ...string) bool {
	for _, header := range strings.Split(raw, ",") {
		header = strings.TrimSpace(header)
		if header != "" && !slices.ContainsFunc(allowed, func(candidate string) bool { return strings.EqualFold(header, candidate) }) {
			return false
		}
	}
	return true
}

func controlWebSocketRoute(request *http.Request) bool {
	if request.Method != http.MethodGet || request.URL.EscapedPath() != request.URL.Path {
		return false
	}
	const prefix = "/api/v1/hosts/"
	if !strings.HasPrefix(request.URL.Path, prefix) {
		return false
	}
	segments := strings.Split(strings.TrimPrefix(request.URL.Path, prefix), "/")
	return len(segments) == 2 && segments[1] == "ssh" && ssh.ValidAlias(segments[0])
}

func controlWebSocketAuthorization(request *http.Request) (string, *http.Request, int) {
	values := request.Header.Values("Sec-WebSocket-Protocol")
	protocols := make([]string, 0, len(values)*2)
	for _, value := range values {
		for _, candidate := range strings.Split(value, ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "" {
				return "", request, http.StatusBadRequest
			}
			protocols = append(protocols, candidate)
		}
	}
	versionCount, bearerCount := 0, 0
	var encoded string
	for _, protocol := range protocols {
		switch {
		case protocol == ssh.ControlWebSocketProtocol:
			versionCount++
		case strings.HasPrefix(protocol, webSocketBearerPrefix):
			bearerCount++
			encoded = strings.TrimPrefix(protocol, webSocketBearerPrefix)
		default:
			return "", request, http.StatusBadRequest
		}
	}
	if versionCount != 1 || bearerCount != 1 || len(protocols) != 2 {
		return "", request, http.StatusBadRequest
	}
	if encoded == "" || len(encoded) > maxWebSocketCredentialProtocolBytes {
		return "", request, http.StatusUnauthorized
	}
	decoded, ok := security.DecodeBase64URL(encoded)
	token := string(decoded)
	if !ok || !security.ValidCredential(token) {
		return "", request, http.StatusUnauthorized
	}
	clean := request.Clone(request.Context())
	clean.Header = request.Header.Clone()
	clean.Header.Del("Authorization")
	clean.Header.Set("Sec-WebSocket-Protocol", ssh.ControlWebSocketProtocol)
	return token, clean, 0
}

func httpOAuthCredentials(header http.Header) (string, bool) {
	if len(header.Values("Authorization")) != 1 {
		return "", false
	}
	fields := strings.Fields(header.Get("Authorization"))
	if len(fields) != 2 || !strings.EqualFold(fields[0], "Bearer") || !security.ValidCredential(fields[1]) {
		return "", false
	}
	return fields[1], true
}

func writeUnauthorized(writer http.ResponseWriter) {
	writer.Header().Set("WWW-Authenticate", "Bearer")
	security.WriteError(writer, security.New("unauthorized", "unauthorized", http.StatusUnauthorized))
}

func (b *oauthBoundary) preflight(writer http.ResponseWriter, request *http.Request, public bool) {
	writer.Header().Add("Vary", "Access-Control-Request-Method")
	writer.Header().Add("Vary", "Access-Control-Request-Headers")
	methods, found := b.next.Methods(request)
	if !found {
		security.WriteError(writer, router.ErrNotFound)
		return
	}
	if !slices.Contains(methods, request.Header.Get("Access-Control-Request-Method")) {
		router.MethodNotAllowed(writer, methods)
		return
	}
	allowed := []string{"authorization", "content-type", "if-none-match"}
	responseHeaders := "Authorization, Content-Type, If-None-Match"
	if public {
		allowed = []string{"content-type"}
		responseHeaders = "Content-Type"
	}
	if !preflightHeadersAllowed(request.Header.Get("Access-Control-Request-Headers"), allowed...) {
		security.WriteError(writer, security.New("preflight_not_allowed", "preflight is not allowed", http.StatusForbidden))
		return
	}
	writer.Header().Set("Access-Control-Allow-Methods", strings.Join(methods, ", "))
	writer.Header().Set("Access-Control-Allow-Headers", responseHeaders)
	writer.Header().Set("Cache-Control", "no-store")
	writer.WriteHeader(http.StatusNoContent)
}

func (b *oauthBoundary) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	_, public := b.publicPaths[request.URL.EscapedPath()]
	_, browser := b.browserPaths[request.URL.EscapedPath()]
	origin := request.Header.Get("Origin")
	if origin != "" {
		if !b.origins.Allowed(origin) {
			security.WriteError(writer, security.ErrOriginNotAllowed)
			return
		}
		writer.Header().Set("Access-Control-Allow-Origin", origin)
		writer.Header().Add("Vary", "Origin")
		writer.Header().Set("Access-Control-Expose-Headers", "ETag, Location")
	} else if browser {
		security.WriteError(writer, security.New("origin_required", "browser origin is required", http.StatusForbidden))
		return
	}
	if request.Method == http.MethodOptions && origin != "" && request.Header.Get("Access-Control-Request-Method") != "" {
		b.preflight(writer, request, public)
		return
	}
	if public {
		b.next.ServeHTTP(writer, request)
		return
	}

	authenticated := request
	var token string
	var ok bool
	if websocket.IsWebSocketUpgrade(request) && controlWebSocketRoute(request) {
		var status int
		token, authenticated, status = controlWebSocketAuthorization(request)
		if status != 0 {
			if status == http.StatusUnauthorized {
				writeUnauthorized(writer)
			} else {
				security.WriteError(writer, security.New("invalid_websocket_auth", "WebSocket authentication is invalid", status))
			}
			return
		}
		ok = true
	} else {
		token, ok = httpOAuthCredentials(request.Header)
	}
	if !ok {
		writeUnauthorized(writer)
		return
	}
	principal, err := b.validate(authenticated.Context(), token)
	if err != nil {
		writeUnauthorized(writer)
		return
	}
	ctx := security.WithPrincipal(authenticated.Context(), principal)
	b.next.ServeHTTP(writer, authenticated.WithContext(ctx))
}

// cilogonTenant scopes every principal: the issuer is pinned, so its subjects share one namespace.
const cilogonTenant = "cilogon"

// validate resolves a bearer both channels have already checked for credential shape to its CILogon principal.
func (s *Service) validate(ctx context.Context, token string) (security.Principal, error) {
	subject, err := s.oidc.Validate(ctx, token)
	return security.Principal{Subject: subject, Tenant: cilogonTenant}, err
}
