// Package devtunnel is the low-level Dev Tunnels management client. It creates, reads, and deletes Dev Tunnels and
// validates every host and URI the service returns. Credential is a connected account's bearer supplied by the
// caller rather than carried from the inbound request.
package devtunnel

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	apiVersion = "2023-09-27-preview"

	maxDevTunnelBody      int64 = 64 << 10
	maxTunnelURI                = 2048
	maxTunnelPorts              = 256
	maxPortForwardingURIs       = 16
	devTunnelTimeout            = 15 * time.Second
	MinDurationSeconds          = uint32(60 * 60)
	MaxDurationSeconds          = uint32(30 * 24 * 60 * 60)
)

var (
	devTunnelIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,58}[a-z0-9]$`)
	clusterIDPattern   = regexp.MustCompile(`^[a-z][a-z0-9-]{0,62}$`)
)

type Credential struct {
	Scheme, Token string
}

func (c Credential) authorization() string { return cmp.Or(c.Scheme, "Bearer") + " " + c.Token }

type Record struct {
	ID           string
	ClusterID    string
	ConnectToken string
	HostToken    string
	Ports        []PortRecord
	ExpiresAt    time.Time
}

type PortRecord struct {
	PortNumber         uint16
	Protocol           string
	PortForwardingURIs []string
}

type PortSpec struct {
	PortNumber  uint16
	Description string
}

type CreateRequest struct {
	Credential
	ID              string
	DurationSeconds uint32
	Ports           []PortSpec
}

type GetRequest struct {
	ConnectToken string
	ID           string
	ClusterID    string
}

type DeleteRequest struct {
	Credential
	ID        string
	ClusterID string
}

type client struct {
	baseURL *url.URL
	client  *http.Client
}

type createTunnelBody struct {
	TunnelID         string             `json:"tunnelId"`
	CustomExpiration uint32             `json:"customExpiration"`
	Options          tunnelOptions      `json:"options"`
	Ports            []createTunnelPort `json:"ports,omitempty"`
}

type createTunnelPort struct {
	PortNumber  uint16 `json:"portNumber"`
	Protocol    string `json:"protocol"`
	Description string `json:"description"`
}

type tunnelOptions struct {
	IsInspectionEnabled bool `json:"isInspectionEnabled"`
}

type tunnelResponse struct {
	TunnelID     string               `json:"tunnelId"`
	ClusterID    string               `json:"clusterId"`
	AccessTokens map[string]string    `json:"accessTokens"`
	Ports        []tunnelPortResponse `json:"ports,omitempty"`
	Expiration   time.Time            `json:"expiration"`
}

type tunnelPortResponse struct {
	PortNumber         uint16   `json:"portNumber"`
	Description        string   `json:"description,omitempty"`
	Protocol           string   `json:"protocol,omitempty"`
	PortForwardingURIs []string `json:"portForwardingUris"`
}

func isAPIHost(host string) bool {
	host = strings.ToLower(host)
	const suffix = ".rel.tunnels.api.visualstudio.com"
	clusterID := strings.TrimSuffix(host, suffix)
	return host == "global.rel.tunnels.api.visualstudio.com" || clusterID != host && clusterIDPattern.MatchString(clusterID)
}

func safeRedirect(from, to *url.URL) bool {
	if security.SameOriginRedirect(from, to) {
		return true
	}
	return from != nil && to != nil && from.Scheme == "https" && to.Scheme == "https" && from.User == nil && to.User == nil &&
		from.Host == from.Hostname() && to.Host == to.Hostname() && isAPIHost(from.Hostname()) && isAPIHost(to.Hostname())
}

func ValidatePublicURI(raw string) error {
	if raw == "" || len(raw) > maxTunnelURI {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	host := strings.ToLower(parsed.Hostname())
	const suffix = ".devtunnels.ms"
	if parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Host != parsed.Hostname() || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Path != "" && parsed.Path != "/" || len(host) <= len(suffix) || len(host) > 253 || !strings.HasSuffix(host, suffix) {
		return errors.New("Dev Tunnel public URI is invalid")
	}
	return nil
}

func (r Record) HTTPURI(portNumber uint16) (string, error) {
	index := slices.IndexFunc(r.Ports, func(port PortRecord) bool { return port.PortNumber == portNumber })
	if index < 0 {
		return "", errors.New("Dev Tunnel port is unavailable")
	}
	port := r.Ports[index]
	if port.Protocol != "http" || port.PortNumber == 0 || len(port.PortForwardingURIs) != 1 {
		return "", errors.New("Dev Tunnel port is invalid")
	}
	uri := strings.TrimSuffix(port.PortForwardingURIs[0], "/")
	if err := ValidatePublicURI(uri); err != nil {
		return "", err
	}
	return uri, nil
}

func validateTunnelPorts(values []tunnelPortResponse) ([]PortRecord, error) {
	if len(values) > maxTunnelPorts {
		return nil, errors.New("Dev Tunnel response has too many ports")
	}
	ports := make([]PortRecord, 0, len(values))
	for _, port := range values {
		if port.PortNumber == 0 || !slices.Contains([]string{"auto", "tcp", "udp", "ssh", "rdp", "http", "https"}, port.Protocol) || len(port.Description) > 1024 || strings.ContainsFunc(port.Description, func(r rune) bool { return r < 0x20 || r == 0x7f }) || len(port.PortForwardingURIs) > maxPortForwardingURIs {
			return nil, errors.New("Dev Tunnel response port is invalid")
		}
		if slices.ContainsFunc(ports, func(seen PortRecord) bool { return seen.PortNumber == port.PortNumber }) {
			return nil, errors.New("Dev Tunnel response has duplicate ports")
		}
		for i, candidate := range port.PortForwardingURIs {
			if ValidatePublicURI(candidate) != nil || slices.Contains(port.PortForwardingURIs[:i], candidate) {
				return nil, errors.New("Dev Tunnel response port is invalid")
			}
		}
		ports = append(ports, PortRecord{PortNumber: port.PortNumber, Protocol: port.Protocol, PortForwardingURIs: slices.Clone(port.PortForwardingURIs)})
	}
	return ports, nil
}

func (m *client) tunnelURL(tunnelID, clusterID string, includeTokens, includePorts bool) string {
	endpoint := *m.baseURL
	if clusterID != "" && endpoint.Hostname() == "global.rel.tunnels.api.visualstudio.com" {
		endpoint.Host = clusterID + ".rel.tunnels.api.visualstudio.com"
	}
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + "/tunnels/" + url.PathEscape(tunnelID)
	query := url.Values{}
	query.Add("api-version", apiVersion)
	if includeTokens {
		query.Add("tokenScopes", "host")
		query.Add("tokenScopes", "connect")
	}
	if includePorts {
		query.Add("includePorts", "true")
	}
	endpoint.RawQuery = query.Encode()
	return endpoint.String()
}

func (m *client) do(request *http.Request, token, action string) ([]byte, int, error) {
	body, status, err := security.Do(m.client, request, maxDevTunnelBody)
	if err != nil {
		return nil, 0, security.Redact(action, err, token)
	}
	return body, status, nil
}

func (m *client) doRecord(request *http.Request, token, expectedID string, requireTokens bool) (Record, error) {
	body, status, err := m.do(request, token, "request Dev Tunnel")
	if err != nil {
		return Record{}, err
	}
	if status < 200 || status >= 300 {
		return Record{}, fmt.Errorf("Dev Tunnel request failed: HTTP %d", status)
	}
	var result tunnelResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&result); err != nil {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if err := decoder.Decode(new(struct{})); !errors.Is(err, io.EOF) {
		return Record{}, errors.New("parse Dev Tunnel response")
	}
	if result.TunnelID != expectedID || !clusterIDPattern.MatchString(result.ClusterID) || result.Expiration.IsZero() {
		return Record{}, errors.New("Dev Tunnel response identity is invalid")
	}
	hostToken := result.AccessTokens["host"]
	connectToken := result.AccessTokens["connect"]
	if requireTokens && (!security.ValidCredential(hostToken) || !security.ValidCredential(connectToken)) {
		return Record{}, errors.New("Dev Tunnel response omitted its host or connect token")
	}
	ports, err := validateTunnelPorts(result.Ports)
	if err != nil {
		return Record{}, err
	}
	return Record{
		ID: result.TunnelID, ClusterID: result.ClusterID,
		HostToken: hostToken, ConnectToken: connectToken, Ports: ports,
		ExpiresAt: result.Expiration.UTC(),
	}, nil
}

func (m *client) Create(ctx context.Context, req CreateRequest) (Record, error) {
	if req.DurationSeconds < MinDurationSeconds || req.DurationSeconds > MaxDurationSeconds {
		return Record{}, errors.New("Dev Tunnel create request is invalid")
	}
	ports := make([]createTunnelPort, 0, len(req.Ports))
	for _, spec := range req.Ports {
		ports = append(ports, createTunnelPort{PortNumber: spec.PortNumber, Protocol: "http", Description: spec.Description})
	}
	body, err := json.Marshal(createTunnelBody{
		TunnelID:         req.ID,
		CustomExpiration: req.DurationSeconds,
		Ports:            ports,
	})
	if err != nil {
		return Record{}, errors.New("marshal Dev Tunnel create request")
	}
	request, err := security.NewRequest(ctx, http.MethodPut, m.tunnelURL(req.ID, "", true, false), req.authorization(), bytes.NewReader(body))
	if err != nil {
		return Record{}, err
	}
	request.Header.Set("If-None-Match", "*")
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	return m.doRecord(request, req.Token, req.ID, true)
}

func (m *client) Get(ctx context.Context, req GetRequest) (Record, error) {
	request, err := security.NewRequest(ctx, http.MethodGet, m.tunnelURL(req.ID, req.ClusterID, false, true), "tunnel "+req.ConnectToken, nil)
	if err != nil {
		return Record{}, err
	}
	return m.doRecord(request, req.ConnectToken, req.ID, false)
}

func (m *client) Delete(ctx context.Context, req DeleteRequest) error {
	request, err := security.NewRequest(ctx, http.MethodDelete, m.tunnelURL(req.ID, req.ClusterID, false, false), req.authorization(), nil)
	if err != nil {
		return err
	}
	_, status, err := m.do(request, req.Token, "delete Dev Tunnel")
	if err != nil {
		return err
	}
	if status == http.StatusNotFound || status >= 200 && status < 300 {
		return nil
	}
	return fmt.Errorf("delete Dev Tunnel: HTTP %d", status)
}

func NewClient(baseURL string, httpClient *http.Client) (*client, error) {
	parsed, err := url.Parse(baseURL)
	if err != nil || parsed.Scheme != "https" || parsed.User != nil || parsed.Host == "" || parsed.Host != parsed.Hostname() ||
		parsed.RawQuery != "" || parsed.Fragment != "" || !isAPIHost(parsed.Hostname()) || parsed.Path != "" && parsed.Path != "/" {
		return nil, errors.New("Dev Tunnels base URL must be a recognized HTTPS management endpoint")
	}
	guarded := security.BoundedClient(httpClient, devTunnelTimeout)
	guarded.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) == 0 || len(via) >= 5 || !safeRedirect(via[0].URL, request.URL) {
			return http.ErrUseLastResponse
		}
		//nolint:gosec // safeRedirect restricts credentials to recognized HTTPS management hosts.
		request.Header.Set("Authorization", via[0].Header.Get("Authorization"))
		return nil
	}
	return &client{baseURL: parsed, client: guarded}, nil
}

func ValidID(value string) bool { return devTunnelIDPattern.MatchString(value) }

func ValidClusterID(value string) bool { return clusterIDPattern.MatchString(value) }
