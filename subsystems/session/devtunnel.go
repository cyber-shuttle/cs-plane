// A session's Dev Tunnel is part of the session state machine: deterministic ports, requested lifetime, remote
// Dev Tunnel validation, compensation, and the private per-run capability all derive from session identity and
// state. The Dev Tunnels manager supplies vendor operations and DevtunnelCredentials supplies the owner's connected
// account; no other subsystem owns or persists session lifecycle state. A defined session that never ran has `seq` 0
// and no capability. The capability, cs-plane's stored per-run credentials, holds the Jupyter and link tokens and,
// only with the devtunnel transport, the connect token.
package session

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/cs-plane/internal/devtunnel"
	"github.com/cyber-shuttle/cs-plane/internal/security"
)

const (
	maxSessionCapability  = 64 << 10
	devtunnelCleanupGrace = 15 * time.Minute
)

type DevtunnelCredentials interface {
	Credential(context.Context, security.Principal) (devtunnel.Credential, error)
}

type sessionPorts struct {
	Control uint16
	Jupyter uint16
}

type sessionCapability struct {
	ConnectToken string `json:"connectToken,omitempty"`
	JupyterToken string `json:"jupyterToken"`
	LinkToken    string `json:"linkToken"`
}

type devtunnelEndpoint struct {
	URI          string
	ConnectToken string
}

func ports(sessionID string, seq int) sessionPorts {
	sum := sha256.Sum256([]byte(sessionID + "/" + strconv.Itoa(seq)))
	base := 20000 + int(binary.BigEndian.Uint16(sum[:2]))%20000
	return sessionPorts{Control: uint16(base), Jupyter: uint16(base + 1)}
}

func capabilityPath(dir, sessionID string, seq int) (string, error) {
	if !filepath.IsAbs(dir) || !idPattern.MatchString(sessionID) || seq < 1 {
		return "", errors.New("capability store identity is invalid")
	}
	return filepath.Join(dir, sessionID+"-"+strconv.Itoa(seq)+".token"), nil
}

func validCapability(capability sessionCapability) bool {
	return (capability.ConnectToken == "" || security.ValidCredential(capability.ConnectToken)) && validSecret(capability.JupyterToken) && validSecret(capability.LinkToken)
}

func validSecret(value string) bool {
	decoded, ok := security.DecodeBase64URL(value)
	return ok && len(decoded) == 32
}

func newSecret() string {
	secret := make([]byte, 32)
	_, _ = rand.Read(secret)
	return base64.RawURLEncoding.EncodeToString(secret)
}

func putCapability(dir, sessionID string, seq int, capability sessionCapability) error {
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if !validCapability(capability) {
		return errors.New("session capability is invalid")
	}
	encoded, err := json.Marshal(capability)
	if err != nil {
		return errors.New("encode session capability")
	}
	if err := security.EnsurePrivateDir(dir); err != nil {
		return err
	}
	return security.ReplaceFile(location, encoded)
}

func getCapability(dir, sessionID string, seq int) (sessionCapability, error) {
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return sessionCapability{}, err
	}
	if err := security.PrivateDir(dir); err != nil {
		return sessionCapability{}, err
	}
	data, err := security.ReadPrivateFile(location, maxSessionCapability)
	if err != nil {
		return sessionCapability{}, err
	}
	var capability sessionCapability
	if err := security.DecodeStrict(bytes.NewReader(data), &capability); err != nil || !validCapability(capability) {
		return sessionCapability{}, errors.New("stored session capability is invalid")
	}
	return capability, nil
}

func deleteCapability(dir, sessionID string, seq int) error {
	if seq == 0 {
		return nil
	}
	location, err := capabilityPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if err := security.RemoveFile(location); err != nil {
		return errors.New("delete session capability")
	}
	return nil
}

func devtunnelDuration(wallMinutes int) uint32 {
	duration := time.Duration(wallMinutes)*time.Minute + devtunnelCleanupGrace
	duration = min(max(duration, time.Duration(devtunnel.MinDurationSeconds)*time.Second), time.Duration(devtunnel.MaxDurationSeconds)*time.Second)
	return uint32(duration / time.Second)
}

func (s Service) sessionEndpoint(ctx context.Context, session Session, number uint16) (devtunnelEndpoint, error) {
	capability, err := getCapability(s.CapabilityDir, session.ID, session.Seq)
	if err != nil || capability.ConnectToken == "" {
		return devtunnelEndpoint{}, errors.New("this run has no Dev Tunnel")
	}
	record, err := s.DevtunnelManager.Get(ctx, devtunnel.GetRequest{
		ConnectToken: capability.ConnectToken, TunnelID: session.Devtunnel.ID, ClusterID: session.Devtunnel.ClusterID,
	})
	if err != nil {
		return devtunnelEndpoint{}, errors.New("the session's Dev Tunnel could not be reached")
	}
	if !record.ExpiresAt.After(s.utcNow()) {
		return devtunnelEndpoint{}, errors.New("the session's Dev Tunnel has expired")
	}
	if record.ID != session.Devtunnel.ID || record.ClusterID != session.Devtunnel.ClusterID {
		return devtunnelEndpoint{}, errors.New("the Dev Tunnel identity does not match the session")
	}
	uri, err := record.HTTPURI(number)
	if err != nil {
		return devtunnelEndpoint{}, errors.New("Dev Tunnel control port is invalid")
	}
	return devtunnelEndpoint{URI: uri, ConnectToken: capability.ConnectToken}, nil
}

func (s Service) reachable(session Session) (sessionCapability, error) {
	capability, err := getCapability(s.CapabilityDir, session.ID, session.Seq)
	var reason string
	switch {
	case session.State != "READY":
		reason = "the session is " + strings.ToLower(session.State)
	case s.link(session) == nil && session.Devtunnel.ID == "":
		reason = errNoRoute.Error()
	case err != nil:
		reason = "this run has no stored tokens"
	default:
		return capability, nil
	}
	return sessionCapability{}, security.New("session_access_unavailable", "Session access is unavailable: "+reason, http.StatusConflict)
}

func (s Service) Access(principal security.Principal, id string) (*SessionAccessResponse, error) {
	session, err := s.Get(principal, id)
	if err != nil {
		return nil, err
	}
	capability, err := s.reachable(*session)
	if err != nil {
		return nil, err
	}
	return &SessionAccessResponse{
		SessionID: session.ID, Seq: session.Seq, ExpiresAt: cmp.Or(session.StartedAt, s.utcNow()).Add(time.Duration(session.Resources.WallMinutes) * time.Minute),
		Jupyter: SessionJupyterAccess{URI: s.PublicURL + "/api/v1/sessions/" + session.ID + "/jupyter/", Token: capability.JupyterToken},
	}, nil
}

func (s Service) issueSession(ctx context.Context, session *Session, principal security.Principal, credential devtunnel.Credential, seq int) (string, sessionCapability, error) {
	devtunnelID := session.ID + "-" + strconv.Itoa(seq)
	if !idPattern.MatchString(session.ID) || seq < 1 || !devtunnel.ValidID(devtunnelID) {
		return "", sessionCapability{}, errors.New("session Dev Tunnel identity is invalid")
	}
	capability := sessionCapability{JupyterToken: newSecret(), LinkToken: newSecret()}
	var metadata devtunnelMetadata
	hostToken := ""
	if credential.Token != "" {
		requestedAt := s.utcNow()
		record, err := s.DevtunnelManager.Create(ctx, devtunnel.CreateRequest{
			Scheme: credential.Scheme, OAuthToken: credential.Token, TunnelID: devtunnelID,
			DurationSeconds: devtunnelDuration(session.Resources.WallMinutes),
			Ports:           []devtunnel.PortSpec{{PortNumber: ports(session.ID, seq).Control, Description: "cybershuttle-control"}},
		})
		if err != nil {
			return "", sessionCapability{}, errors.Join(security.Redact("create session Dev Tunnel", err, credential.Token), s.releaseDevtunnel(credential, session.ID, seq, devtunnelMetadata{ID: devtunnelID}))
		}
		metadata = devtunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
		if record.ID != devtunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !security.ValidCredential(record.HostToken) || !security.ValidCredential(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
			return "", sessionCapability{}, errors.Join(errors.New("created Dev Tunnel metadata is invalid"), s.releaseDevtunnel(credential, session.ID, seq, metadata))
		}
		capability.ConnectToken, hostToken = record.ConnectToken, record.HostToken
	}
	if err := putCapability(s.CapabilityDir, session.ID, seq, capability); err != nil {
		return "", sessionCapability{}, errors.Join(err, s.releaseDevtunnel(credential, session.ID, seq, metadata))
	}
	session.Seq, session.JobName, session.Owner, session.Devtunnel = seq, jobName(session.ID, seq), principal, metadata
	return hostToken, capability, nil
}

func (s Service) releaseDevtunnel(credential devtunnel.Credential, sessionID string, seq int, metadata devtunnelMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.UpstreamTimeout)
	defer cancel()
	var deleteErr error
	if metadata.ID != "" && credential.Token != "" {
		if err := s.DevtunnelManager.Delete(ctx, devtunnel.DeleteRequest{
			Scheme: credential.Scheme, OAuthToken: credential.Token, TunnelID: metadata.ID, ClusterID: metadata.ClusterID,
		}); err != nil {
			deleteErr = security.Redact("compensate session Dev Tunnel", err, credential.Token)
		}
	}
	return errors.Join(deleteErr, deleteCapability(s.CapabilityDir, sessionID, seq))
}
