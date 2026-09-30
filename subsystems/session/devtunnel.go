// A session's Dev Tunnel is part of the session state machine: deterministic ports, requested lifetime, remote
// Dev Tunnel validation, compensation, and the private per-run tokens all derive from session identity and
// state. The Dev Tunnels manager supplies vendor operations and DevtunnelCredentials supplies the owner's connected
// account; no other subsystem owns or persists session lifecycle state. A defined session that never ran has `seq` 0
// and no tokens; a run's tokens are the Jupyter and link tokens plus, with the devtunnel transport, the connect token.
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
	maxRunTokensBytes     = 64 << 10
	devtunnelCleanupGrace = 15 * time.Minute
)

type DevtunnelCredentials interface {
	Credential(context.Context, security.Principal) (devtunnel.Credential, error)
}

type sessionPorts struct {
	Control uint16
	Jupyter uint16
}

type runTokens struct {
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

func runTokensPath(dir, sessionID string, seq int) (string, error) {
	if !filepath.IsAbs(dir) || !idPattern.MatchString(sessionID) || seq < 1 {
		return "", errors.New("run token identity is invalid")
	}
	return filepath.Join(dir, sessionID+"-"+strconv.Itoa(seq)+".token"), nil
}

func validRunTokens(tokens runTokens) bool {
	return (tokens.ConnectToken == "" || security.ValidCredential(tokens.ConnectToken)) && validSecret(tokens.JupyterToken) && validSecret(tokens.LinkToken)
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

func putRunTokens(dir, sessionID string, seq int, tokens runTokens) error {
	location, err := runTokensPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if !validRunTokens(tokens) {
		return errors.New("run tokens are invalid")
	}
	encoded, err := json.Marshal(tokens)
	if err != nil {
		return errors.New("encode run tokens")
	}
	if err := security.EnsurePrivateDir(dir); err != nil {
		return err
	}
	return security.ReplaceFile(location, encoded)
}

func getRunTokens(dir, sessionID string, seq int) (runTokens, error) {
	location, err := runTokensPath(dir, sessionID, seq)
	if err != nil {
		return runTokens{}, err
	}
	if err := security.PrivateDir(dir); err != nil {
		return runTokens{}, err
	}
	data, err := security.ReadPrivateFile(location, maxRunTokensBytes)
	if err != nil {
		return runTokens{}, err
	}
	var tokens runTokens
	if err := security.DecodeStrict(bytes.NewReader(data), &tokens); err != nil || !validRunTokens(tokens) {
		return runTokens{}, errors.New("stored run tokens are invalid")
	}
	return tokens, nil
}

func deleteRunTokens(dir, sessionID string, seq int) error {
	if seq == 0 {
		return nil
	}
	location, err := runTokensPath(dir, sessionID, seq)
	if err != nil {
		return err
	}
	if err := security.RemoveFile(location); err != nil {
		return errors.New("delete run tokens")
	}
	return nil
}

func devtunnelDuration(wallMinutes int) uint32 {
	duration := time.Duration(wallMinutes)*time.Minute + devtunnelCleanupGrace
	duration = min(max(duration, time.Duration(devtunnel.MinDurationSeconds)*time.Second), time.Duration(devtunnel.MaxDurationSeconds)*time.Second)
	return uint32(duration / time.Second)
}

func (s Service) sessionEndpoint(ctx context.Context, session Session, number uint16) (devtunnelEndpoint, error) {
	tokens, err := getRunTokens(s.TokenDir, session.ID, session.Seq)
	if err != nil || tokens.ConnectToken == "" {
		return devtunnelEndpoint{}, errors.New("this run has no Dev Tunnel")
	}
	record, err := s.DevtunnelManager.Get(ctx, devtunnel.GetRequest{
		ConnectToken: tokens.ConnectToken, ID: session.Devtunnel.ID, ClusterID: session.Devtunnel.ClusterID,
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
	return devtunnelEndpoint{URI: uri, ConnectToken: tokens.ConnectToken}, nil
}

func (s Service) reachable(session Session) (runTokens, error) {
	tokens, err := getRunTokens(s.TokenDir, session.ID, session.Seq)
	var reason string
	switch {
	case session.State != stateReady:
		reason = "the session is " + strings.ToLower(session.State)
	case s.link(session) == nil && session.Devtunnel.ID == "":
		reason = errNoRoute.Error()
	case err != nil:
		reason = "this run has no stored tokens"
	default:
		return tokens, nil
	}
	return runTokens{}, security.New("session_access_unavailable", "Session access is unavailable: "+reason, http.StatusConflict)
}

func (s Service) Access(principal security.Principal, id string) (*SessionAccessResponse, error) {
	session, err := s.Get(principal, id)
	if err != nil {
		return nil, err
	}
	tokens, err := s.reachable(*session)
	if err != nil {
		return nil, err
	}
	return &SessionAccessResponse{
		SessionID: session.ID, Seq: session.Seq, ExpiresAt: cmp.Or(session.StartedAt, s.utcNow()).Add(time.Duration(session.Resources.WallMinutes) * time.Minute),
		Jupyter: SessionJupyterAccess{URI: s.PublicURL + "/api/v1/sessions/" + session.ID + "/jupyter/", Token: tokens.JupyterToken},
	}, nil
}

func (s Service) issueSession(ctx context.Context, session *Session, principal security.Principal, credential devtunnel.Credential, seq int) (string, runTokens, error) {
	devtunnelID := session.ID + "-" + strconv.Itoa(seq)
	if !idPattern.MatchString(session.ID) || seq < 1 || !devtunnel.ValidID(devtunnelID) {
		return "", runTokens{}, errors.New("session Dev Tunnel identity is invalid")
	}
	tokens := runTokens{JupyterToken: newSecret(), LinkToken: newSecret()}
	var metadata devtunnelMetadata
	hostToken := ""
	if credential.Token != "" {
		requestedAt := s.utcNow()
		record, err := s.DevtunnelManager.Create(ctx, devtunnel.CreateRequest{
			Credential: credential, ID: devtunnelID,
			DurationSeconds: devtunnelDuration(session.Resources.WallMinutes),
			Ports:           []devtunnel.PortSpec{{PortNumber: ports(session.ID, seq).Control, Description: "cybershuttle-control"}},
		})
		if err != nil {
			return "", runTokens{}, errors.Join(security.Redact("create session Dev Tunnel", err, credential.Token), s.releaseDevtunnel(credential, session.ID, seq, devtunnelMetadata{ID: devtunnelID}))
		}
		metadata = devtunnelMetadata{ID: record.ID, ClusterID: record.ClusterID, ExpiresAt: record.ExpiresAt.UTC()}
		if record.ID != devtunnelID || !devtunnel.ValidClusterID(record.ClusterID) || !security.ValidCredential(record.HostToken) || !security.ValidCredential(record.ConnectToken) || !record.ExpiresAt.After(requestedAt) {
			return "", runTokens{}, errors.Join(errors.New("created Dev Tunnel metadata is invalid"), s.releaseDevtunnel(credential, session.ID, seq, metadata))
		}
		tokens.ConnectToken, hostToken = record.ConnectToken, record.HostToken
	}
	if err := putRunTokens(s.TokenDir, session.ID, seq, tokens); err != nil {
		return "", runTokens{}, errors.Join(err, s.releaseDevtunnel(credential, session.ID, seq, metadata))
	}
	session.Seq, session.JobName, session.Owner, session.Devtunnel = seq, jobName(session.ID, seq), principal, metadata
	return hostToken, tokens, nil
}

func (s Service) releaseDevtunnel(credential devtunnel.Credential, sessionID string, seq int, metadata devtunnelMetadata) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.UpstreamTimeout)
	defer cancel()
	var deleteErr error
	if metadata.ID != "" && credential.Token != "" {
		if err := s.DevtunnelManager.Delete(ctx, devtunnel.DeleteRequest{
			Credential: credential, ID: metadata.ID, ClusterID: metadata.ClusterID,
		}); err != nil {
			deleteErr = security.Redact("compensate session Dev Tunnel", err, credential.Token)
		}
	}
	return errors.Join(deleteErr, deleteRunTokens(s.TokenDir, sessionID, seq))
}
