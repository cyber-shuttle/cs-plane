// SSH key handling validates names and private-key material before writing metadata and protected bytes. A staged
// filename binds an interrupted write to committed metadata so startup can promote or discard it without reading key
// contents. API responses expose only public metadata; deletion also clears SSH host references and rerenders config.
package ssh

import (
	"bytes"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/db"
	"github.com/cyber-shuttle/cs-plane/internal/router"
	"github.com/cyber-shuttle/cs-plane/internal/security"
	internalssh "github.com/cyber-shuttle/cs-plane/internal/ssh"
)

const (
	deletePrefix = ".delete-"
	putPrefix    = ".put-"
)

var (
	errInvalidSSHKeyName = security.New("invalid_ssh_key_id", "invalid SSH key id", http.StatusBadRequest)
	errSSHKeyNotFound    = security.New("ssh_key_not_found", "SSH key is not stored", http.StatusNotFound)
	errSSHKeyExists      = security.New("ssh_key_exists", "SSH key is already stored", http.StatusConflict)
)

func validSSHKeyName(value string) bool {
	return security.SafeName(value, 64) && !strings.HasSuffix(value, ".pub")
}

func (s Store) keyPath(principal, name string) string {
	return filepath.Join(s.PrincipalDir, principal, "keys", name)
}

func keyMetadata(queries *Queries, principal, name string) (SSHKey, bool, error) {
	row, err := queries.GetKey(background, GetKeyParams{Principal: principal, Name: name})
	if errors.Is(err, sql.ErrNoRows) {
		return SSHKey{}, false, nil
	}
	return SSHKey(row), err == nil, err
}

func requireKey(queries *Queries, principal, name string) error {
	_, found, err := keyMetadata(queries, principal, name)
	if err == nil && !found {
		err = errSSHKeyNotFound
	}
	return err
}

func (s Store) listSSHKeys(principal string) ([]SSHKey, error) {
	rows, err := New(s.Database.Reader()).ListKeys(background, principal)
	keys := make([]SSHKey, 0, len(rows))
	for _, row := range rows {
		keys = append(keys, SSHKey(row))
	}
	return keys, err
}

func sshPutStage(path string, row keyRow) string {
	digest := sha256.Sum256([]byte(strings.Join([]string{row.Principal, row.Name, row.Type, row.Fingerprint}, "\x00")))
	return filepath.Join(filepath.Dir(path), putPrefix+filepath.Base(path)+"-"+hex.EncodeToString(digest[:]))
}

func stagedSSHName(filename string) (string, bool) {
	rest := strings.TrimPrefix(filename, putPrefix)
	if len(rest) <= sha256.Size*2+1 || rest[len(rest)-sha256.Size*2-1] != '-' {
		return "", false
	}
	name, encoded := rest[:len(rest)-sha256.Size*2-1], rest[len(rest)-sha256.Size*2:]
	digest, err := hex.DecodeString(encoded)
	return name, err == nil && len(digest) == sha256.Size && validSSHKeyName(name)
}

func (s Store) recoverSSHChanges() error {
	principals, err := os.ReadDir(s.PrincipalDir)
	if err != nil {
		return err
	}
	return s.locked(func(queries *Queries) error {
		for _, principal := range principals {
			if !principal.Type().IsDir() || !security.SafeName(principal.Name(), 128) {
				continue
			}
			principalDir := filepath.Join(s.PrincipalDir, principal.Name())
			if err := security.PrivateDir(principalDir); err != nil {
				return err
			}
			keyDir := filepath.Join(principalDir, "keys")
			if err := security.PrivateDir(keyDir); errors.Is(err, os.ErrNotExist) {
				continue
			} else if err != nil {
				return err
			}
			entries, err := os.ReadDir(keyDir)
			if err != nil {
				return err
			}
			changed := false
			for _, entry := range entries {
				if !entry.Type().IsRegular() {
					continue
				}
				name := strings.TrimPrefix(entry.Name(), deletePrefix)
				deleting := strings.HasPrefix(entry.Name(), deletePrefix) && validSSHKeyName(name)
				if staged, ok := stagedSSHName(entry.Name()); ok {
					name = staged
				} else if !deleting {
					continue
				}
				metadata, exists, err := keyMetadata(queries, principal.Name(), name)
				if err != nil {
					return err
				}
				pending, target := filepath.Join(keyDir, entry.Name()), filepath.Join(keyDir, name)
				switch {
				case deleting && exists:
					if _, err := os.Lstat(target); err == nil {
						return errors.New("SSH key and deletion tombstone both exist")
					} else if !errors.Is(err, os.ErrNotExist) {
						return err
					}
					err = os.Rename(pending, target)
				case deleting:
					err = os.Remove(pending)
				default:
					row := keyRow{Principal: principal.Name(), Name: metadata.Name, Type: metadata.Type, Fingerprint: metadata.Fingerprint}
					committed := exists && filepath.Base(sshPutStage(target, row)) == entry.Name()
					if _, err := security.ReadPrivateFile(pending, 1<<20); err != nil {
						return err
					}
					if committed {
						if _, err := security.ReadPrivateFile(target, 1<<20); err != nil && !errors.Is(err, os.ErrNotExist) {
							return err
						}
						err = os.Rename(pending, target)
					} else {
						err = os.Remove(pending)
					}
				}
				if err != nil {
					return err
				}
				changed = true
			}
			if changed {
				if err := security.SyncDir(keyDir); err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func (s Store) putSSHKey(principal string, key SSHKey, private []byte) error {
	return s.locked(func(queries *Queries) error {
		if _, exists, err := keyMetadata(queries, principal, key.Name); err != nil {
			return err
		} else if exists {
			return errSSHKeyExists
		}
		path := s.keyPath(principal, key.Name)
		if _, err := os.Lstat(path); err == nil {
			return errSSHKeyExists
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := security.EnsurePrivateDir(filepath.Dir(path)); err != nil {
			return err
		}
		row := keyRow{Principal: principal, Name: key.Name, Type: key.Type, Fingerprint: key.Fingerprint}
		stage := sshPutStage(path, row)
		if err := security.ReplaceFile(stage, private); err != nil {
			return err
		}
		if err := queries.InsertKey(background, InsertKeyParams(row)); err != nil {
			if db.IsConstraint(err) {
				err = errSSHKeyExists
			}
			return errors.Join(err, security.RemoveFile(stage))
		}
		if err := os.Rename(stage, path); err != nil {
			return err
		}
		return security.SyncDir(filepath.Dir(path))
	})
}

func (s Store) stageSSHDelete(principal, name string) (func(bool) error, error) {
	path := s.keyPath(principal, name)
	if _, err := security.ReadPrivateFile(path, 1<<20); err != nil {
		return nil, err
	}
	tombstone := filepath.Join(filepath.Dir(path), deletePrefix+name)
	if _, err := os.Lstat(tombstone); err == nil {
		return nil, errors.New("SSH key deletion is already pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.Rename(path, tombstone); err != nil {
		return nil, err
	}
	if syncErr := security.SyncDir(filepath.Dir(path)); syncErr != nil {
		restoreErr := os.Rename(tombstone, path)
		if restoreErr == nil {
			restoreErr = security.SyncDir(filepath.Dir(path))
		}
		return nil, errors.Join(syncErr, restoreErr)
	}
	return func(commit bool) error {
		if commit {
			return security.RemoveFile(tombstone)
		}
		if _, err := os.Lstat(path); err == nil {
			return errors.New("SSH key path was recreated during rollback")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
		err := os.Rename(tombstone, path)
		return errors.Join(err, security.SyncDir(filepath.Dir(path)))
	}, nil
}

func (s Service) writeSSHKey(principal security.Principal, name string, private []byte) (SSHKey, error) {
	name = strings.TrimSpace(name)
	if !validSSHKeyName(name) {
		return SSHKey{}, errInvalidSSHKeyName
	}
	metadata, err := internalssh.InspectPrivateKey(private)
	if err != nil {
		return SSHKey{}, security.New("invalid_ssh_key", "The file is not an SSH private key.", http.StatusBadRequest)
	}
	key := SSHKey{Name: name, Type: metadata.Type, Fingerprint: metadata.Fingerprint}
	private = append(bytes.TrimRight(private, "\r\n"), '\n')
	return key, s.Store.putSSHKey(security.PrincipalDirName(principal), key, private)
}

func (s Service) deleteSSHKey(principal security.Principal, name string) error {
	if !validSSHKeyName(name) {
		return errInvalidSSHKeyName
	}
	return s.Store.deleteSSHKey(security.PrincipalDirName(principal), s.Configs.ConfigPath(principal), name)
}

func (s Service) keyRoutes() router.Routes {
	return router.Routes{
		"/api/v1/keys/ssh": {
			http.MethodGet: security.AnswerAsPrincipal(http.StatusOK, func(principal security.Principal, _ *http.Request) (SSHKeyList, error) {
				keys, err := s.Store.listSSHKeys(security.PrincipalDirName(principal))
				return SSHKeyList{Keys: keys}, err
			}),
			http.MethodPost: security.CreatedAsPrincipal(func(key SSHKey) string { return "/api/v1/keys/ssh/" + url.PathEscape(key.Name) }, func(principal security.Principal, request *http.Request) (SSHKey, error) {
				var body SSHKeyRequest
				if err := security.DecodeJSON(request, &body); err != nil {
					return SSHKey{}, err
				}
				return s.writeSSHKey(principal, body.Name, []byte(body.PrivateKey))
			}),
		},
		"/api/v1/keys/ssh/{id}": {
			http.MethodDelete: security.NoContentAsPrincipal(func(principal security.Principal, request *http.Request) error {
				return s.deleteSSHKey(principal, request.PathValue("id"))
			}),
		},
	}
}
