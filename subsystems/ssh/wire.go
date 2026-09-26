// The JSON shapes this package's routes read and write, kept in this file alone so clients generate their
// TypeScript types from it with tygo; every other type here is internal.

package ssh

type HostEntry struct {
	Alias           string   `json:"alias"`
	Hostname        string   `json:"hostname,omitempty"`
	User            string   `json:"user,omitempty"`
	Port            int      `json:"port,omitempty"`
	Key             string   `json:"keyId,omitempty"`
	ExtraDirectives []string `json:"extraDirectives"`
	Managed         bool     `json:"managed"`
}

type HostList struct {
	Hosts []HostEntry `json:"hosts"`
}

type SSHKey struct {
	Name        string `json:"id"`
	Type        string `json:"type"`
	Fingerprint string `json:"fingerprint"`
}

type SSHKeyList struct {
	Keys []SSHKey `json:"keys"`
}

type SSHKeyRequest struct {
	Name       string `json:"id"`
	PrivateKey string `json:"privateKey"`
}

type AddHostRequest struct {
	Alias   string `json:"alias"`
	Command string `json:"command"`
	Key     string `json:"keyId"`
}

type UpdateHostRequest struct {
	Command string `json:"command"`
	Key     string `json:"keyId"`
}

type HostHealth struct {
	Alias   string `json:"alias"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}
