// SSH host entries parse from a pasted ssh command restricted to connection options and allowlisted directives, and
// render to one OpenSSH stanza. The parsed value is both the wire shape and the stored payload. An SSH host's only
// credential is the stored key its keyId names, so the command takes no -i and no identity option; the key's path is
// supplied at render time and never stored or returned.
package ssh

import (
	"fmt"
	"maps"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/cyber-shuttle/cs-plane/internal/security"
	"github.com/cyber-shuttle/cs-plane/internal/ssh"
)

func (h HostEntry) stanza(identityFile string) []string {
	config := map[string][]string{}
	add := func(key, value string) { config[key] = append(config[key], value) }
	if h.Hostname != "" {
		add("hostname", h.Hostname)
	}
	if h.User != "" {
		add("user", h.User)
	}
	if h.Port != 0 && h.Port != 22 {
		add("port", strconv.Itoa(h.Port))
	}
	for _, directive := range h.ExtraDirectives {
		if key, value, found := strings.Cut(strings.TrimSpace(directive), " "); found {
			add(strings.ToLower(key), strings.TrimSpace(value))
		}
	}
	if h.Key != "" {
		config["identityfile"], config["identitiesonly"] = []string{identityFile}, []string{"yes"}
	}
	lines := []string{"Host " + h.Alias}
	for _, key := range slices.Sorted(maps.Keys(config)) {
		for _, value := range config[key] {
			lines = append(lines, "    "+key+" "+value)
		}
	}
	return append(lines, "")
}

var valuePattern = regexp.MustCompile(`^[A-Za-z0-9_@%:./+=,~-]{1,256}$`)

var allowedOptions = map[string]string{
	"proxyjump":                "ProxyJump",
	"stricthostkeychecking":    "StrictHostKeyChecking",
	"userknownhostsfile":       "UserKnownHostsFile",
	"identitiesonly":           "IdentitiesOnly",
	"forwardagent":             "ForwardAgent",
	"serveraliveinterval":      "ServerAliveInterval",
	"serveralivecountmax":      "ServerAliveCountMax",
	"preferredauthentications": "PreferredAuthentications",
	"pubkeyauthentication":     "PubkeyAuthentication",
	"pubkeyacceptedalgorithms": "PubkeyAcceptedAlgorithms",
	"hostkeyalgorithms":        "HostKeyAlgorithms",
	"kexalgorithms":            "KexAlgorithms",
	"ciphers":                  "Ciphers",
	"macs":                     "MACs",
	"addkeystoagent":           "AddKeysToAgent",
	"compression":              "Compression",
	"requesttty":               "RequestTTY",
}

func invalid(message string) error {
	return security.New("invalid_ssh_command", message, http.StatusBadRequest)
}

func validText(subject, text string) (string, error) {
	if !valuePattern.MatchString(text) {
		return "", invalid(fmt.Sprintf("The %s carries characters an ssh config cannot hold.", subject))
	}
	return text, nil
}

func option(key, value string) (string, error) {
	value, err := validText(key+" value", value)
	if err != nil {
		return "", err
	}
	return key + " " + value, nil
}

func parseCommand(alias, command string) (HostEntry, error) {
	if !ssh.ValidAlias(alias) {
		return HostEntry{}, ssh.ErrInvalidAlias
	}
	fields := strings.Fields(command)
	if len(fields) > 0 && strings.EqualFold(filepath.Base(fields[0]), "ssh") {
		fields = fields[1:]
	}
	host := HostEntry{Alias: alias, Port: 22, ExtraDirectives: []string{}}
	target := ""
	for index := 0; index < len(fields); index++ {
		field := fields[index]
		if field == "--" {
			continue
		}
		if !strings.HasPrefix(field, "-") {
			if target != "" {
				return HostEntry{}, invalid("Remove the remote command; the entry describes the connection only.")
			}
			target = field
			continue
		}
		if len(field) < 2 || !strings.ContainsRune("plJo", rune(field[1])) {
			return HostEntry{}, invalid(fmt.Sprintf("%s is not supported here. Keep the command to the host, user, port, jump host, and -o options; keys are added under /keys/ssh and chosen by keyId.", field))
		}
		value := field[2:]
		if value == "" {
			if index+1 >= len(fields) {
				return HostEntry{}, invalid(fmt.Sprintf("%s expects a value.", field))
			}
			index++
			value = fields[index]
		}
		var err error
		switch field[1] {
		case 'p':
			host.Port, err = strconv.Atoi(value)
			if err != nil || host.Port < 1 || host.Port > 65535 {
				return HostEntry{}, invalid(fmt.Sprintf("%q is not a port.", value))
			}
		case 'l':
			host.User, err = validText("user name", value)
		case 'J':
			var directive string
			directive, err = option("ProxyJump", value)
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		case 'o':
			key, setting, found := strings.Cut(value, "=")
			if !found {
				key, setting, found = strings.Cut(value, " ")
			}
			if !found {
				return HostEntry{}, invalid(fmt.Sprintf("%q is not an ssh option.", value))
			}
			canonical, ok := allowedOptions[strings.ToLower(strings.TrimSpace(key))]
			if !ok {
				return HostEntry{}, invalid(fmt.Sprintf("%s cannot be set from a pasted command.", strings.TrimSpace(key)))
			}
			var directive string
			directive, err = option(canonical, strings.TrimSpace(setting))
			host.ExtraDirectives = append(host.ExtraDirectives, directive)
		}
		if err != nil {
			return HostEntry{}, err
		}
	}
	if target == "" {
		return HostEntry{}, invalid("The command names no host.")
	}
	var err error
	if user, hostname, found := strings.Cut(target, "@"); found {
		if host.User, err = validText("user name", user); err != nil {
			return HostEntry{}, err
		}
		target = hostname
	}
	host.Hostname, err = validText("hostname", target)
	return host, err
}
