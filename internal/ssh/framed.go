// Marker-delimited output is the shared envelope for discovery, scheduler reconciliation, and remote log tails.
// Each section name occupies a line of its own so SSH banner noise remains outside the framed response.
// The SSH host is untrusted: an out-of-order, missing, duplicate, or unknown marker rejects the whole response
// rather than allowing one protocol to interpret another's output.
package ssh

import (
	"errors"
	"strings"
)

func Sections(output, prefix string, names []string) (map[string]string, error) {
	sections := make(map[string]string, len(names))
	next, content := 0, []string(nil)
	flush := func() {
		if next > 0 {
			sections[names[next-1]] = strings.Join(content, "\n")
		}
		content = nil
	}
	for _, line := range strings.Split(strings.TrimSuffix(output, "\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if !strings.HasPrefix(line, prefix) {
			if next == 0 {
				continue
			}
			content = append(content, line)
			continue
		}
		if next == len(names) || line != names[next] {
			return nil, errors.New("malformed, duplicate, or out-of-order framed marker")
		}
		flush()
		next++
	}
	flush()
	if next < len(names) {
		return nil, errors.New("framed output ended before all sections completed")
	}
	return sections, nil
}
