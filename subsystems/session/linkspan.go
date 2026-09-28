// Linkspan's launch contract, owned here so the rest of preparation never spells its CLI: the release floor,
// the transports a session may select, the flags a session job execs Linkspan with for them, and the sbatch
// exports those flags read. The flags reference exported variables rather than values so the script text stays
// free of secrets and per-run identity; the link and Dev Tunnel host tokens reach Linkspan only through its own
// environment names, and each is exported only when its transport is selected.
package session

import (
	"slices"
	"strings"
)

const linkspanFloor = "0.22.0"

const (
	transportDevtunnel = "devtunnel"
	transportLink      = "link"
)

var linkspanTransportFlags = map[string]string{
	transportDevtunnel: `--tunnel-devtunnel-args "--id $CS_DEVTUNNEL_ID --cluster $CS_DEVTUNNEL_CLUSTER"`,
	transportLink:      `--tunnel-link-args "--url $CS_LINK_URL"`,
}

func linkspanTransportArgs(transports []string) string {
	args := "--tunnel-enable --tunnel-mode " + strings.Join(transports, ",")
	for _, transport := range transports {
		args += " " + linkspanTransportFlags[transport]
	}
	return args
}

func linkspanEnvironment(transports []string, linkURL, linkToken string, metadata devtunnelMetadata, hostToken string) map[string]string {
	environment := map[string]string{}
	if slices.Contains(transports, transportLink) {
		environment["CS_LINK_URL"], environment["LINKSPAN_LINK_TOKEN"] = linkURL, linkToken
	}
	if slices.Contains(transports, transportDevtunnel) {
		environment["CS_DEVTUNNEL_ID"], environment["CS_DEVTUNNEL_CLUSTER"], environment["LINKSPAN_TUNNEL_HOST_TOKEN"] = metadata.ID, metadata.ClusterID, hostToken
	}
	return environment
}
