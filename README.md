# cs-plane

[![CI](https://github.com/cyber-shuttle/cs-plane/actions/workflows/ci.yml/badge.svg)](https://github.com/cyber-shuttle/cs-plane/actions/workflows/ci.yml)
[![Go](https://img.shields.io/github/go-mod/go-version/cyber-shuttle/cs-plane)](go.mod)
[![License](https://img.shields.io/github/license/cyber-shuttle/cs-plane?color=blue)](LICENSE)

CyberShuttle is the ARTISAN group's toolset for running Jupyter and VS Code sessions on the compute nodes of HPC
(high-performance computing) clusters, reachable from a browser or editor. cs-plane is its central service. It signs
users in through CILogon; it holds each user's credentials, SSH hosts and session records; and it submits the
[Linkspan](https://github.com/cyber-shuttle/linkspan) job that runs a session through
[Slurm](https://slurm.schedmd.com/), preparing the SSH host first. The job's Linkspan dials out to cs-plane and holds a
link, so a session is reachable without the cluster opening an inbound port.

A session is the record a client defines, starts and polls; a Slurm job serves each run, and one session can
outlive several. Each user's work runs as that user: their own SSH host configuration, their SSH keys, their
Slurm account. One cs-plane serves many users from one machine, listening on loopback behind a TLS reverse
proxy at `--public-url`; clients reach a running session's Jupyter Server and ports through cs-plane over the link,
or over a Dev Tunnel. [cs-infra](https://github.com/cyber-shuttle/cs-infra) deploys it.

## Status

Pre-release. There are no published binaries; `cs version` prints the build's hardcoded version constant.
The `/api/v1` surface is not yet stable. [CHANGELOG.md](CHANGELOG.md) records what has changed on `main`.

## Requirements

- **macOS or Linux**, with an OpenSSH client on `PATH`. CI covers Linux only.
- **Go 1.26 or newer.** Building from source is the only install path.
- **A [CILogon](https://www.cilogon.org/) client, or another OIDC issuer configured the same way.** The
  client must have PKCE and the device flow enabled: cs-plane finishes a browser's PKCE flow and an editor's
  device-code flow. `--oidc-issuer` defaults to `https://cilogon.org`; the client ID
  goes on `--oidc-client-id` and the client secret in `CS_OIDC_CLIENT_SECRET`, since only cs-plane holds
  it.
- **A Postgres server** with a schema cs-plane owns. `CS_DATABASE_URL` names it through `search_path`, for
  example `postgres:///cybershuttle?host=/var/run/postgresql&search_path=cs_plane`; cs-plane creates its tables in that
  schema while it is empty, and refuses one it did not create.
- **Optionally, a Microsoft or GitHub account entitled to
  [Dev Tunnels](https://learn.microsoft.com/en-us/azure/developer/dev-tunnels/overview),** connected once through
  `POST /api/v1/devtunnels/authorizations` and kept sealed under the caller's principal, for a Dev Tunnel made
  with that account per run with the `devtunnel` transport.
- **An SSH-reachable Linux Slurm cluster** whose SSH host provides `sacctmgr`, `sinfo`, `sbatch`, `squeue`,
  `sacct`, `scancel`, `curl`, `tar`, `base64`, `od`, `install`, `printenv`, `sed` and `sort -V`, and whose
  nodes run Linux `x86_64` or `arm64` with `curl`.
- **[Linkspan](https://github.com/cyber-shuttle/linkspan) 0.22.0 or newer**, the release that takes
  `--tunnel-mode link` and `--tunnel-link-args`; cs-plane installs the latest release on an SSH host that has none.
- **Outbound internet.** From the SSH host to `github.com`; from the compute node to `--public-url`, which
  Linkspan links to, and to `astral.sh`, `github.com` and `pypi.org`, which Linkspan installs `uv`, its Python and
  packages from, and, with a Dev Tunnel, to `tunnelsassetsprod.blob.core.windows.net`, which Linkspan fetches
  Microsoft's `devtunnel` CLI from, and to
  `*.rel.tunnels.api.visualstudio.com` and `*.devtunnels.ms`, which it hosts the Dev Tunnel through; and from
  the machine running cs-plane to the configured OIDC issuer, `*.rel.tunnels.api.visualstudio.com`
  and `*.devtunnels.ms`, plus `login.microsoftonline.com` or `github.com` while connecting a Dev Tunnels account. See
  [what it runs on the cluster](#what-it-runs-on-the-cluster).

## Install

```bash
git clone https://github.com/cyber-shuttle/cs-plane.git
cd cs-plane
go build -o cs .
```

## Quick start

```bash
export CS_OIDC_CLIENT_SECRET=...
export CS_DATABASE_URL='postgres:///cybershuttle?host=/var/run/postgresql&search_path=cs_plane'
cs serve \
  --listen 127.0.0.1:8045 \
  --oidc-client-id cilogon:/client_id/<id> \
  --public-url https://api.example.edu \
  --allowed-origin https://workspace.example.edu
```

`--oidc-client-id`, `--public-url`, `CS_OIDC_CLIENT_SECRET` and `CS_DATABASE_URL` are required; `--oidc-issuer` defaults
to `https://cilogon.org`. The issuer must use HTTPS and match its discovery document exactly; the public URL, where
browsers and jobs reach cs-plane, must use HTTPS. `--allowed-origin` is repeatable and at least one is required; HTTPS
origins and loopback HTTP origins are accepted, wildcards are not. `--listen` defaults to `127.0.0.1:8045` and must be
an explicit loopback address.

There are no CLI commands for SSH keys, SSH hosts, or sessions — a client drives cs-plane over the API. Its routes are
under `/api/v1/oauth`, `/api/v1/hosts`, `/api/v1/keys`, `/api/v1/devtunnels`, `/api/v1/sessions`, and
`/api/v1/runs` (run history); see the [API reference](docs/API.md). Confirm it is listening and that authentication is in front:

```console
$ curl -si http://127.0.0.1:8045/api/v1/sessions | head -1
HTTP/1.1 401 Unauthorized
```

`cs help` prints the commands and the global flags; `cs serve -h` prints the serve flags.

## Configuration

| Flag | Environment | Default |
| --- | --- | --- |
| `serve --listen` | — | `127.0.0.1:8045` |
| `serve --oidc-issuer` | — | `https://cilogon.org` |
| `serve --oidc-client-id` | — | required |
| `serve --public-url` | — | required |
| — | `CS_OIDC_CLIENT_SECRET` | required |
| `serve --allowed-origin` (repeatable) | — | required |
| `--linkspan` | `CS_LINKSPAN` | `$HOME/.cybershuttle/bin/linkspan` |
| `--devtunnel-management-url` | `CS_DEVTUNNEL_MANAGEMENT_URL` | `https://global.rel.tunnels.api.visualstudio.com` |

Global flags precede the command. `--linkspan` is a remote path, absolute or anchored at `$HOME/`, resolved per
SSH host. Set `--devtunnel-management-url` to a regional `*.rel.tunnels.api.visualstudio.com` endpoint when the
global Dev Tunnels region's quota is exhausted; it changes Dev Tunnel management only. Management redirects retain
authorization only between recognized HTTPS management hosts.

## What it runs on the cluster

Starting a session prepares the SSH host before it submits anything. In one connection, as your
account, it:

- downloads a [Linkspan](https://github.com/cyber-shuttle/linkspan) release tarball from GitHub into
  `$HOME/.cybershuttle/bin`, unless the installed one is current, and refuses the SSH host if that Linkspan is
  older than 0.22.0;
- writes the workflow document the job will run, under `$HOME/.cybershuttle/sessions/<session id>`.

Linkspan is the CyberShuttle agent that runs as the Slurm job's main process: it links to cs-plane, hosts any
Dev Tunnel, installs `uv`, builds the Python environment under `$HOME/.cybershuttle` and starts Jupyter
Server on the compute node. Nothing runs as root and nothing is installed outside `$HOME/.cybershuttle`. cs-plane
keeps a multiplexed OpenSSH connection to the SSH host open between operations and starts no other long-lived
process there; the session itself runs on a compute node. The job script redirects the job's stdout and stderr to
`$HOME/.cybershuttle/logs/<session id>-<seq>.out` and `.err`; nothing prunes them. The flags and outputs
cs-plane depends on are listed in
[Linkspan's compatibility document](https://github.com/cyber-shuttle/linkspan/blob/main/docs/COMPATIBILITY.md).
A client may instead submit the job itself and admit it through `POST /api/v1/sessions/{id}/attach`; cs-plane then
runs nothing on the cluster for that run.

## Local state

`~/.cybershuttle/control`, created and verified at mode `0700`:

- `credentials/` — each run's Jupyter, link and Dev Tunnel connect tokens, mode `0600`
- `hosts/<principal>/config` — each caller's own SSH host entries, rendered from the database, mode `0600`
- `hosts/<principal>/keys/<id>` — SSH keys the caller uploaded, mode `0600`
- `hosts/<principal>/devtunnels-account` — the caller's connected Dev Tunnels account, sealed, mode `0600`
- `devtunnels-account.key` — the 32-byte key sealing every `devtunnels-account` file, created at mode `0600` on first
  boot

Scheduler, session, Dev Tunnel, SSH host and SSH key metadata live in the Postgres schema. Each caller's SSH host
entries are rendered to that caller's `hosts/<principal>/config`
for `ssh -F`; startup regenerates these files from committed rows and resolves interrupted key writes and deletions.
The API never reads or writes `~/.ssh/config` for the account cs-plane runs as. A schema holding tables without
cs-plane's format marker is refused before anything else is touched.

## Documentation

- [docs/API.md](docs/API.md) — the loopback HTTP and WebSocket API a client drives
- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — package layering, session lifecycle, trust boundaries

## Related projects

- **[cs-jupyter](https://github.com/cyber-shuttle/cs-jupyter)** — the browser client that drives this API: it
  signs in, defines, starts and polls sessions, and connects to a `READY` one.
- **[Linkspan](https://github.com/cyber-shuttle/linkspan)** — the compute-node agent cs-plane installs and
  submits as the job's main process.

## Getting help

Bug reports and feature requests go to [GitHub Issues](https://github.com/cyber-shuttle/cs-plane/issues).
Report a vulnerability privately instead — see [SECURITY.md](SECURITY.md).

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers the development setup, the commands CI runs, and the pull-request
workflow. Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).

## License

Apache-2.0. See [LICENSE](LICENSE).
