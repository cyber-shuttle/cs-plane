# Changelog

Notable changes to cs-plane. The format follows
[Keep a Changelog 1.1.0](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

The next release is 0.4.0.

Upgrading from 0.3.0: stored sessions and runs carry `websocket` and `launcher` and are not migrated, and stored SSH
hosts carry `name`. Stop every session first. With cs-plane stopped, run against its schema (here `cs_plane`):

```sql
DELETE FROM cs_plane.runs;
DELETE FROM cs_plane.sessions;
UPDATE cs_plane.ssh_hosts SET payload = ((payload::jsonb - 'name') || jsonb_build_object('alias', host))::text;
```

Then delete the per-run token files and the old sealed Dev Tunnels account files under the state directory:

```sh
cd ~/.cybershuttle/control
rm -f credentials/*.token hosts/*/tunnel-link tunnel-link.key .tunnel-link-*.lock
```

Each user connects their Dev Tunnels account again.

### Security

- Job submission no longer puts the session environment, including the link and Dev Tunnel host tokens, on
  `sbatch`'s command line, where any user of the SSH host could list it; a stdin program exports it instead.

### Added

- `attach` answers the run's control `port`, and each run in run history names its `platform`.

### Changed

- The request and response types of the API and the SSH authentication frames are exported, so clients generate
  their TypeScript types from them with tygo. JSON shapes are unchanged.
- Stopping a session without a Dev Tunnel no longer reads the connected Dev Tunnels account.
- The transport value `websocket` is now `link`: `tunnelModes` takes `link` and `devtunnel` and defaults to
  `["link"]`, and Linkspan launches with `--tunnel-mode link` and `--tunnel-link-args "--url $CS_LINK_URL"`. Requires
  Linkspan 0.22.0 or newer.
- `launcher` is now `platform` on the session record, with the values `jupyterlab` (cs-plane started the run) and
  `vscode` (a client attached it).
- SSH host records carry `alias` instead of `name`, sessions and runs carry `alias` instead of `sshHost`, and the
  SSH host health and Slurm discovery responses carry `alias` instead of `host`.
- The Dev Tunnels account answers `connected` and `connectedAt` instead of `linked` and `linkedAt`, and a finished
  authorization poll answers the status `connected` instead of `linked`.
- The Dev Tunnels account routes move from `/api/v1/tunnel` to `/api/v1/devtunnels`, and the error
  `tunnel_link_required` is now `devtunnels_account_required`. A connected account is now stored as
  `hosts/<principal>/devtunnels-account` under `devtunnels-account.key`.
- Run history moves from `GET /api/v1/telemetry` to `GET /api/v1/runs`, and a session's usage samples from
  `GET /api/v1/sessions/{id}/metrics` to `GET /api/v1/sessions/{id}/usage`. cs-plane polls Linkspan's
  `GET /api/v1/usage` instead of `GET /api/v1/metrics`. JSON shapes are unchanged.

### Removed

- `POST /api/v1/sessions/{id}/runs`, which only moved CS Bridge's local history into cs-plane.

### Fixed

- Expired SSH authentication while preparing a session answers `409 ssh_authentication_required` instead of
  `502 session_provisioning_failed`.

## [0.3.0] - 2026-09-24

### Changed

- Sessions carry `tunnelModes` (`websocket`, `devtunnel` or both; default `websocket`), chosen on create and on
  `attach`; `devtunnel` needs a linked Dev Tunnels account (`409 tunnel_link_required`) and is the only mode
  that creates a tunnel.
- Linkspan launches with `--tunnel-enable --tunnel-mode` and only the selected modes' `--tunnel-websocket-args` and
  `--tunnel-devtunnel-args`; the Dev Tunnel host token travels as `LINKSPAN_TUNNEL_HOST_TOKEN`. Requires Linkspan
  0.21.0 or newer.
- `attach` takes an optional `tunnelModes` body and answers `link` only with `websocket` and `devtunnel`
  (`id`, `cluster`, `hostToken`) only with `devtunnel`; a client-launched `devtunnel` run is `READY` once Linkspan
  answers through its tunnel.

### Added

- `cs serve`: loopback-only JSON HTTP and WebSocket API under `/api/v1`.
- Sign-in relay for CILogon or another OIDC issuer: browser PKCE (`oauth/config`, `oauth/exchange`), device grant
  (`oauth/device`, `oauth/device/poll`) and `oauth/refresh`.
- Bearer authentication by OIDC ID token, resolved to a principal through Custos `GET /me`.
- One exact-origin policy for the API, the Jupyter proxy and every WebSocket.
- Per-caller SSH hosts from a pasted `ssh` command, with health, Slurm discovery and interactive authentication.
- Per-caller SSH keys, referenced by hosts as `keyId`.
- Optional Dev Tunnels account linking by device code, sealed at rest, for a fallback Dev Tunnel per session seq.
- Sessions: validate, record, start, stop, delete, adopt runs, access, SSH, metrics.
- `POST /sessions/{id}/attach`: a client-launched run, admitted by its link, which cs-plane never schedules.
- Session link: Linkspan dials `GET /sessions/{id}/link`; forwards and the Jupyter proxy ride it as yamux streams.
- Login-node preparation: Linkspan 0.21.0 or newer and the session workflow document.
- Background reconciliation of session state against Slurm every 30 seconds.
- `GET /telemetry`: finished runs per seq with Slurm accounting.
- State in a Postgres schema named by `CS_DATABASE_URL`, with sqlc-generated queries.

[Unreleased]: https://github.com/cyber-shuttle/cs-plane/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/cyber-shuttle/cs-plane/commits/v0.3.0
