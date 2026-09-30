# Architecture

`cs` is one binary; `cs serve` runs the HTTP API that browser and editor clients drive. Each subsystem exports a
route table; `internal/router` unions them, refuses duplicate method-and-path pairs, and answers JSON 404 and 405.
`oauth.Service` contributes the five public sign-in routes and wraps the registry in its identity boundary. Routes
are one-line adapters over service operations that take the acting principal as a parameter and check ownership
themselves.

## Packages

A subsystem imports `internal/*` only, never another subsystem. A cross-subsystem need is an interface the consumer
declares (`session.RunnerProvider`, `session.DevtunnelCredentials`, `session.DevtunnelManager`), which `main.go`
satisfies with `ssh.Configurations`, `devtunnels.Service` and the Dev Tunnels client. Shared code goes in the lowest
`internal/` package that can hold it.

```
internal/testutil      shared test helpers
internal/router        route-table union, duplicate detection, method dispatch, JSON route failures
internal/security      API errors, strict JSON, Principal context, origin policy, protected files, bounded HTTP
                       clients, name predicates, WebSocket subprotocols
internal/db            Postgres connection: schema creation, format check, locking, transactions, unlocked reads
internal/identity      OIDC discovery, validation and grants
internal/ssh           bounded SSH execution, principal-scoped runners, PTY/WebSocket bridge, control masters
internal/slurm         Slurm command construction, framed output parsing, scheduler value types
internal/devtunnel     Dev Tunnels authorization and management protocols, wire types, URI policy

subsystems/oauth       sign-in routes, CORS, bearer extraction, principal resolution
subsystems/ssh         per-principal SSH hosts and SSH keys, config rendering, health, authentication
subsystems/devtunnels  connecting a Dev Tunnels account, sealed credential store, refresh
subsystems/session     session state, Slurm and Dev Tunnel lifecycles, per-run tokens, link, reconciliation, logs,
                       usage, run history

main.go                composition root
```

## Session lifecycle

A session is the durable record; each `start` launches one Slurm job under the next `seq`, named
`cs-<session id>-<seq>`. `POST /sessions` records a session at `seq` 0 without touching an SSH host. `attach` takes the
next `seq` for a job the client submits; cs-plane runs no SSH or scheduler command for it, so reconciliation and
accounting skip it and `stop` retires it locally.

A start runs in this order:

1. Discovery (`id`, `sacctmgr`, `sinfo`, `printenv HOME`) and `sbatch --test-only` against the candidate script.
2. A Dev Tunnel for the run, made with the owner's connected Dev Tunnels account, when the session's
   `tunnelModes` holds `devtunnel`; then the run's tokens written to disk and the record persisted as `SUBMITTING`.
3. SSH host preparation: Linkspan and the workflow document, in one constant script.
4. `sbatch`, fed from stdin by a program that exports the session environment first, so no value reaches an
   argv any user of the SSH host can list.

The record is durable before preparation, so preparation narrates into the log tail the client already polls. A
conclusive submission failure releases the Dev Tunnel and the run's tokens and marks the session `FAILED`. An ambiguous
one, anything other than a refusal `sbatch` reported, stays durable for reconciliation because the job may be queued. A
submission that returns after the session was stopped cancels its job. No `seq` is ever used twice.

### Preparation

Preparation installs Linkspan into the account, not the session: one `$HOME/.cybershuttle` per account. It refuses
a Linkspan older than 0.22.0, the first release that takes `--tunnel-mode link` and `--tunnel-link-args`. It runs on
the service's context, so an abandoned request leaves no half-built state. Preparation is keyed on the caller's
config file plus alias; a concurrent start on the same key is refused `session_provisioning_in_progress`, while
another caller's preparation of the same SSH host proceeds.

The job script execs Linkspan and names no application. The workflow, one `on: start` task with a
`jupyter.sessions.start` step, carries only validated paths and the Jupyter port. Secrets never enter script text:
`JUPYTER_TOKEN` and `CS_CONTROL_PORT`, with `link` `CS_LINK_URL` and `LINKSPAN_LINK_TOKEN`, and with `devtunnel`
`CS_DEVTUNNEL_ID`, `CS_DEVTUNNEL_CLUSTER` and `LINKSPAN_TUNNEL_HOST_TOKEN` reach the job through
`sbatch --export=ALL`. Linkspan runs with `--tunnel-enable --tunnel-mode <transports>` and, per selected transport,
`--tunnel-link-args "--url $CS_LINK_URL"` or
`--tunnel-devtunnel-args "--id $CS_DEVTUNNEL_ID --cluster $CS_DEVTUNNEL_CLUSTER"`. The control and Jupyter ports are
derived from session ID and `seq`, so a Dev Tunnel can declare the control port before the job starts.

### States and reconciliation

States: `SUBMITTING`, `QUEUED`, `STARTING`, `READY`, `STOPPING`, `STOPPED`, `FAILED`. A Slurm state outside this
vocabulary is treated as no observation. A link for the current run moves `QUEUED` or `STARTING` to `READY`, and
reconciliation never demotes a linked `READY` session. Without a link, `STARTING` becomes `READY` once the job runs
and its log has output, and a client-launched `QUEUED` run with a Dev Tunnel once Linkspan's `/api/v1/health` answers
through it. Slurm is otherwise authoritative, including for the end of a run.

Reconciliation runs in the background every 30 seconds, one pass at a time, so no read waits on SSH. A session
unknown to the scheduler past a two-minute propagation window becomes `STOPPED`, as does one whose scheduler is
unreachable ten minutes past its walltime.

### Usage and run history

cs-plane polls each `READY` session's Linkspan `GET /api/v1/usage` every five seconds and serves the samples on
`GET /sessions/{id}/usage`, apart from the session so they do not churn the `GET /sessions` ETag. When a session first
reaches a terminal state, cs-plane freezes a run keyed by `(session id, seq)` holding the final sample window and log
tail, then drops both buffers; `GET /runs` lists them.

## Session link

Linkspan dials `<public-url>/api/v1/sessions/{id}/link` and holds the WebSocket, authenticated by the per-run link
token. Every connection cs-plane makes into the job, whether usage, SSH start, Jupyter proxy or forward, is a
yamux stream over that socket, HTTP pooled per run. The link registry is process-local; when cs-plane starts again
Linkspan redials. A Dev Tunnel is the fallback while the session has no link.

## Dev Tunnels

Connecting an account is optional. The broker runs a Microsoft or GitHub device-code authorization bound to the caller's
principal, then seals the resulting credential with `nacl/secretbox` under `devtunnels-account.key`. The credential is
loaded and, when it has a refresh token, refreshed within two minutes of expiry on use; the request's own bearer is
never used for Dev Tunnels.

Only the `devtunnel` transport needs a connected account (`409 devtunnels_account_required` otherwise), and each run
with that transport gets one Dev Tunnel, made with that account, declaring only the control port, with no anonymous
access and traffic inspection disabled. `customExpiration` is walltime plus 15 minutes, clamped to one hour through
30 days; expiry is the cleanup backstop. Any create error deletes the deterministic Dev Tunnel ID before returning.
`stop` releases best-effort, skipping the Dev Tunnels call without a usable credential. The fallback dial reads the
Dev Tunnel with `Authorization: tunnel <connect token>`, then opens Linkspan's `/api/v1/forward/{port}` with the
connect token in `X-Tunnel-Authorization`.

## SSH configuration

A principal's SSH hosts live in `ssh_hosts`; after each mutation, under the same lock, they are rendered whole to
`hosts/<principal>/config`, where `<principal>` is a hash of subject and tenant. `ssh` always runs with `-F` naming that
file, so an alias resolves only through its owner's configuration, and aliases never collide across callers.
Control masters are keyed by configuration and alias, so one caller's authentication never serves another. The
account cs-plane runs as has no standing: its `~/.ssh/config` is ignored.

A pasted `ssh` command is parsed by cs-plane into hostname, user, port, `ProxyJump` and allowlisted `-o` options;
nothing that runs a local program or includes other configuration is accepted. An SSH host's only credential is an
uploaded SSH key named by `keyId`. Key creation stages the file, commits metadata, then promotes the file; deletion
renames the file to a tombstone before committing. Startup resolves either interruption from committed metadata.

## Persistence

The Postgres schema holds `schema_meta` plus each subsystem's `schema.sql` tables: `sessions` and `runs` (JSON
payload keyed by session ID or `(session_id, seq)`), `ssh_hosts` (keyed by `(principal, host)`, alias unique ignoring
case) and `ssh_keys` (keyed by `(principal, name)`). `internal/db` uses one connection and serializes
read-modify-write cycles behind a process lock and a file lock in the state directory. Session reads are single
statements outside the lock. DDL runs only in an empty schema; a non-empty schema without the current format marker
is refused before any credential file is created. Nothing is migrated. Startup recovers interrupted key changes and
re-renders every SSH config. Files on disk are listed in the [README](../README.md#local-state).

## Trust boundaries

- **Loopback only.** `serve` refuses a non-loopback listen address before binding.
- **Exact origins.** One policy, `security.Origins`, covers the bearer boundary, the Jupyter proxy and the forward
  and link upgrades: a present `Origin` must be allowlisted; an absent one is a native client. `oauth/config` and
  `oauth/exchange` also require one.
- **One bearer, one identity authority.** The ID token is validated against the issuer's discovery document and JWKS,
  with exact issuer and audience pinned to the client ID; its `sub` names the principal under tenant `cilogon`.
- **Ownership.** Every session, log tail, run, SSH host, SSH key and Dev Tunnels account is scoped to the principal.
- **No ambient authentication.** No cookies or static files; only the Jupyter proxy takes its token in the URL, as
  Jupyter clients require. Outside the bearer boundary are only the sign-in routes and the token routes: forward and
  Jupyter proxy by Jupyter token, link by link token.
- **Sign-in routes.** Hold the client secret and never return it; `redirectUri` must be on an allowed origin; issuer
  errors are not echoed.
- **Dev Tunnels broker.** Device codes stay in bounded process memory, polling intervals are enforced, and no
  response carries the account's token.
- **OIDC key refresh.** Coalesced and outside the cache lock; an unknown `kid` forces at most one refresh per 30
  seconds.
- **Validation precedes construction.** Aliases, scheduler values, node names, paths, Dev Tunnel metadata and ports
  are validated before reaching a command line or state; remote scripts are constants taking arguments.
- **Redaction.** Dev Tunnels OAuth, host, connect, link and Jupyter tokens are redacted from errors, logs, scripts and
  responses. The Jupyter token appears only in the job environment and the access response; the link token only in the
  job environment and, for a client-launched run, the `attach` response.
- **Proxying.** cs-plane forwards only to ports Linkspan serves and opens no port forward on the SSH host. The Jupyter
  token that opens a forward already grants code execution as the user, so Linkspan's API adds no power.
- **Shared nodes.** Jobs are not `--exclusive`; any user on the compute node can reach Linkspan's loopback control port
  ([Linkspan security model](https://github.com/cyber-shuttle/linkspan/blob/main/SECURITY.md#security-model)).
