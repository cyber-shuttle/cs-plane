# Contributing to cs-plane

Branch off `main`, keep CI green, cover new behaviour with a test, and open a pull request.

## Prerequisites

- [Go](https://go.dev/dl/) 1.26.0 or newer; CI takes the version from `go.mod`.
- An OpenSSH client, for the tests that drive `ssh`.
- Postgres for the database tests, which are skipped without `CS_TEST_DATABASE_URL`. Each test uses its own schema
  and drops it afterwards.

```bash
docker run -d -p 127.0.0.1:5432:5432 -e POSTGRES_PASSWORD=postgres postgres:17
export CS_TEST_DATABASE_URL='postgres://postgres:postgres@127.0.0.1:5432/postgres?sslmode=disable'
```

## Build and test

```bash
go build ./...
go vet ./...
golangci-lint run ./...
go test -race ./...
```

| Where | What runs |
| --- | --- |
| CI (`.github/workflows/ci.yml`) | the four commands above on `ubuntu-latest`, `golangci-lint` v2.13.2, for every pull request and push to `main` |
| `lefthook.yml` pre-commit | `gofmt`, `go vet`, `golangci-lint`, `go test -race`; enable with `lefthook install` |

Lint suppressions live only in `.golangci.yml`, each with its reason; never `//nolint`.

SQL lives in each subsystem's `schema.sql` and `query.sql`; `go generate ./internal/db` runs
[sqlc](https://sqlc.dev) to regenerate the committed `query.sql.go`, `sql.go` and `sql_models.go`.

## Source layout

`main.go` is the composition root. `internal/` holds packages with no HTTP surface; `subsystems/` holds `oauth`,
`ssh`, `devtunnels` and `session`, each owning its wire shapes, logic and routes. A package's request and response
types live in its `wire.go` and nowhere else, because clients generate their TypeScript types from those files.
[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) gives the import rules and trust boundaries. Comments explain why, not
what.

## Pull requests

Link the issue and list the commands you ran. A change to a route, body, error code, flag or environment variable
updates [docs/API.md](docs/API.md) or the [README](README.md) in the same pull request, and a user-visible change
adds a line under `## [Unreleased]` in [CHANGELOG.md](CHANGELOG.md).

Participation is covered by the [Code of Conduct](CODE_OF_CONDUCT.md).
