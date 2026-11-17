# SentinelScan Backend

A dynamic application security scanner written in Go: HTTP probes over a small
embedded plugin set, optional same-domain crawling, PostgreSQL persistence,
ticket-based remediation, and a WebSocket stream for live results.

> **Status: alpha, not production-ready.** Several headline features from earlier
> documents were never implemented. The authoritative list lives in
> [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md); read it before promising a
> capability. The developer-facing contract (in Indonesian) is
> [docs/BACKEND-DEV.md](docs/BACKEND-DEV.md).

[![Go Version](https://img.shields.io/badge/Go-1.25.10+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

## What actually works

| Area | Status | Notes |
|---|---|---|
| HTTP scanning | Works | 7 embedded plugins: XSS, SQLi (error/boolean/time), path traversal, open redirect, XXE |
| Crawling | Works | Same-domain link discovery; `max_depth`, `max_pages`, `robots.txt` enforced |
| Result integrity | Works | All tasks failed → scan `failed`; partial transport failure → `degraded: true` |
| Tickets | Works | 8 endpoints, 5-state machine, derived severity, SLA, comments, stats, overdue |
| Scan lifecycle | Works | Heartbeat reconciliation: restart/shutdown/lost-heartbeat scans become `failed` with a reason |
| Auth | Works | JWT HS256, 4 roles, ownership checks, login throttling, token revocation via `token_version` |
| Credential vault | Storage only | AES-256-GCM at rest, but the scanner does **not** use credentials yet |
| Report data | Works | `GET /api/scans/{id}/report-data` returns findings + severity summary |
| Live stream | Works | WebSocket `{type,data}` with snapshot catch-up |

## What does not work (and is not claimed)

- **Authenticated scanning.** A credential can be stored but never used: no login
  executor exists and no cookie/header is injected into scan requests.
- **PDF export/download.** Both endpoints return `501`; the generator is empty.
- **Headless/browser engine.** The engine is a stub that returns an error.
- **RabbitMQ / worker autoscaling.** The broker path is refused at startup; the
  autoscaler is a no-op.
- **Nuclei template compatibility.** The engine runs its own small plugin format.
- **User management.** There is no users API; the only accounts are the bootstrap
  admin and rows inserted with SQL.
- **Audit trail.** The table and repository exist, but nothing writes to them.

## Architecture

```
api/            HTTP transport: handlers, router, WebSocket stream
internal/
  application/  use cases: scan, ticket, auth, credential, report
  domain/       entity, policy (RBAC + ownership), repository interfaces
  infrastructure/
    database/postgres/  GORM models and repositories
    crawler/            link discovery, robots, scope, dedupe
    detector/           plugin registry, matchers, HTTP executor, plugins/*.yaml
    scanner/            per-task engine (one plugin per task)
    worker/             bounded worker pool
    event/              in-memory pub/sub for the stream
  security/     ssrf guard, egress budget/rate limit, secretbox, passwd, loginguard
  middleware/   auth (JWT + revocation), CORS, security headers
orchestrator/   scan lifecycle, progress, reconciliation
main.go         composition root
```

Design rules that matter when changing this code:

1. The orchestrator is the single writer of findings; workers never touch the DB.
2. Every outbound request goes through the SSRF-guarded, budget-aware client.
3. Status changes go through the state machine (`UpdateStatus`), never a bare
   column update.
4. Ownership is enforced in the query (`FindByIDOwned`), not only in the handler.

## Quick start

```bash
docker-compose up -d postgres

export DATABASE_HOST=127.0.0.1
export JWT_SECRET="at-least-32-characters-long-change-me"
export CRED_ENC_KEY="separate-key-for-credential-encryption"
export ADMIN_USERNAME=admin
export ADMIN_PASSWORD='a-strong-password-8+'
export CORS_ALLOWED_ORIGINS="http://localhost:5173"

go run .
```

Server listens on `http://localhost:8080`. The schema is created by `AutoMigrate`
on boot (see the migration caveat below).

Local build caches, when `$HOME` is not writable:

```bash
export GOCACHE=$PWD/.gocache GOMODCACHE=$PWD/.gomodcache
export GOFLAGS=-mod=mod GOTOOLCHAIN=local GOTMPDIR=$PWD/.gotmp
```

## Configuration

The full table is in [docs/BACKEND-DEV.md](docs/BACKEND-DEV.md#environment). The
ones that change behaviour the most:

| Variable | Default | Effect |
|---|---|---|
| `JWT_SECRET` | random per boot | signing key; random means every restart logs everybody out |
| `CRED_ENC_KEY` | falls back to `JWT_SECRET` | credential encryption key; random fallback makes stored credentials unrecoverable |
| `JWT_TTL_MINUTES` | 15 | access-token lifetime |
| `ADMIN_PASSWORD` | empty | empty skips admin bootstrap entirely |
| `LOGIN_MAX_ATTEMPTS` | 5 | attempts per client+username per window |
| `LOGIN_MAX_IP_ATTEMPTS` | 100 | attempts per client across usernames (spraying) |
| `LOGIN_WINDOW_SECONDS` | 900 | throttle window |
| `LOGIN_MAX_CONCURRENCY` | `GOMAXPROCS` | simultaneous bcrypt verifications |
| `SSRF_ALLOW_PRIVATE` | false | never enable outside a lab |
| `SCAN_RATE_PER_SECOND` / `SCAN_RATE_BURST` | 5 / 10 | per-host outbound rate |
| `SCAN_MAX_REQUESTS_PER_TARGET` | 60 | request budget per target |
| `RABBITMQ_ENABLED` | false | setting it to true makes startup fail on purpose |

The login throttle is in-memory. It is correct for a single replica and can be
bypassed by spreading attempts across replicas.

## API

29 routes; the full table with behaviour is in
[docs/BACKEND-DEV.md](docs/BACKEND-DEV.md#4-endpoint). Everything under `/api`
requires `Authorization: Bearer <token>` except `POST /api/auth/login`.
`GET /health` is public and is a liveness check only: it does not verify the
database.

Errors are always `{"error":{"code":"...","message":"..."}}`.

## Security posture

Implemented:

- SSRF guard validates the resolved IP at dial time (defeats DNS rebinding) and
  re-validates scheme/port on every redirect hop.
- Per-host rate limiting and a per-scan request budget shared by crawler and
  detector.
- JWT: HS256 pinned, `alg:none` rejected, expiry required, issuer validated.
- Permissions are derived from the role on every request; the token cannot widen
  them, and a role change or deactivation applies immediately.
- Login throttling plus a bounded counter table (the limiter itself cannot be
  turned into a memory exhaustion vector).
- Passwords: bcrypt cost 12, uniform timing for unknown users.
- Credential secrets: AES-256-GCM, never returned to clients (`config` is
  redacted to `{"configured":true}`).
- Response bodies truncated at 2 MiB; request bodies at 1 MiB.

Known gaps (tracked, not hidden):

- Credential encryption key is not backed by a KMS and falls back to
  `JWT_SECRET`; rotating either makes existing ciphertext unreadable.
- `GET /api/scans/{id}/report-data` loads up to 5,000 findings without pagination.
- No foreign keys in the schema; deleting a scan does not clean up tickets.
- No audit trail, metrics, or structured logging.

## Testing

```bash
go vet ./...
go test ./... -count=1
```

Reality check:

- 10 test files carry `//go:build ignore` (119 test functions), including all
  JWT, user-repository, and credential-handler tests. They are not run by
  `go test ./...`.
- `test/e2e` (tag `e2e`) does not compile against current constructors.
- The PostgreSQL repositories have no running tests; API tests use in-memory
  fakes.
- No test ever contacts a real external target; everything is `httptest`.

## Schema migrations

`AutoMigrate` runs on boot and is the only mechanism today. It cannot rename or
drop columns, has no versions or rollback, and takes an `ACCESS EXCLUSIVE` lock.
Two replicas booting together race on DDL. Versioned migrations
(golang-migrate) are the next database task; `db/schema.sql` is stale and should
not be used.

## Documentation

| Document | Purpose |
|---|---|
| [docs/FEATURE-STATUS.md](docs/FEATURE-STATUS.md) | single source of truth for feature status |
| [docs/BACKEND-DEV.md](docs/BACKEND-DEV.md) | development contract: env, endpoints, rules |
| [CHANGELOG.md](CHANGELOG.md) | what changed, release by release |
| [docs/api.md](docs/api.md) | **historical**, superseded by BACKEND-DEV |
| [docs/prd.md](docs/prd.md), [docs/srs.md](docs/srs.md) | **historical requirements**, not normative |
| [docs/architecture.md](docs/architecture.md) | **historical** design notes |
| [docs/deployment.md](docs/deployment.md), [docs/testing.md](docs/testing.md) | partially stale; check BACKEND-DEV first |

## License

MIT.
