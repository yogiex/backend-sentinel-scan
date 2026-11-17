# Architecture (historical)

> **Dokumen historis.** Diagram dan komponen di sini menggambarkan rencana, bukan
> kondisi sekarang: chromedp/RabbitMQ/autoscaler tidak aktif, engine headless
> masih stub, dan PDF belum ada. Susunan paket yang sebenarnya ada di README dan
> [BACKEND-DEV.md](BACKEND-DEV.md); status fitur di
> [FEATURE-STATUS.md](FEATURE-STATUS.md).

> **Pattern:** Domain-Driven Design (DDD) + Hexagonal Architecture
> **Language:** Go 1.21+
> **Module:** `github.com/inkubasi-btp-cybersecurity/vulnerability-scanner`

---

## 1. Layer Overview

```
┌────────────────────────────────────────────────────────┐
│                    API Layer                            │
│  api/ — HTTP handlers, routes, WebSocket               │
├────────────────────────────────────────────────────────┤
│                Application Layer                        │
│  internal/application/ — Use cases, services           │
├────────────────────────────────────────────────────────┤
│                  Domain Layer                           │
│  internal/domain/ — Entities, repository interfaces    │
├────────────────────────────────────────────────────────┤
│              Infrastructure Layer                       │
│  internal/infrastructure/ — GORM, RabbitMQ, chromedp,  │
│                              JWT, scanner engines       │
├────────────────────────────────────────────────────────┤
│              External Integrations                      │
│  PostgreSQL / RabbitMQ / chromedp / Nuclei templates    │
└────────────────────────────────────────────────────────┘
```

---

## 2. Package Map

### 2.1 Root Packages

| Package | Role |
|---------|------|
| `main.go` | Entry point — wires all dependencies, starts HTTP server |
| `config/` | Viper-based configuration loader (YAML + env vars) |
| `event/` | In-memory event bus (pub/sub for real-time streaming) |
| `worker/` | Task/Result types for in-memory worker pool |
| `template/` | Nuclei YAML template loader and type definitions |
| `orchestrator/` | Scan lifecycle coordinator (dispatch, progress, completion) |
| `detection/` | Simple HTTP fingerprinting |
| `db/` | Legacy database connection (superseded by `internal/infrastructure/database/`) |
| `api/` | HTTP handlers, route definitions (router.go), WebSocket |

### 2.2 Internal Packages

```
internal/
├── domain/
│   ├── entity/        — Domain entities (AuthCredential, AuthSession, ScanReportData)
│   └── repository/    — Repository interfaces (Scan, Finding, Ticket, User, etc.)
├── application/
│   └── application.go — Stub services (ScanService, AuthService, ReportService, etc.)
└── infrastructure/
    ├── auth/          — JWT + bcrypt (test-only)
    ├── authscan/      — Session manager + credential executors (stub)
    ├── database/
    │   └── postgres/  — GORM models + repository implementations (stub)
    ├── event/         — Infrastructure event bus (same pattern as root event/)
    ├── messaging/     — RabbitMQ connection, publishers, consumers (stub)
    ├── report/        — PDF report generator (stub)
    ├── scanner/       — HTTP engine + Headless engine (stub)
    └── worker/        — Worker pool (in-memory + RabbitMQ modes)

**Note:** Several infrastructure packages are stubs (compile only, no real logic).
Application services return canned/empty data. See `srs.md §6.2` for details.

---

## 3. Component Details

### 3.1 Config Loader

**File:** `config/config.go`

Loads configuration via Viper with priority:
1. Environment variables (e.g. `SERVER_PORT`)
2. `config.yaml` file (optional, searched in `.` and `./config/`)
3. Hardcoded defaults

Env vars use `_` as separator (e.g. `DATABASE_HOST` maps to `database.host`).

### 3.2 Event Bus

**Files:** `event/bus.go`, `internal/infrastructure/event/bus.go`

In-memory pub/sub with:
- `Subscribe(scanID) → chan Event`
- `Unsubscribe(scanID, ch)`
- `Publish(scanID, Event)` — non-blocking, skips full channels
- Convenience methods: `PublishFinding`, `PublishProgress`, `PublishComplete`

Event types: `finding`, `progress`, `complete`, `failed`

### 3.3 Template Loader

**File:** `template/loader.go`

- Scans a directory recursively for `.yaml` files
- Parses each with `gopkg.in/yaml.v3`
- Returns `[]*NucleiTemplate` with ID, Name, Severity, Tags
- Path traversal protection on `Get(templateID)`
- Creates template directory if it doesn't exist

### 3.4 Worker Pool

**File:** `internal/infrastructure/worker/pool.go`

Two modes:
1. **In-memory mode:** goroutine pool consuming from `chan Task`, publishing to `chan Result`, publishing events to `event.Bus`
2. **RabbitMQ mode:** `HandleTask()` method called by `TaskConsumer`, publishing events via `messaging.EventPublisher`

Features:
- Configurable pool size
- Session injection from `SessionManager`
- Engine routing (HTTP vs headless)
- Event publishing on matched findings
- Autoscaler support (RabbitMQ mode)

### 3.5 Orchestrator

**File:** `orchestrator/orchestrator.go`

Scan lifecycle manager:
- `StartScan()` — load templates, compute tasks (target × template), enqueue to task queue or RabbitMQ, update status to "running"
- `CompleteTask()` — update progress counters, persist to DB, transition to "completed" when all done
- `StartDispatchLoop()` — background goroutine consuming `ResultQueue` and calling `CompleteTask`

### 3.6 Scanner Engines

**Files:** `internal/infrastructure/scanner/` (tests only — source pending)

| Engine | Type | Capability |
|--------|------|------------|
| HTTP | Synchronous | GET request + keyword matching against response body/headers |
| Headless | chromedp-based | XSS detection, open redirect detection, framework fingerprinting, form extraction |

### 3.7 RabbitMQ Messaging

**File:** `internal/infrastructure/messaging/` (tests only — source pending)

Topology (defined in `deployments/rabbitmq/definitions.json`):
- **3 exchanges:** `tasks` (direct), `events` (topic), `dlx` (direct)
- **7 queues:** `tasks.http`, `tasks.headless`, `tasks.retry.http` (with TTL), `tasks.retry.headless` (with TTL), `dlq.http`, `dlq.headless`, `events.persist`
- **Dead Letter Exchange** for failed messages
- Configurable prefetch, heartbeat, connection timeout, retry

### 3.8 HTTP API Handlers

**Files:** `api/handlers.go`, `api/handlers_extended.go`, `api/router.go`

- `handlers.go` — core scan/template handlers + interface definitions
- `handlers_extended.go` — credential vault CRUD + report/WebSocket handlers
- `router.go` — single-source-of-truth route registration via `NewRouter()`

Uses interface-based dependency injection:
- `ScanServiceInterface` — scan CRUD operations
- `TicketServiceInterface` — ticket CRUD
- `AuthServiceInterface` — authentication + permission checks
- `AuthCredentialServiceInterface` — credential vault CRUD
- `ReportServiceInterface` — report data aggregation

Builder pattern via `WithSessionManager()`, `WithReportService()`, `WithEventConsumer()`.

---

## 4. Data Flow

### 4.1 Standard Scan

```
Client POST /api/scans { targets, template_selectors, auth_credential_id? }
  → Handler.CreateScan()
    → persist ScanJob [status: "pending"]
    → [optional] start auth session via SessionManager
    → Orchestrator.StartScan()
      → TemplateLoader.List() — load Nuclei templates
      → Create tasks (target × template)
      → Enqueue to task queue (in-memory) or RabbitMQ
      → Update ScanJob [status: "running"]
  → Worker Pool
    → resolveSession() — attach cookies/headers
    → HTTPEngine / HeadlessEngine — execute
    → FindingRepository.CreateBatch()
    → EventBus.Publish(finding/progress)
  → WebSocket streams to clients
  → All done → status → "completed"
```

### 4.2 Messaging Mode Selection (`main.go:132-212`)

```
RabbitMQ available?
  ├── YES → Start RabbitMQ workers, publishers, consumers
  │         Optionally: start AutoScaler
  └── NO  → Create in-memory task + result channels
            Start in-memory worker pool
```

### 4.3 Event Flow

```
Scanner Engine detects finding
  → Worker Pool publishes to EventBus
    → WebSocket subscriber receives and streams to client
  → (Optional) RabbitMQ EventPublisher broadcasts to `events` exchange
    → EventConsumer processes and persists
```

---

## 5. Configuration Structure

```
config.yaml (optional)
  ├── server        — {host, port}
  ├── database      — {host, port, user, password, dbname, sslmode}
  ├── rabbitmq      — {host, port, user, password, vhost, prefetch, heartbeat, ...}
  ├── worker        — {size, max_retries, task_timeout, autoscale}
  ├── scanner       — {chromium_path, timeout_sec, headless_size}
  ├── authscan      — {session_check_interval, verify_timeout, max_retries}
  ├── report        — {output_dir}
  └── template      — {dir}
```

All values overridable via environment variables with `_` separator.

---

## 6. Implementation Status

| Component | Source | Tests | Status |
|-----------|--------|-------|--------|
| Config loader | ✅ | ✅ | Production |
| Event bus (in-memory) | ✅ | ✅ | Production |
| Template loader | ✅ | ✅ | Production |
| Worker pool | ✅ | — | Production |
| Orchestrator | ✅ | ✅ | Production |
| HTTP API handlers | ✅ | ✅ | Production |
| API router | ✅ | — | Production |
| Domain entities | ✅ | ✅ | Stub + tests |
| Repository interfaces | ✅ | — | Stub |
| Application services | ✅ | — | Stub |
| JWT auth | — | ✅ | Test-only |
| Scanner engines | ✅ | ✅ | Stub + tests |
| RabbitMQ messaging | ✅ | ✅ | Stub + tests |
| PDF report generator | ✅ | ✅ | Stub + tests |
| Session manager | ✅ | — | Stub |
| Credential executors | ✅ | — | Stub |
| GORM repositories | ✅ | — | Stub |
| pkg/errors | ✅ | — | Stub |
| E2E tests (14 tests) | — | ✅ | Production |

See `srs.md §6` for detailed breakdown.
