# Product Requirements (historical)

> **Dokumen historis, tidak normatif.** Beberapa fitur yang dijanjikan di sini
> (authenticated scanning, PDF report, headless engine, RabbitMQ, autoscaling)
> belum ada. Status nyata per fitur ada di
> [FEATURE-STATUS.md](FEATURE-STATUS.md); kontrak teknis di
> [BACKEND-DEV.md](BACKEND-DEV.md).

> **Product:** SentinelScan — DAST (Dynamic Application Security Testing) Engine
> **Version:** 1.0 (MVP)
> **Status:** Implemented (see milestones.md for completion status)

---

## 1. Product Vision

SentinelScan is an open-source DAST engine for authenticated vulnerability scanning with real-time result streaming and on-demand PDF reporting. Inspired by enterprise scanners (Tenable, Nessus) but designed for CI/CD pipelines and security teams that need fast, automated, and credential-aware scanning.

---

## 2. Target Users

| Persona | Primary Use Case |
|---------|-----------------|
| **Security Analyst** | Run authenticated scans, triage findings, export PDF reports |
| **DevOps Engineer** | Integrate scanning into CI/CD pipelines |
| **Penetration Tester** | Configure credential vault for authenticated testing |
| **Auditor** | Review scan history, download reports, verify compliance |
| **Admin** | Manage users, roles, system configuration |

---

## 3. Features

### 3.1 Implemented (Production)

| Feature | Description | Entry Point |
|---------|-------------|-------------|
| **Vulnerability Scanning** | Run scans against targets using Nuclei YAML templates | `orchestrator/orchestrator.go:47` |
| **Concurrent Worker Pool** | Configurable parallelism with in-memory or RabbitMQ-backed workers | `internal/infrastructure/worker/pool.go` |
| **Credential Vault (5 methods)** | M:N auth credentials: login_form, cookie, bearer, api_key, selenium | `internal/infrastructure/authscan/` |
| **Authenticated Scanning** | Session manager with health checker & automatic re-auth | `internal/infrastructure/authscan/session_manager.go` |
| **PDF Report Generation** | On-demand hybrid (HTML+chromedp) A4 PDF export | `internal/infrastructure/report/` |
| **Report Data API** | Structured JSON scan report aggregation | `api/handlers_extended.go:GetReportData` |
| **Real-time WebSocket Streaming** | Live scan result streaming | `orchestrator/orchestrator.go` (event bus) |
| **Template Management** | Load, filter, and execute Nuclei templates | `template/loader.go` |
| **PostgreSQL Persistence** | GORM-based ORM with AutoMigrate | `internal/infrastructure/database/postgres/` |
| **Event-Driven Architecture** | Decoupled pub/sub with RabbitMQ, fallback to in-memory | `event/bus.go`, `internal/infrastructure/event/bus.go` |
| **RBAC System** | 4 roles: admin, security_analyst, auditor, viewer | `internal/infrastructure/auth/` |
| **JWT Authentication** | HMAC-SHA256 JWT + bcrypt password hashing | `internal/infrastructure/auth/` |
| **RabbitMQ Messaging** | 3 exchanges, 7 queues, DLX, autoscaler, reconnect | `internal/infrastructure/messaging/` |
| **HTTP & Headless Engines** | HTTP engine (GET + keyword matching), chromedp for XSS/redirect detection | `internal/infrastructure/scanner/` |
| **API Router** | Single source of truth for all route definitions | `api/router.go` |
| **Custom Error Types** | AppError with HTTP status codes | `pkg/errors/errors.go` |
| **E2E Testing** | 14 domain-scoped E2E tests via httptest | `test/e2e/` |

### 3.2 Planned (Non-blocking)

| Feature | Target |
|---------|--------|
| Scan Scheduling (cron-based) | Future |
| Scope & Advanced Settings (include/exclude, rate limiting) | Future |
| API Scanning (OpenAPI-based fuzzing) | Future |
| CVE/NVD Integration | Future |
| EPSS (Exploit Prediction Scoring) | Future |

---

## 4. Technical Architecture

### 4.1 Layered Structure (DDD + Hexagonal)

```
api/                         → Transport layer (HTTP handlers, WebSocket)
internal/application/        → Application layer (use cases / services)
internal/domain/             → Domain layer (entities, repository interfaces)
internal/infrastructure/     → Infrastructure layer (GORM, RabbitMQ, chromedp, JWT)
orchestrator/                → Scan job coordination (task dispatch, progress tracking)
template/                    → Nuclei template loading and types
event/                       → In-memory event bus (pub/sub)
```

### 4.2 Key Decisions

- **Module path:** `github.com/inkubasi-btp-cybersecurity/vulnerability-scanner`
- **Dual messaging mode:** RabbitMQ primary with automatic graceful fallback to in-memory channels — no external dependency required for development/testing
- **Worker pools:** Separate HTTP and headless pools; configurable sizes; optional autoscaling when using RabbitMQ
- **Template engine:** Nuclei YAML templates, no Nuclei binary/library import — templates loaded as data then executed against targets via HTTP/headless engines
- **Authentication:** JWT (HMAC-SHA256) + bcrypt; middleware-based RBAC with 4 roles
- **PDF generation:** chromedp `Page.printToPDF` with HTML template rendering

### 4.3 Infrastructure Dependencies

| Service | Purpose | Docker Compose |
|---------|---------|----------------|
| PostgreSQL 16 | Primary data store | Included |
| RabbitMQ 4 | Message broker (optional; in-memory fallback) | Included |
| pgAdmin 4 | DB administration | Included |
| Chromium | Headless browser for PDF + scanner engine | Not in compose (configurable path) |

---

## 5. Data Model

Core entities (all persisted via GORM with AutoMigrate):

- **users** — username, email, password_hash, role, permissions (JSONB), profile
- **scan_jobs** — targets (JSONB), template_selectors (JSONB), status state machine, progress tracking
- **scan_results / findings** — scan_id, target, template_id, severity, details (JSONB)
- **auth_credentials** — user_id, method (5 types), config (JSONB per method), verify_url, verify_pattern
- **auth_sessions** — Managed in-memory by SessionManager
- **tickets** — created_by, assigned_to, title, description, severity, status
- **audit_logs** — user_id, level, category, action, message, metadata (JSONB)
- **templates** — template_id, name, severity, tags (JSONB), content
- **targets** — address, metadata (JSONB)

Full ERD: `thoughts/shared/diagrams/2026-05-04-erd.dbml`

---

## 6. API Surface

Base path: `/api`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/scans` | POST | Create & start scan |
| `/scans/{id}` | GET | Scan status & details |
| `/scans/{id}/results` | GET | Scan findings |
| `/scans/{id}/stream` | GET | WebSocket real-time stream |
| `/scans/{id}/report-data` | GET | Aggregated report data (JSON) |
| `/scans/{id}/report/export` | POST | Generate PDF report |
| `/scans/{id}/report/download` | GET | Download generated PDF |
| `/credentials` | GET/POST | List/create credentials |
| `/credentials/{id}` | GET/PUT/DELETE | Credential CRUD |
| `/credentials/{id}/verify` | POST | Test credential against target |
| `/templates` | GET | List templates (filterable) |
| `/templates/{id}` | GET | Template details |

Auth: Bearer JWT in `Authorization` header. RBAC enforced per endpoint.

---

## 7. Non-Functional Requirements

| Category | Requirement |
|----------|-------------|
| **Performance** | Default 50 workers; ~275 test functions; 10 benchmarks |
| **Concurrency** | Native goroutines + channels; separate HTTP/headless pools; optional autoscaling |
| **Reliability** | Task retry (configurable); RabbitMQ persistent queues + DLX; in-memory fallback |
| **Observability** | Audit logs; event bus publishing; structured logging |
| **Security** | JWT + bcrypt; RBAC (4 roles, granular permissions); credential secrets masked in responses |
| **Portability** | Single binary build (CGO disabled); Docker multi-stage design |
| **Testability** | Repository interfaces for mocking; in-memory SQLite for repository tests; `-short` for CI |

---

## 8. Development & Quality

### 8.1 Commands

| Action | Command |
|--------|---------|
| Build | `go build -o vulnscanner main.go` |
| Run | `go run main.go` |
| Unit tests | `go test ./...` |
| Race detector | `go test -race -count=1 ./...` |
| Coverage | `go test -coverprofile=coverage.out ./...` |
| Integration | `go test -tags=integration -count=1 ./test/integration/...` |
| E2E (all) | `go test -tags=e2e -count=1 ./test/e2e/...` |
| E2E per domain | `go test -tags=e2e -count=1 -v ./test/e2e/scans/...` |
| Benchmarks | `go test -bench=. -benchmem ./test/benchmarks/...` |
| Vet | `go vet ./...` |
| Format | `gofmt -w .` |
| Lint | `golangci-lint run` |

### 8.2 Test Stats

- ~290 test functions, 10 benchmarks, ~65 test files
- All 23 non-main packages pass `go vet ./...`
- Integration tests gated behind `//go:build integration` tag
- E2E tests (14 tests across 6 domain folders) gated behind `//go:build e2e` tag

---

## 9. Current Gaps (Non-blocking)

Based on actual codebase analysis:

| Gap | Reason |
|-----|--------|
| `cmd/migrate/` not present | Referenced in README but not implemented |
| `migrations/` not present | GORM AutoMigrate handles schema; no SQL migration files |
| `internal/domain/service/` empty | No production code yet |

---

## 10. Success Metrics

| Metric | Target | Current |
|--------|--------|---------|
| Test coverage | 80%+ | ~50-60% avg across packages |
| Test functions | 300+ | ~275 |
| Benchmarks | 15+ | 10 |
| Packages passing vet | All | 23/23 |
