# Software Requirements (historical)

> **Dokumen historis, tidak normatif.** Requirement di sini tidak semuanya
> diimplementasikan; jangan jadikan dasar klaim ke pengguna. Status per fitur ada
> di [FEATURE-STATUS.md](FEATURE-STATUS.md), kontrak yang berlaku di
> [BACKEND-DEV.md](BACKEND-DEV.md).

> **Version:** 1.0
> **Status:** Draft
> **Last Updated:** 2026-05-30

---

## 1. Introduction

### 1.1 Purpose

SentinelScan is a DAST (Dynamic Application Security Testing) engine that performs automated vulnerability scanning against web targets using Nuclei YAML templates. It supports authenticated scanning via a credential vault, real-time result streaming via WebSocket, and on-demand PDF report generation.

### 1.2 Scope

This SRS covers the backend API service only. It does not cover:
- Frontend web UI (separate repository)
- Nuclei template authorship
- CI/CD pipeline integration
- Mobile or desktop clients

### 1.3 Definitions

| Term | Definition |
|------|------------|
| DAST | Dynamic Application Security Testing |
| Nuclei | YAML-based vulnerability template engine by ProjectDiscovery |
| Finding | A detected vulnerability or security issue |
| Credential Vault | M:N reusable auth credentials for authenticated scanning |
| Session Manager | In-memory manager for auth sessions with health checking |
| RBAC | Role-Based Access Control (4 roles) |
| Event Bus | In-memory pub/sub for real-time events |
| Orchestrator | Component that coordinates scan lifecycle |
| Worker Pool | Configurable goroutine pool for parallel task execution |

---

## 2. Overall Description

### 2.1 Product Perspective

SentinelScan is part of a larger application security platform. The backend exposes a REST API consumed by a frontend web application. It operates as a standalone Go binary with PostgreSQL for persistence and optional RabbitMQ for message brokering.

### 2.2 User Classes

| Class | Description |
|-------|-------------|
| Admin | Full system access, user management, all CRUD operations |
| Security Analyst | Create scans, manage credentials, triage findings, manage tickets |
| Auditor | View-only access to scans, results, credentials |
| Viewer | Limited view access (specific scans or targets) |

### 2.3 Operating Environment

- **Runtime:** Go 1.21+ binary, Linux/amd64 primary target
- **Database:** PostgreSQL 12+
- **Message Broker:** RabbitMQ 3.x+ (optional, graceful fallback)
- **Headless Browser:** Chromium (optional, for PDF generation + headless scanning)
- **Deployment:** Docker container (multi-stage build), bare metal, or VM

### 2.4 Design and Implementation Constraints

- Go 1.21+ with idiomatic patterns
- PostgreSQL + GORM for persistence
- gorilla/mux for HTTP routing
- gorilla/websocket for real-time streaming
- spf13/viper for configuration
- JWT (HMAC-SHA256) for authentication
- bcrypt for password hashing
- testify/mock for testing
- gopkg.in/yaml.v3 for YAML parsing
- chromedp/cdproto for headless Chrome automation

---

## 3. Functional Requirements

### 3.1 Vulnerability Scanning

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-01 | The system shall accept scan requests with one or more target URLs | High | ✅ Implemented |
| FR-02 | The system shall load and execute Nuclei YAML templates against targets | High | ✅ Implemented |
| FR-03 | The system shall support template filtering by severity and tags | Medium | ⚠️ Partial |
| FR-04 | The system shall support template filtering by template IDs | Medium | ⚠️ Partial |
| FR-05 | The system shall track scan progress (total, completed, failed, in-progress) | High | ✅ Implemented |
| FR-06 | The system shall support cancelling a running scan | Medium | ❌ Pending |
| FR-07 | The system shall persist scan jobs and findings to PostgreSQL | High | ✅ Implemented |
| FR-08 | The system shall update scan status through states: pending → running → completed/failed | High | ✅ Implemented |

### 3.2 Authentication & Authorization

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-09 | The system shall authenticate users via username/password with bcrypt hashing | High | ⚠️ Test only |
| FR-10 | The system shall issue JWT tokens (HMAC-SHA256) upon successful authentication | High | ⚠️ Test only |
| FR-11 | The system shall validate JWT tokens on protected endpoints | High | ⚠️ Test only |
| FR-12 | The system shall enforce RBAC with 4 roles: admin, security_analyst, auditor, viewer | High | ⚠️ Test only |
| FR-13 | The system shall support granular permission checks per endpoint | Medium | ⚠️ Test only |

### 3.3 Credential Vault

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-14 | The system shall support 5 auth methods: login_form, cookie, bearer, api_key, selenium | High | ⚠️ Test only |
| FR-15 | The system shall store credentials with secrets masked in API responses | High | ⚠️ Test only |
| FR-16 | The system shall manage M:N credential-to-scan relationships | High | ⚠️ Test only |
| FR-17 | The system shall verify credential health with configurable intervals | Medium | ⚠️ Test only |
| FR-18 | The system shall automatically re-authenticate when sessions expire | Medium | ⚠️ Test only |
| FR-19 | The system shall support credential CRUD operations | High | ⚠️ Test only |

### 3.4 Real-Time Streaming

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-20 | The system shall stream findings via WebSocket as they are detected | High | ⚠️ Test only |
| FR-21 | The system shall stream progress updates via WebSocket | High | ✅ Implemented |
| FR-22 | The system shall stream scan complete/failed events via WebSocket | High | ✅ Implemented |
| FR-23 | The system shall support multiple concurrent WebSocket connections per scan | Medium | ✅ Implemented |
| FR-24 | The system shall clean up disconnected WebSocket subscribers | Medium | ✅ Implemented |

### 3.5 Report Generation

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-25 | The system shall generate PDF scan reports on demand | High | ⚠️ Test only |
| FR-26 | The system shall return structured JSON report data | High | ⚠️ Test only |
| FR-27 | PDF reports shall use A4 format with severity breakdown | Medium | ⚠️ Test only |
| FR-28 | PDF reports shall be cached on disk for subsequent downloads | Medium | ⚠️ Test only |
| FR-29 | The system shall generate reports via headless Chrome (chromedp Page.printToPDF) | High | ⚠️ Test only |

### 3.6 Template Management

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-30 | The system shall load Nuclei YAML templates from a configurable directory | High | ✅ Implemented |
| FR-31 | The system shall list available templates | Medium | ✅ Implemented |
| FR-32 | The system shall filter templates by type to route to appropriate engine (HTTP vs headless) | High | ✅ Implemented |
| FR-33 | The system shall call engine type from template `EngineType()` | High | ✅ Implemented |

### 3.7 Worker & Orchestration

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-34 | The system shall maintain a configurable worker pool for task execution | High | ✅ Implemented |
| FR-35 | The system shall support separate HTTP and headless worker pools | High | ✅ Implemented |
| FR-36 | The system shall support optional autoscaling of worker pools (RabbitMQ mode) | Medium | ✅ Implemented |
| FR-37 | The system shall retry failed tasks up to a configurable limit | Medium | ✅ Implemented |
| FR-38 | The system shall dispatch tasks to RabbitMQ when available, otherwise in-memory channels | High | ✅ Implemented |
| FR-39 | The orchestrator shall coordinate scan lifecycle from dispatch to completion | High | ✅ Implemented |
| FR-40 | The system shall track progress in-memory and persist to database | High | ✅ Implemented |

### 3.8 Event System

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-41 | The system shall provide an in-memory event bus with pub/sub semantics | High | ✅ Implemented |
| FR-42 | The system shall support event types: finding, progress, complete, failed | High | ✅ Implemented |
| FR-43 | The event bus shall use non-blocking publish with backpressure handling | Medium | ✅ Implemented |
| FR-44 | The system shall publish events to RabbitMQ when available | High | ✅ Implemented |

### 3.9 Scanning Engines

| ID | Requirement | Priority | Status |
|----|-------------|----------|--------|
| FR-45 | The HTTP engine shall execute GET requests against targets | High | ✅ Implemented |
| FR-46 | The HTTP engine shall perform keyword matching on responses | High | ✅ Implemented |
| FR-47 | The headless engine shall use chromedp for JavaScript-enabled scanning | High | ⚠️ Test only |
| FR-48 | The headless engine shall detect XSS vulnerabilities | Medium | ⚠️ Test only |
| FR-49 | The headless engine shall detect open redirect vulnerabilities | Medium | ⚠️ Test only |
| FR-50 | The headless engine shall detect web frameworks from responses | Low | ⚠️ Test only |
| FR-51 | The headless engine shall extract form structures from pages | Low | ⚠️ Test only |

---

## 4. Non-Functional Requirements

### 4.1 Performance

| ID | Requirement | Target |
|----|-------------|--------|
| NFR-01 | Default worker pool size | 50 concurrent workers |
| NFR-02 | Headless worker pool size | 10 concurrent workers |
| NFR-03 | In-memory task queue capacity | 1000 tasks |
| NFR-04 | Event bus channel buffer | 10 events per subscriber |
| NFR-05 | Task timeout | 30 seconds (configurable) |
| NFR-06 | HTTP engine timeout | 15 seconds (configurable) |
| NFR-07 | Max task retries | 3 (configurable) |

### 4.2 Reliability

| ID | Requirement | Implementation |
|----|-------------|----------------|
| NFR-08 | RabbitMQ connection retry with exponential backoff | ✅ Implemented |
| NFR-09 | Graceful fallback from RabbitMQ to in-memory channels | ✅ Implemented |
| NFR-10 | Task-level retry for transient failures | ✅ Implemented |
| NFR-11 | RabbitMQ DLX (Dead Letter Exchange) for failed messages | ✅ Implemented |
| NFR-12 | PostgreSQL health checks in docker-compose | ✅ Implemented |
| NFR-13 | Non-blocking event bus (skip slow subscribers) | ✅ Implemented |

### 4.3 Security

| ID | Requirement | Implementation |
|----|-------------|----------------|
| NFR-14 | Password hashing with bcrypt | ⚠️ Test only |
| NFR-15 | JWT authentication with HMAC-SHA256 | ⚠️ Test only |
| NFR-16 | RBAC with 4 roles (admin, security_analyst, auditor, viewer) | ⚠️ Test only |
| NFR-17 | Credential secrets masked in API responses | ⚠️ Test only |
| NFR-18 | Template ID path traversal protection (sanitize `../` and `/`) | ✅ Implemented |
| NFR-19 | No hardcoded secrets in production config | ✅ Config via env vars |

### 4.4 Maintainability

| ID | Requirement | Implementation |
|----|-------------|----------------|
| NFR-20 | Layered architecture (DDD + hexagonal) | ✅ Implemented |
| NFR-21 | Interface-based abstractions for testability | ⚠️ Partial |
| NFR-22 | Repository pattern for data access | ⚠️ Partial |
| NFR-23 | Configuration via Viper (YAML + env vars) | ✅ Implemented |
| NFR-24 | AutoMigrate for schema management | ✅ Implemented |

### 4.5 Testability

| ID | Requirement | Implementation |
|----|-------------|----------------|
| NFR-25 | Unit tests with testify mocks | ✅ ~275 test functions |
| NFR-26 | Race detector support (`-race`) | ✅ 23/23 packages pass |
| NFR-27 | Integration tests behind build tag | ✅ 13 integration tests |
| NFR-28 | Benchmarks for performance-critical paths | ✅ 10 benchmarks |

---

## 5. External Interface Requirements

### 5.1 REST API

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/health` | GET | No | Health check |
| `/api/scans` | POST | JWT | Create and start scan |
| `/api/scans/{id}` | GET | JWT | Get scan status |
| `/api/scans/{id}/results` | GET | JWT | Get scan findings |
| `/api/scans/{id}/stream` | GET | JWT | WebSocket real-time stream |
| `/api/scans/{id}/report-data` | GET | JWT | Aggregated report JSON |
| `/api/scans/{id}/report/export` | POST | JWT | Generate PDF report |
| `/api/scans/{id}/report/download` | GET | JWT | Download PDF report |
| `/api/credentials` | GET/POST | JWT | List/create credentials |
| `/api/credentials/{id}` | GET/PUT/DELETE | JWT | Credential CRUD |
| `/api/credentials/{id}/verify` | POST | JWT | Test credential |
| `/api/templates` | GET | JWT | List templates |
| `/api/templates/{id}` | GET | JWT | Get template details |

### 5.2 WebSocket Protocol

Connection: `ws://host:port/api/scans/{id}/stream`

**Server → Client events (JSON):**

| Type | Payload | Description |
|------|---------|-------------|
| `finding` | `{target, template_id, matched, severity, details}` | Vulnerability found |
| `progress` | `{completed, total}` | Progress update |
| `complete` | `{scan_id}` | Scan finished |
| `failed` | `{scan_id, error}` | Scan failed |

### 5.3 Database Schema

Managed via GORM AutoMigrate. Entities:

- **users** — Authentication and RBAC
- **scan_jobs** — Scan configuration and status
- **scan_results / findings** — Detected vulnerabilities
- **auth_credentials** — Credential vault entries
- **auth_sessions** — In-memory session management
- **tickets** — Remediation tickets
- **audit_logs** — System audit trail
- **templates** — Nuclei template metadata
- **targets** — Target URL registry
- **scan_targets** — Many-to-many junction

Full ERD: `thoughts/shared/diagrams/2026-05-04-erd.dbml`

---

## 6. Implementation Status Summary

### 6.1 Fully Implemented (Production Source Code Exists)

- Config loading (Viper + YAML + env vars) — `config/config.go`
- Database connection and models — `db/connection.go`, `db/models.go`
- Event bus (in-memory pub/sub) — `event/bus.go`
- Base-level event bus in infrastructure — `internal/infrastructure/event/bus.go`
- Worker pool (in-memory + RabbitMQ) — `internal/infrastructure/worker/pool.go`
- Worker task types — `internal/infrastructure/worker/task.go`
- Template loader and types — `template/loader.go`, `template/types.go`
- Scan orchestrator — `orchestrator/orchestrator.go`
- HTTP handlers (interfaces + create/get/results) — `api/handlers.go`
- Worker task types (simplified) — `worker/task.go`
- Fingerprint/detection — `detection/fingerprint.go`
- Application wiring and server startup — `main.go`

### 6.2 Test-Only (Implementation Pending)

These packages have test files but **no corresponding production source code**:

| Package | Tests Exist | Source Missing |
|---------|-------------|----------------|
| `internal/domain/entity/` | ✅ `auth_entity_test.go` | Entity types (AuthCredential, AuthSession, ScanReportData) |
| `internal/application/auth/` | ✅ `service_test.go` | Auth service (Register, Login, GetUserByID) |
| `internal/infrastructure/auth/` | ✅ `jwt_test.go` | JWT token generation and validation |
| `internal/infrastructure/database/postgres/` | ✅ `user_repository_test.go` | User repository implementation |
| `internal/infrastructure/messaging/` | ✅ `messaging_test.go` | RabbitMQ connection, publishers, consumers |
| `internal/infrastructure/report/` | ✅ `generator_test.go` | PDF report generator |
| `internal/infrastructure/scanner/` | ✅ `headless_engine_test.go` | HTTP engine, headless engine |
| `api/` | ✅ `websocket_test.go` | WebSocket handler |
| `api/` | ✅ `handlers_extended_test.go` | Credential, report, ticket handlers |

### 6.3 Not Yet Started

| Package | Required For |
|---------|-------------|
| `internal/domain/repository/` | Repository interfaces (Scan, Finding, Ticket, User, etc.) |
| `internal/infrastructure/authscan/` | Session manager, credential executors |
| `internal/application/` | Scan service, ticket service, report service, credential service |
| `pkg/errors/` | Custom error types (AppError) |
| `cmd/migrate/` | Migration CLI tool |
| `migrations/` | SQL migration files |

---

## 7. Configuration Reference

### 7.1 Environment Variables

All config values use `_` as separator (e.g. `SERVER_PORT` maps to `server.port`).

| Variable | Default | Description |
|----------|---------|-------------|
| `SERVER_HOST` | `localhost` | Server bind host |
| `SERVER_PORT` | `8080` | Server bind port |
| `DATABASE_HOST` | `localhost` | PostgreSQL host |
| `DATABASE_PORT` | `5432` | PostgreSQL port |
| `DATABASE_USER` | `postgres` | PostgreSQL user |
| `DATABASE_PASSWORD` | `postgres` | PostgreSQL password |
| `DATABASE_DBNAME` | `vulnscanner` | PostgreSQL database name |
| `DATABASE_SSLMODE` | `disable` | PostgreSQL SSL mode |
| `WORKER_SIZE` | `50` | Worker pool size |
| `WORKER_MAXRETRIES` | `3` | Max task retries |
| `WORKER_TASKTIMEOUT` | `30` | Task timeout (seconds) |
| `TEMPLATE_DIR` | `./templates` | Nuclei templates directory |
| `SCANNER_CHROMIUM_PATH` | `""` | Chromium binary path |
| `SCANNER_TIMEOUT_SEC` | `15` | Scanner timeout per request |
| `SCANNER_HEADLESS_SIZE` | `10` | Headless worker pool size |
| `RABBITMQ_HOST` | `localhost` | RabbitMQ host |
| `RABBITMQ_PORT` | `5672` | RabbitMQ port |
| `RABBITMQ_USER` | `admin` | RabbitMQ user |
| `RABBITMQ_PASSWORD` | `admin` | RabbitMQ password |

### 7.2 YAML Config File

Optional `config.yaml` loaded from current directory or `./config/`. See `config.yaml` in repository root for full example.

---

## 8. Data Flow — Standard Scan

```
Client → POST /api/scans {targets, template_selectors, auth_credential_id?}
  → Handler.CreateScan()
    → ScanService.StartScan() — persist to DB [status: pending]
    → [optional] SessionManager.StartSession() — authenticate + health check
    → Orchestrator.StartScan()
      → TemplateLoader.List() — load all templates
      → Create tasks (target × template) → enqueue to task queue / RabbitMQ
      → Update status to "running"
  → Worker Pool
    → ResolveSession() — attach cookies/headers from session
    → HTTPEngine / HeadlessEngine — execute task against target
    → FindingRepository.CreateBatch() — persist findings
    → EventBus.Publish() — stream to WebSocket clients
  → All tasks complete → status → "completed"
```

---

## 9. Assumptions and Dependencies

### 9.1 Assumptions

- PostgreSQL is available at configured endpoint (or AutoMigrate will fail)
- Nuclei templates are cloned to `./templates/` directory
- Chromium binary is available if using headless engine or PDF generation
- RabbitMQ is optional; system degrades gracefully to in-memory channels

### 9.2 External Dependencies

| Dependency | Purpose | License |
|-----------|---------|---------|
| gorilla/mux | HTTP routing | BSD-3 |
| gorilla/websocket | WebSocket support | BSD-3 |
| spf13/viper | Configuration management | Apache 2.0 |
| gorm.io/gorm | ORM | MIT |
| gorm.io/driver/postgres | PostgreSQL driver | MIT |
| gorm.io/datatypes | JSON data types | MIT |
| stretchr/testify | Testing framework | MIT |
| gopkg.in/yaml.v3 | YAML parsing | Apache 2.0 |
| chromedp | Headless Chrome automation | MIT |
| cdproto | Chrome DevTools Protocol | MIT |
| rabbitmq/amqp091-go | AMQP 0-9-1 client | MIT |

### 9.3 Development Dependencies

| Dependency | Purpose |
|-----------|---------|
| golangci-lint | Linting |
| gofmt | Code formatting |
| Go test -race | Race detection |
