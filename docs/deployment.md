# SentinelScan Backend — Deployment Guide

---

## 1. Prerequisites

- Go 1.21+ (build only)
- Docker + Docker Compose v2 (infrastructure services)
- PostgreSQL 12+ (production — alternatively use compose)
- RabbitMQ 3.x+ (optional — system degrades gracefully)
- Chromium (optional — needed for headless scanning and PDF generation)
- Nuclei templates: `git clone https://github.com/projectdiscovery/nuclei-templates.git ./templates`

---

## 2. Quick Start (Development)

### 2.1 Initialize Go Module

```bash
go mod init github.com/inkubasi-btp-cybersecurity/vulnerability-scanner
go mod tidy
```

### 2.2 Start Infrastructure

```bash
docker compose up -d
```

Starts:
- **PostgreSQL** on `localhost:5432`
- **pgAdmin** on `localhost:5050` (email: `admin@sentinel.local`, password: `admin`)
- **RabbitMQ** on `localhost:5672` (AMQP) + `localhost:15672` (management UI)

### 2.3 Configure Environment

```bash
# Option A: Export env vars
export SERVER_HOST=0.0.0.0
export SERVER_PORT=8080
export DATABASE_HOST=localhost
export DATABASE_PORT=5432
export DATABASE_USER=postgres
export DATABASE_PASSWORD=postgres
export DATABASE_DBNAME=vulnscanner

# Option B: Use .env file (requires manual export)
cp deployments/development/.env.example .env
export $(grep -v '^#' .env | xargs)
```

### 2.4 Download Nuclei Templates

```bash
git clone https://github.com/projectdiscovery/nuclei-templates.git ./templates
```

### 2.5 Run Application

```bash
go run main.go
```

Server starts on `http://localhost:8080`.

---

## 3. Build

### 3.1 Standard Build

```bash
go build -o vulnscanner main.go
```

### 3.2 Build with Version Info

```bash
go build -ldflags "-X main.Version=$(git describe --tags)" -o vulnscanner main.go
```

### 3.3 Cross-Compilation

```bash
GOOS=linux GOARCH=amd64 go build -o vulnscanner-linux-amd64 main.go
GOOS=linux GOARCH=arm64 go build -o vulnscanner-linux-arm64 main.go
```

---

## 4. Docker Deployment

### 4.1 Current State

The `docker-compose.yml` in the repository root provides **infrastructure only** (PostgreSQL, pgAdmin, RabbitMQ). The Go application must be run separately or added to compose.

### 4.2 Adding the App to Compose

```yaml
services:
  # ... existing postgres, pgadmin, rabbitmq ...

  sentinel-backend:
    build:
      context: .
      dockerfile: Dockerfile  # (not yet created)
    ports:
      - "8080:8080"
    environment:
      SERVER_HOST: "0.0.0.0"
      DATABASE_HOST: postgres
      DATABASE_USER: postgres
      DATABASE_PASSWORD: postgres
      DATABASE_DBNAME: vulnscanner
      RABBITMQ_HOST: rabbitmq
      SCANNER_CHROMIUM_PATH: /usr/bin/chromium
    depends_on:
      postgres:
        condition: service_healthy
    restart: unless-stopped
```

### 4.3 Multi-Stage Dockerfile (Reference Design)

A multi-stage Dockerfile is planned at `deployments/shared/Dockerfile.base`:

```
Stage 1 (builder):   golang:1.25-alpine → CGO_ENABLED=0 go build
Stage 2 (runtime):   alpine:3.20 → copy binary, CA certs, run as non-root UID 1000
```

---

## 5. Production Considerations

### 5.1 Environment Variables

Set via secure mechanism (Docker secrets, Kubernetes Secrets, Vault, etc.):

```bash
SERVER_HOST=0.0.0.0
SERVER_PORT=8080
DATABASE_HOST=<production-db-host>
DATABASE_PORT=5432
DATABASE_USER=<db-user>
DATABASE_PASSWORD=<db-password>
DATABASE_DBNAME=vulnscanner
DATABASE_SSLMODE=require
WORKER_SIZE=100
SCANNER_TIMEOUT_SEC=30
RABBITMQ_HOST=<rabbitmq-host>
```

### 5.2 Resource Allocation

| Component | vCPU | Memory | Storage |
|-----------|------|--------|---------|
| SentinelScan (100 workers) | 2 | 2 GB | 100 MB |
| PostgreSQL 16 | 2 | 4 GB | 50 GB+ |
| RabbitMQ 4 | 1 | 1 GB | 10 GB |
| Chromium (headless) | 2 | 2 GB | 500 MB |

### 5.3 Secrets Management

- **Development:** Environment variables
- **Production:** Docker secrets or Kubernetes Secrets
- Never commit secrets to the repository
- `.env.example` provides the shape only

### 5.4 Health Checks

The server exposes `GET /health` returning `{"status": "healthy"}`.

---

## 6. Configuration Reference

### 6.1 Priority Order

1. Environment variables (highest)
2. `config.yaml` file
3. Hardcoded defaults (lowest)

### 6.2 Key Configuration

| Setting | Default | Description |
|---------|---------|-------------|
| `server.host` | `localhost` | Bind address |
| `server.port` | `8080` | Bind port |
| `worker.size` | `50` | Worker pool size |
| `worker.maxretries` | `3` | Task retry limit |
| `worker.tasktimeout` | `30` | Task timeout (seconds) |
| `scanner.timeout_sec` | `15` | HTTP request timeout |
| `scanner.headless_size` | `10` | Headless worker pool size |
| `template.dir` | `./templates` | Nuclei templates directory |
| `report.output_dir` | `./reports` | PDF output directory |

---

## 7. Troubleshooting

### 7.1 RabbitMQ Connection Failure

The application logs:
```
RabbitMQ not available (<error>), falling back to in-memory channels
```

This is **not an error** — the system continues with in-memory messaging. All scan functionality works. The difference is that workers and state are lost on app restart.

### 7.2 Database Migration

Schema is managed via GORM AutoMigrate in `main.go:61-67`. Run the application to apply migrations:

```bash
go run main.go
```

### 7.3 Common Issues

| Issue | Solution |
|-------|----------|
| `pq: role "postgres" does not exist` | Create PostgreSQL role: `createuser -s postgres` |
| `failed to connect to database` | Verify PostgreSQL is running and credentials match `config.yaml` or env vars |
| `no such file or directory` for templates | Clone Nuclei templates: `git clone https://github.com/projectdiscovery/nuclei-templates.git ./templates` |
| `chromium not found` | Install Chromium or set `SCANNER_CHROMIUM_PATH` to empty to disable headless features |
