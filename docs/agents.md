# SentinelScan Backend — Agent Instructions

## Architecture

DDD + hexagonal layers. Reading order: `api/` → `internal/application/` → `internal/domain/` → `internal/infrastructure/`. Entrypoint: `main.go:47`.

## Initial Setup

```bash
go mod init github.com/inkubasi-btp-cybersecurity/vulnerability-scanner
go mod tidy
```

Nuclei templates (required for scanning):

```bash
git clone https://github.com/projectdiscovery/nuclei-templates.git ./templates
```

## Dual messaging

RabbitMQ primary, automatic fallback to in-memory channels (`event/bus.go`). Worker pool at `internal/infrastructure/worker/pool.go` handles both modes. Tests do not require RabbitMQ.

## docker-compose

Starts **postgres**, **pgadmin**, **rabbitmq** only — the Go app is NOT in compose. Run separately: `go run main.go`.

## Config

Viper reads `config.yaml` (optional) + env vars with `_` separator (e.g. `SERVER_PORT`). No auto `.env` loading — use `export $(grep -v '^#' .env \| xargs)`. Defaults in `config/config.go:44-61`.

## Commands

| Action | Command |
|--------|---------|
| Build | `go build -o vulnscanner main.go` |
| Run | `go run main.go` |
| All tests | `go test ./...` |
| Race | `go test -race -count=1 ./...` |
| Coverage | `go test -coverprofile=coverage.out ./...` |
| Single pkg | `go test -count=1 -v ./internal/application/...` |
| Short mode | `go test -short ./...` |
| E2E (all) | `go test -tags=e2e -count=1 ./test/e2e/...` |
| E2E per domain | `go test -tags=e2e -count=1 -v ./test/e2e/scans/...` |
| Integration | `go test -tags=integration -count=1 ./test/integration/...` |
| Benchmarks | `go test -bench=. -benchmem ./test/benchmarks/...` |
| Vet | `go vet ./...` |
| Format | `gofmt -w .` |

## E2E test structure

```
test/e2e/
├── testutil/       # NewTestServer + MustGET/MustPOST/MustDecode
├── health/         # 1 test
├── scans/          # 6 tests
├── credentials/    # 5 tests
├── templates/      # 1 test
├── reports/        # 1 test
└── auth/           # placeholder
```

Domain folders are independent packages — each runs with `go test -tags=e2e ./test/e2e/<domain>/...`.

## Testing conventions

- **Mocking:** `testify/mock` — see `api/handlers_extended_test.go` for pattern
- **Handler tests:** `httptest.NewRecorder()` + `httptest.NewRequest()`
- **E2E tests:** `httptest.NewServer` + real router, guarded by `//go:build e2e`
- **Integration tests:** guarded by `//go:build integration` build tag
- **No golangci-lint config** — relies on defaults

## Known gaps

- `main.go` does not compile — `config.Config` needs `Scanner`, `RabbitMQ`, `AuthScan`, `Report` struct fields
- `internal/application/auth/service.go` — test only, no production source
- Several infrastructure packages are stubs (compile only, no real logic)
