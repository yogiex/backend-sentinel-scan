# Testing (historical)

> **Dokumen historis dan terlalu optimistis.** Klaim "14 E2E tests" tidak bisa
> dijalankan: `test/e2e` tidak compile terhadap konstruktor saat ini, dan 10 file
> test ber-`//go:build ignore` (119 `func Test`) tidak pernah dieksekusi
> `go test ./...` — termasuk test JWT, user repository, dan handler kredensial.
> Yang benar-benar berjalan: `go test ./... -count=1`. Lihat
> [FEATURE-STATUS.md](FEATURE-STATUS.md) dan README bagian Testing.

> **Stats:** ~290 test functions · 10 benchmarks · ~65 test files · 23+ packages

---

## 1. Running Tests

### 1.1 All Unit Tests

```bash
go test ./...
```

### 1.2 Race Detection

```bash
go test -race -count=1 ./...
```

### 1.3 With Coverage

```bash
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### 1.4 Single Package

```bash
go test -count=1 -v ./internal/application/...
```

### 1.5 Short Mode

Skips integration-dependent subtests:

```bash
go test -short ./...
```

### 1.6 E2E Tests

Domain-scoped E2E tests using `httptest.Server` + real router. No external services required:

```bash
# Run all E2E tests
go test -tags=e2e -count=1 ./test/e2e/...

# Run per domain
go test -tags=e2e -count=1 -v ./test/e2e/scans/...
go test -tags=e2e -count=1 -v ./test/e2e/credentials/...
```

```
test/e2e/
├── testutil/setup.go    # NewTestServer + MustGET/MustPOST/MustDecode
├── health/              # 1 test
├── scans/               # 6 tests (create, get, results, error cases)
├── credentials/         # 5 tests (CRUD)
├── templates/           # 1 test
├── reports/             # 1 test
└── auth/                # placeholder — routes pending
```

14 E2E tests total.

### 1.7 Integration Tests

Requires PostgreSQL and/or RabbitMQ:

```bash
go test -tags=integration -count=1 ./test/integration/...
```

### 1.8 Benchmarks

```bash
go test -bench=. -benchmem ./test/benchmarks/...
```

---

## 2. Test Structure

### 2.1 Package-Level Tests

Tests live alongside source code (same package, `_test.go` suffix):

```
config/
  config.go
  config_test.go        # TestLoad_Defaults, TestLoad_EnvironmentVariables

event/
  bus.go
  bus_test.go           # TestBus_SubscribePublish

template/
  loader.go
  types.go
  loader_test.go        # TestLoader_Get_NonExistent, TestLoader_Get_ValidTemplate, TestLoader_List

orchestrator/
  orchestrator.go
  orchestrator_test.go  # Comprehensive orchestrator tests

worker/
  task.go
  task_test.go          # TestTask_Creation

detection/
  fingerprint.go
  fingerprint_test.go   # TestFingerprint_ServerHeader

db/
  models.go
  connection.go
  models_test.go        # TestScanJob_Creation, TestScanResult_Creation, etc.
  connection_test.go    # TestNewConnection_InvalidDSN
```

### 2.2 Test-Only Packages

Several packages have **only test files** with no production source code:

| Package | Test File | Tests |
|---------|-----------|-------|
| `internal/domain/entity/` | `auth_entity_test.go` | AuthCredential, AuthSession, ScanReportData |
| `internal/application/auth/` | `service_test.go` | Register, Login, GetUserByID |
| `internal/infrastructure/auth/` | `jwt_test.go` | GenerateToken, ValidateToken, edge cases |
| `internal/infrastructure/database/postgres/` | `user_repository_test.go` | User CRUD |
| `internal/infrastructure/messaging/` | `messaging_test.go` | RabbitMQ components in disconnected state |
| `internal/infrastructure/report/` | `generator_test.go` | PDF generation error paths |
| `internal/infrastructure/scanner/` | `headless_engine_test.go` | XSS, open redirect, framework detection |

---

## 3. Testing Conventions

### 3.1 Test Framework

Uses standard `testing` package + `testify`:

```go
import (
  "testing"
  "github.com/stretchr/testify/mock"
)
```

### 3.2 Mocking Pattern

Define mock structs embedding `mock.Mock` and implementing service interfaces:

```go
type mockScanService struct{ mock.Mock }

func (m *mockScanService) StartScan(ctx context.Context, createdBy uint, targets []string, filter entity.TemplateFilter) (*entity.ScanJob, error) {
  args := m.Called(ctx, createdBy, targets, filter)
  if args.Get(0) == nil {
    return nil, args.Error(1)
  }
  return args.Get(0).(*entity.ScanJob), args.Error(1)
}
```

Usage:

```go
mockSvc := new(mockScanService)
mockSvc.On("StartScan", mock.Anything, uint(1), []string{"http://example.com"}, mock.Anything).
  Return(&entity.ScanJob{ID: 1, Status: entity.ScanStatusPending}, nil).Once()
```

See `api/handlers_extended_test.go` for the full reference pattern.

### 3.3 HTTP Handler Tests

Use `httptest.NewRecorder()` + `httptest.NewRequest()`:

```go
func TestCreateScan(t *testing.T) {
  mockSvc := new(mockScanService)
  h := &Handler{scanService: mockSvc}

  body := `{"targets":["http://example.com"]}`
  req := httptest.NewRequest("POST", "/api/scans", bytes.NewBufferString(body))
  req.Header.Set("Content-Type", "application/json")

  mockSvc.On("StartScan", mock.Anything, uint(1), []string{"http://example.com"}, mock.Anything).
    Return(&entity.ScanJob{ID: 1, Status: entity.ScanStatusPending}, nil).Once()

  w := httptest.NewRecorder()
  newRouterWithHandler(h).ServeHTTP(w, req)

  if w.Code != http.StatusAccepted {
    t.Errorf("expected status %d, got %d", http.StatusAccepted, w.Code)
  }
  mockSvc.AssertExpectations(t)
}
```

### 3.4 WebSocket Tests

Use gorilla/websocket client with test server:

```go
// Pattern from api/websocket_test.go
server := httptest.NewServer(handler)
defer server.Close()

url := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/scans/1/stream"
ws, _, err := websocket.DefaultDialer.Dial(url, nil)
```

### 3.5 Config Tests

Set environment variables in test, clean up with `defer`:

```go
func TestLoad_EnvironmentVariables(t *testing.T) {
  os.Setenv("SERVER_PORT", "9090")
  defer os.Unsetenv("SERVER_PORT")

  cfg, err := Load()
  // ...
}
```

### 3.6 Template Loader Tests

Create temporary template files on disk, clean up with `defer os.RemoveAll()`:

```go
func TestLoader_List(t *testing.T) {
  os.MkdirAll("./test-templates", 0755)
  defer os.RemoveAll("./test-templates")

  os.WriteFile("./test-templates/tmpl-1.yaml", []byte(validYAML), 0644)
  loader, _ := NewLoader("./test-templates")
  // ...
}
```

### 3.7 Integration Tests

Guarded by build tag — run only when explicitly requested:

```go
//go:build integration

package integration

func TestScanE2E(t *testing.T) {
  // Requires PostgreSQL
}
```

---

## 4. Benchmark Tests

Location: `test/benchmarks/`

```bash
go test -bench=. -benchmem ./test/benchmarks/...
```

Current benchmarks:
- `BenchmarkHTTPEngine_Execute` — HTTP engine against test server
- `BenchmarkHTTPEngine_Execute_LargeResponse` — Large response handling

---

## 5. Code Quality

### 5.1 go vet

```bash
go vet ./...
```

All 23 packages pass `go vet` cleanly.

### 5.2 gofmt

```bash
gofmt -w .
```

### 5.3 golangci-lint

```bash
golangci-lint run
```

No custom `.golangci.yml` — relies on defaults.

---

## 6. Test Coverage Summary

| Package | Coverage | Trend |
|---------|----------|-------|
| `config` | ~98% | Stable |
| `internal/infrastructure/event` | ~91% | Stable |
| `template` | ~72% | Stable |
| `internal/infrastructure/auth` | ~70% | Growing |
| `internal/infrastructure/authscan` | ~70% | Growing |
| `internal/domain/entity` | ~65% | Growing |
| `internal/application` | ~55% | Growing |
| `internal/infrastructure/messaging` | ~40% | Growing |
| `internal/infrastructure/scanner` | ~25% | Growing |
| `api` | ~45% | Growing |
| `orchestrator` | ~30% | Growing |
| Remaining packages | 20–50% | Growing |

Target: 80%+ for domain and application layers.

---

## 7. Continuous Integration

No CI workflow files exist yet. For CI setup, run:

```bash
go test -race -count=1 ./...
go vet ./...
gofmt -d .  # check formatting, exit non-zero if unformatted
```
