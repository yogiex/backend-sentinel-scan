# QA Reference — Test Patterns & Examples

## Mocking Pattern (testify/mock)

Canonical example from `api/handlers_extended_test.go`:

```go
type mockScanService struct{ mock.Mock }

func (m *mockScanService) StartScan(ctx context.Context, createdBy uint, targets []string, filter entity.TemplateFilter) (*entity.ScanJob, error) {
	args := m.Called(ctx, createdBy, targets, filter)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.ScanJob), args.Error(1)
}

func (m *mockScanService) GetScan(ctx context.Context, id uint) (*entity.ScanJob, error) {
	args := m.Called(ctx, id)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*entity.ScanJob), args.Error(1)
}
```

**Rules:**
- Every method of the interface must be implemented on the mock struct
- Return type assertions: use `args.Get(0).(*ReturnType)` for non-nil, `args.Error(1)` for error
- Use `mock.Anything` for context and other values you don't need to match exactly

## HTTP Handler Test Pattern

From `api/handlers_extended_test.go`:

```go
func TestCreateScan(t *testing.T) {
	mockSvc := new(mockScanService)
	h := &Handler{scanService: mockSvc}

	t.Run("success", func(t *testing.T) {
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
	})

	t.Run("invalid body", func(t *testing.T) {
		req := httptest.NewRequest("POST", "/api/scans", bytes.NewBufferString("not-json"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		newRouterWithHandler(h).ServeHTTP(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("expected status %d, got %d", http.StatusBadRequest, w.Code)
		}
	})
}
```

**Pattern:**
1. Create mock service
2. Construct handler with mock
3. Create HTTP request with `httptest.NewRequest`
4. Record response with `httptest.NewRecorder`
5. Serve through router
6. Assert status code + mock expectations

## WebSocket Test Pattern

From `api/websocket_test.go`:

```go
server := httptest.NewServer(handler)
defer server.Close()

url := "ws" + strings.TrimPrefix(server.URL, "http") + "/api/scans/1/stream"
ws, _, err := websocket.DefaultDialer.Dial(url, nil)
if err != nil {
	t.Fatalf("Failed to connect: %v", err)
}
defer ws.Close()

// Read messages
_, msg, err := ws.ReadMessage()
```

## Config Test Pattern

From `config/config_test.go`:

```go
func TestLoad_Defaults(t *testing.T) {
	os.Unsetenv("SERVER_PORT")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	if cfg.Server.Port != 8080 {
		t.Errorf("Expected server port 8080, got %d", cfg.Server.Port)
	}
}

func TestLoad_EnvironmentVariables(t *testing.T) {
	os.Setenv("SERVER_PORT", "9090")
	defer os.Unsetenv("SERVER_PORT")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Server.Port != 9090 {
		t.Errorf("Expected server port 9090, got %d", cfg.Server.Port)
	}
}
```

## Template Loader Test Pattern

From `template/loader_test.go`:

```go
func TestLoader_List(t *testing.T) {
	os.MkdirAll("./test-templates", 0755)
	defer os.RemoveAll("./test-templates")

	valid1 := `
id: tmpl-1
info:
  name: Valid 1
  severity: high
  tags: [web]
`
	os.WriteFile("./test-templates/tmpl-1.yaml", []byte(valid1), 0644)
	os.WriteFile("./test-templates/invalid.yaml", []byte("invalid yaml: ["), 0644)

	loader, _ := NewLoader("./test-templates")
	templates, err := loader.List()
	if err != nil {
		t.Fatalf("List() returned error: %v", err)
	}
	if len(templates) != 1 {
		t.Errorf("Expected 1 valid template, got %d", len(templates))
	}
}
```

## Benchmark Pattern

From `test/benchmarks/engine_benchmark_test.go`:

```go
func BenchmarkHTTPEngine_Execute(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "<html><body>Welcome</body></html>")
	}))
	defer server.Close()

	engine := scanner.NewHTTPEngine(scanner.EngineConfig{TimeoutSec: 30})
	task := scanner.Task{Target: server.URL, TemplateID: "bench-test"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := engine.Execute(context.Background(), task)
		if result.Error != nil {
			b.Fatalf("Execute failed: %v", result.Error)
		}
	}
}
```

## Integration Test Guard

```go
//go:build integration

package integration

func TestScanFlow_E2E(t *testing.T) {
	// Requires PostgreSQL and optionally RabbitMQ
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}
	// ...
}
```

## Error Handling in Tests

```go
// For expected errors from mocks:
mockSvc.On("GetScan", mock.Anything, uint(999)).
	Return(nil, errors.NewAppError("NOT_FOUND", "not found", 404)).Once()

// Custom error helper:
func assertError(msg string) error {
	return &simpleError{msg}
}

type simpleError struct{ msg string }
func (e *simpleError) Error() string { return e.msg }
```

## Common Test Commands

```bash
# Quick verification (no external deps)
go test -short ./... && go vet ./...

# Full suite
go test -race -count=1 ./...

# Coverage HTML report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html

# Single test function
go test -count=1 -v -run TestCreateScan ./api

# Benchmarks
go test -bench=. -benchmem ./test/benchmarks/...
```

## Assertion Best Practices

- Always call `mockSvc.AssertExpectations(t)` at the end of each test case
- Prefer `t.Errorf` (non-fatal) over `t.Fatalf` for assertions in table-driven subtests
- Use `t.Run("name", func(t *testing.T) { ... })` for table-driven or scenario subtests
- Clean up temp files/env vars with `defer` immediately after creation/setting
