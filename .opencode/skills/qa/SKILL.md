---
name: qa
description: This skill should be used when the user asks to "run tests", "check coverage", "run benchmarks", "run linter", "run vet", "format code", "run race detection", "run integration tests", "run short tests", "review code quality", "run quality assurance", "verify code", "check test results", "improve test coverage", "add tests", "write tests", "mocking", or "test pattern". Provides comprehensive Go testing and QA workflows for the SentinelScan backend project.
---

# Quality Assurance — SentinelScan Backend

## Running Tests

### All unit tests
```
go test ./...
```

### Race detection
```
go test -race -count=1 ./...
```

### Coverage
```
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out -o coverage.html
```

### Single package
```
go test -count=1 -v ./internal/application/...
```

### Short mode (skip integration-dependent subtests)
```
go test -short ./...
```

### Integration tests (requires PostgreSQL)
```
go test -tags=integration -count=1 ./test/integration/...
```

### Benchmarks
```
go test -bench=. -benchmem ./test/benchmarks/...
```

## Code Quality

### go vet (all 23 packages must pass)
```
go vet ./...
```

### Format code
```
gofmt -w .
```

### Lint (requires golangci-lint, uses defaults — no config file)
```
golangci-lint run
```

## Testing Conventions

### Framework
- Standard `testing` package + `testify/mock`
- See `api/handlers_extended_test.go` for the canonical mock pattern

### Mocking pattern
1. Define struct embedding `mock.Mock`
2. Implement service interface methods by delegating to `m.Called()`
3. In tests: `mockSvc.On("Method", args...).Return(result, nil).Once()`
4. Assert: `mockSvc.AssertExpectations(t)`

### HTTP handler tests
- `httptest.NewRecorder()` for response capture
- `httptest.NewRequest()` for request creation
- Register routes with `mux.NewRouter()`, then call `router.ServeHTTP(w, req)`

### Integration tests
- Guarded by `//go:build integration` build tag
- Require external services (PostgreSQL)
- Run with `-tags=integration`

### Config tests
- Set env vars with `os.Setenv`, clean up with `defer os.Unsetenv`
- Load config and assert expected values

### Template loader tests
- Create temp template files with `os.MkdirAll` + `os.WriteFile`
- Clean up with `defer os.RemoveAll`

## Coverage Targets

| Layer | Target |
|-------|--------|
| Domain & Application | 80%+ |
| Infrastructure | 60%+ |
| API handlers | 70%+ |

Current project stats: ~275 test functions, 10 benchmarks, ~60 test files, 23 packages.

## Code Review Checklist

Before submitting code:
- [ ] `go vet ./...` passes
- [ ] `go test ./...` passes (all packages)
- [ ] `go test -race -count=1 ./...` passes
- [ ] `gofmt -w .` has been run
- [ ] New code includes tests
- [ ] Mock assertions (`AssertExpectations`) are present
- [ ] Interface types used for injectable dependencies (not concrete types)
- [ ] Error wrapping with `fmt.Errorf("context: %w", err)` for propagation
- [ ] No hardcoded secrets or credentials
- [ ] Test files use `_test.go` suffix in same package

## Reference

For detailed test patterns and examples:
- **`references/test-reference.md`** — Mocking patterns, WebSocket tests, benchmark patterns, error handling in tests
