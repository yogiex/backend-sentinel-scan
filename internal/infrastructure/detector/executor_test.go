package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewHTTPExecutor(t *testing.T) {
	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	if exec == nil {
		t.Fatal("expected non-nil executor")
	}
}

func TestExecutorExecute(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if r.URL.Query().Get("id") != "'test'" {
			t.Errorf("expected id='test', got id=%s", r.URL.Query().Get("id"))
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("response body"))
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/?id=FUZZ",
	}
	payload := Payload{Name: "test", Value: "'test'"}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Body != "response body" {
		t.Errorf("expected 'response body', got %q", resp.Body)
	}
}

func TestExecutorExecutePOST(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte("created"))
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "POST",
		Path:   "/api/data",
	}
	payload := Payload{Name: "test", Value: "test"}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("expected 201, got %d", resp.StatusCode)
	}
}

func TestExecutorExecuteWithBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "POST",
		Path:   "/",
		Body:   "data=FUZZ",
	}
	payload := Payload{Name: "test", Value: "payload_value"}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestExecutorExecuteWithHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "FUZZ" {
			t.Errorf("expected X-Custom header FUZZ, got %s", r.Header.Get("X-Custom"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method:  "GET",
		Path:    "/",
		Headers: map[string]string{"X-Custom": "FUZZ"},
	}
	payload := Payload{Name: "test", Value: "testvalue"}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestExecutorExecuteContextCancel(t *testing.T) {
	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/",
	}
	payload := Payload{Name: "test", Value: "test"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := exec.Execute(ctx, "http://127.0.0.1:1", plugin, payload)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}

func TestExecutorInvalidURL(t *testing.T) {
	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/",
	}
	payload := Payload{Name: "test", Value: "test"}

	_, err := exec.Execute(context.Background(), "://invalid", plugin, payload)
	if err == nil {
		t.Fatal("expected error with invalid URL")
	}
}

func TestExecutorEncodedPayload(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.RawQuery != "id=%3Cscript%3E" {
			t.Errorf("expected encoded query, got %s", r.URL.RawQuery)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/?id=FUZZ",
	}
	payload := Payload{Name: "xss", Value: "<script>", Encoded: true}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestExecutorDuration(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{Method: "GET", Path: "/"}
	payload := Payload{Name: "test", Value: "test"}

	resp, err := exec.Execute(context.Background(), ts.URL, plugin, payload)
	if err != nil {
		t.Fatalf("execute failed: %v", err)
	}
	if resp.Duration <= 0 {
		t.Errorf("expected positive duration, got %v", resp.Duration)
	}
}

func TestExecuteBaseline(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/baseline" {
			t.Errorf("expected /baseline, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("baseline response"))
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/?id=FUZZ",
		Baseline: &BaselineRequest{
			Method: "GET",
			Path:   "/baseline",
		},
	}

	resp, err := exec.ExecuteBaseline(context.Background(), ts.URL, plugin)
	if err != nil {
		t.Fatalf("exec baseline failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	if resp.Body != "baseline response" {
		t.Errorf("expected 'baseline response', got %q", resp.Body)
	}
}

func TestExecuteBaselineWithoutOverride(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			t.Errorf("expected /, got %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/",
	}

	resp, err := exec.ExecuteBaseline(context.Background(), ts.URL, plugin)
	if err != nil {
		t.Fatalf("exec baseline failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestExecuteBaselineWithHeaders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer test" {
			t.Errorf("expected Authorization header, got %s", r.Header.Get("Authorization"))
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "GET",
		Path:   "/",
		Baseline: &BaselineRequest{
			Headers: map[string]string{"Authorization": "Bearer test"},
		},
	}

	resp, err := exec.ExecuteBaseline(context.Background(), ts.URL, plugin)
	if err != nil {
		t.Fatalf("exec baseline failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}

func TestExecuteBaselineContextCancel(t *testing.T) {
	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{Method: "GET", Path: "/"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := exec.ExecuteBaseline(ctx, "http://127.0.0.1:1", plugin)
	if err == nil {
		t.Fatal("expected error with cancelled context")
	}
}

func TestExecuteBaselineInvalidURL(t *testing.T) {
	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{Method: "GET", Path: "/"}

	_, err := exec.ExecuteBaseline(context.Background(), "://invalid", plugin)
	if err == nil {
		t.Fatal("expected error with invalid URL")
	}
}

func TestExecuteBaselineWithBody(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	cfg := DefaultDetectionConfig()
	exec := NewHTTPExecutor(cfg)
	plugin := &Plugin{
		Method: "POST",
		Path:   "/",
		Baseline: &BaselineRequest{
			Body: "test=data",
		},
	}

	resp, err := exec.ExecuteBaseline(context.Background(), ts.URL, plugin)
	if err != nil {
		t.Fatalf("exec baseline failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
}
