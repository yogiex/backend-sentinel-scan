package scanner

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
)

func newTestEngine(t *testing.T) *HTTPEngine {
	t.Helper()
	det := detector.New(detector.DetectionConfig{
		DefaultSeverity:      detector.SeverityInfo,
		MaxPayloadsPerPlugin: 20,
		Timeout:              2 * time.Second,
		Client:               &http.Client{Timeout: 2 * time.Second},
	})
	if err := det.LoadPlugins(); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	return NewHTTPEngine(EngineConfig{TimeoutSec: 2}, det)
}

// TestExecuteRunsExactlyOnePlugin proves the task granularity: the engine must
// run the plugin named by TemplateID and nothing else, because the orchestrator
// computes progress as targets x plugins.
func TestExecuteRunsExactlyOnePlugin(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		// Echo the decoded query back so a reflection probe matches on its first
		// payload; echoing RawQuery would only ever contain percent-encoding.
		w.Write([]byte("<html>" + r.URL.Query().Get("q") + r.URL.Query().Get("search") + "</html>"))
	}))
	defer server.Close()

	engine := newTestEngine(t)

	result := engine.Execute(context.Background(), Task{
		Target:     server.URL,
		TemplateID: "xss-reflected",
	})
	if result.Error != nil {
		t.Fatalf("execute: %v", result.Error)
	}
	if result.Finding == nil || !result.Finding.Matched {
		t.Fatalf("reflection should be detected, got %+v", result.Finding)
	}
	if got := requests.Load(); got != 1 {
		t.Fatalf("a matching plugin costs 1 request, got %d", got)
	}
	if result.Finding.Severity != "high" {
		t.Fatalf("severity should come from the plugin, got %q", result.Finding.Severity)
	}
}

// TestExecuteSendsOnlyThePluginPayloads pins the request count for a plugin
// that does not match: four payloads, not four payloads times nine plugins.
func TestExecuteSendsOnlyThePluginPayloads(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Write([]byte("<html>nothing here</html>"))
	}))
	defer server.Close()

	engine := newTestEngine(t)

	result := engine.Execute(context.Background(), Task{
		Target:     server.URL,
		TemplateID: "path-traversal",
	})
	if result.Error != nil {
		t.Fatalf("execute: %v", result.Error)
	}
	if result.Finding.Matched {
		t.Fatal("nothing should match an echo of 'nothing here'")
	}
	if got := requests.Load(); got != 4 {
		t.Fatalf("path-traversal has 4 payloads, got %d requests", got)
	}
}

func TestExecuteReportsUnknownTemplate(t *testing.T) {
	engine := newTestEngine(t)
	result := engine.Execute(context.Background(), Task{Target: "http://example.invalid", TemplateID: "no-such-plugin"})
	if !errors.Is(result.Error, ErrUnknownTemplate) {
		t.Fatalf("expected ErrUnknownTemplate, got %v", result.Error)
	}
	if result.Finding != nil {
		t.Fatal("an unknown template must not produce a finding")
	}
}

func TestExecuteWithoutDetectorFailsLoudly(t *testing.T) {
	engine := NewHTTPEngine(EngineConfig{}, nil)
	result := engine.Execute(context.Background(), Task{Target: "http://example.invalid", TemplateID: "xss-reflected"})
	if !errors.Is(result.Error, ErrEngineNotConfigured) {
		t.Fatalf("expected ErrEngineNotConfigured, got %v", result.Error)
	}
}

func TestHeadlessEngineIsNotSilentlyClean(t *testing.T) {
	engine := NewHeadlessEngine(EngineConfig{})
	result := engine.Execute(context.Background(), Task{Target: "http://example.invalid", TemplateID: "xss-reflected"})
	if !errors.Is(result.Error, ErrHeadlessNotImplemented) {
		t.Fatalf("expected ErrHeadlessNotImplemented, got %v", result.Error)
	}
}

// TestDetailsCarryEvidenceButNotTheBody keeps the JSONB column small and free of
// target data.
func TestDetailsCarryEvidenceButNotTheBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("<html>secret-page " + r.URL.Query().Get("q") + "</html>"))
	}))
	defer server.Close()

	engine := newTestEngine(t)
	result := engine.Execute(context.Background(), Task{Target: server.URL, TemplateID: "xss-reflected"})
	if result.Error != nil {
		t.Fatalf("execute: %v", result.Error)
	}
	details := result.Finding.Details
	if details["plugin_id"] != "xss-reflected" {
		t.Fatalf("details need the plugin id: %v", details)
	}
	matches, ok := details["matches"].([]map[string]interface{})
	if !ok || len(matches) == 0 {
		t.Fatalf("details need matches: %v", details)
	}
	if _, leaked := details["response_body"]; leaked {
		t.Fatal("the full response body must never be persisted")
	}
	if _, leaked := details["body"]; leaked {
		t.Fatal("the full response body must never be persisted")
	}
}

// An unreachable target must produce an error, not an empty "clean" result.
// Otherwise the orchestrator counts the task as completed and the report claims
// the host was checked.
func TestExecuteReportsUnreachableTargetAsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close()

	engine := newTestEngine(t)
	result := engine.Execute(context.Background(), Task{Target: url, TemplateID: "xss-reflected"})

	if result.Error == nil {
		t.Fatal("a target that never answered must not yield a clean result")
	}
	if !errors.Is(result.Error, ErrNoRequestCompleted) {
		t.Fatalf("expected ErrNoRequestCompleted, got %v", result.Error)
	}
	if result.Checked {
		t.Fatal("Checked must be false when no request completed")
	}
	if result.Finding.Matched {
		t.Fatal("no match can be claimed without a response")
	}
}
