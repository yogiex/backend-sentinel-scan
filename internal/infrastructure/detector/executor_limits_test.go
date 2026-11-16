package detector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExecuteEncodesPayloadInURLButNotInBody(t *testing.T) {
	var gotQuery, gotPath, gotBody string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.Query().Get("q")
		gotPath = r.URL.Path
		var sb strings.Builder
		buf := make([]byte, 1024)
		for {
			n, err := r.Body.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		gotBody = sb.String()
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	exec := NewHTTPExecutor(DetectionConfig{})
	plugin := &Plugin{
		Metadata: PluginMetadata{ID: "p", Severity: SeverityHigh},
		Method:   "POST",
		Path:     "/probe?q=FUZZ",
		Body:     "xml=FUZZ",
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"x"}}},
	}

	payload := Payload{Value: `a&b#c d'e`}
	if _, err := exec.Execute(t.Context(), server.URL, plugin, payload); err != nil {
		t.Fatalf("execute: %v", err)
	}

	// A raw "&" would start a new query parameter and a raw "#" would truncate
	// the URL, so the value must arrive intact after decoding.
	if gotQuery != `a&b#c d'e` {
		t.Fatalf("payload was mangled in the URL: %q", gotQuery)
	}
	if gotPath != "/probe" {
		t.Fatalf("path should stay /probe, got %q", gotPath)
	}
	// Bodies are not URL-encoded: an XXE payload is XML, not a URL.
	if gotBody != `xml=a&b#c d'e` {
		t.Fatalf("payload was encoded in the body: %q", gotBody)
	}
}

func TestExecuteTruncatesOversizedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		big := strings.Repeat("A", MaxResponseBytes+1024)
		w.Write([]byte(big))
	}))
	defer server.Close()

	exec := NewHTTPExecutor(DetectionConfig{})
	plugin := &Plugin{
		Metadata: PluginMetadata{ID: "p", Severity: SeverityInfo},
		Method:   "GET",
		Path:     "/?q=FUZZ",
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"x"}}},
	}

	resp, err := exec.Execute(t.Context(), server.URL, plugin, Payload{Value: "1"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if len(resp.Body) != MaxResponseBytes {
		t.Fatalf("body should be capped at %d bytes, got %d", MaxResponseBytes, len(resp.Body))
	}
	if !resp.Truncated {
		t.Fatal("oversized body must be flagged as truncated, not treated as complete")
	}
}
