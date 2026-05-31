package detector

import (
	"testing"
)

func TestParsePlugin(t *testing.T) {
	data := []byte(`
metadata:
  id: "test-plugin"
  name: "Test"
  severity: "high"
  tags: ["test"]

engine: "http"
method: "GET"
path: "/?q=FUZZ"

payloads:
  - name: "test-payload"
    value: "test"

matchers:
  - type: "keyword"
    patterns:
      - "test"
`)
	plugin, err := ParsePlugin(data)
	if err != nil {
		t.Fatalf("failed to parse plugin: %v", err)
	}
	if plugin.Metadata.ID != "test-plugin" {
		t.Errorf("expected id test-plugin, got %s", plugin.Metadata.ID)
	}
	if plugin.Method != "GET" {
		t.Errorf("expected method GET, got %s", plugin.Method)
	}
	if len(plugin.Payloads) != 1 {
		t.Errorf("expected 1 payload, got %d", len(plugin.Payloads))
	}
	if len(plugin.Matchers) != 1 {
		t.Errorf("expected 1 matcher, got %d", len(plugin.Matchers))
	}
}

func TestParsePluginMissingID(t *testing.T) {
	data := []byte(`
metadata:
  name: "Test"

engine: "http"
method: "GET"
path: "/?q=FUZZ"

matchers:
  - type: "keyword"
    patterns:
      - "test"
`)
	_, err := ParsePlugin(data)
	if err == nil {
		t.Fatal("expected error for missing id")
	}
}

func TestParsePluginMissingPath(t *testing.T) {
	data := []byte(`
metadata:
  id: "test-plugin"
  name: "Test"

engine: "http"
method: "GET"

matchers:
  - type: "keyword"
    patterns:
      - "test"
`)
	_, err := ParsePlugin(data)
	if err == nil {
		t.Fatal("expected error for missing path")
	}
}

func TestParsePluginNoMatchers(t *testing.T) {
	data := []byte(`
metadata:
  id: "test-plugin"
  name: "Test"

engine: "http"
method: "GET"
path: "/"
`)
	_, err := ParsePlugin(data)
	if err == nil {
		t.Fatal("expected error for no matchers")
	}
}

func TestParsePluginDefaultMethod(t *testing.T) {
	data := []byte(`
metadata:
  id: "test-plugin"
  name: "Test"

path: "/?q=FUZZ"

matchers:
  - type: "keyword"
    patterns:
      - "test"
`)
	plugin, err := ParsePlugin(data)
	if err != nil {
		t.Fatalf("failed to parse plugin: %v", err)
	}
	if plugin.Method != "GET" {
		t.Errorf("expected default method GET, got %s", plugin.Method)
	}
}

func TestValidatePlugin(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "test"},
		Method:   "GET",
		Path:     "/",
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"test"}}},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestValidatePluginMissingID(t *testing.T) {
	p := &Plugin{
		Path:     "/",
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"test"}}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected validation error for missing id")
	}
}

func TestValidatePluginMissingPath(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "test"},
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"test"}}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected validation error for missing path")
	}
}

func TestValidatePluginNoMatchers(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "test"},
		Path:     "/",
	}
	if err := p.Validate(); err == nil {
		t.Fatal("expected validation error for no matchers")
	}
}
