package detector

import (
	"context"
	"testing"
)

func TestDetectorCreate(t *testing.T) {
	cfg := DefaultDetectionConfig()
	d := New(cfg)
	if d == nil {
		t.Fatal("expected non-nil detector")
	}
}

func TestDetectorLoadEmbedded(t *testing.T) {
	cfg := DefaultDetectionConfig()
	d := New(cfg)
	err := d.LoadPlugins()
	if err != nil {
		t.Fatalf("failed to load embedded plugins: %v", err)
	}
	plugins := d.Plugins()
	if len(plugins) == 0 {
		t.Fatal("expected at least 1 embedded plugin")
	}
}

func TestDetectorListPlugins(t *testing.T) {
	reg := NewRegistry()
	err := reg.LoadEmbedded()
	if err != nil {
		t.Fatalf("failed to load embedded plugins: %v", err)
	}
	plugins := reg.List()
	if len(plugins) == 0 {
		t.Fatal("expected at least 1 plugin")
	}

	ids := make(map[string]bool)
	for _, p := range plugins {
		if p.Metadata.ID == "" {
			t.Error("plugin missing id")
		}
		if ids[p.Metadata.ID] {
			t.Errorf("duplicate plugin id: %s", p.Metadata.ID)
		}
		ids[p.Metadata.ID] = true
	}
}

func TestDetectorGetPlugin(t *testing.T) {
	reg := NewRegistry()
	reg.LoadEmbedded()
	p := reg.Get("sql-injection-error")
	if p == nil {
		t.Fatal("expected to find sql-injection-error plugin")
	}
}

func TestDetectorGetPluginNotFound(t *testing.T) {
	reg := NewRegistry()
	reg.LoadEmbedded()
	p := reg.Get("nonexistent")
	if p != nil {
		t.Fatal("expected nil for nonexistent plugin")
	}
}

func TestDetectorRunWithNoPlugins(t *testing.T) {
	cfg := DefaultDetectionConfig()
	d := New(cfg)
	results := d.RunWithPlugins(context.Background(), "http://example.com", nil)
	if len(results) != 0 {
		t.Fatal("expected 0 results with nil plugins")
	}
}

func TestDetectorRunWithEmptyPlugins(t *testing.T) {
	cfg := DefaultDetectionConfig()
	d := New(cfg)
	results := d.RunWithPlugins(context.Background(), "http://example.com", []*Plugin{})
	if len(results) != 0 {
		t.Fatal("expected 0 results with empty plugins")
	}
}

func TestDetectorLoadAllPlugins(t *testing.T) {
	cfg := DefaultDetectionConfig()
	d := New(cfg)
	err := d.LoadPlugins()
	if err != nil {
		t.Fatalf("failed to load embedded plugins: %v", err)
	}
	plugins := d.Plugins()

	expectedIDs := map[string]bool{
		"sql-injection-error":   false,
		"xss-reflected":         false,
		"path-traversal":        false,
		"idor":                  false,
		"open-redirect":         false,
		"xxe":                   false,
		"ssrf":                  false,
		"sql-injection-boolean": false,
		"sql-injection-time":    false,
	}

	for _, p := range plugins {
		if _, ok := expectedIDs[p.Metadata.ID]; ok {
			expectedIDs[p.Metadata.ID] = true
		}
	}

	for id, found := range expectedIDs {
		if !found {
			t.Errorf("expected plugin %s was not loaded", id)
		}
	}
}

func TestDetectorPluginCount(t *testing.T) {
	reg := NewRegistry()
	err := reg.LoadEmbedded()
	if err != nil {
		t.Fatalf("failed to load embedded plugins: %v", err)
	}
	if len(reg.List()) != 9 {
		t.Errorf("expected 9 plugins, got %d", len(reg.List()))
	}
}

func TestNeedsBaselineTrue(t *testing.T) {
	matchers := []MatcherConfig{
		{Type: MatcherBoolean},
	}
	if !needsBaseline(matchers) {
		t.Fatal("expected needsBaseline=true for boolean matcher")
	}
}

func TestNeedsBaselineTrueTime(t *testing.T) {
	matchers := []MatcherConfig{
		{Type: MatcherTimeBased},
	}
	if !needsBaseline(matchers) {
		t.Fatal("expected needsBaseline=true for time_based matcher")
	}
}

func TestNeedsBaselineFalse(t *testing.T) {
	matchers := []MatcherConfig{
		{Type: MatcherKeyword, Patterns: []string{"test"}},
		{Type: MatcherStatus},
	}
	if needsBaseline(matchers) {
		t.Fatal("expected needsBaseline=false for keyword+status")
	}
}

func TestNeedsBaselineEmpty(t *testing.T) {
	if needsBaseline(nil) {
		t.Fatal("expected needsBaseline=false for nil matchers")
	}
}

func TestDetectorGetBooleanPlugin(t *testing.T) {
	reg := NewRegistry()
	reg.LoadEmbedded()
	p := reg.Get("sql-injection-boolean")
	if p == nil {
		t.Fatal("expected to find sql-injection-boolean plugin")
	}
	if p.Baseline == nil {
		t.Fatal("expected boolean plugin to have baseline config")
	}
}

func TestDetectorGetTimePlugin(t *testing.T) {
	reg := NewRegistry()
	reg.LoadEmbedded()
	p := reg.Get("sql-injection-time")
	if p == nil {
		t.Fatal("expected to find sql-injection-time plugin")
	}
	if p.Baseline == nil {
		t.Fatal("expected time plugin to have baseline config")
	}
}

