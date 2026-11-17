package detector

import (
	"strings"
	"testing"
)

func TestValidateRejectsQueryParamsWithoutQuestionMark(t *testing.T) {
	// This is the exact shape of the defect found in idor.yaml and
	// path_traversal.yaml: every parameter after the first became part of the
	// path, so three of four injection points were never exercised.
	plugin := &Plugin{
		Metadata: PluginMetadata{ID: "broken", Severity: SeverityHigh},
		Method:   "GET",
		Path:     "/api/users/FUZZ&id=FUZZ",
		Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"x"}}},
		Payloads: []Payload{{Name: "p", Value: "1"}},
	}
	err := plugin.Validate()
	if err == nil {
		t.Fatal("expected a validation error for parameters without '?'")
	}
	if !strings.Contains(err.Error(), "no '?'") {
		t.Fatalf("error should explain the missing '?': %v", err)
	}
}

func TestValidateRejectsUnknownMethodSeverityAndMatcher(t *testing.T) {
	base := func() *Plugin {
		return &Plugin{
			Metadata: PluginMetadata{ID: "p", Severity: SeverityHigh},
			Method:   "GET",
			Path:     "/?q=FUZZ",
			Matchers: []MatcherConfig{{Type: MatcherKeyword, Patterns: []string{"x"}}},
			Payloads: []Payload{{Name: "p", Value: "1"}},
		}
	}

	tests := map[string]func(*Plugin){
		"method":   func(p *Plugin) { p.Method = "TRACE" },
		"severity": func(p *Plugin) { p.Metadata.Severity = "urgent" },
		"matcher":  func(p *Plugin) { p.Matchers[0].Type = "vibes" },
		"payload":  func(p *Plugin) { p.Payloads[0].Value = " " },
		"id":       func(p *Plugin) { p.Metadata.ID = "Not Valid" },
		"baseline": func(p *Plugin) { p.Baseline = &BaselineRequest{Path: "/?q=FUZZ"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			p := base()
			mutate(p)
			if err := p.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", name)
			}
		})
	}
}

func TestEmbeddedPluginsAllValidate(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("embedded plugins must all parse and validate: %v", err)
	}
	if reg.Len() != 7 {
		t.Fatalf("expected 7 embedded plugins, got %d", reg.Len())
	}
	for _, p := range reg.List() {
		if len(p.Payloads) == 0 {
			t.Errorf("plugin %s has no payloads", p.Metadata.ID)
		}
	}
}

func TestResolveSelectors(t *testing.T) {
	reg := NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("load: %v", err)
	}

	ids := func(plugins []*Plugin) []string {
		out := make([]string, len(plugins))
		for i, p := range plugins {
			out[i] = p.Metadata.ID
		}
		return out
	}

	if got := ids(mustResolve(t, reg, "")); len(got) != 7 {
		t.Fatalf("empty selector should mean all plugins, got %d", len(got))
	}
	if got := ids(mustResolve(t, reg, "xss-reflected")); len(got) != 1 || got[0] != "xss-reflected" {
		t.Fatalf("id selector: %v", got)
	}
	critical := mustResolve(t, reg, "critical")
	if len(critical) == 0 {
		t.Fatal("severity selector matched nothing")
	}
	for _, p := range critical {
		if p.Metadata.Severity != SeverityCritical {
			t.Fatalf("severity selector returned %s with severity %s", p.Metadata.ID, p.Metadata.Severity)
		}
	}
	tagHits := ids(mustResolve(t, reg, "xss"))
	if len(tagHits) != 1 || tagHits[0] != "xss-reflected" {
		t.Fatalf("tag selector: %v", tagHits)
	}
	// Two selectors, one of them matching several plugins, must not duplicate.
	combined := ids(mustResolve(t, reg, "xss, xss-reflected"))
	if len(combined) != 1 {
		t.Fatalf("duplicate selectors produced %v", combined)
	}

	if _, err := reg.Resolve("no-such-plugin"); err == nil {
		t.Fatal("unknown selector must be an error, not a silent scan of everything")
	}
}

func mustResolve(t *testing.T, reg *Registry, selectors string) []*Plugin {
	t.Helper()
	plugins, err := reg.Resolve(selectors)
	if err != nil {
		t.Fatalf("resolve %q: %v", selectors, err)
	}
	return plugins
}
