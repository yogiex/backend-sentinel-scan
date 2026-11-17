package detector

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// pluginIDPattern keeps ids usable as selector terms and as URL/JSON values.
var pluginIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*$`)

var validMethods = map[string]struct{}{
	"GET": {}, "POST": {}, "PUT": {}, "PATCH": {}, "DELETE": {}, "HEAD": {},
}

var validSeverities = map[Severity]struct{}{
	SeverityCritical: {}, SeverityHigh: {}, SeverityMedium: {},
	SeverityLow: {}, SeverityInfo: {},
}

var validMatcherTypes = map[MatcherType]struct{}{
	MatcherKeyword: {}, MatcherRegex: {}, MatcherErrorBased: {},
	MatcherBoolean: {}, MatcherTimeBased: {}, MatcherStatus: {},
}

func ParsePlugin(data []byte) (*Plugin, error) {
	var plugin Plugin
	if err := yaml.Unmarshal(data, &plugin); err != nil {
		return nil, fmt.Errorf("failed to parse plugin: %w", err)
	}

	if plugin.Metadata.ID == "" {
		return nil, fmt.Errorf("plugin missing required field: metadata.id")
	}
	if plugin.Method == "" {
		plugin.Method = "GET"
	}
	plugin.Method = strings.ToUpper(plugin.Method)
	if plugin.Path == "" {
		return nil, fmt.Errorf("plugin %s missing required field: path", plugin.Metadata.ID)
	}
	if plugin.Engine == "" {
		plugin.Engine = "http"
	}
	if plugin.Metadata.Severity == "" {
		plugin.Metadata.Severity = SeverityInfo
	}

	for i := range plugin.Matchers {
		m := &plugin.Matchers[i]
		if m.Condition == "" {
			m.Condition = "or"
		}
		if m.Location == "" {
			m.Location = "body"
		}
		if m.Threshold == 0 {
			m.Threshold = 10
		}
		if m.Timeout == 0 {
			m.Timeout = 5
		}
	}

	if plugin.Baseline != nil {
		if plugin.Baseline.Method == "" {
			plugin.Baseline.Method = "GET"
		}
		plugin.Baseline.Method = strings.ToUpper(plugin.Baseline.Method)
		if plugin.Baseline.Path == "" {
			plugin.Baseline.Path = plugin.Path
		}
	}

	if err := plugin.Validate(); err != nil {
		return nil, err
	}
	return &plugin, nil
}

// Validate rejects definitions that would either produce no request at all or
// fail silently at execution time.
//
// The path check exists because of a real defect: a template written as
// "/api/users/FUZZ&id=FUZZ" has no "?", so every parameter after the first
// becomes part of the path and is never sent as a query value. The probe looks
// like it covers four injection points and covers one.
func (p *Plugin) Validate() error {
	if p.Metadata.ID == "" {
		return fmt.Errorf("plugin id is required")
	}
	if !pluginIDPattern.MatchString(p.Metadata.ID) {
		return fmt.Errorf("plugin %q id must match %s", p.Metadata.ID, pluginIDPattern)
	}
	if p.Method != "" {
		if _, ok := validMethods[p.Method]; !ok {
			return fmt.Errorf("plugin %s has unsupported method %q", p.Metadata.ID, p.Method)
		}
	}
	if p.Path == "" {
		return fmt.Errorf("plugin %s path is required", p.Metadata.ID)
	}
	if !strings.HasPrefix(p.Path, "/") {
		return fmt.Errorf("plugin %s path must start with /", p.Metadata.ID)
	}
	if eq := strings.Index(p.Path, "="); eq >= 0 {
		if q := strings.Index(p.Path, "?"); q < 0 || eq < q {
			return fmt.Errorf(
				"plugin %s path %q has parameters but no '?': everything after the first '&' would be sent as part of the path",
				p.Metadata.ID, p.Path)
		}
	}
	// An empty severity means "default it": ParsePlugin fills it in, but tests
	// and programmatic callers may leave it zero.
	if p.Metadata.Severity != "" {
		if _, ok := validSeverities[p.Metadata.Severity]; !ok {
			return fmt.Errorf("plugin %s has invalid severity %q", p.Metadata.ID, p.Metadata.Severity)
		}
	}
	if len(p.Matchers) == 0 {
		return fmt.Errorf("plugin %s must have at least one matcher", p.Metadata.ID)
	}
	for i, m := range p.Matchers {
		if _, ok := validMatcherTypes[m.Type]; !ok {
			return fmt.Errorf("plugin %s matcher %d has unknown type %q", p.Metadata.ID, i, m.Type)
		}
		if m.Location == MatcherLocationHeader && strings.TrimSpace(m.HeaderName) == "" {
			return fmt.Errorf("plugin %s matcher %d reads a header but has no header_name", p.Metadata.ID, i)
		}
	}
	if err := p.validateEvidence(p.Matchers); err != nil {
		return err
	}
	for i, payload := range p.Payloads {
		if strings.TrimSpace(payload.Value) == "" {
			return fmt.Errorf("plugin %s payload %d has an empty value", p.Metadata.ID, i)
		}
	}
	if p.Baseline != nil && strings.Contains(p.Baseline.Path, PlaceholderFUZZ) {
		return fmt.Errorf("plugin %s baseline path must not contain %s: the baseline is the control request",
			p.Metadata.ID, PlaceholderFUZZ)
	}
	return nil
}

// validateEvidence rejects matcher sets that cannot distinguish a vulnerable
// target from a working one.
//
// A matcher that accepts any 2xx response is the reason the previous IDOR and
// SSRF plugins reported almost every live server: "200 OK" means the page
// exists, not that a vulnerability does. A plugin whose only evidence is a
// success code is therefore refused at load time instead of being allowed to
// generate false findings.
func (p *Plugin) validateEvidence(matchers []MatcherConfig) error {
	hasContentMatcher := false
	for _, m := range matchers {
		if m.Type != MatcherStatus {
			hasContentMatcher = true
			break
		}
	}
	if hasContentMatcher {
		return nil
	}
	for _, m := range matchers {
		for _, pattern := range m.Patterns {
			var code int
			n, _ := parseStrictInt(pattern, &code)
			if n > 0 && code >= 200 && code < 300 {
				return fmt.Errorf(
					"plugin %s only matches HTTP %s, which every working page returns; add a keyword, regex, or header matcher that proves the issue",
					p.Metadata.ID, pattern)
			}
		}
	}
	return nil
}
