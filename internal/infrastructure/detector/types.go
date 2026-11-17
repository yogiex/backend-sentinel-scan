package detector

import (
	"net/http"
	"time"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// HTTPClient is the contract the detector needs from an HTTP client. It exists
// so the caller can supply a client hardened by the SSRF guard and the egress
// limiter; a nil value falls back to a plain client (tests only).
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type DetectionConfig struct {
	PluginsDir           string
	DefaultSeverity      Severity
	MaxPayloadsPerPlugin int
	Timeout              time.Duration
	// Client is shared by every plugin executed by one Detector. Sharing it is
	// what keeps connection pools and the egress budget meaningful.
	Client HTTPClient
}

type PluginMetadata struct {
	ID          string   `yaml:"id"`
	Name        string   `yaml:"name"`
	Description string   `yaml:"description"`
	Severity    Severity `yaml:"severity"`
	Tags        []string `yaml:"tags"`
	Reference   string   `yaml:"reference"`
}

type Plugin struct {
	Metadata PluginMetadata    `yaml:"metadata"`
	Engine   string            `yaml:"engine"`
	Method   string            `yaml:"method"`
	Path     string            `yaml:"path"`
	Headers  map[string]string `yaml:"headers"`
	Body     string            `yaml:"body"`
	Payloads []Payload         `yaml:"payloads"`
	Matchers []MatcherConfig   `yaml:"matchers"`
	Baseline *BaselineRequest  `yaml:"baseline"`
	// NoRedirect stops the executor at the first redirect so the response still
	// carries the Location header. Without it Go follows the redirect and an
	// open-redirect probe sees the final page instead of the evidence.
	NoRedirect bool `yaml:"no_redirect"`
}

type BaselineRequest struct {
	Method  string            `yaml:"method"`
	Path    string            `yaml:"path"`
	Headers map[string]string `yaml:"headers"`
	Body    string            `yaml:"body"`
}

type Payload struct {
	Name    string `yaml:"name"`
	Value   string `yaml:"value"`
	Encoded bool   `yaml:"encoded"`
}

type MatcherType string

const (
	MatcherKeyword    MatcherType = "keyword"
	MatcherRegex      MatcherType = "regex"
	MatcherErrorBased MatcherType = "error_based"
	MatcherBoolean    MatcherType = "boolean"
	MatcherTimeBased  MatcherType = "time_based"
	MatcherStatus     MatcherType = "status"
)

// Matcher locations. "header" needs HeaderName; the other two are carried for
// readability and to keep old plugin files valid.
const (
	MatcherLocationBody   = "body"
	MatcherLocationStatus = "status"
	MatcherLocationHeader = "header"
)

type MatcherConfig struct {
	Type     MatcherType `yaml:"type"`
	Patterns []string    `yaml:"patterns"`
	Location string      `yaml:"location"`
	// HeaderName selects the response header read when Location is "header".
	// Without it a header matcher has nothing to read and would silently never
	// match.
	HeaderName string `yaml:"header_name"`
	Negative   bool   `yaml:"negative"`
	Condition  string `yaml:"condition"`
	Comparison string `yaml:"comparison"`
	Threshold  int    `yaml:"threshold"`
	Timeout    int    `yaml:"timeout"`
}

type MatchResult struct {
	Matched  bool
	Type     MatcherType
	Pattern  string
	Evidence string
	Payload  string
}

type PluginResult struct {
	PluginID     string
	Target       string
	Matched      bool
	Severity     Severity
	Matches      []MatchResult
	ResponseBody string
	StatusCode   int
	// ResponseTruncated reports that the evidence came from a body cut at
	// MaxResponseBytes, so a "not matched" verdict is not authoritative.
	ResponseTruncated bool
	Duration          time.Duration
}

// CheckStats reports how much of a check actually happened.
//
// A detector that returns only matches cannot tell "the target is clean" apart
// from "every request failed", and the difference decides whether a report may
// be trusted. Attempted counts issued requests, Succeeded counts requests that
// produced any response (including 4xx/5xx), and Failed counts transport-level
// failures such as timeouts, refused connections, and cancelled contexts.
type CheckStats struct {
	Attempted int
	Succeeded int
	Failed    int
	// LastError is the most recent transport error, for the failure reason.
	LastError error
}

// Checked reports that at least one request reached the target. Without this,
// a plugin that matched nothing proves nothing.
func (s CheckStats) Checked() bool { return s.Succeeded > 0 }

// CheckResult is the outcome of running one or more plugins against a target.
type CheckResult struct {
	Matches []PluginResult
	Stats   CheckStats
}

func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		PluginsDir:           "./plugins",
		DefaultSeverity:      SeverityInfo,
		MaxPayloadsPerPlugin: 20,
		Timeout:              10 * time.Second,
	}
}
