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

type MatcherConfig struct {
	Type       MatcherType `yaml:"type"`
	Patterns   []string    `yaml:"patterns"`
	Location   string      `yaml:"location"`
	Negative   bool        `yaml:"negative"`
	Condition  string      `yaml:"condition"`
	Comparison string      `yaml:"comparison"`
	Threshold  int         `yaml:"threshold"`
	Timeout    int         `yaml:"timeout"`
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

func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		PluginsDir:           "./plugins",
		DefaultSeverity:      SeverityInfo,
		MaxPayloadsPerPlugin: 20,
		Timeout:              10 * time.Second,
	}
}
