package detector

import "time"

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type DetectionConfig struct {
	PluginsDir            string
	DefaultSeverity       Severity
	MaxPayloadsPerPlugin  int
	Timeout               time.Duration
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
	Metadata  PluginMetadata    `yaml:"metadata"`
	Engine    string            `yaml:"engine"`
	Method    string            `yaml:"method"`
	Path      string            `yaml:"path"`
	Headers   map[string]string `yaml:"headers"`
	Body      string            `yaml:"body"`
	Payloads  []Payload         `yaml:"payloads"`
	Matchers  []MatcherConfig   `yaml:"matchers"`
	Baseline  *BaselineRequest  `yaml:"baseline"`
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
	Duration     time.Duration
}

func DefaultDetectionConfig() DetectionConfig {
	return DetectionConfig{
		PluginsDir:           "./plugins",
		DefaultSeverity:      SeverityInfo,
		MaxPayloadsPerPlugin: 20,
		Timeout:              10 * time.Second,
	}
}
