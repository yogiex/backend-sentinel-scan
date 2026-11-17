package crawler

import "time"

type ProviderType string

const (
	ProviderLink       ProviderType = "link"
	ProviderBruteForce ProviderType = "bruteforce"
)

type CrawlConfig struct {
	Link       LinkConfig
	BruteForce BruteForceConfig
	// Client, when set, is used by every fetcher the crawler creates. Production
	// callers pass the SSRF-guarded, budget-aware client.
	Client HTTPClient
}

type LinkConfig struct {
	Enabled       bool
	MaxDepth      int
	MaxPages      int
	RateLimit     time.Duration
	Concurrency   int
	RespectRobots bool
	Scope         ScopeRule
	Timeout       time.Duration
	Headers       map[string]string
	UserAgent     string
}

type BruteForceConfig struct {
	Enabled      bool
	WordlistPath string
	Concurrency  int
	RateLimit    time.Duration
	Timeout      time.Duration
	Scope        ScopeRule
}

type ScopeRule int

const (
	ScopeStrict ScopeRule = iota
	ScopeSameDomain
	ScopePathPrefix
	ScopeUnrestricted
)

type Page struct {
	URL        string
	Depth      int
	Links      []string
	Forms      []Form
	Assets     []string
	RawBody    string
	StatusCode int
}

type Form struct {
	Action string
	Method string
	Inputs []FormInput
}

type FormInput struct {
	Name string
	Type string
}

type DiscoveredURL struct {
	URL    string
	Depth  int
	Source string
}

type CrawlResult struct {
	DiscoveredURLs []DiscoveredURL
	Pages          []Page
	Forms          []Form
	TotalRequests  int
	Duration       time.Duration
	Errors         []error
	// Truncated reports that the crawl stopped at MaxPages, so the scan that
	// follows covers only part of the site.
	Truncated bool
}

func DefaultLinkConfig() LinkConfig {
	return LinkConfig{
		Enabled:       false,
		MaxDepth:      2,
		MaxPages:      100,
		RateLimit:     200 * time.Millisecond,
		Concurrency:   5,
		RespectRobots: true,
		Scope:         ScopeStrict,
		Timeout:       10 * time.Second,
		UserAgent:     "SentinelScan-Crawler/1.0",
	}
}

func DefaultBruteForceConfig() BruteForceConfig {
	return BruteForceConfig{
		Enabled:      false,
		WordlistPath: "",
		Concurrency:  10,
		RateLimit:    50 * time.Millisecond,
		Timeout:      5 * time.Second,
		Scope:        ScopeStrict,
	}
}
