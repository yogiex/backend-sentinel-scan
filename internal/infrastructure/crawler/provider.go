package crawler

import "context"

type DiscoveryProvider interface {
	Name() ProviderType
	Start(ctx context.Context, seedURLs []string, results chan<- DiscoveredURL, infra SharedInfra)
}

type SharedInfra struct {
	Dedup     *Deduplicator
	Scope     *ScopeFilter
	Fetcher   *Fetcher
	Robots    *RobotsFilter
	OnURL     func(DiscoveredURL)
	OnError   func(error)
}

func NewSharedInfra(cfg CrawlConfig) SharedInfra {
	scopeRule := ScopeStrict
	if cfg.Link.Enabled {
		scopeRule = cfg.Link.Scope
	} else if cfg.BruteForce.Enabled {
		scopeRule = cfg.BruteForce.Scope
	}

	fetcherCfg := FetcherConfig{
		Timeout:       cfg.Link.Timeout,
		RateLimit:     cfg.Link.RateLimit,
		UserAgent:     cfg.Link.UserAgent,
		Headers:       cfg.Link.Headers,
	}

	return SharedInfra{
		Dedup:   NewDeduplicator(),
		Scope:   NewScopeFilter(scopeRule),
		Fetcher: NewFetcher(fetcherCfg),
		Robots:  nil,
		OnURL:   func(DiscoveredURL) {},
		OnError: func(error) {},
	}
}
