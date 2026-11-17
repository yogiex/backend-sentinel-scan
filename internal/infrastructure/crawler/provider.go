package crawler

import (
	"context"
	"sync/atomic"
)

type DiscoveryProvider interface {
	Name() ProviderType
	Start(ctx context.Context, seedURLs []string, results chan<- DiscoveredURL, infra SharedInfra)
}

type SharedInfra struct {
	Dedup   *Deduplicator
	Scope   *ScopeFilter
	Fetcher *Fetcher
	Robots  *RobotsFilter
	OnURL   func(DiscoveredURL)
	OnError func(error)

	// MaxPages caps how many pages one crawl fetches. Zero means unlimited,
	// which is why the orchestrator always sets it from config.
	MaxPages int
	fetched  *atomic.Int64
	// denied counts pages that were wanted but not allowed, which is what makes
	// a crawl "truncated". Fetching exactly MaxPages pages with nothing left to
	// do is complete, not truncated.
	denied *atomic.Int64
}

func NewSharedInfra(cfg CrawlConfig) SharedInfra {
	scopeRule := ScopeStrict
	if cfg.Link.Enabled {
		scopeRule = cfg.Link.Scope
	} else if cfg.BruteForce.Enabled {
		scopeRule = cfg.BruteForce.Scope
	}

	fetcherCfg := FetcherConfig{
		Timeout:   cfg.Link.Timeout,
		RateLimit: cfg.Link.RateLimit,
		UserAgent: cfg.Link.UserAgent,
		Headers:   cfg.Link.Headers,
		Client:    cfg.Client,
	}

	infra := SharedInfra{
		Dedup:    NewDeduplicator(),
		Scope:    NewScopeFilter(scopeRule),
		Fetcher:  NewFetcher(fetcherCfg),
		Robots:   nil,
		OnURL:    func(DiscoveredURL) {},
		OnError:  func(error) {},
		MaxPages: cfg.Link.MaxPages,
		fetched:  new(atomic.Int64),
		denied:   new(atomic.Int64),
	}
	// The robots filter used to be hard-coded to nil, so respect_robots had no
	// effect at all. Build it when the caller asked for it.
	if cfg.Link.RespectRobots {
		infra.Robots = NewRobotsFilter(infra.Fetcher)
	}
	return infra
}

// reservePage claims one page slot. It returns false once the cap is reached.
func (i SharedInfra) reservePage() bool {
	if i.fetched == nil {
		return true
	}
	for {
		current := i.fetched.Load()
		if i.MaxPages > 0 && current >= int64(i.MaxPages) {
			if i.denied != nil {
				i.denied.Add(1)
			}
			return false
		}
		if i.fetched.CompareAndSwap(current, current+1) {
			return true
		}
	}
}

// PagesFetched reports how many page slots were used.
func (i SharedInfra) PagesFetched() int {
	if i.fetched == nil {
		return 0
	}
	return int(i.fetched.Load())
}

// PageLimitReached reports whether the crawl had to skip at least one page
// because of MaxPages.
func (i SharedInfra) PageLimitReached() bool {
	return i.denied != nil && i.denied.Load() > 0
}
