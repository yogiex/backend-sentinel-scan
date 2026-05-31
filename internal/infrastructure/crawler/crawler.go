package crawler

import (
	"context"
	"sync"
	"time"
)

type Crawler struct {
	config  CrawlConfig
	results []DiscoveredURL
	mu      sync.Mutex
}

func New(cfg CrawlConfig) *Crawler {
	return &Crawler{
		config: cfg,
	}
}

func (c *Crawler) Start(ctx context.Context, seedURLs []string) (<-chan DiscoveredURL, error) {
	infra := NewSharedInfra(c.config)
	resultCh := make(chan DiscoveredURL, 10000)
	outCh := make(chan DiscoveredURL, 10000)

	var providers []DiscoveryProvider
	if c.config.Link.Enabled {
		providers = append(providers, NewLinkDiscovery(c.config.Link))
	}
	if c.config.BruteForce.Enabled {
		providers = append(providers, NewBruteForceDiscovery(c.config.BruteForce))
	}

	go c.collectResults(ctx, resultCh, outCh)

	if len(providers) == 0 {
		close(resultCh)
		return outCh, nil
	}

	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Add(1)
		go func(provider DiscoveryProvider) {
			defer wg.Done()
			provider.Start(ctx, seedURLs, resultCh, infra)
		}(p)
	}

	go func() {
		wg.Wait()
		close(resultCh)
	}()

	return outCh, nil
}

func (c *Crawler) collectResults(ctx context.Context, resultCh <-chan DiscoveredURL, outCh chan<- DiscoveredURL) {
	defer close(outCh)

	for url := range resultCh {
		c.mu.Lock()
		c.results = append(c.results, url)
		c.mu.Unlock()

		select {
		case outCh <- url:
		default:
		}
	}
}

func (c *Crawler) Results() []DiscoveredURL {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make([]DiscoveredURL, len(c.results))
	copy(result, c.results)
	return result
}

func (c *Crawler) Run(ctx context.Context, seedURLs []string) (*CrawlResult, error) {
	start := time.Now()
	outCh, err := c.Start(ctx, seedURLs)
	if err != nil {
		return nil, err
	}

	var discovered []DiscoveredURL
	for url := range outCh {
		discovered = append(discovered, url)
	}

	duration := time.Since(start)

	return &CrawlResult{
		DiscoveredURLs: discovered,
		TotalRequests:  len(discovered),
		Duration:       duration,
	}, nil
}
