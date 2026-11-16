package crawler

import (
	"context"
	"path"
	"strings"
	"sync"
)

type BruteForceDiscovery struct {
	config   BruteForceConfig
	wordlist WordlistLoader
}

func NewBruteForceDiscovery(cfg BruteForceConfig) *BruteForceDiscovery {
	var loader WordlistLoader
	if cfg.WordlistPath != "" {
		loader = NewFileWordlist(cfg.WordlistPath)
	} else {
		loader = NewBuiltinWordlist()
	}

	return &BruteForceDiscovery{
		config:   cfg,
		wordlist: loader,
	}
}

func (d *BruteForceDiscovery) Name() ProviderType {
	return ProviderBruteForce
}

func (d *BruteForceDiscovery) Start(ctx context.Context, seedURLs []string, results chan<- DiscoveredURL, infra SharedInfra) {
	paths, err := d.wordlist.Load(ctx)
	if err != nil {
		infra.OnError(err)
		return
	}

	var wg sync.WaitGroup
	workCh := make(chan bruteTask, 100)

	for i := 0; i < d.config.Concurrency; i++ {
		wg.Add(1)
		go d.worker(ctx, &wg, workCh, results, infra, seedURLs)
	}

	go func() {
		defer close(workCh)
	sendLoop:
		for _, seed := range seedURLs {
			base := strings.TrimRight(seed, "/")
			for _, p := range paths {
				fullURL := base + "/" + strings.TrimLeft(p, "/")
				select {
				case workCh <- bruteTask{URL: fullURL, Path: p}:
				case <-ctx.Done():
					break sendLoop
				}
			}
		}
	}()

	wg.Wait()
}

type bruteTask struct {
	URL  string
	Path string
}

func (d *BruteForceDiscovery) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan bruteTask, results chan<- DiscoveredURL, infra SharedInfra, seedURLs []string) {
	defer wg.Done()

	for task := range tasks {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if !infra.Dedup.TryVisit(task.URL) {
			continue
		}

		if !infra.Scope.Allows(task.URL, seedURLs) {
			continue
		}

		statusCode, err := infra.Fetcher.FetchHEAD(ctx, task.URL)
		if err != nil {
			continue
		}

		if statusCode == 404 || statusCode == 0 {
			continue
		}

		finalURL, ok := d.verifyGET(ctx, task.URL, infra)
		if !ok {
			continue
		}

		if finalURL != "" {
			results <- DiscoveredURL{URL: finalURL, Depth: 0, Source: "bruteforce"}
		} else {
			results <- DiscoveredURL{URL: task.URL, Depth: 0, Source: "bruteforce"}
		}
	}
}

func (d *BruteForceDiscovery) verifyGET(ctx context.Context, urlStr string, infra SharedInfra) (string, bool) {
	result, err := infra.Fetcher.Fetch(ctx, urlStr)
	if err != nil {
		return "", false
	}

	if result.StatusCode == 404 {
		return "", false
	}

	ext := strings.ToLower(path.Ext(urlStr))
	if ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".svg" || ext == ".ico" || ext == ".css" || ext == ".woff" || ext == ".woff2" {
		return "", false
	}

	return result.FinalURL, true
}
