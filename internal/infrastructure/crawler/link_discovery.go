package crawler

import (
	"context"
	"net/url"
	"sync"
)

type LinkDiscovery struct {
	config LinkConfig
}

func NewLinkDiscovery(cfg LinkConfig) *LinkDiscovery {
	return &LinkDiscovery{config: cfg}
}

func (d *LinkDiscovery) Name() ProviderType {
	return ProviderLink
}

func (d *LinkDiscovery) Start(ctx context.Context, seedURLs []string, results chan<- DiscoveredURL, infra SharedInfra) {
	taskCh := make(chan crawlTask, 10000)
	var taskWg sync.WaitGroup

	var workerWg sync.WaitGroup
	for i := 0; i < d.config.Concurrency; i++ {
		workerWg.Add(1)
		go d.worker(ctx, &workerWg, &taskWg, taskCh, results, infra, seedURLs)
	}

	for _, seed := range seedURLs {
		taskWg.Add(1)
		select {
		case taskCh <- crawlTask{URL: seed, Depth: 0}:
		default:
			taskWg.Done()
		}
	}

	go func() {
		taskWg.Wait()
		close(taskCh)
	}()

	workerWg.Wait()
}

type crawlTask struct {
	URL   string
	Depth int
}

func (d *LinkDiscovery) worker(ctx context.Context, workerWg, taskWg *sync.WaitGroup, tasks chan crawlTask, results chan<- DiscoveredURL, infra SharedInfra, seedURLs []string) {
	defer workerWg.Done()

	for task := range tasks {
		select {
		case <-ctx.Done():
			// Account for this task and drain what is still buffered, otherwise
			// the closer goroutine (taskWg.Wait) blocks forever.
			taskWg.Done()
			for range tasks {
				taskWg.Done()
			}
			return
		default:
		}

		if !infra.Dedup.TryVisit(task.URL) {
			taskWg.Done()
			continue
		}

		if !infra.Scope.Allows(task.URL, seedURLs) {
			taskWg.Done()
			continue
		}

		if infra.Robots != nil {
			allowed, err := infra.Robots.Allowed(ctx, task.URL)
			if err != nil || !allowed {
				if err != nil {
					infra.OnError(err)
				}
				taskWg.Done()
				continue
			}
		}

		page, err := d.fetchPage(ctx, task.URL, infra)
		if err != nil {
			infra.OnError(err)
			taskWg.Done()
			continue
		}

		results <- DiscoveredURL{URL: task.URL, Depth: task.Depth, Source: "link"}

		shouldRecurse := d.config.MaxDepth == -1 || task.Depth < d.config.MaxDepth
		if shouldRecurse {
			for _, link := range page.Links {
				if infra.Scope.Allows(link, seedURLs) && !infra.Dedup.IsVisited(link) {
					taskWg.Add(1)
					select {
					case tasks <- crawlTask{URL: link, Depth: task.Depth + 1}:
					default:
						taskWg.Done()
					}
				}
			}

			for _, form := range page.Forms {
				if form.Action != "" && !infra.Dedup.IsVisited(form.Action) {
					results <- DiscoveredURL{URL: form.Action, Depth: task.Depth + 1, Source: "form"}
					if infra.Scope.Allows(form.Action, seedURLs) {
						taskWg.Add(1)
						select {
						case tasks <- crawlTask{URL: form.Action, Depth: task.Depth + 1}:
						default:
							taskWg.Done()
						}
					}
				}
			}
		}

		taskWg.Done()
	}
}

func (d *LinkDiscovery) fetchPage(ctx context.Context, urlStr string, infra SharedInfra) (*Page, error) {
	baseURL, err := url.Parse(urlStr)
	if err != nil {
		return nil, err
	}

	result, err := infra.Fetcher.Fetch(ctx, urlStr)
	if err != nil {
		return nil, err
	}

	page := &Page{
		URL:        result.FinalURL,
		StatusCode: result.StatusCode,
		RawBody:    result.Body,
	}

	if result.StatusCode == 200 {
		page.Links = parseLinks(result.Body, baseURL)
		page.Forms = parseForms(result.Body, baseURL)
		page.Assets = parseAssets(result.Body, baseURL)
	}

	return page, nil
}
