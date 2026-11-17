package orchestrator

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/crawler"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
)

// crawlSite serves a small interlinked site plus one external link that the
// SSRF policy must reject.
func crawlSite(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>
			<a href="/p1">1</a><a href="/p2">2</a><a href="http://evil.test/">out</a>
		</body></html>`))
	})
	mux.HandleFunc("/p1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>p1</body></html>`))
	})
	mux.HandleFunc("/p2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body>p2</body></html>`))
	})
	return httptest.NewServer(mux)
}

func crawlOrchestrator(t *testing.T, site *httptest.Server, opts *entity.CrawlOptions) (*Orchestrator, *fakeScanRepo, chan worker.Task) {
	t.Helper()
	reg := detector.NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	allowed, err := url.Parse(site.URL)
	if err != nil {
		t.Fatalf("parse site url: %v", err)
	}
	scans := &fakeScanRepo{}
	tasks := make(chan worker.Task, 64)
	orch := New(Config{
		Registry:    reg,
		TaskQueue:   tasks,
		ResultQueue: make(chan worker.Result, 64),
		ScanRepo:    scans,
		FindingRepo: &fakeFindingRepo{},
		CrawlDefaults: crawler.CrawlConfig{
			Link: crawler.LinkConfig{
				MaxDepth:      1,
				MaxPages:      5,
				Concurrency:   2,
				RespectRobots: false,
				Scope:         crawler.ScopeSameDomain,
				Timeout:       2 * time.Second,
			},
			Client: site.Client(),
		},
		CrawlClient:  site.Client(),
		CrawlTimeout: 5 * time.Second,
		ValidateTarget: func(_ context.Context, raw string) (string, error) {
			u, err := url.Parse(raw)
			if err != nil {
				return "", err
			}
			if u.Host != allowed.Host {
				return "", errors.New("host outside the target")
			}
			return u.String(), nil
		},
	})
	if err := orch.StartScan(21, []string{site.URL + "/"}, "xss-reflected", opts); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	return orch, scans, tasks
}

func TestCrawlExpandsTargetsAndDropsForeignHosts(t *testing.T) {
	site := crawlSite(t)
	defer site.Close()

	_, scans, tasks := crawlOrchestrator(t, site, &entity.CrawlOptions{
		Enabled: true, MaxDepth: 1, MaxPages: 5, RespectRobots: false,
	})

	// xss-reflected is one plugin, so the task count equals the target count.
	seen := map[string]bool{}
	deadline := time.After(5 * time.Second)
	for len(seen) < 3 {
		select {
		case task := <-tasks:
			seen[task.Target] = true
		case <-deadline:
			t.Fatalf("expected 3 targets, saw %v", seen)
		}
	}
	if !seen[site.URL+"/"] {
		t.Fatalf("submitted target missing from %v", seen)
	}
	if !seen[site.URL+"/p1"] || !seen[site.URL+"/p2"] {
		t.Fatalf("discovered pages missing from %v", seen)
	}
	for target := range seen {
		u, err := url.Parse(target)
		if err != nil {
			t.Fatalf("bad target %q: %v", target, err)
		}
		if u.Host == "evil.test" {
			t.Fatalf("a foreign host was queued for scanning: %s", target)
		}
	}

	waitFor(t, func() bool {
		_, progress, _ := scans.snapshot()
		return progress.Phase == "scanning" && progress.TotalTasks == 3
	})
	_, progress, _ := scans.snapshot()
	if progress.InProgress != 3 {
		t.Fatalf("expected 3 in-progress tasks, got %+v", progress)
	}
}

func TestCrawlTruncationMarksTheScan(t *testing.T) {
	site := crawlSite(t)
	defer site.Close()

	_, scans, tasks := crawlOrchestrator(t, site, &entity.CrawlOptions{
		Enabled: true, MaxDepth: 1, MaxPages: 1, RespectRobots: false,
	})

	// max_pages=1 means the seed is the only page fetched.
	select {
	case task := <-tasks:
		if task.Target != site.URL+"/" {
			t.Fatalf("expected only the seed target, got %s", task.Target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no task queued after the crawl")
	}

	waitFor(t, func() bool {
		_, _, truncated := scans.snapshot()
		return truncated
	})
}

func TestCrawlFailureFallsBackToSubmittedTargets(t *testing.T) {
	// Point the crawler at a closed port: discovery fails, the scan must still
	// run against the target the user submitted.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	reg := detector.NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	tasks := make(chan worker.Task, 8)
	orch := New(Config{
		Registry:    reg,
		TaskQueue:   tasks,
		ResultQueue: make(chan worker.Result, 8),
		ScanRepo:    &fakeScanRepo{},
		FindingRepo: &fakeFindingRepo{},
		CrawlDefaults: crawler.CrawlConfig{
			Link:   crawler.LinkConfig{MaxDepth: 1, MaxPages: 5, Concurrency: 1, Timeout: 300 * time.Millisecond},
			Client: dead.Client(),
		},
		CrawlClient:  dead.Client(),
		CrawlTimeout: 2 * time.Second,
	})
	if err := orch.StartScan(22, []string{deadURL + "/"}, "xss-reflected", &entity.CrawlOptions{
		Enabled: true, MaxDepth: 1, MaxPages: 5, RespectRobots: false,
	}); err != nil {
		t.Fatalf("start scan: %v", err)
	}

	select {
	case task := <-tasks:
		if task.Target != deadURL+"/" {
			t.Fatalf("expected the submitted target, got %s", task.Target)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a failed crawl must still queue the submitted targets")
	}
}
