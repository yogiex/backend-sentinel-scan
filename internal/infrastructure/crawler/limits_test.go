package crawler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// hitCounter records which paths a test server actually served.
type hitCounter struct {
	mu   sync.Mutex
	hits map[string]int
}

func (h *hitCounter) add(path string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.hits == nil {
		h.hits = map[string]int{}
	}
	h.hits[path]++
}

func (h *hitCounter) count(path string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.hits[path]
}

func linkSite(t *testing.T) (*httptest.Server, *hitCounter) {
	t.Helper()
	hits := &hitCounter{}
	mux := http.NewServeMux()
	page := func(path, body string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			hits.add(path)
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(body))
		})
	}
	page("/", `<html><body><a href="/a">a</a><a href="/b">b</a><a href="/c">c</a></body></html>`)
	page("/a", `<html><body><a href="/">home</a><a href="/a2">a2</a></body></html>`)
	page("/b", `<html><body><a href="/">home</a></body></html>`)
	page("/c", `<html><body><a href="/">home</a></body></html>`)
	page("/a2", `<html><body>deep</body></html>`)
	return httptest.NewServer(mux), hits
}

func TestMaxPagesStopsTheCrawl(t *testing.T) {
	srv, hits := linkSite(t)
	defer srv.Close()

	cfg := CrawlConfig{Link: DefaultLinkConfig()}
	cfg.Link.Enabled = true
	cfg.Link.MaxPages = 1
	cfg.Link.MaxDepth = 3
	cfg.Link.Scope = ScopeStrict
	cfg.Link.RespectRobots = false
	cfg.Link.Concurrency = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := New(cfg).Run(ctx, []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}

	if got := len(result.DiscoveredURLs); got != 1 {
		t.Fatalf("max_pages=1 must yield one discovered URL, got %d (%+v)", got, result.DiscoveredURLs)
	}
	if !result.Truncated {
		t.Fatal("hitting max_pages must mark the crawl truncated")
	}
	for _, path := range []string{"/a", "/b", "/c"} {
		if hits.count(path) != 0 {
			t.Fatalf("page cap exceeded: %s was fetched", path)
		}
	}
}

func TestMaxDepthBoundsRecursion(t *testing.T) {
	srv, hits := linkSite(t)
	defer srv.Close()

	cfg := CrawlConfig{Link: DefaultLinkConfig()}
	cfg.Link.Enabled = true
	cfg.Link.MaxPages = 50
	cfg.Link.MaxDepth = 1
	cfg.Link.Scope = ScopeStrict
	cfg.Link.RespectRobots = false
	cfg.Link.Concurrency = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := New(cfg).Run(ctx, []string{srv.URL + "/"})
	if err != nil {
		t.Fatalf("crawl: %v", err)
	}
	if result.Truncated {
		t.Fatal("max_pages was not reached, so the crawl must not be truncated")
	}
	if hits.count("/a2") != 0 {
		t.Fatal("depth 2 link /a2 must not be fetched when max_depth=1")
	}
	if hits.count("/a") == 0 {
		t.Fatal("depth 1 link /a should be fetched")
	}
}

func TestRobotsDisallowIsHonoured(t *testing.T) {
	hits := &hitCounter{}
	mux := http.NewServeMux()
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /private\n"))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		hits.add("/")
		_, _ = w.Write([]byte(`<html><body><a href="/private">secret</a><a href="/public">ok</a></body></html>`))
	})
	mux.HandleFunc("/private", func(w http.ResponseWriter, r *http.Request) {
		hits.add("/private")
		_, _ = w.Write([]byte("secret"))
	})
	mux.HandleFunc("/public", func(w http.ResponseWriter, r *http.Request) {
		hits.add("/public")
		_, _ = w.Write([]byte("ok"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	cfg := CrawlConfig{Link: DefaultLinkConfig()}
	cfg.Link.Enabled = true
	cfg.Link.MaxPages = 20
	cfg.Link.MaxDepth = 1
	cfg.Link.Scope = ScopeStrict
	cfg.Link.RespectRobots = true
	cfg.Link.Concurrency = 2

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := New(cfg).Run(ctx, []string{srv.URL + "/"}); err != nil {
		t.Fatalf("crawl: %v", err)
	}

	if hits.count("/private") != 0 {
		t.Fatal("robots.txt disallow was ignored")
	}
	if hits.count("/public") == 0 {
		t.Fatal("robots allowed page was not fetched")
	}
}
