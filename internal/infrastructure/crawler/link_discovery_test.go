package crawler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLinkDiscovery_SinglePage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page1">Link</a><a href="/page2">Link</a></body></html>`)
	}))
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 0
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL)
}

func TestLinkDiscovery_RecursiveCrawl(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page1">Page 1</a></body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page2">Page 2</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>No more links</body></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 2
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL + "/"}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL+"/")
	assert.Contains(t, urls, server.URL+"/page1")
	assert.Contains(t, urls, server.URL+"/page2")
}

func TestLinkDiscovery_ScopeFiltering(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="http://other.com/page">Outside</a><a href="/internal">Internal</a></body></html>`)
	})
	mux.HandleFunc("/internal", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>Internal page</body></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 1
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeStrict

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL + "/"}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL+"/")
	assert.Contains(t, urls, server.URL+"/internal")
	assert.NotContains(t, urls, "http://other.com/page")
}

func TestLinkDiscovery_FormDiscovery(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>
			<form action="/login" method="POST">
				<input name="username" type="text">
				<input name="password" type="password">
			</form>
		</body></html>`)
	}))
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 0
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL)
}

func TestLinkDiscovery_DepthLimit(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page1">Page 1</a></body></html>`)
	})
	mux.HandleFunc("/page1", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page2">Page 2</a></body></html>`)
	})
	mux.HandleFunc("/page2", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>Deep page</body></html>`)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 1
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL + "/"}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL+"/")
	assert.Contains(t, urls, server.URL+"/page1")
	assert.NotContains(t, urls, server.URL+"/page2", "depth 2 should not be crawled with MaxDepth=1")
}

func TestLinkDiscovery_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		fmt.Fprint(w, `<html><body><a href="/page">Page</a></body></html>`)
	}))
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 1
	cfg.MaxPages = 100
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)
	results := make(chan DiscoveredURL, 100)

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	require.NotPanics(t, func() {
		provider.Start(ctx, []string{server.URL}, results, infra)
	})
	close(results)
}

func TestLinkDiscovery_Non200StatusCode(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "Not Found")
	}))
	defer server.Close()

	cfg := DefaultLinkConfig()
	cfg.Enabled = true
	cfg.MaxDepth = 0
	cfg.MaxPages = 10
	cfg.Timeout = 5 * time.Second
	cfg.RateLimit = 0
	cfg.Scope = ScopeUnrestricted
	cfg.RespectRobots = false

	infra := NewSharedInfra(CrawlConfig{Link: cfg})
	provider := NewLinkDiscovery(cfg)

	results := make(chan DiscoveredURL, 100)
	provider.Start(context.Background(), []string{server.URL}, results, infra)
	close(results)

	var urls []string
	for u := range results {
		urls = append(urls, u.URL)
	}

	assert.Contains(t, urls, server.URL, "even non-200 pages should be reported as discovered")
}
