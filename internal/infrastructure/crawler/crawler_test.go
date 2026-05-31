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

func TestCrawler_NoProviders(t *testing.T) {
	cfg := CrawlConfig{}
	c := New(cfg)

	results, err := c.Start(context.Background(), []string{"http://example.com"})
	require.NoError(t, err)

	var urls []DiscoveredURL
	for u := range results {
		urls = append(urls, u)
	}
	assert.Empty(t, urls)
}

func newLinkOnlyCfg() CrawlConfig {
	linkCfg := DefaultLinkConfig()
	linkCfg.Enabled = true
	linkCfg.MaxDepth = 1
	linkCfg.MaxPages = 10
	linkCfg.Timeout = 5 * time.Second
	linkCfg.RateLimit = 0
	linkCfg.Scope = ScopeUnrestricted
	linkCfg.RespectRobots = false
	return CrawlConfig{Link: linkCfg}
}

func TestCrawler_LinkOnly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page">Page</a></body></html>`)
	}))
	defer server.Close()

	c := New(newLinkOnlyCfg())
	result, err := c.Run(context.Background(), []string{server.URL})
	require.NoError(t, err)
	assert.NotEmpty(t, result.DiscoveredURLs)
	assert.Greater(t, result.TotalRequests, 0)
	assert.Greater(t, result.Duration, time.Duration(0))
}

func TestCrawler_Results(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body><a href="/page1">Page 1</a><a href="/page2">Page 2</a></body></html>`)
	}))
	defer server.Close()

	c := New(newLinkOnlyCfg())
	_, err := c.Run(context.Background(), []string{server.URL})
	require.NoError(t, err)

	results := c.Results()
	assert.NotEmpty(t, results)
}

func TestCrawler_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		fmt.Fprint(w, `<html><body>OK</body></html>`)
	}))
	defer server.Close()

	cfg := newLinkOnlyCfg()
	cfg.Link.Timeout = 1 * time.Second

	c := New(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	result, err := c.Run(ctx, []string{server.URL})
	require.NoError(t, err)
	assert.Empty(t, result.DiscoveredURLs, "should have 0 results when cancelled early")
}

func TestCrawler_MultipleSeedURLs(t *testing.T) {
	server1 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>Server 1</body></html>`)
	}))
	defer server1.Close()

	server2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>Server 2</body></html>`)
	}))
	defer server2.Close()

	cfg := newLinkOnlyCfg()
	cfg.Link.MaxDepth = 0

	c := New(cfg)
	result, err := c.Run(context.Background(), []string{server1.URL, server2.URL})
	require.NoError(t, err)
	assert.Len(t, result.DiscoveredURLs, 2)
}

func TestCrawler_DefaultConfigs(t *testing.T) {
	linkCfg := DefaultLinkConfig()
	assert.False(t, linkCfg.Enabled)
	assert.Equal(t, 2, linkCfg.MaxDepth)
	assert.Equal(t, 100, linkCfg.MaxPages)
	assert.Equal(t, ScopeStrict, linkCfg.Scope)
	assert.Equal(t, 5, linkCfg.Concurrency)

	bfCfg := DefaultBruteForceConfig()
	assert.False(t, bfCfg.Enabled)
	assert.Equal(t, "", bfCfg.WordlistPath)
}

func TestNewSharedInfra(t *testing.T) {
	linkCfg := DefaultLinkConfig()
	linkCfg.Enabled = true
	linkCfg.Scope = ScopeSameDomain
	linkCfg.RateLimit = 100 * time.Millisecond
	linkCfg.UserAgent = "test-agent"
	linkCfg.RespectRobots = false

	cfg := CrawlConfig{Link: linkCfg}
	infra := NewSharedInfra(cfg)
	assert.NotNil(t, infra.Dedup)
	assert.NotNil(t, infra.Scope)
	assert.NotNil(t, infra.Fetcher)
	assert.Nil(t, infra.Robots)
}
