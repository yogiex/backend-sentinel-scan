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

func TestRobotsFilter_Allowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			fmt.Fprint(w, "User-agent: *\nDisallow: /private/\nDisallow: /admin/\nAllow: /admin/public/\n")
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	robots := NewRobotsFilter(fetcher)

	allowed, err := robots.Allowed(context.Background(), server.URL+"/public/page")
	require.NoError(t, err)
	assert.True(t, allowed)

	disallowed, err := robots.Allowed(context.Background(), server.URL+"/private/data")
	require.NoError(t, err)
	assert.False(t, disallowed)

	disallowed2, err := robots.Allowed(context.Background(), server.URL+"/admin/config")
	require.NoError(t, err)
	assert.False(t, disallowed2)

	override, err := robots.Allowed(context.Background(), server.URL+"/admin/public/")
	require.NoError(t, err)
	assert.True(t, override)
}

func TestRobotsFilter_NoRobotsTxt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			w.WriteHeader(http.StatusNotFound)
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	robots := NewRobotsFilter(fetcher)

	allowed, err := robots.Allowed(context.Background(), server.URL+"/any/path")
	require.NoError(t, err)
	assert.True(t, allowed)
}

func TestRobotsFilter_Cache(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			requestCount++
			fmt.Fprint(w, "User-agent: *\nDisallow: /secret/\n")
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	robots := NewRobotsFilter(fetcher)

	robots.Allowed(context.Background(), server.URL+"/public/page")
	robots.Allowed(context.Background(), server.URL+"/other/page")

	assert.Equal(t, 1, requestCount, "robots.txt should be cached after first fetch")
}

func TestRobotsFilter_ClearCache(t *testing.T) {
	requestCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" {
			requestCount++
			fmt.Fprint(w, "User-agent: *\nDisallow: /secret/\n")
		} else {
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer server.Close()

	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	robots := NewRobotsFilter(fetcher)

	robots.Allowed(context.Background(), server.URL+"/page")
	robots.ClearCache()
	robots.Allowed(context.Background(), server.URL+"/page2")

	assert.Equal(t, 2, requestCount, "should fetch again after cache clear")
}

func TestParseRobotsTxt(t *testing.T) {
	body := `User-agent: *
Disallow: /private/
Disallow: /tmp/
Allow: /tmp/public/
Crawl-delay: 5

User-agent: googlebot
Disallow: /
`

	rt := parseRobotsTxt(body)
	require.NotNil(t, rt)
	assert.ElementsMatch(t, []string{"/private/", "/tmp/"}, rt.disallows)
	assert.ElementsMatch(t, []string{"/tmp/public/"}, rt.allows)
	assert.Equal(t, 5, rt.crawlDelay)
}

func TestParseRobotsTxt_Empty(t *testing.T) {
	rt := parseRobotsTxt("")
	require.NotNil(t, rt)
	assert.Empty(t, rt.disallows)
	assert.Empty(t, rt.allows)
}

func TestParseRobotsTxt_NoUserAgent(t *testing.T) {
	body := `Disallow: /secret/`
	rt := parseRobotsTxt(body)
	assert.Empty(t, rt.disallows, "disallow without user-agent should be ignored")
}

func TestRobotsFilter_InvalidURL(t *testing.T) {
	fetcher := NewFetcher(FetcherConfig{Timeout: 5 * time.Second})
	robots := NewRobotsFilter(fetcher)
	allowed, err := robots.Allowed(context.Background(), "://invalid")
	require.NoError(t, err)
	assert.True(t, allowed)
}
