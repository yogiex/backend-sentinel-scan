package crawler

import (
	"net/url"
	"sort"
	"strings"
	"sync"
)

type Deduplicator struct {
	visited map[string]bool
	mu      sync.RWMutex
}

func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		visited: make(map[string]bool),
	}
}

func (d *Deduplicator) IsVisited(rawURL string) bool {
	normalized := normalizeURL(rawURL)
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.visited[normalized]
}

func (d *Deduplicator) MarkVisited(rawURL string) {
	normalized := normalizeURL(rawURL)
	d.mu.Lock()
	defer d.mu.Unlock()
	d.visited[normalized] = true
}

func (d *Deduplicator) TryVisit(rawURL string) bool {
	normalized := normalizeURL(rawURL)
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.visited[normalized] {
		return false
	}
	d.visited[normalized] = true
	return true
}

func normalizeURL(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}

	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""

	if u.Port() == "80" && u.Scheme == "http" {
		u.Host = strings.TrimSuffix(u.Host, ":80")
	}
	if u.Port() == "443" && u.Scheme == "https" {
		u.Host = strings.TrimSuffix(u.Host, ":443")
	}

	if u.RawQuery != "" {
		params := strings.Split(u.RawQuery, "&")
		sort.Strings(params)
		u.RawQuery = strings.Join(params, "&")
	}

	if u.Path == "" {
		u.Path = "/"
	}

	return u.String()
}
