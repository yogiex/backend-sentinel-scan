package crawler

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"sync"
)

type RobotsFilter struct {
	fetcher *Fetcher
	cache   map[string]*RobotsTxt
	mu      sync.RWMutex
}

type RobotsTxt struct {
	disallows  []string
	allows     []string
	crawlDelay int
}

func NewRobotsFilter(fetcher *Fetcher) *RobotsFilter {
	return &RobotsFilter{
		fetcher: fetcher,
		cache:   make(map[string]*RobotsTxt),
	}
}

func (r *RobotsFilter) Allowed(ctx context.Context, targetURL string) (bool, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return true, nil
	}

	robotsURL := u.Scheme + "://" + u.Host + "/robots.txt"

	r.mu.RLock()
	rt, ok := r.cache[robotsURL]
	r.mu.RUnlock()

	if !ok {
		rt = r.fetchRobotsTxt(ctx, robotsURL)
		if rt == nil {
			return true, nil
		}
		r.mu.Lock()
		r.cache[robotsURL] = rt
		r.mu.Unlock()
	}

	path := u.Path
	if path == "" {
		path = "/"
	}

	for _, disallow := range rt.disallows {
		if strings.HasPrefix(path, disallow) {
			for _, allow := range rt.allows {
				if strings.HasPrefix(path, allow) {
					return true, nil
				}
			}
			return false, nil
		}
	}

	return true, nil
}

func (r *RobotsFilter) fetchRobotsTxt(ctx context.Context, robotsURL string) *RobotsTxt {
	result, err := r.fetcher.Fetch(ctx, robotsURL)
	if err != nil || result.StatusCode != 200 {
		return nil
	}

	return parseRobotsTxt(result.Body)
}

func parseRobotsTxt(body string) *RobotsTxt {
	rt := &RobotsTxt{}
	inUserAgent := false

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(strings.ToLower(parts[0]))
		value := strings.TrimSpace(parts[1])

		switch key {
		case "user-agent":
			inUserAgent = value == "*"
		case "disallow":
			if inUserAgent && value != "" {
				rt.disallows = append(rt.disallows, value)
			}
		case "allow":
			if inUserAgent {
				rt.allows = append(rt.allows, value)
			}
		case "crawl-delay":
			if inUserAgent {
				fmt.Sscanf(value, "%d", &rt.crawlDelay)
			}
		}
	}

	return rt
}

func (r *RobotsFilter) ClearCache() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]*RobotsTxt)
}
