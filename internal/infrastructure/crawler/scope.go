package crawler

import (
	"net/url"
	"strings"
)

type ScopeFilter struct {
	rule ScopeRule
}

func NewScopeFilter(rule ScopeRule) *ScopeFilter {
	return &ScopeFilter{rule: rule}
}

func (s *ScopeFilter) Allows(targetURL string, seedURLs []string) bool {
	u, err := url.Parse(targetURL)
	if err != nil {
		return false
	}

	if !u.IsAbs() {
		return false
	}

	switch s.rule {
	case ScopeUnrestricted:
		return true
	case ScopeStrict:
		return isSameOrigin(u, seedURLs)
	case ScopeSameDomain:
		return isSameDomain(u, seedURLs)
	case ScopePathPrefix:
		return hasPathPrefix(u, seedURLs)
	default:
		return false
	}
}

func isSameOrigin(u *url.URL, seedURLs []string) bool {
	for _, seed := range seedURLs {
		seedParsed, err := url.Parse(seed)
		if err != nil {
			continue
		}
		if u.Scheme == seedParsed.Scheme && u.Host == seedParsed.Host {
			return true
		}
	}
	return false
}

func isSameDomain(u *url.URL, seedURLs []string) bool {
	hostname := u.Hostname()
	for _, seed := range seedURLs {
		seedParsed, err := url.Parse(seed)
		if err != nil {
			continue
		}
		seedHost := seedParsed.Hostname()
		if hostname == seedHost || strings.HasSuffix(hostname, "."+seedHost) {
			return true
		}
	}
	return false
}

func hasPathPrefix(u *url.URL, seedURLs []string) bool {
	for _, seed := range seedURLs {
		seedParsed, err := url.Parse(seed)
		if err != nil {
			continue
		}
		if u.Scheme == seedParsed.Scheme &&
			u.Host == seedParsed.Host &&
			strings.HasPrefix(u.Path, seedParsed.Path) {
			return true
		}
	}
	return false
}
