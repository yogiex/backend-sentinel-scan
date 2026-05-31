package crawler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestScopeFilter_Strict(t *testing.T) {
	s := NewScopeFilter(ScopeStrict)
	seeds := []string{"http://example.com/app"}

	assert.True(t, s.Allows("http://example.com/app/page", seeds))
	assert.True(t, s.Allows("http://example.com/app/", seeds))
	assert.False(t, s.Allows("http://other.com/page", seeds))
	assert.False(t, s.Allows("https://example.com/page", seeds), "different scheme")
	assert.False(t, s.Allows("http://sub.example.com/page", seeds), "different subdomain")
}

func TestScopeFilter_SameDomain(t *testing.T) {
	s := NewScopeFilter(ScopeSameDomain)
	seeds := []string{"http://example.com/app"}

	assert.True(t, s.Allows("http://example.com/page", seeds))
	assert.True(t, s.Allows("http://sub.example.com/page", seeds))
	assert.True(t, s.Allows("http://deep.sub.example.com/page", seeds))
	assert.False(t, s.Allows("http://other.com/page", seeds))
	assert.False(t, s.Allows("http://notexample.com/page", seeds))
}

func TestScopeFilter_PathPrefix(t *testing.T) {
	s := NewScopeFilter(ScopePathPrefix)
	seeds := []string{"http://example.com/app"}

	assert.True(t, s.Allows("http://example.com/app/page", seeds))
	assert.True(t, s.Allows("http://example.com/app/admin", seeds))
	assert.False(t, s.Allows("http://example.com/other", seeds))
	assert.False(t, s.Allows("http://other.com/app/page", seeds))
}

func TestScopeFilter_Unrestricted(t *testing.T) {
	s := NewScopeFilter(ScopeUnrestricted)
	seeds := []string{"http://example.com"}

	assert.True(t, s.Allows("http://example.com/page", seeds))
	assert.True(t, s.Allows("http://other.com/page", seeds))
	assert.True(t, s.Allows("https://other.com/page", seeds))
}

func TestScopeFilter_InvalidURL(t *testing.T) {
	s := NewScopeFilter(ScopeStrict)
	assert.False(t, s.Allows("not-a-url", []string{"http://example.com"}))
	assert.False(t, s.Allows("", []string{"http://example.com"}))
}

func TestScopeFilter_RelativeURL(t *testing.T) {
	s := NewScopeFilter(ScopeStrict)
	assert.False(t, s.Allows("/relative/path", []string{"http://example.com"}))
}
