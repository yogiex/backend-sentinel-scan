package crawler

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDeduplicator_IsVisited(t *testing.T) {
	d := NewDeduplicator()
	assert.False(t, d.IsVisited("http://example.com/page"))

	d.MarkVisited("http://example.com/page")
	assert.True(t, d.IsVisited("http://example.com/page"))
}

func TestDeduplicator_TryVisit(t *testing.T) {
	d := NewDeduplicator()
	assert.True(t, d.TryVisit("http://example.com/page"))
	assert.False(t, d.TryVisit("http://example.com/page"))
}

func TestDeduplicator_NormalizeURL(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"HTTP://EXAMPLE.COM/Path", "http://example.com/Path"},
		{"http://example.com:80/page", "http://example.com/page"},
		{"https://example.com:443/page", "https://example.com/page"},
		{"http://example.com/page#fragment", "http://example.com/page"},
		{"http://example.com/page?b=2&a=1", "http://example.com/page?a=1&b=2"},
		{"http://example.com", "http://example.com/"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeURL(tt.input))
		})
	}
}

func TestDeduplicator_TryVisit_Normalized(t *testing.T) {
	d := NewDeduplicator()
	assert.True(t, d.TryVisit("http://EXAMPLE.com:80/page"))
	assert.False(t, d.TryVisit("http://example.com/page"), "should be deduplicated after normalization")
}

func TestDeduplicator_Concurrent(t *testing.T) {
	d := NewDeduplicator()
	done := make(chan bool, 10)
	for i := 0; i < 10; i++ {
		go func() {
			d.TryVisit("http://example.com/page")
			d.IsVisited("http://example.com/page")
			done <- true
		}()
	}
	for i := 0; i < 10; i++ {
		<-done
	}
}
