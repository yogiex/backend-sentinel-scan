package crawler

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseLinks(t *testing.T) {
	base, _ := url.Parse("http://example.com/")

	tests := []struct {
		name     string
		html     string
		expected []string
	}{
		{
			name:     "simple links",
			html:     `<a href="/page1">Link1</a><a href="http://other.com">Link2</a>`,
			expected: []string{"http://example.com/page1", "http://other.com"},
		},
		{
			name:     "skip javascript and mailto",
			html:     `<a href="javascript:void(0)">JS</a><a href="mailto:test@test.com">Email</a><a href="/valid">Valid</a>`,
			expected: []string{"http://example.com/valid"},
		},
		{
			name:     "skip empty href",
			html:     `<a href="">Empty</a><a href="/real">Real</a>`,
			expected: []string{"http://example.com/real"},
		},
		{
			name:     "skip fragment-only",
			html:     `<a href="#section">Section</a><a href="/page">Page</a>`,
			expected: []string{"http://example.com/page"},
		},
		{
			name:     "handle base tag",
			html:     `<html><head><base href="http://example.com/sub/"></head><body><a href="page">Page</a></body></html>`,
			expected: []string{"http://example.com/sub/page"},
		},
		{
			name:     "malformed html",
			html:     `<a href="/ok">OK<div><a href="/also-ok">Also</div>`,
			expected: []string{"http://example.com/ok", "http://example.com/also-ok"},
		},
		{
			name:     "no links",
			html:     `<html><body><p>No links here</p></body></html>`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			links := parseLinks(tt.html, base)
			assert.ElementsMatch(t, tt.expected, links)
		})
	}
}

func TestParseForms(t *testing.T) {
	base, _ := url.Parse("http://example.com/")

	tests := []struct {
		name     string
		html     string
		expected []Form
	}{
		{
			name: "simple form",
			html: `<form action="/login" method="POST"><input name="username" type="text"><input name="password" type="password"></form>`,
			expected: []Form{
				{Action: "http://example.com/login", Method: "POST", Inputs: []FormInput{
					{Name: "username", Type: "text"},
					{Name: "password", Type: "password"},
				}},
			},
		},
		{
			name: "form with GET default method",
			html: `<form action="/search"><input name="q" type="text"></form>`,
			expected: []Form{
				{Action: "http://example.com/search", Method: "GET", Inputs: []FormInput{
					{Name: "q", Type: "text"},
				}},
			},
		},
		{
			name: "form with select and textarea",
			html: `<form action="/submit" method="POST"><input name="name"><textarea name="bio"></textarea><select name="country"><option>ID</option></select></form>`,
			expected: []Form{
				{Action: "http://example.com/submit", Method: "POST", Inputs: []FormInput{
					{Name: "name", Type: "text"},
					{Name: "bio", Type: "textarea"},
					{Name: "country", Type: "select"},
				}},
			},
		},
		{
			name: "form with no action",
			html: `<form><input name="x" type="hidden"></form>`,
			expected: []Form{
				{Action: "http://example.com/", Method: "GET", Inputs: []FormInput{
					{Name: "x", Type: "hidden"},
				}},
			},
		},
		{
			name:     "no forms",
			html:     `<html><body><p>No forms</p></body></html>`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			forms := parseForms(tt.html, base)
			assert.Equal(t, len(tt.expected), len(forms))
			for i := range tt.expected {
				if i < len(forms) {
					assert.Equal(t, tt.expected[i].Action, forms[i].Action)
					assert.Equal(t, tt.expected[i].Method, forms[i].Method)
					assert.ElementsMatch(t, tt.expected[i].Inputs, forms[i].Inputs)
				}
			}
		})
	}
}

func TestParseAssets(t *testing.T) {
	base, _ := url.Parse("http://example.com/")

	tests := []struct {
		name     string
		html     string
		expected []string
	}{
		{
			name:     "script src",
			html:     `<script src="/app.js"></script>`,
			expected: []string{"http://example.com/app.js"},
		},
		{
			name:     "link href",
			html:     `<link href="style.css" rel="stylesheet">`,
			expected: []string{"http://example.com/style.css"},
		},
		{
			name:     "iframe src",
			html:     `<iframe src="/embed.html"></iframe>`,
			expected: []string{"http://example.com/embed.html"},
		},
		{
			name:     "img src",
			html:     `<img src="/photo.jpg">`,
			expected: []string{"http://example.com/photo.jpg"},
		},
		{
			name:     "multiple assets",
			html:     `<script src="/app.js"></script><link href="/style.css" rel="stylesheet"><img src="/img.png">`,
			expected: []string{"http://example.com/app.js", "http://example.com/style.css", "http://example.com/img.png"},
		},
		{
			name:     "no assets",
			html:     `<html><body>Plain text</body></html>`,
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assets := parseAssets(tt.html, base)
			assert.ElementsMatch(t, tt.expected, assets)
		})
	}
}

func TestResolveURL(t *testing.T) {
	base, _ := url.Parse("http://example.com/base/")

	tests := []struct {
		href     string
		expected string
	}{
		{"/absolute/path", "http://example.com/absolute/path"},
		{"relative/path", "http://example.com/base/relative/path"},
		{"http://other.com/page", "http://other.com/page"},
		{"#fragment", ""},
		{"javascript:void(0)", ""},
		{"mailto:test@test.com", ""},
		{"tel:+123456789", ""},
		{"data:text/plain,hello", ""},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.href, func(t *testing.T) {
			assert.Equal(t, tt.expected, resolveURL(tt.href, base))
		})
	}
}

func TestFilterLinksByScope(t *testing.T) {
	scope := NewScopeFilter(ScopeStrict)
	seeds := []string{"http://example.com/"}

	links := []string{
		"http://example.com/page1",
		"http://other.com/page2",
		"http://example.com/page3",
	}

	filtered := filterLinksByScope(links, seeds, scope)
	assert.ElementsMatch(t, []string{"http://example.com/page1", "http://example.com/page3"}, filtered)
}

func TestFilterLinksByScope_NilScope(t *testing.T) {
	links := []string{"http://example.com/page1", "http://other.com/page2"}
	filtered := filterLinksByScope(links, nil, nil)
	assert.ElementsMatch(t, links, filtered)
}
