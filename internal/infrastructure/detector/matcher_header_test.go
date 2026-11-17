package detector

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func headerMatcher(name string) MatcherConfig {
	return MatcherConfig{
		Type:       MatcherRegex,
		Patterns:   []string{`^https?://sentinel-scan-open-redirect\.invalid`},
		Location:   MatcherLocationHeader,
		HeaderName: name,
		Condition:  "or",
	}
}

// A keyword or regex matcher with location "header" must read the header, not
// the body. Reading the body is what made the open-redirect plugin unable to
// ever fire on the header it declared.
func TestMatchResponseWithHeaders_ReadsHeaderNotBody(t *testing.T) {
	matcher := headerMatcher("Location")

	headers := http.Header{}
	headers.Set("Location", "https://sentinel-scan-open-redirect.invalid/probe")

	match := MatchResponseWithHeaders("<html>nothing here</html>", 302, headers, matcher, "payload")
	if !match.Matched {
		t.Fatal("a Location header pointing at the canary must match")
	}

	// The same string in the body is not evidence of a redirect.
	noHeaders := MatchResponseWithHeaders(
		"<html>https://sentinel-scan-open-redirect.invalid/probe</html>", 200, http.Header{}, matcher, "payload")
	if noHeaders.Matched {
		t.Fatal("the canary in the body must not match a header matcher")
	}
}

// A same-host login redirect that merely echoes the canary in a query
// parameter is not an open redirect; anchoring to the start of Location keeps
// that common pattern out of the findings.
func TestMatchResponseWithHeaders_RejectsEchoedCanaryInSameHostRedirect(t *testing.T) {
	headers := http.Header{}
	headers.Set("Location", "/login?next=https://sentinel-scan-open-redirect.invalid/probe")

	match := MatchResponseWithHeaders("", 302, headers, headerMatcher("Location"), "payload")
	if match.Matched {
		t.Fatal("a same-host redirect that echoes the canary must not match")
	}
}

func TestPluginValidate_RejectsHeaderMatcherWithoutHeaderName(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "broken-header", Severity: SeverityMedium},
		Method:   "GET",
		Path:     "/?q=FUZZ",
		Payloads: []Payload{{Name: "x", Value: "x"}},
		Matchers: []MatcherConfig{{
			Type:     MatcherKeyword,
			Patterns: []string{"anything"},
			Location: MatcherLocationHeader,
		}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("a header matcher without header_name must be rejected at load time")
	}
}

// The rule that would have caught IDOR and SSRF before they shipped: a matcher
// set that can only accept a successful status proves nothing.
func TestPluginValidate_RejectsStatusOnly2xx(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "status-only", Severity: SeverityHigh},
		Method:   "GET",
		Path:     "/?q=FUZZ",
		Payloads: []Payload{{Name: "x", Value: "x"}},
		Matchers: []MatcherConfig{{
			Type:     MatcherStatus,
			Patterns: []string{"200"},
			Location: MatcherLocationStatus,
		}},
	}
	if err := p.Validate(); err == nil {
		t.Fatal("status 200 alone must not be accepted as evidence")
	}
}

// A status matcher alongside real evidence stays valid (open redirect uses a
// non-2xx status plus a header match).
func TestPluginValidate_AllowsStatusWithContentMatcher(t *testing.T) {
	p := &Plugin{
		Metadata: PluginMetadata{ID: "status-and-header", Severity: SeverityMedium},
		Method:   "GET",
		Path:     "/?q=FUZZ",
		Payloads: []Payload{{Name: "x", Value: "x"}},
		Matchers: []MatcherConfig{
			{Type: MatcherStatus, Patterns: []string{"302"}},
			{Type: MatcherKeyword, Patterns: []string{"canary"}, Location: MatcherLocationBody},
		},
	}
	if err := p.Validate(); err != nil {
		t.Fatalf("status plus content matcher should be valid: %v", err)
	}
}

// The executor must stop at the redirect so Location is still observable.
func TestExecutor_NoRedirectKeepsLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://sentinel-scan-open-redirect.invalid/probe", http.StatusFound)
	}))
	defer server.Close()

	exec := NewHTTPExecutor(DetectionConfig{Client: server.Client(), Timeout: time.Second})
	plugin := &Plugin{Method: "GET", Path: "/?q=FUZZ", NoRedirect: true}

	res, err := exec.Execute(context.Background(), server.URL, plugin, Payload{Value: "x"})
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected the redirect itself (302), got %d", res.StatusCode)
	}
	if got := res.Headers.Get("Location"); got != "https://sentinel-scan-open-redirect.invalid/probe" {
		t.Fatalf("Location header lost: %q", got)
	}
}
