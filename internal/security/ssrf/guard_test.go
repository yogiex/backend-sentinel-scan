package ssrf

import (
	"net/netip"
	"testing"
)

func TestIsBlockedRejectsInternalAddresses(t *testing.T) {
	g := New([]string{"80", "443", "8080"}, false)
	blocked := []string{
		"0.0.0.0", "10.1.2.3", "100.64.0.1", "127.0.0.1", "127.1.1.1",
		"169.254.169.254", "172.16.5.5", "192.0.0.1", "192.168.1.1",
		"198.18.0.1", "224.0.0.1", "240.0.0.1",
		"::1", "fc00::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1",
	}
	for _, raw := range blocked {
		if !g.IsBlocked(netip.MustParseAddr(raw)) {
			t.Errorf("IsBlocked(%s) = false, want true", raw)
		}
	}

	for _, raw := range []string{"93.184.216.34", "1.1.1.1", "2606:4700:4700::1111"} {
		if g.IsBlocked(netip.MustParseAddr(raw)) {
			t.Errorf("IsBlocked(%s) = true, want false", raw)
		}
	}
}

func TestIsBlockedAllowsPrivateWhenConfigured(t *testing.T) {
	g := New([]string{"80"}, true)
	if g.IsBlocked(netip.MustParseAddr("10.1.2.3")) {
		t.Error("private address should be allowed in lab mode")
	}
	// Metadata endpoints and multicast stay blocked even in lab mode.
	if !g.IsBlocked(netip.MustParseAddr("ff02::1")) {
		t.Error("multicast must stay blocked")
	}
}

func TestParseValidatesShape(t *testing.T) {
	g := New([]string{"80", "443", "8080"}, false)

	valid := []string{
		"https://example.com",
		"http://example.com/path?q=1",
		"http://example.com:8080/",
		"https://93.184.216.34/",
	}
	for _, raw := range valid {
		if _, err := g.Parse(raw); err != nil {
			t.Errorf("Parse(%q) unexpected error: %v", raw, err)
		}
	}

	invalid := []string{
		"",
		"file:///etc/passwd",
		"ftp://example.com",
		"gopher://example.com",
		"http://user:pass@example.com/",
		"http://example.com:22/",
		"http://example.com:5432/",
		"//example.com",
	}
	for _, raw := range invalid {
		if _, err := g.Parse(raw); err == nil {
			t.Errorf("Parse(%q) = nil error, want rejection", raw)
		}
	}
}

func TestParseRejectsOverlongURL(t *testing.T) {
	g := New([]string{"80", "443"}, false)
	long := "https://example.com/"
	for len(long) < 2100 {
		long += "a"
	}
	if _, err := g.Parse(long); err == nil {
		t.Error("expected overlong URL to be rejected")
	}
}
