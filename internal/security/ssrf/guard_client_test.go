package ssrf

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestGuardClientBlocksLoopbackByDefault is the property that makes the guard
// meaningful: without it, a scan task could be pointed at the scanner's own
// admin port.
func TestGuardClientBlocksLoopbackByDefault(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("the guarded client must not reach a loopback server")
	}))
	defer server.Close()

	client := New([]string{"80", "443"}, false).Client(2*time.Second, 3)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if _, err := client.Do(req); err == nil {
		t.Fatal("expected the request to be blocked")
	}
}

// TestGuardClientBlocksRedirectToCloudMetadata covers the bypass that mattered:
// a reachable public host answering 302 towards the metadata service. Lab mode
// allows loopback, so only the IP check on the redirect can stop this.
func TestGuardClientBlocksRedirectToCloudMetadata(t *testing.T) {
	var reachedMetadata bool
	metadata := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reachedMetadata = true
	}))
	defer metadata.Close()

	// The redirect points at a link-local address, which stays blocked even in
	// lab mode; the httptest server above is only a stand-in for the listener.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer server.Close()

	client := New([]string{"80", "443"}, true).Client(2*time.Second, 3)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err == nil {
		resp.Body.Close()
		t.Fatal("redirect to the metadata service must fail")
	}
	if reachedMetadata {
		t.Fatal("the metadata listener must never be contacted")
	}
	if !errors.Is(err, ErrBlockedAddress) && !errors.Is(err, ErrTooManyRedirects) {
		t.Logf("blocked with: %v", err)
	}
}

// TestGuardClientAllowsLabLoopback documents the intentional test-only escape
// hatch: SSRF_ALLOW_PRIVATE=true permits loopback, which the test suites need.
func TestGuardClientAllowsLabLoopback(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := New([]string{"80", "443"}, true).Client(2*time.Second, 3)
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("lab mode should allow loopback: %v", err)
	}
	resp.Body.Close()
}
