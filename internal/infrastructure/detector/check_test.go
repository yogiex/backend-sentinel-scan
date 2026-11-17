package detector

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func probePlugin(t *testing.T) *Plugin {
	t.Helper()
	p, err := ParsePlugin([]byte(`
metadata:
  id: "probe-coverage"
  name: "Coverage probe"
  severity: "high"
method: "GET"
path: "/?q=FUZZ"
payloads:
  - name: "ok"
    value: "ok"
  - name: "boom"
    value: "boom"
matchers:
  - type: "keyword"
    patterns: ["never-present-in-a-clean-page"]
`))
	if err != nil {
		t.Fatalf("parse probe plugin: %v", err)
	}
	return p
}

// A target that refuses the connection must not look like a clean target: the
// request accounting is what lets the engine tell the two apart.
func TestCheckWithPlugins_AllRequestsFail(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	url := server.URL
	server.Close() // nothing is listening any more

	d := New(DetectionConfig{Client: &http.Client{Timeout: time.Second}, Timeout: time.Second})
	res := d.CheckWithPlugins(context.Background(), url, []*Plugin{probePlugin(t)})

	if res.Stats.Attempted != 2 {
		t.Fatalf("expected 2 attempts, got %d", res.Stats.Attempted)
	}
	if res.Stats.Succeeded != 0 {
		t.Fatalf("no request should have succeeded, got %d", res.Stats.Succeeded)
	}
	if res.Stats.Failed != 2 {
		t.Fatalf("expected 2 failures, got %d", res.Stats.Failed)
	}
	if res.Stats.Checked() {
		t.Fatal("a check where nothing succeeded must not report Checked")
	}
	if res.Stats.LastError == nil {
		t.Fatal("the transport error must be kept for the failure reason")
	}
}

// One payload timing out must not hide the payload that did run: the scan is
// still checked, but the loss is recorded.
func TestCheckWithPlugins_PartialFailureIsCounted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("q") == "boom" {
			// Abort the connection so the client sees a transport error.
			panic(http.ErrAbortHandler)
		}
		fmt.Fprint(w, "clean page")
	}))
	defer server.Close()

	d := New(DetectionConfig{Client: server.Client(), Timeout: time.Second})
	res := d.CheckWithPlugins(context.Background(), server.URL, []*Plugin{probePlugin(t)})

	if res.Stats.Succeeded != 1 || res.Stats.Failed != 1 {
		t.Fatalf("expected 1 success and 1 failure, got %+v", res.Stats)
	}
	if !res.Stats.Checked() {
		t.Fatal("one successful request means the target was checked")
	}
	if len(res.Matches) != 0 {
		t.Fatalf("a clean page must not match, got %d matches", len(res.Matches))
	}
}

func TestCheckWithPlugins_AllSucceedNoMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "clean page")
	}))
	defer server.Close()

	d := New(DetectionConfig{Client: server.Client(), Timeout: time.Second})
	res := d.CheckWithPlugins(context.Background(), server.URL, []*Plugin{probePlugin(t)})

	if res.Stats.Succeeded != 2 || res.Stats.Failed != 0 || res.Stats.Attempted != 2 {
		t.Fatalf("unexpected accounting %+v", res.Stats)
	}
	if !res.Stats.Checked() {
		t.Fatal("a fully answered check must report Checked")
	}
}
