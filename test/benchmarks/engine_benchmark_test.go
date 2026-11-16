package benchmarks

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/scanner"
)

// newEngine returns an HTTP engine wired to a local, intentionally unguarded
// client: the targets are httptest servers on loopback, which the production
// guard rejects by design.
func newEngine(b *testing.B) *scanner.HTTPEngine {
	b.Helper()
	det := detector.New(detector.DetectionConfig{
		DefaultSeverity:      detector.SeverityInfo,
		MaxPayloadsPerPlugin: 20,
		Timeout:              5 * time.Second,
		Client:               &http.Client{Timeout: 5 * time.Second},
	})
	if err := det.LoadPlugins(); err != nil {
		b.Fatalf("load plugins: %v", err)
	}
	return scanner.NewHTTPEngine(scanner.EngineConfig{TimeoutSec: 5}, det)
}

func BenchmarkHTTPEngine_Execute(b *testing.B) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.41")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>Welcome to Test %s</body></html>", r.URL.RawQuery)
	}))
	defer server.Close()

	engine := newEngine(b)
	task := scanner.Task{Target: server.URL, TemplateID: "xss-reflected"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if result := engine.Execute(context.Background(), task); result.Error != nil {
			b.Fatalf("Execute failed: %v", result.Error)
		}
	}
}

func BenchmarkHTTPEngine_Execute_LargeResponse(b *testing.B) {
	body := ""
	for i := 0; i < 1000; i++ {
		body += fmt.Sprintf("<div id='block-%d'>content</div>\n", i)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.20.1")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "<html><body>%s</body></html>", body)
	}))
	defer server.Close()

	engine := newEngine(b)
	task := scanner.Task{Target: server.URL, TemplateID: "xss-reflected"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if result := engine.Execute(context.Background(), task); result.Error != nil {
			b.Fatalf("Execute failed: %v", result.Error)
		}
	}
}
