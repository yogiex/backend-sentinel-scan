package detector

import (
	"context"
	"io"
	"net/http"
	"strings"
	"time"
)

// MaxResponseBytes caps how much of a response body is read into memory. A
// scanner that trusts the target's Content-Length is a memory-exhaustion bug:
// fifty workers reading an endless body take the process down.
const MaxResponseBytes = 2 << 20 // 2 MiB

// DefaultUserAgent identifies the scanner to the target. Being identifiable is
// part of scanning responsibly.
const DefaultUserAgent = "SentinelScan-Detector/1.0"

type ExecutorResponse struct {
	Body       string
	StatusCode int
	Headers    http.Header
	Duration   time.Duration
	// Truncated reports that the body exceeded MaxResponseBytes and was cut.
	Truncated bool
}

type HTTPExecutor struct {
	client HTTPClient
	config DetectionConfig
}

// NewHTTPExecutor returns an executor using cfg.Client when provided. Callers
// outside tests must provide a client hardened by the SSRF guard and the egress
// limiter; the fallback below exists only so unit tests stay simple.
func NewHTTPExecutor(cfg DetectionConfig) *HTTPExecutor {
	client := cfg.Client
	if client == nil {
		client = NewDefaultClient(cfg.Timeout)
	}
	return &HTTPExecutor{client: client, config: cfg}
}

// NewDefaultClient builds the unguarded client used when no client is injected.
func NewDefaultClient(timeout time.Duration) HTTPClient {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}
}

func (e *HTTPExecutor) Execute(ctx context.Context, target string, plugin *Plugin, payload Payload) (*ExecutorResponse, error) {
	// The payload is percent-encoded for the URL but left raw in the body: an
	// XXE payload carries XML entities, and encoding those would destroy them.
	reqURL := ResolveTargetPath(target, plugin.Path, EncodePayload(payload.Value))

	var bodyReader io.Reader
	if plugin.Body != "" {
		bodyReader = strings.NewReader(ReplacePlaceholders(plugin.Body, target, payload.Value))
	}

	req, err := http.NewRequestWithContext(ctx, plugin.Method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range plugin.Headers {
		req.Header.Set(k, v)
	}
	return e.do(req, plugin.NoRedirect)
}

func (e *HTTPExecutor) ExecuteBaseline(ctx context.Context, target string, plugin *Plugin) (*ExecutorResponse, error) {
	method := plugin.Method
	path := plugin.Path
	headers := plugin.Headers
	body := plugin.Body

	if plugin.Baseline != nil {
		if plugin.Baseline.Method != "" {
			method = plugin.Baseline.Method
		}
		if plugin.Baseline.Path != "" {
			path = plugin.Baseline.Path
		}
		if plugin.Baseline.Headers != nil {
			headers = plugin.Baseline.Headers
		}
		if plugin.Baseline.Body != "" {
			body = plugin.Baseline.Body
		}
	}

	reqURL := strings.TrimRight(target, "/")
	if strings.HasPrefix(path, "/") {
		reqURL += path
	} else {
		reqURL += "/" + path
	}

	var bodyReader io.Reader
	if body != "" {
		bodyReader = strings.NewReader(body)
	}

	req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	return e.do(req, false)
}

// noRedirectClient returns a client that stops at the first redirect, keeping
// the 3xx response and its Location header. The value is a shallow copy sharing
// the original Transport, so the connection pool, SSRF guard, and egress budget
// still apply.
//
// A non-*http.Client cannot be cloned, and is returned unchanged: the bundled
// plugin that needs this always runs with a real client.
func noRedirectClient(client HTTPClient) HTTPClient {
	c, ok := client.(*http.Client)
	if !ok {
		return client
	}
	clone := *c
	clone.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &clone
}

// do sends req and reads at most MaxResponseBytes of the response body.
func (e *HTTPExecutor) do(req *http.Request, noRedirect bool) (*ExecutorResponse, error) {
	if req.Header.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", DefaultUserAgent)
	}

	client := e.client
	if noRedirect {
		client = noRedirectClient(client)
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, truncated, err := readBounded(resp.Body, MaxResponseBytes)
	if err != nil {
		return nil, err
	}

	return &ExecutorResponse{
		Body:       body,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
		Duration:   duration,
		Truncated:  truncated,
	}, nil
}

// readBounded reads at most limit bytes, reporting whether the body was longer.
func readBounded(r io.Reader, limit int64) (string, bool, error) {
	if limit <= 0 {
		limit = MaxResponseBytes
	}
	buf, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(buf)) > limit {
		return string(buf[:limit]), true, nil
	}
	return string(buf), false, nil
}
