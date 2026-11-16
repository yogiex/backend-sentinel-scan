package crawler

import (
	"context"
	"io"
	"net/http"
	"time"
)

// HTTPClient is the contract the crawler needs from an HTTP client, so callers
// can supply one hardened by the SSRF guard and the egress limiter.
type HTTPClient interface {
	Do(req *http.Request) (*http.Response, error)
}

// MaxBodyBytes caps how much of a crawled page is read into memory.
const MaxBodyBytes = 2 << 20 // 2 MiB

type FetcherConfig struct {
	Timeout   time.Duration
	RateLimit time.Duration
	UserAgent string
	Headers   map[string]string
	// Client is used as-is when set; the fallback below is unguarded and only
	// appropriate for tests.
	Client HTTPClient
}

type Fetcher struct {
	config    FetcherConfig
	client    HTTPClient
	rateLimit *time.Ticker
}

type FetchResult struct {
	StatusCode int
	Body       string
	Headers    http.Header
	FinalURL   string
}

func NewFetcher(cfg FetcherConfig) *Fetcher {
	client := cfg.Client
	if client == nil {
		timeout := cfg.Timeout
		if timeout <= 0 {
			timeout = 10 * time.Second
		}
		client = &http.Client{
			Timeout: timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		}
	}
	f := &Fetcher{config: cfg, client: client}

	if cfg.RateLimit > 0 {
		f.rateLimit = time.NewTicker(cfg.RateLimit)
	}

	return f
}

func (f *Fetcher) Fetch(ctx context.Context, urlStr string) (*FetchResult, error) {
	if f.rateLimit != nil {
		select {
		case <-f.rateLimit.C:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, err
	}

	if f.config.UserAgent != "" {
		req.Header.Set("User-Agent", f.config.UserAgent)
	}
	for k, v := range f.config.Headers {
		req.Header.Set(k, v)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxBodyBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxBodyBytes {
		body = body[:MaxBodyBytes]
	}

	finalURL := urlStr
	if resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	return &FetchResult{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		Headers:    resp.Header,
		FinalURL:   finalURL,
	}, nil
}

func (f *Fetcher) FetchHEAD(ctx context.Context, urlStr string) (int, error) {
	if f.rateLimit != nil {
		select {
		case <-f.rateLimit.C:
		case <-ctx.Done():
			return 0, ctx.Err()
		}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, urlStr, nil)
	if err != nil {
		return 0, err
	}

	if f.config.UserAgent != "" {
		req.Header.Set("User-Agent", f.config.UserAgent)
	}

	resp, err := f.client.Do(req)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()

	return resp.StatusCode, nil
}

func (f *Fetcher) Close() {
	if f.rateLimit != nil {
		f.rateLimit.Stop()
	}
}
