package crawler

import (
	"context"
	"io"
	"net/http"
	"time"
)

type FetcherConfig struct {
	Timeout   time.Duration
	RateLimit time.Duration
	UserAgent string
	Headers   map[string]string
}

type Fetcher struct {
	config    FetcherConfig
	client    *http.Client
	rateLimit *time.Ticker
}

type FetchResult struct {
	StatusCode int
	Body       string
	Headers    http.Header
	FinalURL   string
}

func NewFetcher(cfg FetcherConfig) *Fetcher {
	f := &Fetcher{
		config: cfg,
		client: &http.Client{
			Timeout: cfg.Timeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return http.ErrUseLastResponse
				}
				return nil
			},
		},
	}

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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
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
