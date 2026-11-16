// Package egress bounds outbound scan traffic.
//
// Two policies are enforced in an http.RoundTripper so that every code path
// that dials out — the detector executor and the crawler fetcher alike — is
// covered, instead of each of them re-implementing the policy (and drifting).
//
//  1. Budget: a hard cap on the number of requests one scan may issue. The cap
//     lives in the context, so a worker only has to pass the scan context
//     through. Exhausting it cancels the scan context, which stops in-flight
//     and queued work instead of silently truncating a report.
//  2. Rate: a token bucket per target host, shared by every worker, because
//     fifty workers hammering the same host are not "rate limited" by a
//     per-worker limiter.
package egress

import (
	"context"
	"errors"
	"math"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// ErrBudgetExhausted is returned instead of dialling once a scan has spent its
// request budget. Callers can compare with errors.Is.
var ErrBudgetExhausted = errors.New("egress: scan request budget exhausted")

type budgetKey struct{}

// Budget counts the requests issued by one scan.
type Budget struct {
	max   int64
	used  atomic.Int64
	spent atomic.Bool

	mu     sync.Mutex
	cancel context.CancelFunc
}

// NewBudget returns a budget that allows max requests. A non-positive max means
// "unlimited", which is only ever appropriate in tests.
func NewBudget(max int64) *Budget {
	return &Budget{max: max}
}

// WithCancel registers the function that stops the scan once the budget is
// gone. It must be called before the budget is placed in a context.
func (b *Budget) WithCancel(cancel context.CancelFunc) *Budget {
	b.mu.Lock()
	b.cancel = cancel
	b.mu.Unlock()
	return b
}

// Max reports the configured cap (0 when unlimited).
func (b *Budget) Max() int64 { return b.max }

// Used reports how many requests have been issued.
func (b *Budget) Used() int64 { return b.used.Load() }

// Exhausted reports whether the cap was reached.
func (b *Budget) Exhausted() bool { return b.spent.Load() }

// take reserves one request. It returns false when the budget is spent, in
// which case the scan context is cancelled so that remaining work stops.
func (b *Budget) take() bool {
	if b.max <= 0 {
		b.used.Add(1)
		return true
	}
	for {
		cur := b.used.Load()
		if cur >= b.max {
			if b.spent.CompareAndSwap(false, true) {
				b.mu.Lock()
				cancel := b.cancel
				b.mu.Unlock()
				if cancel != nil {
					cancel()
				}
			}
			return false
		}
		if b.used.CompareAndSwap(cur, cur+1) {
			return true
		}
	}
}

// WithBudget attaches a budget to ctx.
func WithBudget(ctx context.Context, b *Budget) context.Context {
	if b == nil {
		return ctx
	}
	return context.WithValue(ctx, budgetKey{}, b)
}

// FromContext returns the budget attached to ctx, or nil.
func FromContext(ctx context.Context) *Budget {
	if ctx == nil {
		return nil
	}
	b, _ := ctx.Value(budgetKey{}).(*Budget)
	return b
}

// Config configures a Transport.
type Config struct {
	// RatePerSecond is the per-host request rate. Zero disables rate limiting.
	RatePerSecond float64
	// Burst is how many requests may be issued back to back per host.
	Burst int
	// Base is the underlying transport; the SSRF guard's transport belongs
	// here so its dial-time IP checks still run.
	Base http.RoundTripper
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Transport enforces the budget from the request context and the per-host rate
// limit from its config.
type Transport struct {
	cfg Config

	mu    sync.Mutex
	hosts map[string]*bucket
}

// NewTransport wraps base with the configured policies.
func NewTransport(cfg Config) *Transport {
	if cfg.Burst <= 0 {
		cfg.Burst = 1
	}
	return &Transport{cfg: cfg, hosts: make(map[string]*bucket)}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if b := FromContext(req.Context()); b != nil && !b.take() {
		return nil, ErrBudgetExhausted
	}
	if t.cfg.RatePerSecond > 0 {
		if err := t.wait(req.Context(), req.URL.Host); err != nil {
			return nil, err
		}
	}
	base := t.cfg.Base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req)
}

// wait blocks until a token is available for host.
func (t *Transport) wait(ctx context.Context, host string) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}

		t.mu.Lock()
		b, ok := t.hosts[host]
		now := time.Now()
		if !ok {
			b = &bucket{tokens: float64(t.cfg.Burst), last: now}
			t.hosts[host] = b
		}
		elapsed := now.Sub(b.last).Seconds()
		b.tokens = math.Min(float64(t.cfg.Burst), b.tokens+elapsed*t.cfg.RatePerSecond)
		b.last = now
		if b.tokens >= 1 {
			b.tokens--
			t.mu.Unlock()
			return nil
		}
		need := (1 - b.tokens) / t.cfg.RatePerSecond
		t.mu.Unlock()

		timer := time.NewTimer(time.Duration(need * float64(time.Second)))
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		}
	}
}

// Client builds a client that applies this transport. timeout <= 0 disables the
// client-level timeout, leaving deadlines to the context.
func (t *Transport) Client(timeout time.Duration) *http.Client {
	return &http.Client{Transport: t, Timeout: timeout}
}
