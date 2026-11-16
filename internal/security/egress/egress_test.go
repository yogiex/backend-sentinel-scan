package egress

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBudgetStopsRequestsAndCancelsScan(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	budget := NewBudget(2).WithCancel(cancel)
	client := NewTransport(Config{Burst: 10}).Client(0)

	reqs := []string{server.URL, server.URL, server.URL}
	for i, u := range reqs {
		req, err := http.NewRequestWithContext(WithBudget(ctx, budget), http.MethodGet, u, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp, err := client.Do(req)
		if err != nil {
			if i < 2 {
				t.Fatalf("request %d should have been allowed: %v", i, err)
			}
			if !errors.Is(err, ErrBudgetExhausted) {
				t.Fatalf("request %d: expected ErrBudgetExhausted, got %v", i, err)
			}
			continue
		}
		resp.Body.Close()
	}

	if got := hits.Load(); got != 2 {
		t.Fatalf("expected 2 requests to reach the server, got %d", got)
	}
	if !budget.Exhausted() {
		t.Fatal("budget should report exhausted")
	}
	if ctx.Err() == nil {
		t.Fatal("exhausting the budget must cancel the scan context")
	}
}

func TestBudgetWithoutLimitNeverBlocks(t *testing.T) {
	budget := NewBudget(0)
	for i := 0; i < 100; i++ {
		if !budget.take() {
			t.Fatalf("unlimited budget refused request %d", i)
		}
	}
	if budget.Exhausted() {
		t.Fatal("unlimited budget must never report exhausted")
	}
}

func TestRateLimitSerialisesBursts(t *testing.T) {
	var hits atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
	}))
	defer server.Close()

	// Five requests per second with a burst of one: the second request must
	// wait ~200ms. A per-worker limiter would let it through immediately.
	transport := NewTransport(Config{RatePerSecond: 5, Burst: 1})
	client := transport.Client(0)

	start := time.Now()
	for i := 0; i < 2; i++ {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
	}
	elapsed := time.Since(start)

	if hits.Load() != 2 {
		t.Fatalf("expected 2 requests, got %d", hits.Load())
	}
	if elapsed < 150*time.Millisecond {
		t.Fatalf("second request was not rate limited (elapsed %v)", elapsed)
	}
}

func TestRateLimitRespectsContext(t *testing.T) {
	transport := NewTransport(Config{RatePerSecond: 1, Burst: 1})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()

	first, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	resp, err := transport.Client(0).Do(first)
	if err != nil {
		t.Fatalf("first request: %v", err)
	}
	resp.Body.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	second, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if _, err := transport.Client(0).Do(second); err == nil {
		t.Fatal("expected the waited request to give up when the context expired")
	}
}
