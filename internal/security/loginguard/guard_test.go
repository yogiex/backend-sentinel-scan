package loginguard

import (
	"net/http"
	"testing"
	"time"
)

func TestAllowBlocksAfterMaxAttempts(t *testing.T) {
	g := New(Config{MaxAttempts: 3, MaxIPAttempts: 100, Window: time.Minute})

	for i := 0; i < 3; i++ {
		if retry, ok := g.Allow("10.0.0.1", "alice"); !ok {
			t.Fatalf("attempt %d should be allowed, retry=%v", i+1, retry)
		}
	}
	retry, ok := g.Allow("10.0.0.1", "alice")
	if ok {
		t.Fatal("the fourth attempt must be refused")
	}
	if retry <= 0 {
		t.Fatalf("a refusal must say when to retry, got %v", retry)
	}
}

func TestResetClearsSuccess(t *testing.T) {
	g := New(Config{MaxAttempts: 2, Window: time.Minute})
	g.Allow("10.0.0.1", "alice")
	g.Allow("10.0.0.1", "alice")
	if _, ok := g.Allow("10.0.0.1", "alice"); ok {
		t.Fatal("expected refusal before reset")
	}

	g.Reset("10.0.0.1", "alice")
	if _, ok := g.Allow("10.0.0.1", "alice"); !ok {
		t.Fatal("a successful login must clear the counter")
	}
}

func TestWindowExpiry(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	g := NewWithClock(Config{MaxAttempts: 1, Window: 15 * time.Minute}, func() time.Time { return now })

	if _, ok := g.Allow("10.0.0.1", "alice"); !ok {
		t.Fatal("first attempt allowed")
	}
	if _, ok := g.Allow("10.0.0.1", "alice"); ok {
		t.Fatal("second attempt refused")
	}

	now = now.Add(16 * time.Minute)
	if _, ok := g.Allow("10.0.0.1", "alice"); !ok {
		t.Fatal("the window has passed, attempt must be allowed again")
	}
}

func TestSprayingIsLimitedPerClient(t *testing.T) {
	g := New(Config{MaxAttempts: 3, MaxIPAttempts: 4, Window: time.Minute})

	for i := 0; i < 4; i++ {
		if _, ok := g.Allow("10.0.0.1", "user"+string(rune('a'+i))); !ok {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	// A new username does not help once the client ceiling is reached.
	if _, ok := g.Allow("10.0.0.1", "another"); ok {
		t.Fatal("per-client ceiling must stop password spraying")
	}
	// A different client is unaffected.
	if _, ok := g.Allow("10.0.0.2", "alice"); !ok {
		t.Fatal("another client must not be throttled by 10.0.0.1")
	}
}

func TestCounterTableIsBounded(t *testing.T) {
	g := New(Config{MaxKeys: 10, MaxAttempts: 5, Window: time.Hour})
	for i := 0; i < 100; i++ {
		g.Allow("10.0.0.1", "user-"+string(rune(i)))
	}
	g.mu.Lock()
	size := len(g.buckets)
	g.mu.Unlock()
	if size > 10 {
		t.Fatalf("counter table must stay bounded, got %d entries", size)
	}
}

func TestConcurrencyCap(t *testing.T) {
	g := New(Config{MaxConcurrent: 1})
	if !g.Acquire() {
		t.Fatal("first slot should be free")
	}
	if g.Acquire() {
		t.Fatal("second slot must be refused while the first is held")
	}
	g.Release()
	if !g.Acquire() {
		t.Fatal("releasing must free the slot")
	}
}

func TestClientIPIgnoresForwardedFor(t *testing.T) {
	r := &http.Request{
		RemoteAddr: "192.0.2.10:54321",
		Header:     http.Header{"X-Forwarded-For": []string{"1.2.3.4"}},
	}
	if got := ClientIP(r); got != "192.0.2.10" {
		t.Fatalf("ClientIP must use the connection address, got %q", got)
	}
}
