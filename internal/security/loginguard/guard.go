// Package loginguard throttles password authentication.
//
// Login is the one endpoint an unauthenticated attacker can call, and every call
// costs a bcrypt verification (cost 12, hundreds of milliseconds of CPU). Without
// a limit it is both a brute-force target and a cheap CPU exhaustion vector, so
// this guard does three things: it counts attempts per client and per
// client+username, it caps how many verifications run at once, and it keeps the
// counters in a bounded table so an attacker cannot grow memory without limit.
package loginguard

import (
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"
)

// Config controls the guard. Zero values mean the documented defaults.
type Config struct {
	// MaxAttempts is how many failures one client+username pair may accumulate
	// inside Window before it is refused.
	MaxAttempts int
	// MaxIPAttempts is the per-client ceiling across all usernames, which is
	// what stops password spraying.
	MaxIPAttempts int
	Window        time.Duration
	// MaxConcurrent bounds simultaneous bcrypt verifications.
	MaxConcurrent int
	// MaxKeys bounds the counter table.
	MaxKeys int
}

func (c Config) withDefaults() Config {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 5
	}
	if c.MaxIPAttempts <= 0 {
		c.MaxIPAttempts = 100
	}
	if c.Window <= 0 {
		c.Window = 15 * time.Minute
	}
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = runtime.GOMAXPROCS(0)
		if c.MaxConcurrent < 1 {
			c.MaxConcurrent = 1
		}
	}
	if c.MaxKeys <= 0 {
		c.MaxKeys = 10_000
	}
	return c
}

type bucket struct {
	count int
	reset time.Time
}

// Guard is safe for concurrent use.
type Guard struct {
	cfg     Config
	now     func() time.Time
	mu      sync.Mutex
	buckets map[string]*bucket
	sem     chan struct{}
}

func New(cfg Config) *Guard { return NewWithClock(cfg, time.Now) }

// NewWithClock takes the time source so tests can advance the window without
// sleeping.
func NewWithClock(cfg Config, now func() time.Time) *Guard {
	if now == nil {
		now = time.Now
	}
	cfg = cfg.withDefaults()
	return &Guard{
		cfg:     cfg,
		now:     now,
		buckets: make(map[string]*bucket, cfg.MaxKeys),
		sem:     make(chan struct{}, cfg.MaxConcurrent),
	}
}

// Allow records one login attempt for (ip, username) and reports whether it may
// proceed. When refused, retryAfter says how long the window has left.
//
// A successful login must call Reset; otherwise a legitimate user who signs in
// repeatedly during one window locks themselves out.
func (g *Guard) Allow(ip, username string) (retryAfter time.Duration, ok bool) {
	if g == nil {
		return 0, true
	}
	now := g.now()
	g.mu.Lock()
	defer g.mu.Unlock()
	g.evictLocked(now)

	checks := []struct {
		key   string
		limit int
	}{
		{key: userKey(ip, username), limit: g.cfg.MaxAttempts},
		{key: ipKey(ip), limit: g.cfg.MaxIPAttempts},
	}

	for _, c := range checks {
		if b := g.liveBucketLocked(c.key, now); b != nil && b.count >= c.limit {
			wait := b.reset.Sub(now)
			if wait < time.Second {
				wait = time.Second
			}
			return wait, false
		}
	}
	for _, c := range checks {
		b := g.liveBucketLocked(c.key, now)
		if b == nil {
			b = &bucket{reset: now.Add(g.cfg.Window)}
			g.buckets[c.key] = b
		}
		b.count++
	}
	return 0, true
}

// Reset clears the counter for a successful login. The per-client bucket is left
// alone on purpose: one valid account must not reset the spraying limit.
func (g *Guard) Reset(ip, username string) {
	if g == nil {
		return
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.buckets, userKey(ip, username))
}

// Acquire reserves one bcrypt slot, reporting false instead of queueing when
// every slot is busy. Callers must Release after verification.
func (g *Guard) Acquire() bool {
	if g == nil {
		return true
	}
	select {
	case g.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release returns a slot taken by Acquire.
func (g *Guard) Release() {
	if g == nil {
		return
	}
	select {
	case <-g.sem:
	default:
	}
}

func (g *Guard) liveBucketLocked(key string, now time.Time) *bucket {
	b := g.buckets[key]
	if b == nil {
		return nil
	}
	if !now.Before(b.reset) {
		delete(g.buckets, key)
		return nil
	}
	return b
}

// evictLocked keeps the table bounded. Expired entries go first; if an attacker
// keeps every entry live, entries are dropped down to half the limit rather than
// refusing new keys, because refusing new keys would let them lock the endpoint
// for everyone. Halving (instead of trimming to the limit) leaves room for the
// two keys the next Allow call adds.
func (g *Guard) evictLocked(now time.Time) {
	if len(g.buckets) < g.cfg.MaxKeys {
		return
	}
	for k, b := range g.buckets {
		if !now.Before(b.reset) {
			delete(g.buckets, k)
		}
	}
	target := g.cfg.MaxKeys / 2
	if target < 1 {
		target = 1
	}
	for k := range g.buckets {
		if len(g.buckets) <= target {
			break
		}
		delete(g.buckets, k)
	}
}

func ipKey(ip string) string { return "ip\x00" + ip }

func userKey(ip, username string) string {
	return "user\x00" + ip + "\x00" + strings.ToLower(strings.TrimSpace(username))
}

// ClientIP returns the remote IP of the request.
//
// X-Forwarded-For is deliberately not read. Without an explicit trusted-proxy
// configuration the header is attacker-controlled, and honouring it would let a
// single client rotate its apparent address to defeat the per-IP bucket.
func ClientIP(r *http.Request) string {
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	if r.RemoteAddr == "" {
		return "unknown"
	}
	return r.RemoteAddr
}
