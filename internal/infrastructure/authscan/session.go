package authscan

import (
	"context"
	"sync"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

// DefaultSessionTTL bounds how long an authenticated scanning session may live.
const DefaultSessionTTL = 30 * time.Minute

type Session struct {
	CredentialID    uint
	Cookies         []map[string]string
	Headers         map[string]string
	IsAuthenticated bool
}

type Executor interface {
	Authenticate(ctx context.Context, cred *entity.AuthCredential) (*Session, error)
	Verify(ctx context.Context, session *Session, verifyURL string, verifyPattern string) (bool, error)
}

type sessionEntry struct {
	session   *Session
	expiresAt time.Time
}

// SessionManager keeps per-scan authentication state in memory.
//
// Bounded by TTL and cleaned by Sweep so a long-running process cannot grow
// without limit. Guarded by a mutex because handlers and workers share it.
type SessionManager struct {
	mu      sync.RWMutex
	entries map[uint]sessionEntry
	ttl     time.Duration
}

// NewSessionManager returns a manager with the default TTL.
func NewSessionManager() *SessionManager {
	return NewSessionManagerWithTTL(DefaultSessionTTL)
}

// NewSessionManagerWithTTL returns a manager with an explicit TTL.
func NewSessionManagerWithTTL(ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = DefaultSessionTTL
	}
	return &SessionManager{
		entries: make(map[uint]sessionEntry),
		ttl:     ttl,
	}
}

// StartSession records an authenticated session for scanID.
func (sm *SessionManager) StartSession(ctx context.Context, scanID uint, cred *entity.AuthCredential) (*Session, error) {
	session := &Session{
		CredentialID:    cred.ID,
		IsAuthenticated: true,
	}
	sm.mu.Lock()
	sm.entries[scanID] = sessionEntry{session: session, expiresAt: time.Now().Add(sm.ttl)}
	sm.mu.Unlock()
	return session, nil
}

// GetSession returns the live session for scanID, or nil when absent/expired.
func (sm *SessionManager) GetSession(scanID uint) *Session {
	sm.mu.RLock()
	entry, ok := sm.entries[scanID]
	sm.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil
	}
	return entry.session
}

// EndSession drops the session for scanID.
func (sm *SessionManager) EndSession(scanID uint) {
	sm.mu.Lock()
	delete(sm.entries, scanID)
	sm.mu.Unlock()
}

// Len reports the number of live entries (used by metrics/health checks).
func (sm *SessionManager) Len() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.entries)
}

// Sweep removes expired sessions until ctx is cancelled. It owns its ticker,
// so stopping the goroutine also stops the ticker.
func (sm *SessionManager) Sweep(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			sm.mu.Lock()
			for id, entry := range sm.entries {
				if now.After(entry.expiresAt) {
					delete(sm.entries, id)
				}
			}
			sm.mu.Unlock()
		}
	}
}
