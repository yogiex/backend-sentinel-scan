package authscan

import (
	"context"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

type Session struct {
	CredentialID uint
	Cookies      []map[string]string
	Headers      map[string]string
	IsAuthenticated bool
}

type Executor interface {
	Authenticate(ctx context.Context, cred *entity.AuthCredential) (*Session, error)
	Verify(ctx context.Context, session *Session, verifyURL string, verifyPattern string) (bool, error)
}

type SessionManager struct {
	sessions map[uint]*Session
}

func NewSessionManager() *SessionManager {
	return &SessionManager{
		sessions: make(map[uint]*Session),
	}
}

func (sm *SessionManager) StartSession(ctx context.Context, scanID uint, cred *entity.AuthCredential) (*Session, error) {
	session := &Session{
		CredentialID:    cred.ID,
		IsAuthenticated: true,
	}
	sm.sessions[scanID] = session
	return session, nil
}

func (sm *SessionManager) GetSession(scanID uint) *Session {
	return sm.sessions[scanID]
}

func (sm *SessionManager) EndSession(scanID uint) {
	delete(sm.sessions, scanID)
}
