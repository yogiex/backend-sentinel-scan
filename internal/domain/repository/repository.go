package repository

import (
	"context"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

// ScanRepository persists scan jobs. FindByID is unscoped and must only be
// called after an authorisation check; FindByIDOwned enforces the ownership
// rule inside the query (IDOR defence in depth).
type ScanRepository interface {
	Create(ctx context.Context, scan *entity.ScanJob) error
	FindByID(ctx context.Context, id uint) (*entity.ScanJob, error)
	FindByIDOwned(ctx context.Context, id, ownerID uint) (*entity.ScanJob, error)
	UpdateStatus(ctx context.Context, id uint, status entity.ScanStatus) error
	UpdateProgress(ctx context.Context, id uint, progress *entity.ScanProgress) error
	// SetTruncated records that the scan stopped at its request budget.
	SetTruncated(ctx context.Context, id uint) error
	List(ctx context.Context, filter ScanFilter) ([]*entity.ScanJob, error)
	Count(ctx context.Context, filter ScanFilter) (int64, error)
	Delete(ctx context.Context, id uint) error
}

type ScanFilter struct {
	CreatedBy uint
	Status    string
	Page      int
	PageSize  int
}

type FindingRepository interface {
	Create(ctx context.Context, finding *entity.Finding) error
	CreateBatch(ctx context.Context, findings []*entity.Finding) error
	FindByScanID(ctx context.Context, scanID uint) ([]*entity.Finding, error)
	FindByScanIDLimit(ctx context.Context, scanID uint, limit int) ([]*entity.Finding, error)
	FindByID(ctx context.Context, id uint) (*entity.Finding, error)
}

type TicketRepository interface {
	Create(ctx context.Context, ticket *entity.Ticket) error
	Update(ctx context.Context, ticket *entity.Ticket) error
	FindByID(ctx context.Context, id uint) (*entity.Ticket, error)
	List(ctx context.Context, filter TicketFilter) ([]*entity.Ticket, error)
}

type TicketFilter struct {
	Status     entity.TicketStatus
	CreatedBy  uint
	AssignedTo uint
	Severity   string
	Page       int
	PageSize   int
}

type UserRepository interface {
	Create(ctx context.Context, user *entity.User) error
	FindByID(ctx context.Context, id uint) (*entity.User, error)
	FindByUsername(ctx context.Context, username string) (*entity.User, error)
	Update(ctx context.Context, user *entity.User) error
}

type AuditLogRepository interface {
	Create(ctx context.Context, log *AuditLogEntry) error
}

type AuditLogEntry struct {
	ID       uint           `json:"id"`
	UserID   uint           `json:"user_id"`
	Level    string         `json:"level"`
	Category string         `json:"category"`
	Action   string         `json:"action"`
	Message  string         `json:"message"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// AuthCredentialRepository stores per-user secrets. Every method that reads or
// writes a single credential is scoped by user ID.
type AuthCredentialRepository interface {
	Create(ctx context.Context, cred *entity.AuthCredential) error
	FindByID(ctx context.Context, id uint) (*entity.AuthCredential, error)
	FindByIDOwned(ctx context.Context, id, userID uint) (*entity.AuthCredential, error)
	FindByUserID(ctx context.Context, userID uint) ([]*entity.AuthCredential, error)
	Update(ctx context.Context, cred *entity.AuthCredential) error
	DeleteOwned(ctx context.Context, id, userID uint) error
	UpdateLastVerified(ctx context.Context, id uint) error
}
