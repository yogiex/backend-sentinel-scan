package repository

import (
	"context"
	"time"

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
	// TouchHeartbeat records that the process that owns the scan is still alive.
	TouchHeartbeat(ctx context.Context, id uint) error
	// MarkInterrupted fails every scan that is still in a non-terminal state,
	// recording reason. When staleBefore is not zero, only scans whose heartbeat
	// is missing or older than that instant are touched, so a live scan in
	// another process is left alone.
	MarkInterrupted(ctx context.Context, reason string, staleBefore time.Time) (int64, error)
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

// TicketRepository stores remediation tickets. FindByID is unscoped; callers
// must use the ownership rule in the service (or FindByIDOwned).
type TicketRepository interface {
	Create(ctx context.Context, ticket *entity.Ticket) error
	Update(ctx context.Context, ticket *entity.Ticket) error
	FindByID(ctx context.Context, id uint) (*entity.Ticket, error)
	FindByIDOwned(ctx context.Context, id, ownerID uint) (*entity.Ticket, error)
	List(ctx context.Context, filter TicketFilter) ([]*entity.Ticket, error)
	Count(ctx context.Context, filter TicketFilter) (int64, error)
	Stats(ctx context.Context, filter TicketFilter) (*entity.TicketStats, error)
	CreateComment(ctx context.Context, comment *entity.TicketComment) error
	ListComments(ctx context.Context, ticketID uint) ([]*entity.TicketComment, error)
}

type TicketFilter struct {
	Status    entity.TicketStatus
	Priority  entity.TicketPriority
	Severity  string
	ScanID    uint
	CreatedBy uint
	// AssignedTo filters on the assignee.
	AssignedTo uint
	// VisibleTo limits the result to tickets the actor created or was assigned.
	// It is the list-level counterpart of the ownership check, and it is why an
	// assignee can finally see the work they were given.
	VisibleTo   uint
	Search      string
	OverdueOnly bool
	Page        int
	PageSize    int
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
