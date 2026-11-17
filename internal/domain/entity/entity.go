package entity

import (
	"fmt"
	"time"
)

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type ScanJob struct {
	ID                uint       `json:"id"`
	CreatedBy         uint       `json:"created_by"`
	Targets           []string   `json:"targets"`
	TemplateSelectors string     `json:"template_selectors"`
	Status            ScanStatus `json:"status"`
	// Truncated reports that the scan stopped early because it hit its request
	// budget. A truncated report is partial by design and must say so.
	Truncated bool `json:"truncated"`
	// Degraded reports that the scan finished but some tasks never produced a
	// response, so their targets were not really checked. A degraded report is
	// partial in a different way from a truncated one: "no findings" there
	// means "not checked", not "clean".
	Degraded bool `json:"degraded"`
	// Crawl is the crawl configuration this scan was submitted with. It is
	// persisted so the report can explain which pages were discovered and so a
	// scan can be reproduced.
	Crawl            *CrawlOptions `json:"crawl,omitempty"`
	Progress         *ScanProgress `json:"progress,omitempty"`
	AuthCredentialID *uint         `json:"auth_credential_id,omitempty"`
	// FailureReason explains an abnormal end. It is set by reconciliation (a
	// scan whose process died) and by the auth phase, never by a normal scan:
	// an empty reason with status "failed" is still possible for failures that
	// carry no stable code.
	FailureReason string `json:"failure_reason,omitempty"`
	// HeartbeatAt is the last time the process that owns this scan proved it was
	// alive. A scan that stopped heartbeating is not running any more, whatever
	// the status column says.
	HeartbeatAt *time.Time `json:"heartbeat_at,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
}

type ScanProgress struct {
	TotalTasks int `json:"total_tasks"`
	Completed  int `json:"completed"`
	Failed     int `json:"failed"`
	InProgress int `json:"in_progress"`
	// Phase is "crawling" while URLs are being discovered and "scanning" once
	// requests are being sent. Empty for scans that never crawled.
	Phase string `json:"phase,omitempty"`
}

// CrawlOptions is the per-scan crawl configuration.
//
// Only link discovery is exposed: brute-force path guessing is deliberately not
// reachable from the API, because it turns one submission into thousands of
// requests against a host the caller may not own.
type CrawlOptions struct {
	Enabled  bool `json:"enabled"`
	MaxDepth int  `json:"max_depth"`
	MaxPages int  `json:"max_pages"`
	// RespectRobots defaults to true; a caller may turn it off for a host it
	// owns, and that decision is persisted with the scan.
	RespectRobots bool `json:"respect_robots"`
}

type Finding struct {
	ID         uint                   `json:"id"`
	ScanID     uint                   `json:"scan_id"`
	Target     string                 `json:"target"`
	TemplateID string                 `json:"template_id"`
	Matched    bool                   `json:"matched"`
	Severity   string                 `json:"severity"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time              `json:"created_at"`
}

type TemplateFilter struct {
	Severity []string
	Tags     []string
	IDs      []string
}

type TicketStatus string

// The remediation lifecycle. "closed" is deliberately absent: it said nothing
// about whether the fix was verified, and every board state is now explicit.
const (
	TicketStatusOpen       TicketStatus = "open"
	TicketStatusInProgress TicketStatus = "in_progress"
	TicketStatusFixed      TicketStatus = "fixed"
	TicketStatusVerified   TicketStatus = "verified"
	TicketStatusWontFix    TicketStatus = "wont_fix"
)

// TicketPriority is the remediation urgency, not the finding severity. It is
// seeded from the severity of the finding a ticket was created from and may be
// raised or lowered by a human afterwards.
type TicketPriority string

const (
	TicketPriorityCritical TicketPriority = "critical"
	TicketPriorityHigh     TicketPriority = "high"
	TicketPriorityMedium   TicketPriority = "medium"
	TicketPriorityLow      TicketPriority = "low"
)

// ticketTransitions is the remediation state machine. Every state can be
// reopened to in_progress, because a fix that fails verification has to go back
// to work; verified and wont_fix are otherwise terminal.
var ticketTransitions = map[TicketStatus][]TicketStatus{
	TicketStatusOpen:       {TicketStatusInProgress, TicketStatusFixed, TicketStatusWontFix},
	TicketStatusInProgress: {TicketStatusOpen, TicketStatusFixed, TicketStatusWontFix},
	TicketStatusFixed:      {TicketStatusVerified, TicketStatusInProgress, TicketStatusWontFix},
	TicketStatusVerified:   {TicketStatusInProgress, TicketStatusWontFix},
	TicketStatusWontFix:    {TicketStatusOpen},
}

// IsValidTicketStatus reports whether s is one of the five lifecycle states.
func IsValidTicketStatus(s TicketStatus) bool {
	_, ok := ticketTransitions[s]
	return ok
}

// CanTransitionTicket reports whether a ticket may move from one state to
// another. Staying in the same state is always allowed so a repeated update is
// idempotent; moving out of a state that does not exist is not.
func CanTransitionTicket(from, to TicketStatus) bool {
	if from == to {
		return IsValidTicketStatus(to)
	}
	for _, next := range ticketTransitions[from] {
		if next == to {
			return true
		}
	}
	return false
}

// PriorityFromSeverity maps a finding severity onto a remediation priority. An
// unknown or "info" severity is low urgency, not "forget about it".
func PriorityFromSeverity(severity string) TicketPriority {
	switch severity {
	case "critical":
		return TicketPriorityCritical
	case "high":
		return TicketPriorityHigh
	case "medium":
		return TicketPriorityMedium
	default:
		return TicketPriorityLow
	}
}

type Ticket struct {
	ID uint `json:"id"`
	// Code is the human-facing reference (TKT-000123). It is derived from the ID
	// by the persistence layer and never stored, so it cannot drift.
	Code        string         `json:"code"`
	CreatedBy   uint           `json:"created_by"`
	AssignedTo  *uint          `json:"assigned_to,omitempty"`
	ScanID      uint           `json:"scan_id"`
	FindingID   uint           `json:"finding_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    string         `json:"severity"`
	Priority    TicketPriority `json:"priority"`
	Status      TicketStatus   `json:"status"`
	DueDate     *time.Time     `json:"due_date,omitempty"`
	ClosedAt    *time.Time     `json:"closed_at,omitempty"`
	// UpdatedBy is the last actor who changed the ticket; it is what makes an
	// audit trail possible without a second write.
	UpdatedBy uint      `json:"updated_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// TicketComment is one remark on a ticket. Comments are append-only: editing
// history is exactly what an auditor needs to see.
type TicketComment struct {
	ID        uint      `json:"id"`
	TicketID  uint      `json:"ticket_id"`
	AuthorID  uint      `json:"author_id"`
	Message   string    `json:"message"`
	CreatedAt time.Time `json:"created_at"`
}

// FormatTicketCode renders the human-facing ticket reference.
func FormatTicketCode(id uint) string {
	return fmt.Sprintf("TKT-%06d", id)
}

// TicketStats is the board overview: how much remediation work exists, split by
// state and urgency, and how much of it is late.
type TicketStats struct {
	Total      int64            `json:"total"`
	ByStatus   map[string]int64 `json:"by_status"`
	ByPriority map[string]int64 `json:"by_priority"`
	Overdue    int64            `json:"overdue"`
}

type User struct {
	ID           uint       `json:"id"`
	Username     string     `json:"username"`
	Email        string     `json:"email"`
	PasswordHash string     `json:"-"`
	Role         Role       `json:"role"`
	IsActive     bool       `json:"is_active"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	// TokenVersion is the server-side revocation counter. Every token carries
	// the value it was issued with; incrementing this column invalidates all of
	// them at once. It is never serialised.
	TokenVersion int       `json:"-"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type Role string

const (
	RoleAdmin           Role = "admin"
	RoleSecurityAnalyst Role = "security_analyst"
	RoleAuditor         Role = "auditor"
	RoleViewer          Role = "viewer"
)

type Permission string

const (
	PermScanCreate     Permission = "scan:create"
	PermScanRead       Permission = "scan:read"
	PermScanCancel     Permission = "scan:cancel"
	PermCredCreate     Permission = "credential:create" // #nosec G101 -- permission identifier, not a secret
	PermCredRead       Permission = "credential:read"   // #nosec G101 -- permission identifier, not a secret
	PermCredUpdate     Permission = "credential:update" // #nosec G101 -- permission identifier, not a secret
	PermCredDelete     Permission = "credential:delete" // #nosec G101 -- permission identifier, not a secret
	PermCredVerify     Permission = "credential:verify" // #nosec G101 -- permission identifier, not a secret
	PermTicketCreate   Permission = "ticket:create"
	PermTicketUpdate   Permission = "ticket:update"
	PermReportGenerate Permission = "report:generate"
	PermReportDownload Permission = "report:download"
	PermUserManage     Permission = "user:manage"
	PermAuditView      Permission = "audit:view"
)

type AuthMethod string

const (
	AuthMethodLoginForm AuthMethod = "login_form"
	AuthMethodCookie    AuthMethod = "cookie"
	AuthMethodBearer    AuthMethod = "bearer"
	AuthMethodAPIKey    AuthMethod = "api_key"
	AuthMethodSelenium  AuthMethod = "selenium"
)

type AuthCredential struct {
	ID            uint                   `json:"id"`
	UserID        uint                   `json:"user_id"`
	Name          string                 `json:"name"`
	Method        AuthMethod             `json:"method"`
	Config        map[string]interface{} `json:"config"`
	LoginURL      string                 `json:"login_url,omitempty"`
	VerifyURL     string                 `json:"verify_url,omitempty"`
	VerifyPattern string                 `json:"verify_pattern,omitempty"`
	IsActive      bool                   `json:"is_active"`
	LastVerified  *time.Time             `json:"last_verified,omitempty"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
}

type AuthSession struct {
	CredentialID uint
	Cookies      []map[string]string
	Headers      map[string]string
	LastVerified time.Time
	ExpiresAt    time.Time
	HealthOK     bool
	FailureCount int
}

type ScanReportData struct {
	Scan     *ScanJob       `json:"scan"`
	Summary  *ReportSummary `json:"summary"`
	Findings []*Finding     `json:"findings"`
}

type ReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}
