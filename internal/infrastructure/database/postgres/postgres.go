package postgres

import (
	"encoding/json"
	"time"

	"gorm.io/datatypes"
	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

// ── GORM models (source of truth for the schema) ─────────────
//
// Progress is stored as integer columns rather than JSONB: workers increment
// it concurrently and a read-modify-write on JSONB would lose updates.

type ScanJob struct {
	gorm.Model
	CreatedBy         uint           `gorm:"not null;index"`
	Targets           datatypes.JSON `gorm:"type:jsonb;not null"`
	TemplateSelectors datatypes.JSON `gorm:"type:jsonb"`
	Status            string         `gorm:"type:varchar(20);not null;default:pending;index"`
	Truncated         bool           `gorm:"not null;default:false"`
	CrawlEnabled      bool           `gorm:"not null;default:false"`
	CrawlMaxDepth     int            `gorm:"not null;default:0"`
	CrawlMaxPages     int            `gorm:"not null;default:0"`
	CrawlRobots       bool           `gorm:"not null;default:true"`
	Phase             string         `gorm:"type:varchar(20)"`
	TotalTasks        int            `gorm:"not null;default:0"`
	CompletedTasks    int            `gorm:"not null;default:0"`
	FailedTasks       int            `gorm:"not null;default:0"`
	InProgressTasks   int            `gorm:"not null;default:0"`
	AuthCredentialID  *uint          `gorm:"index"`
	// FailureReason explains an abnormal end (restart, shutdown, auth failure).
	FailureReason string `gorm:"type:varchar(64)"`
	// HeartbeatAt is written by the orchestrator that owns the scan, so a scan
	// that stopped heartbeating can be told apart from one that is still work.
	HeartbeatAt *time.Time `gorm:"index"`
}

// Finding carries a partial unique index on (scan_id, target, template_id).
//
// Without it "insert if absent" is a no-op: clause.OnConflict needs a real
// constraint to conflict with, so a task executed twice used to add a second
// row and inflate the report. The index is partial because findings are
// soft-deleted; a deleted finding must not block a re-scan.
type Finding struct {
	gorm.Model
	ScanID     uint           `gorm:"not null;uniqueIndex:idx_findings_scan_target_template,where:deleted_at IS NULL"`
	Target     string         `gorm:"type:text;not null;uniqueIndex:idx_findings_scan_target_template,where:deleted_at IS NULL"`
	TemplateID string         `gorm:"type:text;not null;uniqueIndex:idx_findings_scan_target_template,where:deleted_at IS NULL"`
	Matched    bool           `gorm:"not null;default:false"`
	Severity   string         `gorm:"type:varchar(20);not null;default:info;index"`
	Details    datatypes.JSON `gorm:"type:jsonb"`
}

type Ticket struct {
	gorm.Model
	CreatedBy   uint   `gorm:"not null;index"`
	AssignedTo  *uint  `gorm:"index"`
	ScanID      uint   `gorm:"index"`
	FindingID   uint   `gorm:"index"`
	Title       string `gorm:"type:varchar(200);not null"`
	Description string `gorm:"type:text"`
	Severity    string `gorm:"type:varchar(20);default:info;index"`
	Priority    string `gorm:"type:varchar(20);not null;default:medium;index"`
	Status      string `gorm:"type:varchar(20);not null;default:open;index"`
	// DueDate drives the overdue list. Nullable because a ticket may be created
	// without an agreed deadline.
	DueDate   *time.Time `gorm:"index"`
	ClosedAt  *time.Time
	UpdatedBy uint `gorm:"index"`
}

// TicketComment is append-only by construction: there is no update path.
type TicketComment struct {
	gorm.Model
	TicketID uint   `gorm:"not null;index"`
	AuthorID uint   `gorm:"not null;index"`
	Message  string `gorm:"type:text;not null"`
}

type User struct {
	gorm.Model
	Username     string `gorm:"type:varchar(64);uniqueIndex;not null"`
	Email        string `gorm:"type:varchar(255);uniqueIndex;not null"`
	PasswordHash string `gorm:"type:text;not null"`
	Role         string `gorm:"type:varchar(32);not null;default:viewer"`
	Permissions  datatypes.JSON
	FirstName    string `gorm:"type:varchar(100)"`
	LastName     string `gorm:"type:varchar(100)"`
	IsActive     bool   `gorm:"not null;default:true"`
	LastLogin    *time.Time
}

type AuditLog struct {
	gorm.Model
	UserID   uint           `gorm:"index"`
	Level    string         `gorm:"type:varchar(20)"`
	Category string         `gorm:"type:varchar(50);index"`
	Action   string         `gorm:"type:varchar(100)"`
	Message  string         `gorm:"type:text"`
	Metadata datatypes.JSON `gorm:"type:jsonb"`
}

type AuthCredential struct {
	gorm.Model
	UserID        uint           `gorm:"not null;index"`
	Name          string         `gorm:"type:varchar(100);not null"`
	Method        string         `gorm:"type:varchar(32)"`
	Config        datatypes.JSON `gorm:"type:jsonb"`
	LoginURL      string         `gorm:"type:text"`
	VerifyURL     string         `gorm:"type:text"`
	VerifyPattern string         `gorm:"type:text"`
	IsActive      bool           `gorm:"not null;default:true"`
	LastVerified  *time.Time
}

type AuthSessionModel struct {
	gorm.Model
	ScanID          uint           `gorm:"uniqueIndex;not null"`
	CredentialID    uint           `gorm:"index"`
	Cookies         datatypes.JSON `gorm:"type:jsonb"`
	Headers         datatypes.JSON `gorm:"type:jsonb"`
	IsAuthenticated bool           `gorm:"not null;default:false"`
	LastVerified    *time.Time
	ExpiresAt       *time.Time
	HealthOK        bool `gorm:"not null;default:false"`
	FailureCount    int  `gorm:"not null;default:0"`
}

// ── JSON helpers ────────────────────────────────────────────

func encodeJSON(v any) datatypes.JSON {
	if v == nil {
		return datatypes.JSON([]byte("null"))
	}
	b, err := json.Marshal(v)
	if err != nil {
		return datatypes.JSON([]byte("null"))
	}
	return datatypes.JSON(b)
}

func encodeString(s string) datatypes.JSON {
	b, _ := json.Marshal(s)
	return datatypes.JSON(b)
}

func decodeString(raw datatypes.JSON) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return ""
	}
	return s
}

func decodeStrings(raw datatypes.JSON) []string {
	if len(raw) == 0 {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil || out == nil {
		return []string{}
	}
	return out
}

func decodeMap(raw datatypes.JSON) map[string]any {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// ── Entity mapping ──────────────────────────────────────────

func (m *ScanJob) toEntity() *entity.ScanJob {
	return &entity.ScanJob{
		ID:                m.ID,
		CreatedBy:         m.CreatedBy,
		Targets:           decodeStrings(m.Targets),
		TemplateSelectors: decodeString(m.TemplateSelectors),
		Status:            entity.ScanStatus(m.Status),
		Truncated:         m.Truncated,
		Crawl:             crawlFromModel(m),
		Progress: &entity.ScanProgress{
			TotalTasks: m.TotalTasks,
			Completed:  m.CompletedTasks,
			Failed:     m.FailedTasks,
			InProgress: m.InProgressTasks,
			Phase:      m.Phase,
		},
		AuthCredentialID: m.AuthCredentialID,
		FailureReason:    m.FailureReason,
		HeartbeatAt:      m.HeartbeatAt,
		CreatedAt:        m.CreatedAt,
		UpdatedAt:        m.UpdatedAt,
	}
}

func scanFromEntity(e *entity.ScanJob) *ScanJob {
	status := string(e.Status)
	if status == "" {
		status = string(entity.ScanStatusPending)
	}
	m := &ScanJob{
		CreatedBy:         e.CreatedBy,
		Targets:           encodeJSON(nonNilStrings(e.Targets)),
		TemplateSelectors: encodeString(e.TemplateSelectors),
		Status:            status,
		Truncated:         e.Truncated,
		AuthCredentialID:  e.AuthCredentialID,
		FailureReason:     e.FailureReason,
		HeartbeatAt:       e.HeartbeatAt,
	}
	if e.Crawl != nil {
		m.CrawlEnabled = e.Crawl.Enabled
		m.CrawlMaxDepth = e.Crawl.MaxDepth
		m.CrawlMaxPages = e.Crawl.MaxPages
		m.CrawlRobots = e.Crawl.RespectRobots
	}
	if e.Progress != nil {
		m.TotalTasks = e.Progress.TotalTasks
		m.CompletedTasks = e.Progress.Completed
		m.FailedTasks = e.Progress.Failed
		m.InProgressTasks = e.Progress.InProgress
	}
	if !e.CreatedAt.IsZero() {
		m.CreatedAt = e.CreatedAt
	}
	return m
}

// crawlFromModel rebuilds the crawl options, returning nil for scans that never
// crawled so the API does not advertise a crawl object with zero values.
func crawlFromModel(m *ScanJob) *entity.CrawlOptions {
	if !m.CrawlEnabled {
		return nil
	}
	return &entity.CrawlOptions{
		Enabled:       true,
		MaxDepth:      m.CrawlMaxDepth,
		MaxPages:      m.CrawlMaxPages,
		RespectRobots: m.CrawlRobots,
	}
}

func (m *Finding) toEntity() *entity.Finding {
	return &entity.Finding{
		ID:         m.ID,
		ScanID:     m.ScanID,
		Target:     m.Target,
		TemplateID: m.TemplateID,
		Matched:    m.Matched,
		Severity:   m.Severity,
		Details:    decodeMap(m.Details),
		CreatedAt:  m.CreatedAt,
	}
}

func findingFromEntity(e *entity.Finding) *Finding {
	severity := e.Severity
	if severity == "" {
		severity = "info"
	}
	return &Finding{
		ScanID:     e.ScanID,
		Target:     e.Target,
		TemplateID: e.TemplateID,
		Matched:    e.Matched,
		Severity:   severity,
		Details:    encodeJSON(e.Details),
	}
}

func (m *Ticket) toEntity() *entity.Ticket {
	priority := entity.TicketPriority(m.Priority)
	if priority == "" {
		priority = entity.PriorityFromSeverity(m.Severity)
	}
	return &entity.Ticket{
		ID:          m.ID,
		Code:        entity.FormatTicketCode(m.ID),
		CreatedBy:   m.CreatedBy,
		AssignedTo:  m.AssignedTo,
		ScanID:      m.ScanID,
		FindingID:   m.FindingID,
		Title:       m.Title,
		Description: m.Description,
		Severity:    m.Severity,
		Priority:    priority,
		Status:      entity.TicketStatus(m.Status),
		DueDate:     m.DueDate,
		ClosedAt:    m.ClosedAt,
		UpdatedBy:   m.UpdatedBy,
		CreatedAt:   m.CreatedAt,
		UpdatedAt:   m.UpdatedAt,
	}
}

func (m *TicketComment) toEntity() *entity.TicketComment {
	return &entity.TicketComment{
		ID:        m.ID,
		TicketID:  m.TicketID,
		AuthorID:  m.AuthorID,
		Message:   m.Message,
		CreatedAt: m.CreatedAt,
	}
}

func (m *User) toEntity() *entity.User {
	return &entity.User{
		ID:           m.ID,
		Username:     m.Username,
		Email:        m.Email,
		PasswordHash: m.PasswordHash,
		Role:         entity.Role(m.Role),
		IsActive:     m.IsActive,
		LastLogin:    m.LastLogin,
		CreatedAt:    m.CreatedAt,
		UpdatedAt:    m.UpdatedAt,
	}
}

func userFromEntity(e *entity.User) *User {
	role := string(e.Role)
	if role == "" {
		role = string(entity.RoleViewer)
	}
	return &User{
		Username:     e.Username,
		Email:        e.Email,
		PasswordHash: e.PasswordHash,
		Role:         role,
		IsActive:     e.IsActive,
		LastLogin:    e.LastLogin,
	}
}

func (m *AuthCredential) toEntity() *entity.AuthCredential {
	return &entity.AuthCredential{
		ID:            m.ID,
		UserID:        m.UserID,
		Name:          m.Name,
		Method:        entity.AuthMethod(m.Method),
		Config:        decodeMap(m.Config),
		LoginURL:      m.LoginURL,
		VerifyURL:     m.VerifyURL,
		VerifyPattern: m.VerifyPattern,
		IsActive:      m.IsActive,
		LastVerified:  m.LastVerified,
		CreatedAt:     m.CreatedAt,
		UpdatedAt:     m.UpdatedAt,
	}
}

func credentialFromEntity(e *entity.AuthCredential) *AuthCredential {
	return &AuthCredential{
		UserID:        e.UserID,
		Name:          e.Name,
		Method:        string(e.Method),
		Config:        encodeJSON(e.Config),
		LoginURL:      e.LoginURL,
		VerifyURL:     e.VerifyURL,
		VerifyPattern: e.VerifyPattern,
		IsActive:      e.IsActive,
		LastVerified:  e.LastVerified,
	}
}

func nonNilStrings(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}
