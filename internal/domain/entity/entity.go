package entity

import "time"

type ScanStatus string

const (
	ScanStatusPending   ScanStatus = "pending"
	ScanStatusRunning   ScanStatus = "running"
	ScanStatusCompleted ScanStatus = "completed"
	ScanStatusFailed    ScanStatus = "failed"
	ScanStatusCancelled ScanStatus = "cancelled"
)

type ScanJob struct {
	ID                uint              `json:"id"`
	CreatedBy         uint              `json:"created_by"`
	Targets           []string          `json:"targets"`
	TemplateSelectors string            `json:"template_selectors"`
	Status            ScanStatus        `json:"status"`
	Progress          *ScanProgress     `json:"progress,omitempty"`
	AuthCredentialID  *uint             `json:"auth_credential_id,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

type ScanProgress struct {
	TotalTasks int `json:"total_tasks"`
	Completed  int `json:"completed"`
	Failed     int `json:"failed"`
	InProgress int `json:"in_progress"`
}

type Finding struct {
	ID         uint                 `json:"id"`
	ScanID     uint                 `json:"scan_id"`
	Target     string               `json:"target"`
	TemplateID string               `json:"template_id"`
	Matched    bool                 `json:"matched"`
	Severity   string               `json:"severity"`
	Details    map[string]interface{} `json:"details,omitempty"`
	CreatedAt  time.Time            `json:"created_at"`
}

type TemplateFilter struct {
	Severity []string
	Tags     []string
	IDs      []string
}

type TicketStatus string

const (
	TicketStatusOpen   TicketStatus = "open"
	TicketStatusClosed TicketStatus = "closed"
)

type Ticket struct {
	ID          uint         `json:"id"`
	CreatedBy   uint         `json:"created_by"`
	AssignedTo  *uint        `json:"assigned_to,omitempty"`
	FindingID   uint         `json:"finding_id"`
	Title       string       `json:"title"`
	Description string       `json:"description"`
	Severity    string       `json:"severity"`
	Status      TicketStatus `json:"status"`
	CreatedAt   time.Time    `json:"created_at"`
	UpdatedAt   time.Time    `json:"updated_at"`
}

type User struct {
	ID           uint      `json:"id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"-"`
	Role         Role      `json:"role"`
	IsActive     bool      `json:"is_active"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
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
	PermCredCreate     Permission = "credential:create"
	PermCredRead       Permission = "credential:read"
	PermCredUpdate     Permission = "credential:update"
	PermCredDelete     Permission = "credential:delete"
	PermCredVerify     Permission = "credential:verify"
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
	ID            uint                 `json:"id"`
	UserID        uint                 `json:"user_id"`
	Name          string               `json:"name"`
	Method        AuthMethod           `json:"method"`
	Config        map[string]interface{} `json:"config"`
	LoginURL      string               `json:"login_url,omitempty"`
	VerifyURL     string               `json:"verify_url,omitempty"`
	VerifyPattern string               `json:"verify_pattern,omitempty"`
	IsActive      bool                 `json:"is_active"`
	LastVerified  *time.Time           `json:"last_verified,omitempty"`
	CreatedAt     time.Time            `json:"created_at"`
	UpdatedAt     time.Time            `json:"updated_at"`
}

type AuthSession struct {
	CredentialID   uint
	Cookies        []map[string]string
	Headers        map[string]string
	LastVerified   time.Time
	ExpiresAt      time.Time
	HealthOK       bool
	FailureCount   int
}

type ScanReportData struct {
	Scan     *ScanJob   `json:"scan"`
	Summary  *ReportSummary `json:"summary"`
	Findings []*Finding `json:"findings"`
}

type ReportSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}
