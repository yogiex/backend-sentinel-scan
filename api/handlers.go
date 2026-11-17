package api

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/ssrf"
)

// Handler wires HTTP routes to application services.
type Handler struct {
	scans      *application.ScanService
	tickets    *application.TicketService
	auth       *application.AuthService
	creds      *application.AuthCredentialService
	reports    *application.ReportService
	guard      *ssrf.Guard
	authIssuer *middleware.Auth

	// events feeds the WebSocket stream; nil means streaming is not wired.
	events *event.Bus
	// allowedOrigins is the exact-match list accepted for WebSocket upgrades.
	allowedOrigins map[string]struct{}
}

// NewHandler builds the HTTP handler.
func NewHandler(
	scans *application.ScanService,
	tickets *application.TicketService,
	auth *application.AuthService,
	creds *application.AuthCredentialService,
	reports *application.ReportService,
	guard *ssrf.Guard,
) *Handler {
	return &Handler{scans: scans, tickets: tickets, auth: auth, creds: creds, reports: reports, guard: guard}
}

// WithEventBus attaches the live event pipeline used by /scans/{id}/stream.
func (h *Handler) WithEventBus(bus *event.Bus) *Handler {
	h.events = bus
	return h
}

// WithAllowedOrigins sets the exact-match origin allowlist for WebSocket
// upgrades. An empty list rejects every origin-bearing handshake rather than
// reflecting whatever the client sent.
func (h *Handler) WithAllowedOrigins(origins []string) *Handler {
	h.allowedOrigins = make(map[string]struct{}, len(origins))
	for _, o := range origins {
		if o = strings.TrimSpace(o); o != "" {
			h.allowedOrigins[o] = struct{}{}
		}
	}
	return h
}

// WithAuthIssuer enables the login endpoint.
func (h *Handler) WithAuthIssuer(a *middleware.Auth) *Handler {
	h.authIssuer = a
	return h
}

// actor returns the authenticated principal or writes a 401.
func actor(w http.ResponseWriter, r *http.Request) (policy.Actor, bool) {
	a, ok := middleware.ActorFrom(r.Context())
	if !ok {
		httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Authentication required")
		return policy.Actor{}, false
	}
	return a, true
}

func pathID(r *http.Request, name string) (uint, bool) {
	raw := mux.Vars(r)[name]
	id, err := strconv.ParseUint(raw, 10, 32)
	if err != nil || id == 0 {
		return 0, false
	}
	return uint(id), true
}

func queryInt(r *http.Request, name string, fallback int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

// ── Health ──────────────────────────────────────────────────

type HealthResponse struct {
	Status    string `json:"status" example:"healthy"`
	Version   string `json:"version,omitempty" example:"1.0.0"`
	Timestamp string `json:"timestamp" example:"2026-05-11T10:00:00Z"`
}

func (h *Handler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, HealthResponse{
		Status:    "healthy",
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	})
}

// ── Auth ────────────────────────────────────────────────────

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	Token     string       `json:"token"`
	TokenType string       `json:"token_type"`
	ExpiresAt time.Time    `json:"expires_at"`
	User      *userPayload `json:"user"`
}

type userPayload struct {
	ID       uint        `json:"id"`
	Username string      `json:"username"`
	Email    string      `json:"email"`
	Role     entity.Role `json:"role"`
}

// LoginHandler exchanges credentials for a bearer token.
func (h *Handler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	if h.authIssuer == nil {
		httpx.Error(w, http.StatusNotImplemented, "NOT_IMPLEMENTED", "Login is not configured")
		return
	}
	var req loginRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Username) == "" || req.Password == "" {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "username and password are required")
		return
	}
	user, err := h.auth.Authenticate(r.Context(), req.Username, req.Password)
	if err != nil {
		// Uniform message: never reveal whether the account exists.
		httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid username or password")
		return
	}
	token, expires, err := h.authIssuer.Issue(user)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, loginResponse{
		Token:     token,
		TokenType: "Bearer",
		ExpiresAt: expires,
		User:      &userPayload{ID: user.ID, Username: user.Username, Email: user.Email, Role: user.Role},
	})
}

// MeHandler returns the caller's profile.
func (h *Handler) MeHandler(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	user, err := h.auth.GetByID(r.Context(), a.ID)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, userPayload{ID: user.ID, Username: user.Username, Email: user.Email, Role: user.Role})
}

// ── Scans ───────────────────────────────────────────────────

type createScanRequest struct {
	Targets           []string `json:"targets"`
	TemplateSelectors string   `json:"template_selectors"`
	AuthCredentialID  *uint    `json:"auth_credential_id,omitempty"`
}

// CreateScan validates and queues a scan. The response is 202: the scan has
// been persisted but execution continues asynchronously.
func (h *Handler) CreateScan(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	var req createScanRequest
	if !httpx.Decode(w, r, &req) {
		return
	}
	scan, err := h.scans.StartScan(r.Context(), a, req.Targets, req.TemplateSelectors, req.AuthCredentialID)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusAccepted, scan)
}

type scanListResponse struct {
	Items    []*entity.ScanJob `json:"items"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

// ListScans returns the caller's scans (all scans for admins).
func (h *Handler) ListScans(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	page := queryInt(r, "page", 1)
	pageSize := queryInt(r, "page_size", 20)
	filter := repository.ScanFilter{
		Status:   strings.TrimSpace(r.URL.Query().Get("status")),
		Page:     page,
		PageSize: pageSize,
	}
	items, total, err := h.scans.ListScans(r.Context(), a, filter)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, scanListResponse{Items: items, Total: total, Page: page, PageSize: pageSize})
}

func (h *Handler) GetScan(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid scan ID")
		return
	}
	scan, err := h.scans.GetScan(r.Context(), a, id)
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, scan)
}

func (h *Handler) CancelScan(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid scan ID")
		return
	}
	if err := h.scans.CancelScan(r.Context(), a, id); err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]string{"status": string(entity.ScanStatusCancelled)})
}

func (h *Handler) GetScanResults(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	id, ok := pathID(r, "id")
	if !ok {
		httpx.Error(w, http.StatusBadRequest, "INVALID_INPUT", "Invalid scan ID")
		return
	}
	findings, err := h.scans.GetResults(r.Context(), a, id, queryInt(r, "limit", 0))
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, findings)
}

// ── Templates ───────────────────────────────────────────────

// ListTemplates returns the built-in detection plugins this backend can run.
// Filters: ?severity=critical,high &tag=xss &search=injection.
func (h *Handler) ListTemplates(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	items, err := h.scans.ListTemplates(r.Context(), a, application.TemplateFilter{
		Severity: splitCSV(q.Get("severity")),
		Tag:      q.Get("tag"),
		Search:   q.Get("search"),
	})
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"items": items, "total": len(items)})
}

func (h *Handler) GetTemplate(w http.ResponseWriter, r *http.Request) {
	a, ok := actor(w, r)
	if !ok {
		return
	}
	item, err := h.scans.GetTemplate(r.Context(), a, mux.Vars(r)["id"])
	if err != nil {
		httpx.ErrorFrom(w, err)
		return
	}
	httpx.JSON(w, http.StatusOK, item)
}

// splitCSV splits a comma-separated query parameter, dropping empty terms.
func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
