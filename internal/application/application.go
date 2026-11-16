// Package application implements the use cases. All ownership checks live here
// (not only in the transport layer) so every entry point — HTTP today, gRPC or
// CLI tomorrow — gets the same IDOR protection.
package application

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/passwd"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/ssrf"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

const (
	maxTargets      = 50
	maxSelectorsLen = 4096
	maxConfigBytes  = 32 << 10
)

// ScanDispatcher starts and stops execution of a persisted scan.
type ScanDispatcher interface {
	StartScan(scanID uint, targets []string, templateSelectors string) error
	// Cancel stops the work in flight. Changing the status alone would leave a
	// scan marked "cancelled" while its workers kept sending requests.
	Cancel(scanID uint) bool
}

// TemplateCatalog resolves template selectors at submission time, so a selector
// that matches nothing is rejected with 400 instead of producing a scan that
// never runs.
type TemplateCatalog interface {
	ResolveIDs(selectors string) ([]string, error)
}

// ── Scan ────────────────────────────────────────────────────

type ScanService struct {
	scans      repository.ScanRepository
	findings   repository.FindingRepository
	creds      repository.AuthCredentialRepository
	guard      *ssrf.Guard
	dispatcher ScanDispatcher
	catalog    TemplateCatalog
}

func NewScanService(
	scans repository.ScanRepository,
	findings repository.FindingRepository,
	creds repository.AuthCredentialRepository,
	guard *ssrf.Guard,
	dispatcher ScanDispatcher,
) *ScanService {
	return &ScanService{scans: scans, findings: findings, creds: creds, guard: guard, dispatcher: dispatcher}
}

// WithCatalog enables selector validation before a scan is persisted.
func (s *ScanService) WithCatalog(catalog TemplateCatalog) *ScanService {
	s.catalog = catalog
	return s
}

// StartScan validates, persists, and dispatches a scan for the given actor.
func (s *ScanService) StartScan(ctx context.Context, actor policy.Actor, targets []string, templateSelectors string, authCredentialID *uint) (*entity.ScanJob, error) {
	if !actor.Can(entity.PermScanCreate) {
		return nil, apperr.ErrForbidden
	}
	clean, err := s.validateTargets(ctx, targets)
	if err != nil {
		return nil, err
	}
	if len(templateSelectors) > maxSelectorsLen {
		return nil, apperr.NewAppError("INVALID_INPUT", "template_selectors is too large", 400)
	}
	if s.catalog != nil {
		ids, err := s.catalog.ResolveIDs(templateSelectors)
		if err != nil {
			return nil, apperr.NewAppError("INVALID_INPUT", "Invalid template_selectors: "+err.Error(), 400)
		}
		if len(ids) == 0 {
			return nil, apperr.NewAppError("INVALID_INPUT", "template_selectors matched no templates", 400)
		}
	}

	if authCredentialID != nil {
		// Ownership is checked in the query: a foreign credential ID is
		// indistinguishable from a missing one (404, not 403).
		cred, err := s.creds.FindByIDOwned(ctx, *authCredentialID, actor.ID)
		if err != nil {
			if errors.Is(err, apperr.ErrNotFound) {
				return nil, apperr.ErrNotFound
			}
			return nil, err
		}
		if !cred.IsActive {
			return nil, apperr.NewAppError("INVALID_INPUT", "Credential is disabled", 400)
		}
	}

	scan := &entity.ScanJob{
		CreatedBy:         actor.ID,
		Targets:           clean,
		TemplateSelectors: templateSelectors,
		Status:            entity.ScanStatusPending,
		AuthCredentialID:  authCredentialID,
	}
	if err := s.scans.Create(ctx, scan); err != nil {
		return nil, err
	}

	if s.dispatcher != nil {
		if err := s.dispatcher.StartScan(scan.ID, clean, templateSelectors); err != nil {
			log.Printf("[scan %d] dispatch failed: %v", scan.ID, err)
			if uerr := s.scans.UpdateStatus(ctx, scan.ID, entity.ScanStatusFailed); uerr != nil {
				log.Printf("[scan %d] marking failed: %v", scan.ID, uerr)
			}
			scan.Status = entity.ScanStatusFailed
		}
	}
	return scan, nil
}

func (s *ScanService) validateTargets(ctx context.Context, targets []string) ([]string, error) {
	if len(targets) == 0 {
		return nil, apperr.NewAppError("INVALID_INPUT", "At least one target is required", 400)
	}
	if len(targets) > maxTargets {
		return nil, apperr.NewAppError("INVALID_INPUT", "Too many targets (max 50)", 400)
	}
	seen := make(map[string]struct{}, len(targets))
	out := make([]string, 0, len(targets))
	for _, raw := range targets {
		if s.guard == nil {
			out = append(out, raw)
			continue
		}
		u, err := s.guard.Validate(ctx, raw)
		if err != nil {
			return nil, apperr.NewAppError("INVALID_TARGET", "Target rejected: "+err.Error(), 400)
		}
		normalized := u.String()
		if _, dup := seen[normalized]; dup {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	return out, nil
}

// getOwnedScan loads a scan, returning 404 for both missing and foreign scans.
func (s *ScanService) getOwnedScan(ctx context.Context, actor policy.Actor, id uint) (*entity.ScanJob, error) {
	if !actor.Can(entity.PermScanRead) {
		return nil, apperr.ErrForbidden
	}
	if actor.IsAdmin() {
		return s.scans.FindByID(ctx, id)
	}
	return s.scans.FindByIDOwned(ctx, id, actor.ID)
}

func (s *ScanService) GetScan(ctx context.Context, actor policy.Actor, id uint) (*entity.ScanJob, error) {
	return s.getOwnedScan(ctx, actor, id)
}

func (s *ScanService) GetProgress(ctx context.Context, actor policy.Actor, id uint) (*entity.ScanProgress, error) {
	scan, err := s.getOwnedScan(ctx, actor, id)
	if err != nil {
		return nil, err
	}
	if scan.Progress == nil {
		return &entity.ScanProgress{}, nil
	}
	return scan.Progress, nil
}

func (s *ScanService) GetResults(ctx context.Context, actor policy.Actor, id uint, limit int) ([]*entity.Finding, error) {
	if _, err := s.getOwnedScan(ctx, actor, id); err != nil {
		return nil, err
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	return s.findings.FindByScanIDLimit(ctx, id, limit)
}

func (s *ScanService) CancelScan(ctx context.Context, actor policy.Actor, id uint) error {
	if !actor.Can(entity.PermScanCancel) {
		return apperr.ErrForbidden
	}
	if _, err := s.getOwnedScan(ctx, actor, id); err != nil {
		return err
	}
	if err := s.scans.UpdateStatus(ctx, id, entity.ScanStatusCancelled); err != nil {
		return err
	}
	// Only stop the workers once the state machine accepted the transition;
	// cancelling a finished scan would be a lie about what happened.
	if s.dispatcher != nil {
		s.dispatcher.Cancel(id)
	}
	return nil
}

// ListScans returns scans visible to actor, newest first.
func (s *ScanService) ListScans(ctx context.Context, actor policy.Actor, filter repository.ScanFilter) ([]*entity.ScanJob, int64, error) {
	if !actor.Can(entity.PermScanRead) {
		return nil, 0, apperr.ErrForbidden
	}
	if !actor.IsAdmin() {
		filter.CreatedBy = actor.ID
	}
	items, err := s.scans.List(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	total, err := s.scans.Count(ctx, filter)
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// ── Auth ────────────────────────────────────────────────────

type AuthService struct {
	users repository.UserRepository
}

func NewAuthService(users repository.UserRepository) *AuthService {
	return &AuthService{users: users}
}

func (s *AuthService) Authenticate(ctx context.Context, username, password string) (*entity.User, error) {
	user, err := s.users.FindByUsername(ctx, strings.TrimSpace(username))
	if err != nil {
		if errors.Is(err, apperr.ErrNotFound) {
			passwd.Burn(password) // keep timing uniform
			return nil, apperr.ErrUnauthorized
		}
		return nil, err
	}
	if err := passwd.Verify(user.PasswordHash, password); err != nil {
		return nil, apperr.ErrUnauthorized
	}
	if !user.IsActive {
		return nil, apperr.ErrForbidden
	}
	now := time.Now()
	user.LastLogin = &now
	if err := s.users.Update(ctx, user); err != nil {
		log.Printf("[auth] last_login update failed: %v", err)
	}
	return user, nil
}

func (s *AuthService) GetByID(ctx context.Context, id uint) (*entity.User, error) {
	return s.users.FindByID(ctx, id)
}

// EnsureAdmin creates the bootstrap admin account when it does not exist.
func EnsureAdmin(ctx context.Context, users repository.UserRepository, username, email, password string, role entity.Role) error {
	if username == "" || password == "" {
		return nil
	}
	if _, err := users.FindByUsername(ctx, username); err == nil {
		return nil
	} else if !errors.Is(err, apperr.ErrNotFound) {
		return err
	}
	hash, err := passwd.Hash(password)
	if err != nil {
		return err
	}
	return users.Create(ctx, &entity.User{
		Username:     username,
		Email:        email,
		PasswordHash: hash,
		Role:         role,
		IsActive:     true,
	})
}

// ── Credentials ─────────────────────────────────────────────

type AuthCredentialService struct {
	repo  repository.AuthCredentialRepository
	guard *ssrf.Guard
}

func NewAuthCredentialService(repo repository.AuthCredentialRepository, guard *ssrf.Guard) *AuthCredentialService {
	return &AuthCredentialService{repo: repo, guard: guard}
}

var validMethods = map[entity.AuthMethod]struct{}{
	entity.AuthMethodLoginForm: {},
	entity.AuthMethodCookie:    {},
	entity.AuthMethodBearer:    {},
	entity.AuthMethodAPIKey:    {},
	entity.AuthMethodSelenium:  {},
}

func (s *AuthCredentialService) validateURL(ctx context.Context, raw string) error {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if s.guard == nil {
		return nil
	}
	if _, err := s.guard.Validate(ctx, raw); err != nil {
		return apperr.NewAppError("INVALID_INPUT", "URL rejected: "+err.Error(), 400)
	}
	return nil
}

func (s *AuthCredentialService) Create(ctx context.Context, actor policy.Actor, name string, method entity.AuthMethod, config map[string]any, loginURL, verifyURL, verifyPattern string) (*entity.AuthCredential, error) {
	if !actor.Can(entity.PermCredCreate) {
		return nil, apperr.ErrForbidden
	}
	if _, ok := validMethods[method]; !ok {
		return nil, apperr.NewAppError("INVALID_INPUT", "Unknown auth method", 400)
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return nil, apperr.NewAppError("INVALID_INPUT", "Name must be 1-100 characters", 400)
	}
	if len(config) > 64 || len(configJSON(config)) > maxConfigBytes {
		return nil, apperr.NewAppError("INVALID_INPUT", "Credential config is too large", 400)
	}
	if err := s.validateURL(ctx, loginURL); err != nil {
		return nil, err
	}
	if err := s.validateURL(ctx, verifyURL); err != nil {
		return nil, err
	}
	cred := &entity.AuthCredential{
		UserID:        actor.ID,
		Name:          name,
		Method:        method,
		Config:        config,
		LoginURL:      loginURL,
		VerifyURL:     verifyURL,
		VerifyPattern: verifyPattern,
		IsActive:      true,
	}
	if err := s.repo.Create(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// GetByID is always scoped to the actor; even admins only see their own secrets.
func (s *AuthCredentialService) GetByID(ctx context.Context, actor policy.Actor, id uint) (*entity.AuthCredential, error) {
	if !actor.Can(entity.PermCredRead) {
		return nil, apperr.ErrForbidden
	}
	return s.repo.FindByIDOwned(ctx, id, actor.ID)
}

func (s *AuthCredentialService) List(ctx context.Context, actor policy.Actor) ([]*entity.AuthCredential, error) {
	if !actor.Can(entity.PermCredRead) {
		return nil, apperr.ErrForbidden
	}
	return s.repo.FindByUserID(ctx, actor.ID)
}

// Update applies an allowlisted set of fields after an ownership check.
func (s *AuthCredentialService) Update(ctx context.Context, actor policy.Actor, id uint, updates map[string]any) (*entity.AuthCredential, error) {
	if !actor.Can(entity.PermCredUpdate) {
		return nil, apperr.ErrForbidden
	}
	cred, err := s.repo.FindByIDOwned(ctx, id, actor.ID)
	if err != nil {
		return nil, err
	}
	if v, ok := updates["name"].(string); ok {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 100 {
			return nil, apperr.NewAppError("INVALID_INPUT", "Name must be 1-100 characters", 400)
		}
		cred.Name = v
	}
	if v, ok := updates["method"].(string); ok {
		m := entity.AuthMethod(v)
		if _, valid := validMethods[m]; !valid {
			return nil, apperr.NewAppError("INVALID_INPUT", "Unknown auth method", 400)
		}
		cred.Method = m
	}
	if v, ok := updates["config"].(map[string]any); ok {
		if len(configJSON(v)) > maxConfigBytes {
			return nil, apperr.NewAppError("INVALID_INPUT", "Credential config is too large", 400)
		}
		cred.Config = v
	}
	if v, ok := updates["login_url"].(string); ok {
		if err := s.validateURL(ctx, v); err != nil {
			return nil, err
		}
		cred.LoginURL = v
	}
	if v, ok := updates["verify_url"].(string); ok {
		if err := s.validateURL(ctx, v); err != nil {
			return nil, err
		}
		cred.VerifyURL = v
	}
	if v, ok := updates["verify_pattern"].(string); ok {
		cred.VerifyPattern = v
	}
	if v, ok := updates["is_active"].(bool); ok {
		cred.IsActive = v
	}
	if err := s.repo.Update(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

func (s *AuthCredentialService) Delete(ctx context.Context, actor policy.Actor, id uint) error {
	if !actor.Can(entity.PermCredDelete) {
		return apperr.ErrForbidden
	}
	return s.repo.DeleteOwned(ctx, id, actor.ID)
}

func (s *AuthCredentialService) UpdateLastVerified(ctx context.Context, actor policy.Actor, id uint) error {
	if !actor.Can(entity.PermCredVerify) {
		return apperr.ErrForbidden
	}
	if _, err := s.repo.FindByIDOwned(ctx, id, actor.ID); err != nil {
		return err
	}
	return s.repo.UpdateLastVerified(ctx, id)
}

// Sanitize strips secrets before a credential leaves the API boundary.
func (s *AuthCredentialService) Sanitize(cred *entity.AuthCredential) {
	if cred == nil {
		return
	}
	configured := len(cred.Config) > 0
	cred.Config = map[string]any{"configured": configured}
}

// ── Tickets ─────────────────────────────────────────────────

type TicketService struct {
	tickets  repository.TicketRepository
	findings repository.FindingRepository
	scans    repository.ScanRepository
}

func NewTicketService(tickets repository.TicketRepository, findings repository.FindingRepository, scans repository.ScanRepository) *TicketService {
	return &TicketService{tickets: tickets, findings: findings, scans: scans}
}

func (s *TicketService) CreateTicket(ctx context.Context, actor policy.Actor, findingID uint, title, description, severity string) (*entity.Ticket, error) {
	if !actor.Can(entity.PermTicketCreate) {
		return nil, apperr.ErrForbidden
	}
	title = strings.TrimSpace(title)
	if title == "" || len(title) > 200 {
		return nil, apperr.NewAppError("INVALID_INPUT", "Title must be 1-200 characters", 400)
	}
	if len(description) > 10000 {
		return nil, apperr.NewAppError("INVALID_INPUT", "Description is too long", 400)
	}
	// A finding may only be turned into a ticket by somebody who can read the
	// scan it belongs to (prevents linking foreign findings).
	finding, err := s.findings.FindByID(ctx, findingID)
	if err != nil {
		return nil, err
	}
	if _, err := s.getOwnedScan(ctx, actor, finding.ScanID); err != nil {
		return nil, apperr.ErrNotFound
	}
	ticket := &entity.Ticket{
		CreatedBy:   actor.ID,
		FindingID:   finding.ID,
		Title:       title,
		Description: description,
		Severity:    severity,
		Status:      entity.TicketStatusOpen,
	}
	if err := s.tickets.Create(ctx, ticket); err != nil {
		return nil, err
	}
	return ticket, nil
}

func (s *TicketService) getOwnedScan(ctx context.Context, actor policy.Actor, id uint) (*entity.ScanJob, error) {
	if actor.IsAdmin() {
		return s.scans.FindByID(ctx, id)
	}
	return s.scans.FindByIDOwned(ctx, id, actor.ID)
}

func (s *TicketService) UpdateStatus(ctx context.Context, actor policy.Actor, id uint, status entity.TicketStatus) error {
	if !actor.Can(entity.PermTicketUpdate) {
		return apperr.ErrForbidden
	}
	if status != entity.TicketStatusOpen && status != entity.TicketStatusClosed {
		return apperr.NewAppError("INVALID_INPUT", "Unknown ticket status", 400)
	}
	ticket, err := s.tickets.FindByID(ctx, id)
	if err != nil {
		return err
	}
	if !actor.IsAdmin() && ticket.CreatedBy != actor.ID && (ticket.AssignedTo == nil || *ticket.AssignedTo != actor.ID) {
		return apperr.ErrNotFound
	}
	ticket.Status = status
	return s.tickets.Update(ctx, ticket)
}

func (s *TicketService) AssignTicket(ctx context.Context, actor policy.Actor, ticketID, userID uint) error {
	if !actor.Can(entity.PermTicketUpdate) {
		return apperr.ErrForbidden
	}
	ticket, err := s.tickets.FindByID(ctx, ticketID)
	if err != nil {
		return err
	}
	if !actor.IsAdmin() && ticket.CreatedBy != actor.ID {
		return apperr.ErrNotFound
	}
	ticket.AssignedTo = &userID
	return s.tickets.Update(ctx, ticket)
}

func (s *TicketService) GetTickets(ctx context.Context, actor policy.Actor, filter repository.TicketFilter) ([]*entity.Ticket, error) {
	if !actor.Can(entity.PermTicketUpdate) && !actor.Can(entity.PermScanRead) {
		return nil, apperr.ErrForbidden
	}
	if !actor.IsAdmin() {
		filter.CreatedBy = actor.ID
	}
	return s.tickets.List(ctx, filter)
}

// ── Report ──────────────────────────────────────────────────

type ReportService struct {
	scans    repository.ScanRepository
	findings repository.FindingRepository
}

func NewReportService(scans repository.ScanRepository, findings repository.FindingRepository) *ReportService {
	return &ReportService{scans: scans, findings: findings}
}

func (s *ReportService) GetReportData(ctx context.Context, actor policy.Actor, scanID uint) (*entity.ScanReportData, error) {
	if !actor.Can(entity.PermScanRead) {
		return nil, apperr.ErrForbidden
	}
	var scan *entity.ScanJob
	var err error
	if actor.IsAdmin() {
		scan, err = s.scans.FindByID(ctx, scanID)
	} else {
		scan, err = s.scans.FindByIDOwned(ctx, scanID, actor.ID)
	}
	if err != nil {
		return nil, err
	}
	findings, err := s.findings.FindByScanIDLimit(ctx, scanID, 5000)
	if err != nil {
		return nil, err
	}
	summary := &entity.ReportSummary{Total: len(findings)}
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			summary.Critical++
		case "high":
			summary.High++
		case "medium":
			summary.Medium++
		case "low":
			summary.Low++
		default:
			summary.Info++
		}
	}
	return &entity.ScanReportData{Scan: scan, Summary: summary, Findings: findings}, nil
}

func configJSON(config map[string]any) []byte {
	if len(config) == 0 {
		return nil
	}
	b, err := json.Marshal(config)
	if err != nil {
		return nil
	}
	return b
}
