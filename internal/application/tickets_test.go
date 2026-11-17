package application

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// ── in-memory fakes ─────────────────────────────────────────

type memoryTicketRepo struct {
	mu       sync.Mutex
	nextID   uint
	items    map[uint]*entity.Ticket
	nextCID  uint
	comments map[uint][]*entity.TicketComment
	// lastFilter is what the service asked for, so the ownership scope can be
	// asserted without a database.
	lastFilter repository.TicketFilter
}

func newMemoryTicketRepo() *memoryTicketRepo {
	return &memoryTicketRepo{items: map[uint]*entity.Ticket{}, comments: map[uint][]*entity.TicketComment{}}
}

func (r *memoryTicketRepo) Create(_ context.Context, t *entity.Ticket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextID++
	t.ID = r.nextID
	t.Code = entity.FormatTicketCode(t.ID)
	stored := *t
	r.items[t.ID] = &stored
	return nil
}

func (r *memoryTicketRepo) Update(_ context.Context, t *entity.Ticket) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.items[t.ID]; !ok {
		return apperr.ErrNotFound
	}
	stored := *t
	r.items[t.ID] = &stored
	return nil
}

func (r *memoryTicketRepo) FindByID(_ context.Context, id uint) (*entity.Ticket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, ok := r.items[id]
	if !ok {
		return nil, apperr.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (r *memoryTicketRepo) FindByIDOwned(_ context.Context, id, ownerID uint) (*entity.Ticket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	item, ok := r.items[id]
	if !ok || (item.CreatedBy != ownerID && (item.AssignedTo == nil || *item.AssignedTo != ownerID)) {
		return nil, apperr.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (r *memoryTicketRepo) matches(item *entity.Ticket, f repository.TicketFilter) bool {
	if f.Status != "" && item.Status != f.Status {
		return false
	}
	if f.Priority != "" && item.Priority != f.Priority {
		return false
	}
	if f.ScanID != 0 && item.ScanID != f.ScanID {
		return false
	}
	if f.CreatedBy != 0 && item.CreatedBy != f.CreatedBy {
		return false
	}
	if f.AssignedTo != 0 && (item.AssignedTo == nil || *item.AssignedTo != f.AssignedTo) {
		return false
	}
	if f.VisibleTo != 0 && item.CreatedBy != f.VisibleTo && (item.AssignedTo == nil || *item.AssignedTo != f.VisibleTo) {
		return false
	}
	if f.Search != "" && !strings.Contains(strings.ToLower(item.Title), strings.ToLower(f.Search)) {
		return false
	}
	if f.OverdueOnly {
		if item.DueDate == nil || item.DueDate.After(time.Now()) {
			return false
		}
		switch item.Status {
		case entity.TicketStatusFixed, entity.TicketStatusVerified, entity.TicketStatusWontFix:
			return false
		}
	}
	return true
}

func (r *memoryTicketRepo) List(_ context.Context, f repository.TicketFilter) ([]*entity.Ticket, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastFilter = f
	var out []*entity.Ticket
	for _, item := range r.items {
		if r.matches(item, f) {
			copied := *item
			out = append(out, &copied)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (r *memoryTicketRepo) Count(ctx context.Context, f repository.TicketFilter) (int64, error) {
	items, err := r.List(ctx, f)
	return int64(len(items)), err
}

func (r *memoryTicketRepo) Stats(_ context.Context, f repository.TicketFilter) (*entity.TicketStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	stats := &entity.TicketStats{ByStatus: map[string]int64{}, ByPriority: map[string]int64{}}
	for _, item := range r.items {
		if f.VisibleTo != 0 && item.CreatedBy != f.VisibleTo && (item.AssignedTo == nil || *item.AssignedTo != f.VisibleTo) {
			continue
		}
		stats.Total++
		stats.ByStatus[string(item.Status)]++
		stats.ByPriority[string(item.Priority)]++
		if item.DueDate != nil && item.DueDate.Before(time.Now()) {
			stats.Overdue++
		}
	}
	return stats, nil
}

func (r *memoryTicketRepo) CreateComment(_ context.Context, c *entity.TicketComment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nextCID++
	c.ID = r.nextCID
	c.CreatedAt = time.Now()
	r.comments[c.TicketID] = append(r.comments[c.TicketID], c)
	return nil
}

func (r *memoryTicketRepo) ListComments(_ context.Context, ticketID uint) ([]*entity.TicketComment, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.comments[ticketID], nil
}

type ticketScanRepo struct {
	scans map[uint]*entity.ScanJob
}

func (r *ticketScanRepo) Create(context.Context, *entity.ScanJob) error { return nil }
func (r *ticketScanRepo) FindByID(_ context.Context, id uint) (*entity.ScanJob, error) {
	if scan, ok := r.scans[id]; ok {
		return scan, nil
	}
	return nil, apperr.ErrNotFound
}
func (r *ticketScanRepo) FindByIDOwned(_ context.Context, id, ownerID uint) (*entity.ScanJob, error) {
	scan, ok := r.scans[id]
	if !ok || scan.CreatedBy != ownerID {
		return nil, apperr.ErrNotFound
	}
	return scan, nil
}
func (r *ticketScanRepo) UpdateStatus(context.Context, uint, entity.ScanStatus) error { return nil }
func (r *ticketScanRepo) UpdateProgress(context.Context, uint, *entity.ScanProgress) error {
	return nil
}
func (r *ticketScanRepo) SetTruncated(context.Context, uint) error   { return nil }
func (r *ticketScanRepo) TouchHeartbeat(context.Context, uint) error { return nil }
func (r *ticketScanRepo) MarkInterrupted(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (r *ticketScanRepo) List(context.Context, repository.ScanFilter) ([]*entity.ScanJob, error) {
	return nil, nil
}
func (r *ticketScanRepo) Count(context.Context, repository.ScanFilter) (int64, error) { return 0, nil }
func (r *ticketScanRepo) Delete(context.Context, uint) error                          { return nil }

type ticketFindingRepo struct{ findings map[uint]*entity.Finding }

func (r *ticketFindingRepo) Create(context.Context, *entity.Finding) error { return nil }
func (r *ticketFindingRepo) CreateBatch(context.Context, []*entity.Finding) error {
	return nil
}
func (r *ticketFindingRepo) FindByScanID(context.Context, uint) ([]*entity.Finding, error) {
	return nil, nil
}
func (r *ticketFindingRepo) FindByScanIDLimit(context.Context, uint, int) ([]*entity.Finding, error) {
	return nil, nil
}
func (r *ticketFindingRepo) FindByID(_ context.Context, id uint) (*entity.Finding, error) {
	if f, ok := r.findings[id]; ok {
		return f, nil
	}
	return nil, apperr.ErrNotFound
}

type ticketUserRepo struct{ users map[uint]*entity.User }

func (r *ticketUserRepo) Create(context.Context, *entity.User) error { return nil }
func (r *ticketUserRepo) FindByID(_ context.Context, id uint) (*entity.User, error) {
	if u, ok := r.users[id]; ok {
		return u, nil
	}
	return nil, apperr.ErrNotFound
}
func (r *ticketUserRepo) FindByUsername(context.Context, string) (*entity.User, error) {
	return nil, apperr.ErrNotFound
}
func (r *ticketUserRepo) Update(context.Context, *entity.User) error { return nil }

// ── harness ─────────────────────────────────────────────────

type ticketHarness struct {
	svc      *TicketService
	tickets  *memoryTicketRepo
	findings *ticketFindingRepo
	scans    *ticketScanRepo
	users    *ticketUserRepo
}

func newTicketHarness() *ticketHarness {
	tickets := newMemoryTicketRepo()
	findings := &ticketFindingRepo{findings: map[uint]*entity.Finding{
		7: {ID: 7, ScanID: 3, Target: "https://contoh.test/", TemplateID: "xss-reflected", Matched: true, Severity: "high"},
		8: {ID: 8, ScanID: 3, Target: "https://contoh.test/info", TemplateID: "open-redirect", Matched: true, Severity: "info"},
	}}
	scans := &ticketScanRepo{scans: map[uint]*entity.ScanJob{
		3: {ID: 3, CreatedBy: 4, Status: entity.ScanStatusCompleted},
	}}
	users := &ticketUserRepo{users: map[uint]*entity.User{
		4: {ID: 4, Username: "analyst", Role: entity.RoleSecurityAnalyst, IsActive: true},
		5: {ID: 5, Username: "viewer", Role: entity.RoleViewer, IsActive: true},
		6: {ID: 6, Username: "gone", Role: entity.RoleViewer, IsActive: false},
	}}
	return &ticketHarness{
		svc:      NewTicketService(tickets, findings, scans, users),
		tickets:  tickets,
		findings: findings,
		scans:    scans,
		users:    users,
	}
}

var (
	analyst  = policy.NewActor(4, entity.RoleSecurityAnalyst)
	admin    = policy.NewActor(1, entity.RoleAdmin)
	auditor  = policy.NewActor(9, entity.RoleAuditor)
	viewer   = policy.NewActor(5, entity.RoleViewer)
	stranger = policy.NewActor(11, entity.RoleViewer)
	// otherAnalyst has the create/update permissions but owns nothing, which is
	// what separates "not allowed" (403) from "not yours" (404).
	otherAnalyst = policy.NewActor(12, entity.RoleSecurityAnalyst)
)

func TestCreateTicketDerivesSeverityScanAndPriority(t *testing.T) {
	h := newTicketHarness()
	ticket, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 8,
		Title:     "Fix open redirect",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ticket.Severity != "info" {
		t.Errorf("severity must come from the finding, got %q", ticket.Severity)
	}
	if ticket.ScanID != 3 {
		t.Errorf("scan_id must come from the finding, got %d", ticket.ScanID)
	}
	if ticket.Priority != entity.TicketPriorityLow {
		t.Errorf("priority for info severity must be low, got %q", ticket.Priority)
	}
	if ticket.Status != entity.TicketStatusOpen {
		t.Errorf("new ticket must be open, got %q", ticket.Status)
	}
	if ticket.DueDate == nil {
		t.Fatal("due date must default from the SLA")
	}
	if got := ticket.DueDate.Sub(time.Now()); got < 29*24*time.Hour {
		t.Errorf("low priority SLA should be about 30 days, got %v", got)
	}
	if ticket.Code == "" {
		t.Error("ticket code must be derived")
	}
}

func TestCreateTicketRejectsUnknownFinding(t *testing.T) {
	h := newTicketHarness()
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 9, Title: "Unknown finding",
	}); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestCreateTicketExplicitPriorityWins(t *testing.T) {
	h := newTicketHarness()
	ticket, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 8,
		Title:     "Raise urgency",
		Priority:  entity.TicketPriorityCritical,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ticket.Priority != entity.TicketPriorityCritical {
		t.Errorf("explicit priority must win, got %q", ticket.Priority)
	}
	if got := ticket.DueDate.Sub(time.Now()); got > 4*24*time.Hour {
		t.Errorf("critical SLA should be about 3 days, got %v", got)
	}
}

func TestCreateTicketRejectsForeignFinding(t *testing.T) {
	h := newTicketHarness()
	// Finding 7 belongs to scan 3, owned by user 4; another analyst cannot read it.
	_, err := h.svc.CreateTicket(context.Background(), otherAnalyst, CreateTicketInput{
		FindingID: 7,
		Title:     "Steal the finding",
	})
	if !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("expected not found, got %v", err)
	}
}

func TestCreateTicketValidatesAssignee(t *testing.T) {
	h := newTicketHarness()
	missing := uint(999)
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 7, Title: "Assign to nobody", AssignedTo: &missing,
	}); err == nil {
		t.Fatal("expected an error for a missing assignee")
	}
	inactive := uint(6)
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 7, Title: "Assign to inactive user", AssignedTo: &inactive,
	}); err == nil {
		t.Fatal("expected an error for an inactive assignee")
	}
	ok := uint(5)
	ticket, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 7, Title: "Assign to viewer", AssignedTo: &ok,
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if ticket.AssignedTo == nil || *ticket.AssignedTo != 5 {
		t.Fatalf("assignee not stored: %+v", ticket.AssignedTo)
	}
}

func TestCreateTicketValidation(t *testing.T) {
	h := newTicketHarness()
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{FindingID: 7, Title: "  "}); err == nil {
		t.Error("empty title must be rejected")
	}
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 7, Title: strings.Repeat("a", 201),
	}); err == nil {
		t.Error("overlong title must be rejected")
	}
	if _, err := h.svc.CreateTicket(context.Background(), auditor, CreateTicketInput{FindingID: 7, Title: "auditor cannot create"}); !errors.Is(err, apperr.ErrForbidden) {
		t.Errorf("auditor must not create tickets, got %v", err)
	}
	if _, err := h.svc.CreateTicket(context.Background(), analyst, CreateTicketInput{
		FindingID: 7, Title: "bad priority", Priority: "urgent",
	}); err == nil {
		t.Error("unknown priority must be rejected")
	}
}

// seedTicket creates a ticket directly through the repository so the test does
// not depend on the create rules it is not exercising.
func (h *ticketHarness) seedTicket(t *testing.T, creator uint, assignee *uint) *entity.Ticket {
	t.Helper()
	ticket := &entity.Ticket{
		CreatedBy: creator, AssignedTo: assignee, ScanID: 3, FindingID: 7,
		Title: "Seeded", Severity: "high", Priority: entity.TicketPriorityHigh,
		Status: entity.TicketStatusOpen,
	}
	if err := h.tickets.Create(context.Background(), ticket); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return ticket
}

func TestListTicketsScopesToAssigneeAndCreator(t *testing.T) {
	h := newTicketHarness()
	assigned := uint(5)
	h.seedTicket(t, 4, &assigned) // created by analyst, assigned to viewer
	h.seedTicket(t, 4, nil)       // created by analyst, unassigned
	h.seedTicket(t, 5, nil)       // created by viewer

	items, total, err := h.svc.ListTickets(context.Background(), viewer, repository.TicketFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if total != 2 || len(items) != 2 {
		t.Fatalf("viewer should see the assigned and own ticket, got %d/%d", total, len(items))
	}
	if h.tickets.lastFilter.VisibleTo != viewer.ID {
		t.Errorf("non-reviewer list must be scoped by visible_to, got %d", h.tickets.lastFilter.VisibleTo)
	}

	items, total, err = h.svc.ListTickets(context.Background(), admin, repository.TicketFilter{})
	if err != nil {
		t.Fatalf("list admin: %v", err)
	}
	if total != 3 || len(items) != 3 {
		t.Fatalf("admin should see every ticket, got %d/%d", total, len(items))
	}
	if h.tickets.lastFilter.VisibleTo != 0 {
		t.Errorf("admin list must not be scoped, got %d", h.tickets.lastFilter.VisibleTo)
	}
}

func TestListTicketsRejectsUnknownFilters(t *testing.T) {
	h := newTicketHarness()
	if _, _, err := h.svc.ListTickets(context.Background(), analyst, repository.TicketFilter{
		Status: entity.TicketStatus("closed"),
	}); err == nil {
		t.Error("legacy closed status must be rejected, not silently ignored")
	}
	if _, _, err := h.svc.ListTickets(context.Background(), analyst, repository.TicketFilter{
		Priority: entity.TicketPriority("urgent"),
	}); err == nil {
		t.Error("unknown priority filter must be rejected")
	}
}

func TestUpdateStatusFollowsLifecycle(t *testing.T) {
	h := newTicketHarness()
	ticket := h.seedTicket(t, 4, nil)

	if _, err := h.svc.UpdateStatus(context.Background(), analyst, ticket.ID, entity.TicketStatus("closed")); err == nil {
		t.Fatal("closed is no longer a valid status")
	}
	if _, err := h.svc.UpdateStatus(context.Background(), analyst, ticket.ID, entity.TicketStatusVerified); err == nil {
		t.Fatal("open cannot jump straight to verified")
	}

	fixed, err := h.svc.UpdateStatus(context.Background(), analyst, ticket.ID, entity.TicketStatusFixed)
	if err != nil {
		t.Fatalf("open -> fixed: %v", err)
	}
	if fixed.ClosedAt != nil {
		t.Error("fixed is not closed")
	}
	verified, err := h.svc.UpdateStatus(context.Background(), analyst, ticket.ID, entity.TicketStatusVerified)
	if err != nil {
		t.Fatalf("fixed -> verified: %v", err)
	}
	if verified.ClosedAt == nil {
		t.Error("verified must stamp closed_at")
	}
	reopened, err := h.svc.UpdateStatus(context.Background(), analyst, ticket.ID, entity.TicketStatusInProgress)
	if err != nil {
		t.Fatalf("verified -> in_progress: %v", err)
	}
	if reopened.ClosedAt != nil {
		t.Error("reopening must clear closed_at")
	}
	if reopened.UpdatedBy != analyst.ID {
		t.Errorf("updated_by must record the actor, got %d", reopened.UpdatedBy)
	}
}

func TestUpdateStatusIsForbiddenForStranger(t *testing.T) {
	h := newTicketHarness()
	ticket := h.seedTicket(t, 4, nil)
	if _, err := h.svc.UpdateStatus(context.Background(), stranger, ticket.ID, entity.TicketStatusInProgress); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("a viewer must be forbidden by permission, got %v", err)
	}
	if _, err := h.svc.UpdateStatus(context.Background(), otherAnalyst, ticket.ID, entity.TicketStatusInProgress); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("a non-owner must not see the ticket, got %v", err)
	}
	// The assignee may move the ticket even though they did not create it.
	assigneeUser := uint(12)
	assigned := h.seedTicket(t, 4, &assigneeUser)
	if _, err := h.svc.UpdateStatus(context.Background(), otherAnalyst, assigned.ID, entity.TicketStatusInProgress); err != nil {
		t.Fatalf("assignee must be able to update: %v", err)
	}
}

func TestAssignAndUnassign(t *testing.T) {
	h := newTicketHarness()
	ticket := h.seedTicket(t, 4, nil)
	target := uint(5)
	updated, err := h.svc.Assign(context.Background(), analyst, ticket.ID, &target)
	if err != nil {
		t.Fatalf("assign: %v", err)
	}
	if updated.AssignedTo == nil || *updated.AssignedTo != 5 {
		t.Fatalf("assignee not stored: %+v", updated.AssignedTo)
	}
	missing := uint(999)
	if _, err := h.svc.Assign(context.Background(), analyst, ticket.ID, &missing); err == nil {
		t.Fatal("assigning a missing user must fail")
	}
	cleared, err := h.svc.Assign(context.Background(), analyst, ticket.ID, nil)
	if err != nil {
		t.Fatalf("unassign: %v", err)
	}
	if cleared.AssignedTo != nil {
		t.Fatal("unassign must clear the assignee")
	}
}

func TestAddCommentRecordsActor(t *testing.T) {
	h := newTicketHarness()
	assignee := uint(5)
	ticket := h.seedTicket(t, 4, &assignee)

	comment, err := h.svc.AddComment(context.Background(), viewer, ticket.ID, "  menunggu jendela maintenance  ")
	if err != nil {
		t.Fatalf("comment: %v", err)
	}
	if comment.AuthorID != viewer.ID {
		t.Errorf("author must come from the actor, got %d", comment.AuthorID)
	}
	if comment.Message != "menunggu jendela maintenance" {
		t.Errorf("message must be trimmed, got %q", comment.Message)
	}
	if _, err := h.svc.AddComment(context.Background(), viewer, ticket.ID, "   "); err == nil {
		t.Error("empty comment must be rejected")
	}
	if _, err := h.svc.AddComment(context.Background(), viewer, ticket.ID, strings.Repeat("x", 2001)); err == nil {
		t.Error("overlong comment must be rejected")
	}
	if _, err := h.svc.AddComment(context.Background(), stranger, ticket.ID, "sneak in"); !errors.Is(err, apperr.ErrNotFound) {
		t.Errorf("stranger must not comment, got %v", err)
	}

	_, comments, err := h.svc.GetTicket(context.Background(), viewer, ticket.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if len(comments) != 1 {
		t.Fatalf("expected one comment, got %d", len(comments))
	}
}

func TestGetTicketIsScoped(t *testing.T) {
	h := newTicketHarness()
	ticket := h.seedTicket(t, 4, nil)
	if _, _, err := h.svc.GetTicket(context.Background(), stranger, ticket.ID); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("stranger must get not found, got %v", err)
	}
	if _, _, err := h.svc.GetTicket(context.Background(), auditor, ticket.ID); err != nil {
		t.Fatalf("auditor must read any ticket: %v", err)
	}
}

func TestStatsScopesToVisibleTickets(t *testing.T) {
	h := newTicketHarness()
	h.seedTicket(t, 4, nil)
	assigned := uint(5)
	h.seedTicket(t, 4, &assigned)

	stats, err := h.svc.Stats(context.Background(), viewer, repository.TicketFilter{})
	if err != nil {
		t.Fatalf("stats: %v", err)
	}
	if stats.Total != 1 {
		t.Fatalf("viewer stats must only count their ticket, got %d", stats.Total)
	}
	adminStats, err := h.svc.Stats(context.Background(), admin, repository.TicketFilter{})
	if err != nil {
		t.Fatalf("admin stats: %v", err)
	}
	if adminStats.Total != 2 {
		t.Fatalf("admin stats must count every ticket, got %d", adminStats.Total)
	}
}

func TestOverdueList(t *testing.T) {
	h := newTicketHarness()
	ticket := h.seedTicket(t, 4, nil)
	past := time.Now().Add(-48 * time.Hour)
	ticket.DueDate = &past
	if err := h.tickets.Update(context.Background(), ticket); err != nil {
		t.Fatalf("update: %v", err)
	}
	items, total, err := h.svc.ListTickets(context.Background(), analyst, repository.TicketFilter{OverdueOnly: true})
	if err != nil {
		t.Fatalf("overdue: %v", err)
	}
	if total != 1 || len(items) != 1 {
		t.Fatalf("expected one overdue ticket, got %d/%d", total, len(items))
	}
}
