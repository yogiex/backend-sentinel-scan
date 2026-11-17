package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// ── in-memory repositories ──────────────────────────────────

type ticketStore struct {
	mu       sync.Mutex
	nextID   uint
	items    map[uint]*entity.Ticket
	comments map[uint][]*entity.TicketComment
}

func newTicketStore() *ticketStore {
	return &ticketStore{items: map[uint]*entity.Ticket{}, comments: map[uint][]*entity.TicketComment{}}
}

func (s *ticketStore) Create(_ context.Context, t *entity.Ticket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextID++
	t.ID = s.nextID
	t.Code = entity.FormatTicketCode(t.ID)
	stored := *t
	s.items[t.ID] = &stored
	return nil
}

func (s *ticketStore) Update(_ context.Context, t *entity.Ticket) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[t.ID]; !ok {
		return apperr.ErrNotFound
	}
	stored := *t
	s.items[t.ID] = &stored
	return nil
}

func (s *ticketStore) FindByID(_ context.Context, id uint) (*entity.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return nil, apperr.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s *ticketStore) FindByIDOwned(_ context.Context, id, ownerID uint) (*entity.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok || (item.CreatedBy != ownerID && (item.AssignedTo == nil || *item.AssignedTo != ownerID)) {
		return nil, apperr.ErrNotFound
	}
	copied := *item
	return &copied, nil
}

func (s *ticketStore) selectItems(f repository.TicketFilter) []*entity.Ticket {
	var out []*entity.Ticket
	for _, item := range s.items {
		if f.Status != "" && item.Status != f.Status {
			continue
		}
		if f.Priority != "" && item.Priority != f.Priority {
			continue
		}
		if f.VisibleTo != 0 && item.CreatedBy != f.VisibleTo && (item.AssignedTo == nil || *item.AssignedTo != f.VisibleTo) {
			continue
		}
		copied := *item
		out = append(out, &copied)
	}
	return out
}

func (s *ticketStore) List(_ context.Context, f repository.TicketFilter) ([]*entity.Ticket, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.selectItems(f), nil
}

func (s *ticketStore) Count(ctx context.Context, f repository.TicketFilter) (int64, error) {
	items, err := s.List(ctx, f)
	return int64(len(items)), err
}

func (s *ticketStore) Stats(_ context.Context, f repository.TicketFilter) (*entity.TicketStats, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := &entity.TicketStats{ByStatus: map[string]int64{}, ByPriority: map[string]int64{}}
	for _, item := range s.items {
		if f.VisibleTo != 0 && item.CreatedBy != f.VisibleTo && (item.AssignedTo == nil || *item.AssignedTo != f.VisibleTo) {
			continue
		}
		stats.Total++
		stats.ByStatus[string(item.Status)]++
		stats.ByPriority[string(item.Priority)]++
	}
	return stats, nil
}

func (s *ticketStore) CreateComment(_ context.Context, c *entity.TicketComment) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.ID = uint(len(s.comments[c.TicketID]) + 1)
	c.CreatedAt = time.Now()
	s.comments[c.TicketID] = append(s.comments[c.TicketID], c)
	return nil
}

func (s *ticketStore) ListComments(_ context.Context, ticketID uint) ([]*entity.TicketComment, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.comments[ticketID], nil
}

type findingStore struct{ byID map[uint]*entity.Finding }

func (s findingStore) Create(context.Context, *entity.Finding) error { return nil }
func (s findingStore) CreateBatch(context.Context, []*entity.Finding) error {
	return nil
}
func (s findingStore) FindByScanID(context.Context, uint) ([]*entity.Finding, error) {
	return nil, nil
}
func (s findingStore) FindByScanIDLimit(context.Context, uint, int) ([]*entity.Finding, error) {
	return nil, nil
}
func (s findingStore) FindByID(_ context.Context, id uint) (*entity.Finding, error) {
	if f, ok := s.byID[id]; ok {
		return f, nil
	}
	return nil, apperr.ErrNotFound
}

type scanStore struct{ byID map[uint]*entity.ScanJob }

func (s scanStore) Create(context.Context, *entity.ScanJob) error               { return nil }
func (s scanStore) UpdateStatus(context.Context, uint, entity.ScanStatus) error { return nil }
func (s scanStore) UpdateProgress(context.Context, uint, *entity.ScanProgress) error {
	return nil
}
func (s scanStore) SetTruncated(context.Context, uint) error   { return nil }
func (s scanStore) TouchHeartbeat(context.Context, uint) error { return nil }
func (s scanStore) SetOutcome(context.Context, uint, bool, string) error {
	return nil
}
func (s scanStore) MarkInterrupted(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (s scanStore) FindByID(_ context.Context, id uint) (*entity.ScanJob, error) {
	if scan, ok := s.byID[id]; ok {
		return scan, nil
	}
	return nil, apperr.ErrNotFound
}
func (s scanStore) FindByIDOwned(_ context.Context, id, ownerID uint) (*entity.ScanJob, error) {
	scan, ok := s.byID[id]
	if !ok || scan.CreatedBy != ownerID {
		return nil, apperr.ErrNotFound
	}
	return scan, nil
}
func (s scanStore) List(context.Context, repository.ScanFilter) ([]*entity.ScanJob, error) {
	return nil, nil
}
func (s scanStore) Count(context.Context, repository.ScanFilter) (int64, error) { return 0, nil }
func (s scanStore) Delete(context.Context, uint) error                          { return nil }

type userStore struct{ byID map[uint]*entity.User }

func (s userStore) Create(context.Context, *entity.User) error { return nil }
func (s userStore) FindByID(_ context.Context, id uint) (*entity.User, error) {
	if u, ok := s.byID[id]; ok {
		return u, nil
	}
	return nil, apperr.ErrNotFound
}
func (s userStore) FindByUsername(_ context.Context, username string) (*entity.User, error) {
	for _, u := range s.byID {
		if u.Username == username {
			return u, nil
		}
	}
	return nil, apperr.ErrNotFound
}
func (s userStore) Update(context.Context, *entity.User) error { return nil }
func (s userStore) IncrementTokenVersion(_ context.Context, id uint) (int, error) {
	if u, ok := s.byID[id]; ok {
		u.TokenVersion++
		return u.TokenVersion, nil
	}
	return 0, apperr.ErrNotFound
}
func (s userStore) UpdateLastLogin(_ context.Context, id uint, at time.Time) error {
	if u, ok := s.byID[id]; ok {
		u.LastLogin = &at
		return nil
	}
	return apperr.ErrNotFound
}

// ── harness ─────────────────────────────────────────────────

type ticketAPIHarness struct {
	store  *ticketStore
	router http.Handler
	tokens map[string]string
}

func newTicketAPIHarness(t *testing.T) *ticketAPIHarness {
	t.Helper()
	store := newTicketStore()
	svc := application.NewTicketService(
		store,
		findingStore{byID: map[uint]*entity.Finding{
			7: {ID: 7, ScanID: 3, Target: "https://contoh.test/", TemplateID: "xss-reflected", Severity: "high"},
		}},
		scanStore{byID: map[uint]*entity.ScanJob{
			3: {ID: 3, CreatedBy: 4, Status: entity.ScanStatusCompleted},
		}},
		userStore{byID: map[uint]*entity.User{
			5: {ID: 5, Username: "viewer", IsActive: true},
		}},
	)
	h := NewHandler(nil, svc, nil, nil, nil, nil)

	// A real Auth instance means the test goes through the real router and the
	// real middleware, including the role-to-permission mapping.
	auth, err := middleware.NewAuth(strings.Repeat("k", 32), time.Hour)
	if err != nil {
		t.Fatalf("auth: %v", err)
	}
	users := map[string]entity.User{
		"admin":    {ID: 1, Role: entity.RoleAdmin},
		"auditor":  {ID: 9, Role: entity.RoleAuditor},
		"analyst":  {ID: 4, Role: entity.RoleSecurityAnalyst},
		"analyst2": {ID: 12, Role: entity.RoleSecurityAnalyst},
		"viewer":   {ID: 5, Role: entity.RoleViewer},
	}
	tokens := make(map[string]string, len(users))
	for name, user := range users {
		token, _, err := auth.Issue(&user)
		if err != nil {
			t.Fatalf("issue %s: %v", name, err)
		}
		tokens[name] = token
	}
	return &ticketAPIHarness{store: store, router: NewRouter(h, RouterDeps{Auth: auth}), tokens: tokens}
}

func (h *ticketAPIHarness) do(t *testing.T, method, path, body, as string) *httptest.ResponseRecorder {
	t.Helper()
	var reader *strings.Reader
	if body == "" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	token, ok := h.tokens[as]
	if !ok {
		t.Fatalf("no token for actor %q", as)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *ticketAPIHarness) seed(t *testing.T, creator uint, assignee *uint) *entity.Ticket {
	t.Helper()
	ticket := &entity.Ticket{
		CreatedBy: creator, AssignedTo: assignee, ScanID: 3, FindingID: 7,
		Title: "Seeded ticket", Severity: "high", Priority: entity.TicketPriorityHigh,
		Status: entity.TicketStatusOpen,
	}
	if err := h.store.Create(context.Background(), ticket); err != nil {
		t.Fatalf("seed: %v", err)
	}
	return ticket
}

// ── tests ───────────────────────────────────────────────────

func TestCreateTicketIgnoresClientSeverity(t *testing.T) {
	h := newTicketAPIHarness(t)
	body := `{"finding_id":7,"title":"Fix XSS","severity":"critical","scan_id":999,"priority":"medium"}`
	rec := h.do(t, http.MethodPost, "/api/tickets", body, "analyst")
	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d (%s)", rec.Code, rec.Body.String())
	}
	var ticket entity.Ticket
	if err := json.Unmarshal(rec.Body.Bytes(), &ticket); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if ticket.Severity != "high" {
		t.Errorf("severity must come from the finding, got %q", ticket.Severity)
	}
	if ticket.ScanID != 3 {
		t.Errorf("scan_id must come from the finding, got %d", ticket.ScanID)
	}
	if ticket.Priority != entity.TicketPriorityMedium {
		t.Errorf("explicit priority must be honoured, got %q", ticket.Priority)
	}
	if ticket.Code != "TKT-000001" {
		t.Errorf("unexpected code %q", ticket.Code)
	}
	if ticket.DueDate == nil {
		t.Error("due_date must default from the SLA")
	}
}

func TestCreateTicketRejectsForeignFinding(t *testing.T) {
	h := newTicketAPIHarness(t)
	rec := h.do(t, http.MethodPost, "/api/tickets", `{"finding_id":7,"title":"Steal"}`, "analyst2")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a foreign finding, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestCreateTicketValidatesTitle(t *testing.T) {
	h := newTicketAPIHarness(t)
	rec := h.do(t, http.MethodPost, "/api/tickets", `{"finding_id":7,"title":"   "}`, "analyst")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestListTicketsShowsAssignedWork(t *testing.T) {
	h := newTicketAPIHarness(t)
	assignee := uint(5)
	h.seed(t, 4, &assignee) // created by the analyst, assigned to the viewer
	h.seed(t, 4, nil)       // created by the analyst only

	rec := h.do(t, http.MethodGet, "/api/tickets", "", "viewer")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var list ticketListResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if list.Total != 1 || len(list.Items) != 1 {
		t.Fatalf("viewer should see exactly the assigned ticket, got total=%d items=%d", list.Total, len(list.Items))
	}
	if list.Page != 1 || list.PageSize != 20 {
		t.Errorf("pagination defaults missing: page=%d size=%d", list.Page, list.PageSize)
	}

	rec = h.do(t, http.MethodGet, "/api/tickets", "", "admin")
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode admin: %v", err)
	}
	if list.Total != 2 {
		t.Fatalf("admin should see both tickets, got %d", list.Total)
	}
}

func TestTicketStaticRoutesBeatIDRoute(t *testing.T) {
	h := newTicketAPIHarness(t)
	h.seed(t, 4, nil)

	rec := h.do(t, http.MethodGet, "/api/tickets/stats", "", "analyst")
	if rec.Code != http.StatusOK {
		t.Fatalf("/tickets/stats was swallowed by /tickets/{id}: %d (%s)", rec.Code, rec.Body.String())
	}
	var stats entity.TicketStats
	if err := json.Unmarshal(rec.Body.Bytes(), &stats); err != nil {
		t.Fatalf("decode stats: %v", err)
	}
	if stats.Total != 1 || stats.ByStatus[string(entity.TicketStatusOpen)] != 1 {
		t.Fatalf("unexpected stats %+v", stats)
	}

	rec = h.do(t, http.MethodGet, "/api/tickets/overdue", "", "analyst")
	if rec.Code != http.StatusOK {
		t.Fatalf("/tickets/overdue: %d (%s)", rec.Code, rec.Body.String())
	}

	// This router does not distinguish a wrong method from an unknown path (it
	// answers 404 for both, as it already did for /api/scans), so the meaningful
	// assertion is that a POST is not routed to a ticket handler.
	rec = h.do(t, http.MethodPost, "/api/tickets/stats", `{}`, "analyst")
	if rec.Code == http.StatusOK || rec.Code == http.StatusCreated {
		t.Fatalf("POST to a read-only route must not succeed, got %d", rec.Code)
	}
}

func TestTicketStatusAndCommentsEndpoints(t *testing.T) {
	h := newTicketAPIHarness(t)
	ticket := h.seed(t, 4, nil)

	rec := h.do(t, http.MethodPatch, "/api/tickets/1/status", `{"status":"verified"}`, "analyst")
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("open -> verified must be rejected, got %d (%s)", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodPatch, "/api/tickets/1/status", `{"status":"fixed"}`, "analyst")
	if rec.Code != http.StatusOK {
		t.Fatalf("open -> fixed: %d (%s)", rec.Code, rec.Body.String())
	}
	var updated entity.Ticket
	if err := json.Unmarshal(rec.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if updated.Status != entity.TicketStatusFixed {
		t.Errorf("status = %q, want fixed", updated.Status)
	}

	rec = h.do(t, http.MethodPost, "/api/tickets/1/comments", `{"message":"menunggu vendor"}`, "analyst")
	if rec.Code != http.StatusCreated {
		t.Fatalf("comment: %d (%s)", rec.Code, rec.Body.String())
	}

	rec = h.do(t, http.MethodGet, "/api/tickets/1", "", "analyst")
	if rec.Code != http.StatusOK {
		t.Fatalf("detail: %d (%s)", rec.Code, rec.Body.String())
	}
	var detail ticketDetailResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &detail); err != nil {
		t.Fatalf("decode detail: %v", err)
	}
	if detail.Ticket == nil || detail.Ticket.ID != ticket.ID {
		t.Fatalf("detail ticket missing: %+v", detail.Ticket)
	}
	if len(detail.Comments) != 1 || detail.Comments[0].Message != "menunggu vendor" {
		t.Fatalf("comments not included: %+v", detail.Comments)
	}

	rec = h.do(t, http.MethodPost, "/api/tickets/1/assign", `{"assigned_to":5}`, "analyst")
	if rec.Code != http.StatusOK {
		t.Fatalf("assign: %d (%s)", rec.Code, rec.Body.String())
	}
	var assigned entity.Ticket
	if err := json.Unmarshal(rec.Body.Bytes(), &assigned); err != nil {
		t.Fatalf("decode assigned: %v", err)
	}
	if assigned.AssignedTo == nil || *assigned.AssignedTo != 5 {
		t.Fatalf("assignee not stored: %+v", assigned.AssignedTo)
	}
}

func TestTicketDetailHidesForeignTickets(t *testing.T) {
	h := newTicketAPIHarness(t)
	h.seed(t, 4, nil)
	if rec := h.do(t, http.MethodGet, "/api/tickets/1", "", "viewer"); rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for a foreign ticket, got %d", rec.Code)
	}
}
