package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// ── fakes ───────────────────────────────────────────────────

type stubScanRepo struct {
	scan *entity.ScanJob
	err  error
}

func (s stubScanRepo) Create(context.Context, *entity.ScanJob) error { return nil }
func (s stubScanRepo) FindByID(context.Context, uint) (*entity.ScanJob, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.scan, nil
}
func (s stubScanRepo) FindByIDOwned(context.Context, uint, uint) (*entity.ScanJob, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.scan, nil
}
func (s stubScanRepo) UpdateStatus(context.Context, uint, entity.ScanStatus) error { return nil }
func (s stubScanRepo) UpdateProgress(context.Context, uint, *entity.ScanProgress) error {
	return nil
}
func (s stubScanRepo) SetTruncated(context.Context, uint) error   { return nil }
func (s stubScanRepo) TouchHeartbeat(context.Context, uint) error { return nil }
func (s stubScanRepo) MarkInterrupted(context.Context, string, time.Time) (int64, error) {
	return 0, nil
}
func (s stubScanRepo) List(context.Context, repository.ScanFilter) ([]*entity.ScanJob, error) {
	return nil, nil
}
func (s stubScanRepo) Count(context.Context, repository.ScanFilter) (int64, error) { return 0, nil }
func (s stubScanRepo) Delete(context.Context, uint) error                          { return nil }

type stubFindingRepo struct{ findings []*entity.Finding }

func (s stubFindingRepo) Create(context.Context, *entity.Finding) error        { return nil }
func (s stubFindingRepo) CreateBatch(context.Context, []*entity.Finding) error { return nil }
func (s stubFindingRepo) FindByScanID(context.Context, uint) ([]*entity.Finding, error) {
	return s.findings, nil
}
func (s stubFindingRepo) FindByScanIDLimit(context.Context, uint, int) ([]*entity.Finding, error) {
	return s.findings, nil
}
func (s stubFindingRepo) FindByID(context.Context, uint) (*entity.Finding, error) {
	return nil, apperr.ErrNotFound
}

var streamActor = policy.NewActor(4, entity.RoleSecurityAnalyst)

func streamServer(t *testing.T, handler *Handler, scanID string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = mux.SetURLVars(r, map[string]string{"id": scanID})
		r = r.WithContext(middleware.WithActor(r.Context(), streamActor))
		handler.StreamHandler(w, r)
	}))
}

func streamHandler(bus *event.Bus, repo repository.ScanRepository, findings []*entity.Finding, origins ...string) *Handler {
	svc := application.NewScanService(repo, stubFindingRepo{findings: findings}, nil, nil, nil)
	h := NewHandler(svc, nil, nil, nil, nil, nil)
	if bus != nil {
		h = h.WithEventBus(bus)
	}
	return h.WithAllowedOrigins(origins)
}

func dialStream(t *testing.T, srv *httptest.Server, query string, header http.Header) *websocket.Conn {
	t.Helper()
	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/scans/7/stream" + query
	conn, _, err := websocket.DefaultDialer.Dial(url, header)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	return conn
}

func readFrame(t *testing.T, conn *websocket.Conn) streamEnvelope {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatalf("deadline: %v", err)
	}
	_, payload, err := conn.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	var envelope streamEnvelope
	if err := json.Unmarshal(payload, &envelope); err != nil {
		t.Fatalf("decode %q: %v", payload, err)
	}
	return envelope
}

// ── tests ───────────────────────────────────────────────────

func TestStreamSendsSnapshotThenLiveEvents(t *testing.T) {
	bus := event.NewBus()
	scan := &entity.ScanJob{
		ID:       7,
		Status:   entity.ScanStatusRunning,
		Progress: &entity.ScanProgress{TotalTasks: 4, InProgress: 4},
	}
	findings := []*entity.Finding{{ID: 11, ScanID: 7, Target: "https://a.test/", TemplateID: "xss-reflected", Severity: "high"}}
	h := streamHandler(bus, stubScanRepo{scan: scan}, findings, "http://app.test")
	srv := streamServer(t, h, "7")
	defer srv.Close()

	conn := dialStream(t, srv, "?token=fake", http.Header{"Origin": []string{"http://app.test"}})
	defer conn.Close()

	if frame := readFrame(t, conn); frame.Type != "progress" {
		t.Fatalf("expected a progress snapshot first, got %q", frame.Type)
	}
	if frame := readFrame(t, conn); frame.Type != "finding" {
		t.Fatalf("expected the finding snapshot second, got %q", frame.Type)
	}

	bus.PublishProgress("7", 1, 4)
	if frame := readFrame(t, conn); frame.Type != "progress" {
		t.Fatalf("expected live progress, got %q", frame.Type)
	}

	bus.PublishComplete("7")
	frame := readFrame(t, conn)
	if frame.Type != "complete" {
		t.Fatalf("expected complete, got %q", frame.Type)
	}
}

func TestStreamTerminatesWhenBusEventIsDropped(t *testing.T) {
	// The bus drops events for a full subscriber channel, so a terminal status
	// must also be observed from the persisted row.
	bus := event.NewBus()
	repo := newMutableScanRepo(&entity.ScanJob{
		ID:       7,
		Status:   entity.ScanStatusRunning,
		Progress: &entity.ScanProgress{TotalTasks: 1},
	})
	h := streamHandler(bus, repo, nil, "http://app.test")
	srv := streamServer(t, h, "7")
	defer srv.Close()

	conn := dialStream(t, srv, "?token=fake", http.Header{"Origin": []string{"http://app.test"}})
	defer conn.Close()
	if frame := readFrame(t, conn); frame.Type != "progress" {
		t.Fatalf("expected progress snapshot, got %q", frame.Type)
	}

	repo.setStatus(entity.ScanStatusCompleted, true)
	if frame := readFrame(t, conn); frame.Type != "complete" {
		t.Fatalf("expected complete from the status poll, got %q", frame.Type)
	}
}

func TestStreamForeignScanIs404(t *testing.T) {
	h := streamHandler(event.NewBus(), stubScanRepo{err: apperr.ErrNotFound}, nil, "http://app.test")
	srv := streamServer(t, h, "7")
	defer srv.Close()

	url := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/scans/7/stream"
	_, resp, err := websocket.DefaultDialer.Dial(url, http.Header{"Origin": []string{"http://app.test"}})
	if err == nil {
		t.Fatal("expected the handshake to fail for a foreign scan")
	}
	if resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Fatalf("expected 404, got %+v", resp)
	}
}

func TestStreamRejectsUnknownOrigin(t *testing.T) {
	h := streamHandler(event.NewBus(), stubScanRepo{scan: &entity.ScanJob{ID: 7}}, nil, "http://app.test")
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/scans/7/stream", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "7"})
	r.Header.Set("Origin", "http://evil.test")
	r = r.WithContext(middleware.WithActor(r.Context(), streamActor))

	h.StreamHandler(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
	}
}

func TestStreamWithoutBusIs501(t *testing.T) {
	h := streamHandler(nil, stubScanRepo{scan: &entity.ScanJob{ID: 7}}, nil, "http://app.test")
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/scans/7/stream", nil)
	r = mux.SetURLVars(r, map[string]string{"id": "7"})
	r.Header.Set("Origin", "http://app.test")
	r = r.WithContext(middleware.WithActor(r.Context(), streamActor))

	h.StreamHandler(rec, r)
	if rec.Code != http.StatusNotImplemented {
		t.Fatalf("expected 501, got %d (%s)", rec.Code, rec.Body.String())
	}
}

// mutableScanRepo lets a test change the persisted status while a stream is
// open, which is how the poll fallback is exercised.
type mutableScanRepo struct {
	stubScanRepo
	mu     chan struct{}
	status entity.ScanStatus
	trunc  bool
}

func newMutableScanRepo(scan *entity.ScanJob) *mutableScanRepo {
	return &mutableScanRepo{stubScanRepo: stubScanRepo{scan: scan}, mu: make(chan struct{}, 1), status: scan.Status}
}

func (m *mutableScanRepo) setStatus(status entity.ScanStatus, truncated bool) {
	m.mu <- struct{}{}
	m.status = status
	m.trunc = truncated
	<-m.mu
}

func (m *mutableScanRepo) FindByID(context.Context, uint) (*entity.ScanJob, error) {
	m.mu <- struct{}{}
	defer func() { <-m.mu }()
	return &entity.ScanJob{ID: m.scan.ID, Status: m.status, Progress: m.scan.Progress, Truncated: m.trunc}, nil
}

func (m *mutableScanRepo) FindByIDOwned(context.Context, uint, uint) (*entity.ScanJob, error) {
	return m.FindByID(context.Background(), 0)
}
