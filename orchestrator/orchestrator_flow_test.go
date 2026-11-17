package orchestrator

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
)

// ── fakes ───────────────────────────────────────────────────

// interruptCall records how reconciliation asked for interrupted scans to be
// failed, so tests can tell a boot sweep from a stale-heartbeat sweep.
type interruptCall struct {
	reason      string
	staleBefore time.Time
}

type fakeScanRepo struct {
	mu            sync.Mutex
	status        entity.ScanStatus
	progress      entity.ScanProgress
	truncated     bool
	degraded      bool
	failureReason string
	updates       int
	heartbeats    int
	interrupts    []interruptCall
}

func (f *fakeScanRepo) Create(context.Context, *entity.ScanJob) error { return nil }
func (f *fakeScanRepo) FindByID(context.Context, uint) (*entity.ScanJob, error) {
	return &entity.ScanJob{}, nil
}
func (f *fakeScanRepo) FindByIDOwned(context.Context, uint, uint) (*entity.ScanJob, error) {
	return &entity.ScanJob{}, nil
}
func (f *fakeScanRepo) UpdateStatus(_ context.Context, _ uint, status entity.ScanStatus) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status = status
	return nil
}
func (f *fakeScanRepo) UpdateProgress(_ context.Context, _ uint, p *entity.ScanProgress) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.progress = *p
	f.updates++
	return nil
}
func (f *fakeScanRepo) SetTruncated(context.Context, uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.truncated = true
	return nil
}
func (f *fakeScanRepo) SetOutcome(_ context.Context, _ uint, degraded bool, failureReason string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.degraded = degraded
	f.failureReason = failureReason
	return nil
}
func (f *fakeScanRepo) TouchHeartbeat(context.Context, uint) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.heartbeats++
	return nil
}
func (f *fakeScanRepo) MarkInterrupted(_ context.Context, reason string, staleBefore time.Time) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.interrupts = append(f.interrupts, interruptCall{reason: reason, staleBefore: staleBefore})
	return 0, nil
}
func (f *fakeScanRepo) List(context.Context, repository.ScanFilter) ([]*entity.ScanJob, error) {
	return nil, nil
}
func (f *fakeScanRepo) Count(context.Context, repository.ScanFilter) (int64, error) { return 0, nil }
func (f *fakeScanRepo) Delete(context.Context, uint) error                          { return nil }

// lifecycleSnapshot reports what the lifecycle code asked the repository to do.
func (f *fakeScanRepo) lifecycleSnapshot() (int, []interruptCall) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.heartbeats, append([]interruptCall(nil), f.interrupts...)
}

func (f *fakeScanRepo) snapshot() (entity.ScanStatus, entity.ScanProgress, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.status, f.progress, f.truncated
}

// outcomeSnapshot reports what the orchestrator recorded about completeness.
func (f *fakeScanRepo) outcomeSnapshot() (bool, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.degraded, f.failureReason
}

type fakeFindingRepo struct {
	mu       sync.Mutex
	findings []*entity.Finding
}

func (f *fakeFindingRepo) Create(context.Context, *entity.Finding) error { return nil }
func (f *fakeFindingRepo) CreateBatch(_ context.Context, findings []*entity.Finding) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.findings = append(f.findings, findings...)
	return nil
}
func (f *fakeFindingRepo) FindByScanID(context.Context, uint) ([]*entity.Finding, error) {
	return nil, nil
}
func (f *fakeFindingRepo) FindByScanIDLimit(context.Context, uint, int) ([]*entity.Finding, error) {
	return nil, nil
}
func (f *fakeFindingRepo) FindByID(context.Context, uint) (*entity.Finding, error) {
	return nil, nil
}

func (f *fakeFindingRepo) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.findings)
}

// ── helpers ─────────────────────────────────────────────────

func newTestOrchestrator(t *testing.T) (*Orchestrator, *fakeScanRepo, *fakeFindingRepo, chan worker.Task, chan worker.Result) {
	t.Helper()
	reg := detector.NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	scans := &fakeScanRepo{}
	findings := &fakeFindingRepo{}
	tasks := make(chan worker.Task, 64)
	results := make(chan worker.Result, 64)
	orch := New(Config{
		Registry:    reg,
		TaskQueue:   tasks,
		ResultQueue: results,
		ScanRepo:    scans,
		FindingRepo: findings,
	})
	return orch, scans, findings, tasks, results
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before the deadline")
}

// ── tests ───────────────────────────────────────────────────

func TestStartScanQueuesOneTaskPerTargetAndPlugin(t *testing.T) {
	orch, scans, _, tasks, _ := newTestOrchestrator(t)

	// path-traversal has four payloads but is a single plugin: the queue must
	// carry exactly one task for it.
	if err := orch.StartScan(1, []string{"http://example.test"}, "path-traversal", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}

	var task worker.Task
	select {
	case task = <-tasks:
	case <-time.After(time.Second):
		t.Fatal("no task queued")
	}
	if task.TemplateID != "path-traversal" {
		t.Fatalf("unexpected plugin %q", task.TemplateID)
	}
	if task.Ctx == nil {
		t.Fatal("tasks must carry the scan context so cancellation can reach workers")
	}

	status, progress, _ := scans.snapshot()
	if status != entity.ScanStatusRunning {
		t.Fatalf("expected running, got %s", status)
	}
	if progress.TotalTasks != 1 || progress.InProgress != 1 {
		t.Fatalf("unexpected progress %+v", progress)
	}
}

func TestUnknownSelectorIsRejected(t *testing.T) {
	orch, _, _, _, _ := newTestOrchestrator(t)
	if err := orch.StartScan(1, []string{"http://example.test"}, "not-a-plugin", nil); err == nil {
		t.Fatal("unknown selector must fail instead of scanning everything")
	}
}

func TestDispatchPersistsOnlyMatchesAndCompletesScan(t *testing.T) {
	orch, scans, findings, tasks, results := newTestOrchestrator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(7, []string{"http://example.test"}, "path-traversal", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	<-tasks

	results <- worker.Result{
		ScanID:  7,
		Finding: &worker.Finding{Target: "http://example.test", TemplateID: "path-traversal", Matched: true, Severity: "high"},
	}

	waitFor(t, func() bool {
		status, _, _ := scans.snapshot()
		return status == entity.ScanStatusCompleted
	})

	if got := findings.count(); got != 1 {
		t.Fatalf("matched finding should be persisted once, got %d", got)
	}
	_, progress, _ := scans.snapshot()
	if progress.Completed != 1 || progress.InProgress != 0 {
		t.Fatalf("unexpected progress %+v", progress)
	}

	// A second, non-matching result for a scan that already finished must not
	// resurrect it or add rows.
	results <- worker.Result{ScanID: 7, Finding: &worker.Finding{Target: "x", TemplateID: "path-traversal"}}
	time.Sleep(50 * time.Millisecond)
	if got := findings.count(); got != 1 {
		t.Fatalf("non-matching findings must not be stored, got %d rows", got)
	}
}

func TestTruncatedResultStopsTheScan(t *testing.T) {
	orch, scans, _, tasks, results := newTestOrchestrator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(9, []string{"http://example.test"}, "xss", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	var task worker.Task
	select {
	case task = <-tasks:
	case <-time.After(time.Second):
		t.Fatal("no task queued")
	}

	results <- worker.Result{ScanID: 9, Truncated: true, Finding: &worker.Finding{Target: "t", TemplateID: "xss-reflected"}}

	waitFor(t, func() bool {
		status, _, truncated := scans.snapshot()
		return status == entity.ScanStatusCompleted && truncated
	})
	if task.Ctx.Err() == nil {
		t.Fatal("hitting the budget must cancel the remaining work")
	}
}

func TestCancelStopsQueuedWork(t *testing.T) {
	orch, _, _, tasks, _ := newTestOrchestrator(t)
	if err := orch.StartScan(11, []string{"http://example.test"}, "xss", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	var task worker.Task
	select {
	case task = <-tasks:
	case <-time.After(time.Second):
		t.Fatal("no task queued")
	}
	if !orch.Cancel(11) {
		t.Fatal("cancelling a live scan must report true")
	}
	if task.Ctx.Err() == nil {
		t.Fatal("cancel must propagate to the task context")
	}
	if orch.Cancel(11) {
		t.Fatal("cancelling twice must report false")
	}
}
