package orchestrator

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
)

// A scan where not one task produced a response must fail, not complete. A
// "completed, no findings" report for an unreachable host is the most dangerous
// output this product can produce.
func TestAllTasksFailedMarksScanFailed(t *testing.T) {
	orch, scans, _, tasks, results := newTestOrchestrator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(21, []string{"http://unreachable.test"}, "xss", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	select {
	case <-tasks:
	case <-time.After(time.Second):
		t.Fatal("no task queued")
	}

	results <- worker.Result{
		ScanID: 21,
		Error:  errors.New("dial tcp: connection refused"),
		Finding: &worker.Finding{
			Target:     "http://unreachable.test",
			TemplateID: "xss-reflected",
			Matched:    false,
		},
	}

	waitFor(t, func() bool {
		status, _, _ := scans.snapshot()
		return status == entity.ScanStatusFailed
	})

	degraded, reason := scans.outcomeSnapshot()
	if degraded {
		t.Fatal("a fully failed scan is failed, not degraded")
	}
	if reason != ReasonAllTasksFailed {
		t.Fatalf("expected reason %q, got %q", ReasonAllTasksFailed, reason)
	}
}

// Partial transport failure keeps the scan completed but marks the coverage as
// partial, so the report can say "not everything was checked".
func TestPartialTaskFailureMarksScanDegraded(t *testing.T) {
	orch, scans, _, tasks, results := newTestOrchestrator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(22, []string{"http://ok.test", "http://down.test"}, "xss", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-tasks:
		case <-time.After(time.Second):
			t.Fatal("expected two tasks")
		}
	}

	results <- worker.Result{ScanID: 22, Checked: true, Finding: &worker.Finding{Target: "http://ok.test", TemplateID: "xss-reflected"}}
	results <- worker.Result{ScanID: 22, Checked: false, Error: errors.New("i/o timeout"), Finding: &worker.Finding{Target: "http://down.test", TemplateID: "xss-reflected"}}

	waitFor(t, func() bool {
		status, _, _ := scans.snapshot()
		return status == entity.ScanStatusCompleted
	})

	degraded, reason := scans.outcomeSnapshot()
	if !degraded {
		t.Fatal("a scan with a failed task must be marked degraded")
	}
	if reason != "" {
		t.Fatalf("degraded scan should carry no failure reason, got %q", reason)
	}
	_, progress, _ := scans.snapshot()
	if progress.Completed != 1 || progress.Failed != 1 {
		t.Fatalf("unexpected progress %+v", progress)
	}
}

// A clean scan must explicitly clear the outcome rather than leave a stale
// degraded flag from a previous write.
func TestCleanScanIsNotDegraded(t *testing.T) {
	orch, scans, _, tasks, results := newTestOrchestrator(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(23, []string{"http://ok.test"}, "xss", nil); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	select {
	case <-tasks:
	case <-time.After(time.Second):
		t.Fatal("no task queued")
	}

	results <- worker.Result{ScanID: 23, Checked: true, Finding: &worker.Finding{Target: "http://ok.test", TemplateID: "xss-reflected"}}

	waitFor(t, func() bool {
		status, _, _ := scans.snapshot()
		return status == entity.ScanStatusCompleted
	})

	degraded, reason := scans.outcomeSnapshot()
	if degraded || reason != "" {
		t.Fatalf("clean scan must not be degraded (degraded=%v reason=%q)", degraded, reason)
	}
}
