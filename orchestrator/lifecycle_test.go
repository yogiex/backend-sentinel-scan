package orchestrator

import (
	"context"
	"testing"
	"time"
)

// newLifecycleOrchestrator builds the smallest orchestrator that can exercise
// the heartbeat and reconciliation paths: no registry, no queues, one fake repo.
func newLifecycleOrchestrator(repo *fakeScanRepo) *Orchestrator {
	return New(Config{ScanRepo: repo})
}

// installRun puts a live run in the orchestrator exactly as StartScan would.
func installRun(o *Orchestrator, scanID uint) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(o.baseCtx)
	o.runs[scanID] = &scanRun{ctx: ctx, cancel: cancel}
	return ctx, cancel
}

func TestReconcileInterruptedFailsEverythingLeftBehind(t *testing.T) {
	repo := &fakeScanRepo{}
	orch := newLifecycleOrchestrator(repo)

	if _, err := orch.ReconcileInterrupted(context.Background(), ReasonInterruptedRestart); err != nil {
		t.Fatalf("reconcile: %v", err)
	}
	_, calls := repo.lifecycleSnapshot()
	if len(calls) != 1 {
		t.Fatalf("expected one reconciliation call, got %d", len(calls))
	}
	if calls[0].reason != ReasonInterruptedRestart {
		t.Errorf("reason = %q, want %q", calls[0].reason, ReasonInterruptedRestart)
	}
	if !calls[0].staleBefore.IsZero() {
		t.Errorf("boot reconciliation must not be limited by heartbeat age, got %v", calls[0].staleBefore)
	}
}

func TestReconcileInterruptedWithoutRepository(t *testing.T) {
	orch := New(Config{})
	if marked, err := orch.ReconcileInterrupted(context.Background(), ReasonInterruptedRestart); err != nil || marked != 0 {
		t.Fatalf("expected a silent no-op, got %d, %v", marked, err)
	}
}

func TestShutdownCancelsRunsAndRecordsReason(t *testing.T) {
	repo := &fakeScanRepo{}
	orch := newLifecycleOrchestrator(repo)
	runCtx, _ := installRun(orch, 42)

	if err := orch.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	select {
	case <-runCtx.Done():
	case <-time.After(time.Second):
		t.Fatal("shutdown must cancel the scan context")
	}
	if _, live := orch.GetProgress(42); live {
		t.Error("the run must be dropped from the live map")
	}
	_, calls := repo.lifecycleSnapshot()
	if len(calls) != 1 || calls[0].reason != ReasonInterruptedShutdown {
		t.Fatalf("expected one shutdown reconciliation, got %+v", calls)
	}
}

func TestMaintenanceHeartbeatsLiveRunsAndFailsSilentOnes(t *testing.T) {
	repo := &fakeScanRepo{}
	orch := newLifecycleOrchestrator(repo)
	orch.cfg.HeartbeatInterval = 10 * time.Millisecond
	installRun(orch, 7)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartMaintenance(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		beats, calls := repo.lifecycleSnapshot()
		if beats > 0 && len(calls) > 0 {
			if calls[0].reason != ReasonHeartbeatLost {
				t.Fatalf("reason = %q, want %q", calls[0].reason, ReasonHeartbeatLost)
			}
			if calls[0].staleBefore.IsZero() {
				t.Fatal("a maintenance sweep must be limited to stale heartbeats")
			}
			if age := time.Since(calls[0].staleBefore); age < 10*time.Millisecond {
				t.Fatalf("stale cutoff should be at least one interval in the past, got %v", age)
			}
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("maintenance never heartbeated or reconciled")
}

func TestMaintenanceStopsWithItsContext(t *testing.T) {
	repo := &fakeScanRepo{}
	orch := newLifecycleOrchestrator(repo)
	orch.cfg.HeartbeatInterval = 5 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	orch.StartMaintenance(ctx)
	time.Sleep(20 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	before, _ := repo.lifecycleSnapshot()
	time.Sleep(40 * time.Millisecond)
	after, _ := repo.lifecycleSnapshot()
	if after != before {
		t.Fatalf("maintenance kept running after cancel: %d -> %d beats", before, after)
	}
}
