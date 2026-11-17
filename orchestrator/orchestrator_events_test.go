package orchestrator

import (
	"context"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
)

func newEventOrchestrator(t *testing.T) (*Orchestrator, *event.Bus, chan worker.Result) {
	t.Helper()
	reg := detector.NewRegistry()
	if err := reg.LoadEmbedded(); err != nil {
		t.Fatalf("load plugins: %v", err)
	}
	bus := event.NewBus()
	results := make(chan worker.Result, 8)
	orch := New(Config{
		Registry:    reg,
		TaskQueue:   make(chan worker.Task, 8),
		ResultQueue: results,
		ScanRepo:    &fakeScanRepo{},
		FindingRepo: &fakeFindingRepo{},
		Events:      bus,
	})
	return orch, bus, results
}

func nextEvent(t *testing.T, ch chan event.Event) event.Event {
	t.Helper()
	select {
	case ev := <-ch:
		return ev
	case <-time.After(2 * time.Second):
		t.Fatal("no event published before the deadline")
		return event.Event{}
	}
}

func TestStartScanPublishesInitialProgress(t *testing.T) {
	orch, bus, _ := newEventOrchestrator(t)
	ch := bus.Subscribe("3")
	defer bus.Unsubscribe("3", ch)

	if err := orch.StartScan(3, []string{"http://example.test"}, "xss"); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	ev := nextEvent(t, ch)
	if ev.Type != event.EventTypeProgress {
		t.Fatalf("expected progress first, got %q", ev.Type)
	}
	payload, ok := ev.Payload.(map[string]int)
	if !ok {
		t.Fatalf("unexpected payload type %T", ev.Payload)
	}
	if payload["total"] == 0 || payload["in_progress"] != payload["total"] {
		t.Fatalf("unexpected progress payload %+v", payload)
	}
}

func TestDispatchPublishesFindingProgressAndComplete(t *testing.T) {
	orch, bus, results := newEventOrchestrator(t)
	ch := bus.Subscribe("5")
	defer bus.Unsubscribe("5", ch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.StartDispatchLoop(ctx)

	if err := orch.StartScan(5, []string{"http://example.test"}, "xss"); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if ev := nextEvent(t, ch); ev.Type != event.EventTypeProgress {
		t.Fatalf("expected initial progress, got %q", ev.Type)
	}

	results <- worker.Result{
		ScanID:  5,
		Finding: &worker.Finding{Target: "http://example.test", TemplateID: "xss-reflected", Matched: true, Severity: "high"},
	}

	var sawFinding, sawProgress, sawComplete bool
	timeout := time.After(3 * time.Second)
	for !(sawFinding && sawProgress && sawComplete) {
		select {
		case ev := <-ch:
			switch ev.Type {
			case event.EventTypeFinding:
				sawFinding = true
			case event.EventTypeProgress:
				sawProgress = true
			case event.EventTypeComplete:
				sawComplete = true
			}
		case <-timeout:
			t.Fatalf("events missing: finding=%v progress=%v complete=%v", sawFinding, sawProgress, sawComplete)
		}
	}
}

func TestCancelPublishesFailure(t *testing.T) {
	orch, bus, _ := newEventOrchestrator(t)
	ch := bus.Subscribe("8")
	defer bus.Unsubscribe("8", ch)

	if err := orch.StartScan(8, []string{"http://example.test"}, "xss"); err != nil {
		t.Fatalf("start scan: %v", err)
	}
	if ev := nextEvent(t, ch); ev.Type != event.EventTypeProgress {
		t.Fatalf("expected initial progress, got %q", ev.Type)
	}

	if !orch.Cancel(8) {
		t.Fatal("cancel should report a live scan")
	}
	ev := nextEvent(t, ch)
	if ev.Type != event.EventTypeFailed {
		t.Fatalf("expected a failed event, got %q", ev.Type)
	}
	payload, ok := ev.Payload.(map[string]string)
	if !ok || payload["reason"] != "cancelled" {
		t.Fatalf("unexpected payload %+v", ev.Payload)
	}
}
