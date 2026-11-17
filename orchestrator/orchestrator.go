package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/repository"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/egress"
)

// Config wires the orchestrator. The RabbitMQ publisher is deliberately absent:
// the messaging implementation is still a stub, and a stub that accepts tasks
// and silently drops them is worse than having no broker path at all.
type Config struct {
	Registry    *detector.Registry
	TaskQueue   chan worker.Task
	ResultQueue chan worker.Result
	ScanRepo    repository.ScanRepository
	FindingRepo repository.FindingRepository
	// MaxRequestsPerScan caps outbound requests for one scan. Zero means the
	// cap is derived from RequestsPerTarget x targets.
	MaxRequestsPerScan int64
	// RequestsPerTarget is the implied per-target request budget; 60 covers the
	// 38 payloads and 2 baselines of the built-in plugin set with headroom.
	RequestsPerTarget int64
	// Events carries live scan progress to WebSocket subscribers. Optional:
	// nil means nothing is published, which is what unit tests want.
	Events *event.Bus
}

// scanRun is the live state of one scan: its context (so cancellation and
// budget exhaustion stop in-flight work), its budget, and its progress.
type scanRun struct {
	ctx      context.Context
	cancel   context.CancelFunc
	budget   *egress.Budget
	progress entity.ScanProgress
}

type Orchestrator struct {
	cfg     Config
	baseCtx context.Context

	mu   sync.Mutex
	runs map[uint]*scanRun
}

func New(cfg Config) *Orchestrator {
	return &Orchestrator{
		cfg:     cfg,
		baseCtx: context.Background(),
		runs:    make(map[uint]*scanRun),
	}
}

// WithBaseContext sets the parent of every scan context, normally the signal
// context so a shutdown stops scanning too.
func (o *Orchestrator) WithBaseContext(ctx context.Context) *Orchestrator {
	if ctx != nil {
		o.baseCtx = ctx
	}
	return o
}

// StartScan expands the selectors, records progress, and queues one task per
// (target, plugin) pair.
func (o *Orchestrator) StartScan(scanID uint, targets []string, templateSelectors string) error {
	if o.cfg.Registry == nil {
		return errors.New("orchestrator: no plugin registry configured")
	}
	plugins, err := o.cfg.Registry.Resolve(templateSelectors)
	if err != nil {
		return err
	}
	if len(plugins) == 0 {
		return errors.New("orchestrator: selectors matched no plugins")
	}
	total := len(targets) * len(plugins)
	if total == 0 {
		return errors.New("orchestrator: nothing to scan")
	}
	if o.cfg.TaskQueue == nil {
		return errors.New("orchestrator: no task queue configured")
	}

	budgetMax := o.cfg.MaxRequestsPerScan
	if budgetMax <= 0 {
		perTarget := o.cfg.RequestsPerTarget
		if perTarget <= 0 {
			perTarget = 60
		}
		budgetMax = int64(len(targets)) * perTarget
	}

	ctx, cancel := context.WithCancel(o.baseCtx)
	budget := egress.NewBudget(budgetMax).WithCancel(cancel)
	ctx = egress.WithBudget(ctx, budget)

	run := &scanRun{
		ctx:      ctx,
		cancel:   cancel,
		budget:   budget,
		progress: entity.ScanProgress{TotalTasks: total, InProgress: total},
	}

	o.mu.Lock()
	if _, running := o.runs[scanID]; running {
		o.mu.Unlock()
		cancel()
		return fmt.Errorf("orchestrator: scan %d is already running", scanID)
	}
	o.runs[scanID] = run
	o.mu.Unlock()

	if err := o.cfg.ScanRepo.UpdateProgress(ctx, scanID, &run.progress); err != nil {
		o.drop(scanID)
		cancel()
		return fmt.Errorf("orchestrator: record progress: %w", err)
	}
	if err := o.cfg.ScanRepo.UpdateStatus(ctx, scanID, entity.ScanStatusRunning); err != nil {
		o.drop(scanID)
		cancel()
		return fmt.Errorf("orchestrator: mark running: %w", err)
	}
	o.publishProgress(scanID, run.progress)

	for _, target := range targets {
		for _, plugin := range plugins {
			task := worker.Task{
				ID:         fmt.Sprintf("%d-%s-%s", scanID, target, plugin.Metadata.ID),
				ScanID:     scanID,
				Target:     target,
				TemplateID: plugin.Metadata.ID,
				Ctx:        ctx,
			}
			select {
			case o.cfg.TaskQueue <- task:
			case <-ctx.Done():
				o.drop(scanID)
				return fmt.Errorf("orchestrator: scan %d stopped while queueing: %w", scanID, ctx.Err())
			}
		}
	}
	return nil
}

// Cancel stops a running scan. It reports whether the scan was live: a scan
// that already finished is not an error, but the caller may want to know.
func (o *Orchestrator) Cancel(scanID uint) bool {
	o.mu.Lock()
	run, ok := o.runs[scanID]
	delete(o.runs, scanID)
	o.mu.Unlock()
	if ok {
		run.cancel()
		o.publish(event.EventTypeFailed, scanID, map[string]string{"reason": "cancelled"})
	}
	return ok
}

// StopAll cancels every running scan, used on shutdown.
func (o *Orchestrator) StopAll() {
	o.mu.Lock()
	runs := o.runs
	o.runs = make(map[uint]*scanRun)
	o.mu.Unlock()
	for _, run := range runs {
		run.cancel()
	}
}

func (o *Orchestrator) drop(scanID uint) {
	o.mu.Lock()
	delete(o.runs, scanID)
	o.mu.Unlock()
}

// GetProgress returns the in-memory progress of a running scan.
func (o *Orchestrator) GetProgress(scanID uint) (*entity.ScanProgress, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	run, ok := o.runs[scanID]
	if !ok {
		return nil, false
	}
	progress := run.progress
	return &progress, true
}

// StartDispatchLoop consumes task results, persists findings, and advances
// progress. It is the single writer of findings: workers stay free of database
// access and of the ordering questions that come with it.
func (o *Orchestrator) StartDispatchLoop(ctx context.Context) {
	if o.cfg.ResultQueue == nil {
		return
	}
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case result, ok := <-o.cfg.ResultQueue:
				if !ok {
					return
				}
				o.persistFinding(ctx, result)
				if err := o.record(result); err != nil {
					log.Printf("dispatch: scan %d: %v", result.ScanID, err)
				}
			}
		}
	}()
}

// persistFinding stores a matched finding. Only matches are stored: writing one
// row per (target, plugin) pair would add hundreds of "nothing found" rows per
// scan and make the report unreadable.
func (o *Orchestrator) persistFinding(ctx context.Context, result worker.Result) {
	if result.Error != nil || result.Finding == nil || !result.Finding.Matched {
		return
	}
	if o.cfg.FindingRepo == nil {
		return
	}
	finding := &entity.Finding{
		ScanID:     result.ScanID,
		Target:     result.Finding.Target,
		TemplateID: result.Finding.TemplateID,
		Matched:    true,
		Severity:   result.Finding.Severity,
		Details:    result.Finding.Details,
	}
	// The scan context may already be cancelled (user cancel, budget), which
	// must not stop the write that records what was found.
	writeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if err := o.cfg.FindingRepo.CreateBatch(writeCtx, []*entity.Finding{finding}); err != nil {
		log.Printf("dispatch: scan %d: persist finding: %v", result.ScanID, err)
		return
	}
	o.publish(event.EventTypeFinding, result.ScanID, map[string]any{
		"scan_id":     finding.ScanID,
		"target":      finding.Target,
		"template_id": finding.TemplateID,
		"severity":    finding.Severity,
		"details":     finding.Details,
	})
}

// record advances progress for one finished task and closes the scan when the
// budget ran out or every task reported back.
func (o *Orchestrator) record(result worker.Result) error {
	o.mu.Lock()
	run, ok := o.runs[result.ScanID]
	if !ok {
		o.mu.Unlock()
		return nil
	}
	if result.Error != nil {
		run.progress.Failed++
	} else {
		run.progress.Completed++
	}
	if run.progress.InProgress > 0 {
		run.progress.InProgress--
	}
	allDone := run.progress.Completed+run.progress.Failed >= run.progress.TotalTasks
	truncated := result.Truncated || run.budget.Exhausted()
	if allDone || truncated {
		delete(o.runs, result.ScanID)
	}
	progress := run.progress
	cancel := run.cancel
	o.mu.Unlock()

	ctx, done := context.WithTimeout(context.WithoutCancel(o.baseCtx), 10*time.Second)
	defer done()

	if err := o.cfg.ScanRepo.UpdateProgress(ctx, result.ScanID, &progress); err != nil {
		return fmt.Errorf("update progress: %w", err)
	}
	o.publishProgress(result.ScanID, progress)
	if truncated {
		// Stop the tasks still in flight or queued: the budget is spent.
		cancel()
		if err := o.cfg.ScanRepo.SetTruncated(ctx, result.ScanID); err != nil {
			return fmt.Errorf("mark truncated: %w", err)
		}
		if err := o.cfg.ScanRepo.UpdateStatus(ctx, result.ScanID, entity.ScanStatusCompleted); err != nil {
			return err
		}
		o.publish(event.EventTypeComplete, result.ScanID, map[string]any{"truncated": true})
		return nil
	}
	if allDone {
		if err := o.cfg.ScanRepo.UpdateStatus(ctx, result.ScanID, entity.ScanStatusCompleted); err != nil {
			return err
		}
		o.publish(event.EventTypeComplete, result.ScanID, map[string]any{"truncated": false})
	}
	return nil
}

// publishProgress emits the current counters. Progress is best-effort: the bus
// drops events for a subscriber that cannot keep up, and every subscriber also
// reads the persisted progress on connect, so a gap is recoverable.
func (o *Orchestrator) publishProgress(scanID uint, progress entity.ScanProgress) {
	o.publish(event.EventTypeProgress, scanID, map[string]int{
		"completed":   progress.Completed,
		"failed":      progress.Failed,
		"total":       progress.TotalTasks,
		"in_progress": progress.InProgress,
	})
}

func (o *Orchestrator) publish(eventType event.EventType, scanID uint, payload any) {
	if o.cfg.Events == nil {
		return
	}
	o.cfg.Events.Publish(fmt.Sprint(scanID), event.Event{Type: eventType, Payload: payload})
}
