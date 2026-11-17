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
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/crawler"
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

	// CrawlDefaults is the base crawl configuration. Per-scan options may lower
	// depth and page caps; the SSRF client and the scope rule come from here.
	CrawlDefaults crawler.CrawlConfig
	// CrawlClient is the hardened client used for discovery. It shares the
	// per-scan budget with the detector, so crawler requests count too.
	CrawlClient crawler.HTTPClient
	// CrawlTimeout bounds the discovery phase of one scan.
	CrawlTimeout time.Duration
	// ValidateTarget re-checks every discovered URL against the SSRF policy.
	// Discovered links are attacker-controlled input, so an unvalidated URL must
	// never be scanned. Nil means "no policy configured" and is for tests only.
	ValidateTarget func(ctx context.Context, raw string) (string, error)
}

const (
	phaseCrawling = "crawling"
	phaseScanning = "scanning"
)

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
//
// When the scan enables crawling, discovery runs in its own goroutine: a real
// site takes seconds to minutes to crawl and must not hold the 202 response. The
// scan context, and therefore the budget, is created here — before discovery —
// so crawl requests are counted against the same allowance as scan requests.
func (o *Orchestrator) StartScan(scanID uint, targets []string, templateSelectors string, crawl *entity.CrawlOptions) error {
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
	if len(targets) == 0 {
		return errors.New("orchestrator: nothing to scan")
	}
	if o.cfg.TaskQueue == nil {
		return errors.New("orchestrator: no task queue configured")
	}

	crawlPages := 0
	if crawl != nil && crawl.Enabled {
		crawlPages = crawl.MaxPages
		if crawlPages <= 0 {
			crawlPages = o.cfg.CrawlDefaults.Link.MaxPages
		}
		if crawlPages <= 0 {
			crawlPages = 50
		}
	}

	budgetMax := o.cfg.MaxRequestsPerScan
	if budgetMax <= 0 {
		perTarget := o.cfg.RequestsPerTarget
		if perTarget <= 0 {
			perTarget = 60
		}
		budgetMax = int64(len(targets)+crawlPages) * perTarget
	}

	ctx, cancel := context.WithCancel(o.baseCtx)
	budget := egress.NewBudget(budgetMax).WithCancel(cancel)
	ctx = egress.WithBudget(ctx, budget)

	run := &scanRun{ctx: ctx, cancel: cancel, budget: budget}
	if crawlPages > 0 {
		// The task count is only known after discovery, so the crawl phase
		// reports progress without a denominator.
		run.progress = entity.ScanProgress{Phase: phaseCrawling}
	} else {
		total := len(targets) * len(plugins)
		run.progress = entity.ScanProgress{TotalTasks: total, InProgress: total, Phase: phaseScanning}
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

	if crawlPages > 0 {
		go o.crawlThenQueue(scanID, run, targets, plugins, crawl)
		return nil
	}
	return o.queueTasks(scanID, run, targets, plugins)
}

// queueTasks turns a final target list into worker tasks.
func (o *Orchestrator) queueTasks(scanID uint, run *scanRun, targets []string, plugins []*detector.Plugin) error {
	for _, target := range targets {
		for _, plugin := range plugins {
			task := worker.Task{
				ID:         fmt.Sprintf("%d-%s-%s", scanID, target, plugin.Metadata.ID),
				ScanID:     scanID,
				Target:     target,
				TemplateID: plugin.Metadata.ID,
				Ctx:        run.ctx,
			}
			select {
			case o.cfg.TaskQueue <- task:
			case <-run.ctx.Done():
				o.drop(scanID)
				return fmt.Errorf("orchestrator: scan %d stopped while queueing: %w", scanID, run.ctx.Err())
			}
		}
	}
	return nil
}

// crawlThenQueue runs discovery, rewrites the progress counters with the real
// task count, and queues the scan. A crawl failure degrades to the submitted
// targets instead of losing the scan.
func (o *Orchestrator) crawlThenQueue(scanID uint, run *scanRun, targets []string, plugins []*detector.Plugin, crawl *entity.CrawlOptions) {
	final, truncated, err := o.discover(run.ctx, targets, crawl)
	if err != nil {
		log.Printf("crawl: scan %d: %v (scanning the submitted targets only)", scanID, err)
	}
	if run.ctx.Err() != nil {
		// Cancelled mid-crawl: the Cancel path already updated the scan.
		return
	}
	if truncated {
		o.markTruncated(scanID)
	}

	total := len(final) * len(plugins)
	o.mu.Lock()
	run.progress = entity.ScanProgress{TotalTasks: total, InProgress: total, Phase: phaseScanning}
	progress := run.progress
	o.mu.Unlock()

	writeCtx, done := context.WithTimeout(context.WithoutCancel(o.baseCtx), 10*time.Second)
	defer done()
	if err := o.cfg.ScanRepo.UpdateProgress(writeCtx, scanID, &progress); err != nil {
		log.Printf("crawl: scan %d: record progress: %v", scanID, err)
	}
	o.publishProgress(scanID, progress)

	if total == 0 {
		if err := o.cfg.ScanRepo.UpdateStatus(writeCtx, scanID, entity.ScanStatusCompleted); err != nil {
			log.Printf("crawl: scan %d: complete: %v", scanID, err)
		}
		o.publish(event.EventTypeComplete, scanID, map[string]any{"truncated": truncated})
		return
	}
	if err := o.queueTasks(scanID, run, final, plugins); err != nil {
		log.Printf("crawl: scan %d: queue tasks: %v", scanID, err)
	}
}

// discover crawls the seeds and returns the merged target list.
func (o *Orchestrator) discover(ctx context.Context, seeds []string, crawl *entity.CrawlOptions) ([]string, bool, error) {
	cfg := o.crawlConfig(crawl)
	if o.cfg.CrawlTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, o.cfg.CrawlTimeout)
		defer cancel()
	}
	result, err := crawler.New(cfg).Run(ctx, seeds)
	if err != nil {
		return seeds, false, err
	}
	return mergeTargets(seeds, o.validateDiscovered(ctx, result.DiscoveredURLs)), result.Truncated, nil
}

// validateDiscovered drops every discovered URL the SSRF policy rejects.
func (o *Orchestrator) validateDiscovered(ctx context.Context, discovered []crawler.DiscoveredURL) []string {
	out := make([]string, 0, len(discovered))
	for _, d := range discovered {
		raw := d.URL
		if o.cfg.ValidateTarget != nil {
			validated, err := o.cfg.ValidateTarget(ctx, raw)
			if err != nil {
				continue
			}
			raw = validated
		}
		out = append(out, raw)
	}
	return out
}

func (o *Orchestrator) crawlConfig(crawl *entity.CrawlOptions) crawler.CrawlConfig {
	cfg := o.cfg.CrawlDefaults
	if cfg.Client == nil {
		cfg.Client = o.cfg.CrawlClient
	}
	link := cfg.Link
	link.Enabled = true
	if crawl != nil {
		if crawl.MaxDepth > 0 {
			link.MaxDepth = crawl.MaxDepth
		}
		if crawl.MaxPages > 0 {
			link.MaxPages = crawl.MaxPages
		}
		link.RespectRobots = crawl.RespectRobots
	}
	if link.MaxDepth <= 0 {
		link.MaxDepth = 2
	}
	if link.MaxPages <= 0 {
		link.MaxPages = 50
	}
	if link.Concurrency <= 0 {
		link.Concurrency = 4
	}
	if link.Scope == crawler.ScopeUnrestricted {
		// Never let a caller widen the crawl beyond the target's own domain.
		link.Scope = crawler.ScopeSameDomain
	}
	cfg.Link = link
	cfg.BruteForce.Enabled = false
	return cfg
}

func (o *Orchestrator) markTruncated(scanID uint) {
	ctx, done := context.WithTimeout(context.WithoutCancel(o.baseCtx), 10*time.Second)
	defer done()
	if err := o.cfg.ScanRepo.SetTruncated(ctx, scanID); err != nil {
		log.Printf("crawl: scan %d: mark truncated: %v", scanID, err)
	}
}

// mergeTargets keeps the submitted targets first and appends discovered URLs,
// removing duplicates.
func mergeTargets(seeds, discovered []string) []string {
	seen := make(map[string]struct{}, len(seeds)+len(discovered))
	out := make([]string, 0, len(seeds)+len(discovered))
	for _, list := range [][]string{seeds, discovered} {
		for _, target := range list {
			if target == "" {
				continue
			}
			if _, dup := seen[target]; dup {
				continue
			}
			seen[target] = struct{}{}
			out = append(out, target)
		}
	}
	return out
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
	o.publish(event.EventTypeProgress, scanID, map[string]any{
		"completed":   progress.Completed,
		"failed":      progress.Failed,
		"total":       progress.TotalTasks,
		"in_progress": progress.InProgress,
		"phase":       progress.Phase,
	})
}

func (o *Orchestrator) publish(eventType event.EventType, scanID uint, payload any) {
	if o.cfg.Events == nil {
		return
	}
	o.cfg.Events.Publish(fmt.Sprint(scanID), event.Event{Type: eventType, Payload: payload})
}
