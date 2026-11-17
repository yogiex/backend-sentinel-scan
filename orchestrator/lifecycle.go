package orchestrator

import (
	"context"
	"errors"
	"log"
	"time"

	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// heartbeatTimeout bounds the two database calls of one maintenance tick. A slow
// database must not pile up ticks.
const heartbeatTimeout = 5 * time.Second

// ReconcileInterrupted fails every scan that is still pending or running. It is
// meant for start-up, before any scan can be live: with the orchestrator living
// in this process, a row left in a non-terminal state belongs to a process that
// is gone.
//
// The single-writer assumption is deliberate and documented in
// docs/BACKEND-DEV.md: dispatching through a broker (RabbitMQ) is not
// implemented, so a second replica could not run the scan anyway.
func (o *Orchestrator) ReconcileInterrupted(ctx context.Context, reason string) (int64, error) {
	if o.cfg.ScanRepo == nil {
		return 0, nil
	}
	return o.cfg.ScanRepo.MarkInterrupted(ctx, reason, time.Time{})
}

// StartMaintenance keeps the heartbeat alive for the scans this process owns and
// fails scans whose owner stopped beating. Without it, a process that dies
// without running Shutdown (SIGKILL, OOM, panic) leaves its scans "running"
// until the next restart.
func (o *Orchestrator) StartMaintenance(ctx context.Context) {
	if o.cfg.ScanRepo == nil {
		return
	}
	interval := o.heartbeatInterval()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				o.maintenanceTick(ctx, interval)
			}
		}
	}()
}

func (o *Orchestrator) maintenanceTick(ctx context.Context, interval time.Duration) {
	o.mu.Lock()
	ids := make([]uint, 0, len(o.runs))
	for id := range o.runs {
		ids = append(ids, id)
	}
	o.mu.Unlock()

	// The tick must finish even if the caller's context is already cancelled:
	// that is exactly when the last heartbeat matters.
	tickCtx, done := context.WithTimeout(context.WithoutCancel(ctx), heartbeatTimeout)
	defer done()

	for _, id := range ids {
		if err := o.cfg.ScanRepo.TouchHeartbeat(tickCtx, id); err != nil && !errors.Is(err, apperr.ErrNotFound) {
			log.Printf("heartbeat: scan %d: %v", id, err)
		}
	}

	staleBefore := time.Now().Add(-interval * heartbeatGrace)
	marked, err := o.cfg.ScanRepo.MarkInterrupted(tickCtx, ReasonHeartbeatLost, staleBefore)
	if err != nil {
		log.Printf("heartbeat: reconcile: %v", err)
		return
	}
	if marked > 0 {
		log.Printf("heartbeat: marked %d scan(s) failed: no heartbeat for %s", marked, interval*heartbeatGrace)
	}
}

// Shutdown stops every running scan and records why. It is the clean-exit
// counterpart of ReconcileInterrupted: a scan stopped here says
// "interrupted_by_shutdown" instead of leaving an unexplained failure.
func (o *Orchestrator) Shutdown(ctx context.Context) error {
	o.StopAll()
	if o.cfg.ScanRepo == nil {
		return nil
	}
	if _, err := o.cfg.ScanRepo.MarkInterrupted(ctx, ReasonInterruptedShutdown, time.Time{}); err != nil {
		return err
	}
	return nil
}

func (o *Orchestrator) heartbeatInterval() time.Duration {
	if o.cfg.HeartbeatInterval > 0 {
		return o.cfg.HeartbeatInterval
	}
	return defaultHeartbeatInterval
}
