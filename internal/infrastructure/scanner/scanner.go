package scanner

import (
	"context"
	"errors"
	"fmt"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/detector"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/egress"
)

type EngineType string

const (
	EngineHTTP     EngineType = "http"
	EngineHeadless EngineType = "headless"
)

// Errors returned by the engines. Callers map them to failed tasks; they are
// never reported as "no finding", because that would hide a broken scan.
var (
	ErrEngineNotConfigured    = errors.New("scanner: engine is not configured")
	ErrUnknownTemplate        = errors.New("scanner: unknown template")
	ErrHeadlessNotImplemented = errors.New("scanner: headless engine is not implemented")
	// ErrNoRequestCompleted means the target never produced a response, so the
	// plugin was not actually checked. It is an error, not a clean result.
	ErrNoRequestCompleted = errors.New("scanner: no request produced a response")
)

type EngineConfig struct {
	ChromiumPath string
	TimeoutSec   int
}

type Task struct {
	ScanID     uint
	Target     string
	TemplateID string
	Engine     EngineType
	Session    interface{}
}

type Result struct {
	Finding *Finding
	Error   error
	// Truncated reports that the scan's request budget was exhausted while this
	// task was running, so the report is partial by design.
	Truncated bool
	// Checked reports that at least one request reached the target. A task that
	// was never checked cannot be counted as "no vulnerability found".
	Checked bool
}

type Finding struct {
	Target     string
	TemplateID string
	Matched    bool
	Severity   string
	Details    map[string]interface{}
}

// HTTPEngine executes exactly one plugin per task.
//
// One plugin per task is not a detail: the orchestrator computes progress as
// targets x plugins, so an engine that ran every plugin on every task would
// issue N times the expected traffic while reporting N times the progress.
type HTTPEngine struct {
	config   EngineConfig
	detector *detector.Detector
}

func NewHTTPEngine(cfg EngineConfig, det *detector.Detector) *HTTPEngine {
	return &HTTPEngine{config: cfg, detector: det}
}

func (e *HTTPEngine) Execute(ctx context.Context, task Task) *Result {
	if e.detector == nil || e.detector.Registry() == nil {
		return &Result{Error: ErrEngineNotConfigured}
	}

	plugin := e.detector.Registry().Get(task.TemplateID)
	if plugin == nil {
		return &Result{Error: fmt.Errorf("%w: %q", ErrUnknownTemplate, task.TemplateID)}
	}

	checked := e.detector.CheckWithPlugins(ctx, task.Target, []*detector.Plugin{plugin})

	result := &Result{
		Finding: &Finding{
			Target:     task.Target,
			TemplateID: plugin.Metadata.ID,
			Matched:    len(checked.Matches) > 0,
			Severity:   string(plugin.Metadata.Severity),
		},
		Truncated: budgetExhausted(ctx),
		Checked:   checked.Stats.Checked(),
	}
	if len(checked.Matches) > 0 {
		result.Finding.Details = buildDetails(plugin, checked.Matches[0])
	}
	// Every request failed: the plugin was never really checked. Reporting that
	// as a clean task is how a broken scan becomes a false "no findings" report.
	if !result.Checked && checked.Stats.Failed > 0 {
		result.Error = fmt.Errorf("%w after %d attempt(s): %v",
			ErrNoRequestCompleted, checked.Stats.Attempted, checked.Stats.LastError)
	}
	return result
}

// budgetExhausted reports whether this scan ran out of request budget.
func budgetExhausted(ctx context.Context) bool {
	b := egress.FromContext(ctx)
	return b != nil && b.Exhausted()
}

// buildDetails produces the JSONB payload stored with a finding.
//
// The response body is deliberately absent: it belongs to the target, may be
// large, and may contain personal data. Only the extracted evidence survives.
func buildDetails(plugin *detector.Plugin, res detector.PluginResult) map[string]interface{} {
	matches := make([]map[string]interface{}, 0, len(res.Matches))
	for _, m := range res.Matches {
		evidence := m.Evidence
		if len(evidence) > maxEvidenceBytes {
			evidence = evidence[:maxEvidenceBytes]
		}
		matches = append(matches, map[string]interface{}{
			"type":     string(m.Type),
			"pattern":  m.Pattern,
			"payload":  m.Payload,
			"evidence": evidence,
		})
	}

	details := map[string]interface{}{
		"plugin_id":   plugin.Metadata.ID,
		"plugin_name": plugin.Metadata.Name,
		"severity":    string(plugin.Metadata.Severity),
		"tags":        plugin.Metadata.Tags,
		"response": map[string]interface{}{
			"status_code":    res.StatusCode,
			"body_truncated": res.ResponseTruncated,
			"duration_ms":    res.Duration.Milliseconds(),
		},
		"matches": matches,
	}
	if plugin.Metadata.Reference != "" {
		details["reference"] = plugin.Metadata.Reference
	}
	return details
}

// maxEvidenceBytes keeps one finding's details far below the 4 KB budget; the
// matcher already trims evidence, this is the second line of defence.
const maxEvidenceBytes = 1024

// HeadlessEngine is a placeholder. It returns an error rather than an empty
// result so a headless scan cannot be mistaken for a clean one.
type HeadlessEngine struct {
	config EngineConfig
}

func NewHeadlessEngine(cfg EngineConfig) *HeadlessEngine {
	return &HeadlessEngine{config: cfg}
}

func (e *HeadlessEngine) Execute(ctx context.Context, task Task) *Result {
	return &Result{Error: ErrHeadlessNotImplemented}
}
