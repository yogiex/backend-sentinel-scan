package worker

import "context"

type Task struct {
	ID         string
	ScanID     uint
	Target     string
	TemplateID string
	// Ctx carries the scan's context: cancelling a scan or exhausting its
	// request budget must stop the work already handed to a worker, which is
	// impossible with a pool-global context.
	Ctx     context.Context
	Session any
}

type Finding struct {
	Target     string
	TemplateID string
	Matched    bool
	Severity   string
	Details    map[string]interface{}
}

type Result struct {
	TaskID  string
	ScanID  uint
	Finding *Finding
	// Truncated reports that the scan ran out of request budget; the report is
	// partial on purpose and must say so.
	Truncated bool
	// Checked reports that at least one request reached the target. A task that
	// was never checked must not be counted as a clean "nothing found".
	Checked bool
	Error   error
}
