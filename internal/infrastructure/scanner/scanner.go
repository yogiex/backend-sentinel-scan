package scanner

import (
	"context"
	"time"
)

type EngineType string

const (
	EngineHTTP    EngineType = "http"
	EngineHeadless EngineType = "headless"
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
}

type Finding struct {
	Target     string
	TemplateID string
	Matched    bool
	Severity   string
	Details    map[string]interface{}
}

type HTTPEngine struct {
	config EngineConfig
	client *httpClient
}

type httpClient struct {
	timeout time.Duration
}

func NewHTTPEngine(cfg EngineConfig) *HTTPEngine {
	return &HTTPEngine{
		config: cfg,
		client: &httpClient{timeout: time.Duration(cfg.TimeoutSec) * time.Second},
	}
}

func (e *HTTPEngine) Execute(ctx context.Context, task Task) *Result {
	return &Result{
		Finding: &Finding{
			Target:     task.Target,
			TemplateID: task.TemplateID,
			Matched:    false,
			Severity:   "info",
		},
	}
}

type HeadlessEngine struct {
	config EngineConfig
}

func NewHeadlessEngine(cfg EngineConfig) *HeadlessEngine {
	return &HeadlessEngine{config: cfg}
}

func (e *HeadlessEngine) Execute(ctx context.Context, task Task) *Result {
	return &Result{
		Finding: &Finding{
			Target:     task.Target,
			TemplateID: task.TemplateID,
			Matched:    false,
			Severity:   "info",
		},
	}
}
