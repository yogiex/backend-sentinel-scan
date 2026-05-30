package messaging

import (
	"context"
	"time"
)

const (
	QueueTasksHTTP     = "tasks.http"
	QueueTasksHeadless = "tasks.headless"

	TaskStatusSuccess = "success"
	TaskStatusRetry   = "retry"
	TaskStatusFailed  = "failed"
)

type Config struct {
	Host              string
	Port              int
	User              string
	Password          string
	VHost             string
	PrefetchCount     int
	Heartbeat         int
	ConnectionTimeout int
	MaxRetries        int
	RetryDelayMS      int
}

func DefaultConfig() Config {
	return Config{
		Host:              "localhost",
		Port:              5672,
		User:              "admin",
		Password:          "admin",
		VHost:             "/",
		PrefetchCount:     10,
		Heartbeat:         30,
		ConnectionTimeout: 5,
		MaxRetries:        3,
		RetryDelayMS:      30000,
	}
}

type Connection struct {
	config Config
}

func NewConnection(cfg Config) *Connection {
	return &Connection{config: cfg}
}

func (c *Connection) Connect() error {
	return nil
}

func (c *Connection) Close() error {
	return nil
}

type TaskMessage struct {
	ScanID     uint
	Target     string
	TemplateID string
	Engine     string
	RetryCount int
}

type TaskResult struct {
	Status  string
	Finding *FindingPayload
	Error   error
}

type FindingPayload struct {
	Target     string                 `json:"target"`
	TemplateID string                 `json:"template_id"`
	Matched    bool                   `json:"matched"`
	Severity   string                 `json:"severity"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

type TaskHandler interface {
	HandleTask(ctx context.Context, msg TaskMessage) TaskResult
}

type TaskPublisher struct{}

func NewTaskPublisher(conn *Connection) *TaskPublisher {
	return &TaskPublisher{}
}

func (p *TaskPublisher) PublishHTTP(ctx context.Context, scanID uint, target, templateID string) error {
	return nil
}

func (p *TaskPublisher) PublishHeadless(ctx context.Context, scanID uint, target, templateID string) error {
	return nil
}

type EventPublisher struct{}

func NewEventPublisher(conn *Connection) *EventPublisher {
	return &EventPublisher{}
}

func (p *EventPublisher) PublishProgress(ctx context.Context, scanID uint, completed, total int) {}

func (p *EventPublisher) PublishFinding(ctx context.Context, scanID uint, finding *FindingPayload) {}

type EventConsumer struct{}

func NewEventConsumer(conn *Connection) *EventConsumer {
	return &EventConsumer{}
}

type TaskConsumer struct{}

func NewTaskConsumer(conn *Connection, handler TaskHandler, publisher *TaskPublisher, cfg Config, queueName string) *TaskConsumer {
	return &TaskConsumer{}
}

func (c *TaskConsumer) Consume(ctx context.Context, workerID int) error {
	return nil
}

type AutoScaleConfig struct {
	Enabled            bool
	MinWorkers         int
	MaxWorkers         int
	ScaleUpThreshold   int
	ScaleDownThreshold int
	ScaleUpBy          int
	ScaleDownBy        int
	PollInterval       time.Duration
	Cooldown           time.Duration
}
