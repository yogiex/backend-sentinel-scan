package config

import (
	"fmt"
	"log"
	"strings"

	"github.com/spf13/viper"
)

type Config struct {
	Server   ServerConfig
	Database DatabaseConfig
	Worker   WorkerPoolConfig
	Template TemplateConfig
	Scanner  ScannerConfig
	RabbitMQ RabbitMQConfig
	Report   ReportConfig
	Crawler  CrawlerConfig
}

// CrawlerConfig holds the defaults for link discovery. Per-scan options may
// lower max_depth/max_pages but the orchestrator never raises them above these
// limits on its own.
type CrawlerConfig struct {
	MaxDepth       int
	MaxPages       int
	Concurrency    int
	RateLimitMS    int
	TimeoutSec     int
	MaxDurationSec int
	RespectRobots  bool
	UserAgent      string
}

type ReportConfig struct {
	OutputDir string
}

type ScannerConfig struct {
	ChromiumPath string
	TimeoutSec   int
	HeadlessSize int
}

type RabbitMQConfig struct {
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

type ServerConfig struct {
	Port int
	Host string
}

type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string
	DBName   string
	SSLMode  string
}

type WorkerPoolConfig struct {
	Size        int
	MaxRetries  int
	TaskTimeout int // seconds
	AutoScale   WorkerAutoScaleConfig
}

type WorkerAutoScaleConfig struct {
	Enabled            bool
	MinWorkers         int
	MaxWorkers         int
	ScaleUpThreshold   int
	ScaleDownThreshold int
	ScaleUpBy          int
	ScaleDownBy        int
	PollIntervalSec    int
	CooldownSec        int
}

type TemplateConfig struct {
	Dir string
}

func Load() (*Config, error) {
	v := viper.New()

	// Default values
	v.SetDefault("server.host", "localhost")
	v.SetDefault("server.port", 8080)
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "postgres")
	v.SetDefault("database.password", "postgres")
	v.SetDefault("database.dbname", "vulnscanner")
	v.SetDefault("database.sslmode", "disable")
	v.SetDefault("worker.size", 50)
	v.SetDefault("worker.maxretries", 3)
	v.SetDefault("worker.tasktimeout", 30)
	v.SetDefault("worker.autoscale.enabled", false)
	v.SetDefault("worker.autoscale.minworkers", 5)
	v.SetDefault("worker.autoscale.maxworkers", 50)
	v.SetDefault("worker.autoscale.scaleupthreshold", 10)
	v.SetDefault("worker.autoscale.scaledownthreshold", 3)
	v.SetDefault("worker.autoscale.scaleupby", 5)
	v.SetDefault("worker.autoscale.scaledownby", 5)
	v.SetDefault("worker.autoscale.pollintervalsec", 30)
	v.SetDefault("worker.autoscale.cooldownsec", 60)
	v.SetDefault("template.dir", "./templates")
	v.SetDefault("scanner.chromiumpath", "")
	v.SetDefault("scanner.timeoutsec", 30)
	v.SetDefault("scanner.headlesssize", 0)
	v.SetDefault("rabbitmq.host", "localhost")
	v.SetDefault("rabbitmq.port", 5672)
	v.SetDefault("rabbitmq.user", "admin")
	v.SetDefault("rabbitmq.password", "admin")
	v.SetDefault("rabbitmq.vhost", "/")
	v.SetDefault("rabbitmq.prefetchcount", 10)
	v.SetDefault("rabbitmq.heartbeat", 30)
	v.SetDefault("rabbitmq.connectiontimeout", 5)
	v.SetDefault("rabbitmq.maxretries", 3)
	v.SetDefault("rabbitmq.retrydelayms", 30000)
	v.SetDefault("report.outputdir", "./reports")
	v.SetDefault("crawler.maxdepth", 2)
	v.SetDefault("crawler.maxpages", 50)
	v.SetDefault("crawler.concurrency", 4)
	v.SetDefault("crawler.ratelimitms", 200)
	v.SetDefault("crawler.timeoutsec", 10)
	v.SetDefault("crawler.maxdurationsec", 60)
	v.SetDefault("crawler.respectrobots", true)
	v.SetDefault("crawler.useragent", "SentinelScan-Crawler/1.0")

	v.SetConfigName("config")
	v.SetConfigType("yaml")
	v.AddConfigPath(".")
	v.AddConfigPath("./config")

	// Configure environment variable handling
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.SetEnvPrefix("") // No prefix, so SERVER_PORT maps to server.port
	v.AutomaticEnv()

	// Explicitly bind environment variables to ensure they're picked up
	v.BindEnv("server.host", "SERVER_HOST")
	v.BindEnv("server.port", "SERVER_PORT")
	v.BindEnv("database.host", "DATABASE_HOST")
	v.BindEnv("database.port", "DATABASE_PORT")
	v.BindEnv("database.user", "DATABASE_USER")
	v.BindEnv("database.password", "DATABASE_PASSWORD")
	v.BindEnv("database.dbname", "DATABASE_DBNAME")
	v.BindEnv("database.sslmode", "DATABASE_SSLMODE")
	v.BindEnv("worker.size", "WORKER_SIZE")
	v.BindEnv("worker.maxretries", "WORKER_MAXRETRIES")
	v.BindEnv("worker.tasktimeout", "WORKER_TASKTIMEOUT")
	v.BindEnv("worker.autoscale.enabled", "WORKER_AUTOSCALE_ENABLED")
	v.BindEnv("worker.autoscale.minworkers", "WORKER_AUTOSCALE_MINWORKERS")
	v.BindEnv("worker.autoscale.maxworkers", "WORKER_AUTOSCALE_MAXWORKERS")
	v.BindEnv("worker.autoscale.scaleupthreshold", "WORKER_AUTOSCALE_SCALEUPTHRESHOLD")
	v.BindEnv("worker.autoscale.scaledownthreshold", "WORKER_AUTOSCALE_SCALEDOWNTHRESHOLD")
	v.BindEnv("worker.autoscale.scaleupby", "WORKER_AUTOSCALE_SCALEUPBY")
	v.BindEnv("worker.autoscale.scaledownby", "WORKER_AUTOSCALE_SCALEDOWNBY")
	v.BindEnv("worker.autoscale.pollintervalsec", "WORKER_AUTOSCALE_POLLINTERVALSEC")
	v.BindEnv("worker.autoscale.cooldownsec", "WORKER_AUTOSCALE_COOLDOWNSEC")
	v.BindEnv("template.dir", "TEMPLATE_DIR")
	v.BindEnv("scanner.chromiumpath", "SCANNER_CHROMIUMPATH")
	v.BindEnv("scanner.timeoutsec", "SCANNER_TIMEOUTSEC")
	v.BindEnv("scanner.headlesssize", "SCANNER_HEADLESSSIZE")
	v.BindEnv("rabbitmq.host", "RABBITMQ_HOST")
	v.BindEnv("rabbitmq.port", "RABBITMQ_PORT")
	v.BindEnv("rabbitmq.user", "RABBITMQ_USER")
	v.BindEnv("rabbitmq.password", "RABBITMQ_PASSWORD")
	v.BindEnv("rabbitmq.vhost", "RABBITMQ_VHOST")
	v.BindEnv("rabbitmq.prefetchcount", "RABBITMQ_PREFETCHCOUNT")
	v.BindEnv("rabbitmq.heartbeat", "RABBITMQ_HEARTBEAT")
	v.BindEnv("rabbitmq.connectiontimeout", "RABBITMQ_CONNECTIONTIMEOUT")
	v.BindEnv("rabbitmq.maxretries", "RABBITMQ_MAXRETRIES")
	v.BindEnv("rabbitmq.retrydelayms", "RABBITMQ_RETRYDELAYMS")
	v.BindEnv("report.outputdir", "REPORT_OUTPUTDIR")
	v.BindEnv("crawler.maxdepth", "CRAWLER_MAXDEPTH")
	v.BindEnv("crawler.maxpages", "CRAWLER_MAXPAGES")
	v.BindEnv("crawler.concurrency", "CRAWLER_CONCURRENCY")
	v.BindEnv("crawler.ratelimitms", "CRAWLER_RATELIMITMS")
	v.BindEnv("crawler.timeoutsec", "CRAWLER_TIMEOUTSEC")
	v.BindEnv("crawler.maxdurationsec", "CRAWLER_MAXDURATIONSEC")
	v.BindEnv("crawler.respectrobots", "CRAWLER_RESPECTROBOTS")
	v.BindEnv("crawler.useragent", "CRAWLER_USERAGENT")

	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return nil, fmt.Errorf("failed to read config: %w", err)
		}
		log.Println("No config file found, using defaults and environment variables")
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("failed to unmarshal config: %w", err)
	}

	return &cfg, nil
}
