// main.go
//
// @title           SentinelScan API
// @version         1.0
// @description     Vulnerability scanning engine powered by Nuclei templates.
// @termsOfService  https://github.com/inkubasi-btp-cybersecurity

// @contact.name   SentinelScan Team
// @contact.email  support@sentinelscan.dev

// @license.name  MIT
// @license.url   https://opensource.org/licenses/MIT

// @host      localhost:8080
// @BasePath  /api

// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @description Type "Bearer" followed by a space and JWT token.
package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/api"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/config"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/authscan"
	dbpkg "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/database/postgres"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/messaging"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/scanner"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/worker"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/secretbox"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/ssrf"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/orchestrator"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/template"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("fatal: %v", err)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	// ── Database ────────────────────────────────────────────
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=%s sslmode=%s",
		cfg.Database.Host, cfg.Database.Port, cfg.Database.User,
		cfg.Database.Password, cfg.Database.DBName, cfg.Database.SSLMode)
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("connect database: %w", err)
	}
	if err := db.AutoMigrate(
		&dbpkg.ScanJob{}, &dbpkg.Finding{}, &dbpkg.Ticket{},
		&dbpkg.User{}, &dbpkg.AuditLog{}, &dbpkg.AuthCredential{},
		&dbpkg.AuthSessionModel{},
	); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}

	// ── Repositories ────────────────────────────────────────
	scanRepo := dbpkg.NewScanRepository(db)
	findingRepo := dbpkg.NewFindingRepository(db)
	ticketRepo := dbpkg.NewTicketRepository(db)
	userRepo := dbpkg.NewUserRepository(db)
	credKey := env("CRED_ENC_KEY", os.Getenv("JWT_SECRET"))
	if credKey == "" {
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		credKey = base64.StdEncoding.EncodeToString(buf)
		log.Printf("CRED_ENC_KEY not set: stored credentials use an ephemeral key")
	}
	credBox, err := secretbox.New(secretbox.Derive(credKey))
	if err != nil {
		return fmt.Errorf("credential cipher: %w", err)
	}
	credRepo := dbpkg.NewAuthCredentialRepository(db, credBox)
	auditRepo := dbpkg.NewAuditLogRepository(db)
	_ = auditRepo // reserved for the audit trail

	// ── Security primitives ─────────────────────────────────
	guard := ssrf.New(
		splitCSV(env("SSRF_ALLOWED_PORTS", "80,443,8080,8443")),
		envBool("SSRF_ALLOW_PRIVATE", false),
	)

	authMW, err := newAuthMiddleware()
	if err != nil {
		return err
	}

	// ── Scanning infrastructure ─────────────────────────────
	templateLoader, err := template.NewLoader(cfg.Template.Dir)
	if err != nil {
		return fmt.Errorf("template loader: %w", err)
	}
	eventBus := event.NewBus()

	engineCfg := scanner.EngineConfig{
		ChromiumPath: cfg.Scanner.ChromiumPath,
		TimeoutSec:   cfg.Scanner.TimeoutSec,
	}
	httpEngine := scanner.NewHTTPEngine(engineCfg)
	var headlessEngine *scanner.HeadlessEngine
	if cfg.Scanner.HeadlessSize > 0 {
		headlessEngine = scanner.NewHeadlessEngine(engineCfg)
	}

	sessionManager := authscan.NewSessionManager()
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	go sessionManager.Sweep(ctx)

	useRabbitMQ := envBool("RABBITMQ_ENABLED", false)
	var mqConn *messaging.Connection
	if useRabbitMQ {
		mqConfig := messaging.Config{
			Host: cfg.RabbitMQ.Host, Port: cfg.RabbitMQ.Port,
			User: cfg.RabbitMQ.User, Password: cfg.RabbitMQ.Password,
			VHost: cfg.RabbitMQ.VHost, PrefetchCount: cfg.RabbitMQ.PrefetchCount,
			Heartbeat: cfg.RabbitMQ.Heartbeat, ConnectionTimeout: cfg.RabbitMQ.ConnectionTimeout,
			MaxRetries: cfg.RabbitMQ.MaxRetries, RetryDelayMS: cfg.RabbitMQ.RetryDelayMS,
		}
		mqConn = messaging.NewConnection(mqConfig)
		if err := mqConn.Connect(); err != nil {
			log.Printf("rabbitmq unavailable (%v), using in-memory queues", err)
			useRabbitMQ = false
			mqConn = nil
		} else {
			defer mqConn.Close()
		}
	}

	orchCfg := orchestrator.Config{
		DB:             db,
		TemplateLoader: templateLoader,
		EventBus:       eventBus,
		ScanRepo:       scanRepo,
		FindingRepo:    findingRepo,
	}
	if mqConn != nil {
		orchCfg.TaskPublisher = messaging.NewTaskPublisher(mqConn)
		orchCfg.MessagingConfig = &orchestrator.ConfigMessaging{RabbitMQ: messaging.Config{}}
	} else {
		taskQueue := make(chan worker.Task, 1000)
		resultQueue := make(chan worker.Result, 1000)
		orchCfg.TaskQueue = taskQueue
		orchCfg.ResultQueue = resultQueue
		pool := worker.NewPool(ctx, cfg.Worker.Size, taskQueue, resultQueue, eventBus)
		pool.WithEngines(httpEngine, headlessEngine).WithSessionManager(sessionManager)
		pool.Start()
		defer pool.Stop()
	}

	orch := orchestrator.New(orchCfg)
	orch.StartDispatchLoop(ctx)

	// ── Application services ────────────────────────────────
	scanService := application.NewScanService(scanRepo, findingRepo, credRepo, guard, orchestratorDispatcher{orch: orch})
	ticketService := application.NewTicketService(ticketRepo, findingRepo, scanRepo)
	authService := application.NewAuthService(userRepo)
	credService := application.NewAuthCredentialService(credRepo, guard)
	reportService := application.NewReportService(scanRepo, findingRepo)

	// ── Bootstrap admin ─────────────────────────────────────
	adminUser := env("ADMIN_USERNAME", "admin")
	adminPass := env("ADMIN_PASSWORD", "")
	if adminPass == "" {
		log.Printf("ADMIN_PASSWORD not set: skipping admin bootstrap")
	} else {
		if err := application.EnsureAdmin(ctx, userRepo,
			adminUser, env("ADMIN_EMAIL", "admin@sentinel.local"), adminPass, entity.RoleAdmin); err != nil {
			return fmt.Errorf("bootstrap admin: %w", err)
		}
	}

	// ── HTTP ────────────────────────────────────────────────
	handler := api.NewHandler(scanService, ticketService, authService, credService, reportService, guard).
		WithAuthIssuer(authMW)

	router := api.NewRouter(handler, api.RouterDeps{
		Auth:             authMW,
		AllowedOrigins:   splitCSV(env("CORS_ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173")),
		AllowCredentials: envBool("CORS_ALLOW_CREDENTIALS", false),
	})

	addr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:              addr,
		Handler:           router,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	serverErr := make(chan error, 1)
	go func() {
		log.Printf("SentinelScan listening on %s (rabbitmq=%v)", addr, useRabbitMQ)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
		}
	}()

	select {
	case err := <-serverErr:
		return err
	case <-ctx.Done():
		log.Println("shutting down")
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer shutdownCancel()
		return srv.Shutdown(shutdownCtx)
	}
}

// orchestratorDispatcher adapts the orchestrator to application.ScanDispatcher.
type orchestratorDispatcher struct{ orch *orchestrator.Orchestrator }

func (d orchestratorDispatcher) StartScan(scanID uint, targets []string, selectors string) error {
	if d.orch == nil {
		return nil
	}
	return d.orch.StartScan(scanID, targets, selectors)
}

func newAuthMiddleware() (*middleware.Auth, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		// Dev convenience: a random secret per boot. Tokens do not survive a
		// restart, which is acceptable locally but never in production.
		buf := make([]byte, 32)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		secret = base64.StdEncoding.EncodeToString(buf)
		log.Printf("JWT_SECRET not set: generated an ephemeral signing key")
	}
	ttl := time.Duration(envInt("JWT_TTL_MINUTES", 15)) * time.Minute
	return middleware.NewAuth(secret, ttl)
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.ParseBool(raw)
	if err != nil {
		return fallback
	}
	return v
}

func envInt(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	return v
}

func splitCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
