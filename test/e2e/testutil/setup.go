//go:build e2e

package testutil

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/api"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/event"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/database/postgres"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/report"
	"gorm.io/gorm"
)

func NewTestServer(t *testing.T) *httptest.Server {
	t.Helper()

	var db *gorm.DB = nil

	scanRepo := postgres.NewScanRepository(db)
	findingRepo := postgres.NewFindingRepository(db)
	ticketRepo := postgres.NewTicketRepository(db)
	userRepo := postgres.NewUserRepository(db)
	authCredRepo := postgres.NewAuthCredentialRepository(db)

	scanService := application.NewScanService(scanRepo, findingRepo)
	ticketService := application.NewTicketService(ticketRepo, findingRepo, userRepo)
	authService := application.NewAuthService(userRepo)
	authCredService := application.NewAuthCredentialService(authCredRepo)

	handler := api.NewHandler(scanService, ticketService, authService, authCredService, nil)

	reportSvc := application.NewReportService(scanRepo, findingRepo)
	pdfGen := report.NewPDFGenerator("")
	rg := report.NewGenerator(reportSvc, pdfGen, "")
	handler.WithReportService(reportSvc, rg)

	eb := event.NewBus()
	router := api.NewRouter(handler, eb)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func MustGET(t *testing.T, server *httptest.Server, path string) *http.Response {
	t.Helper()
	resp, err := http.Get(server.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	return resp
}

func MustPOST(t *testing.T, server *httptest.Server, path, body string) *http.Response {
	t.Helper()
	resp, err := http.Post(server.URL+path, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	return resp
}

func MustDecode(t *testing.T, resp *http.Response, v interface{}) {
	t.Helper()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("Failed to decode JSON: %v — body: %s", err, string(data))
	}
}
