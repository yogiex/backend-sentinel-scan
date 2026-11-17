package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
)

type staticCatalog struct{ items []application.TemplateSummary }

func (s staticCatalog) ResolveIDs(string) ([]string, error) { return nil, nil }
func (s staticCatalog) List() []application.TemplateSummary { return s.items }
func (s staticCatalog) Get(id string) (application.TemplateSummary, bool) {
	for _, item := range s.items {
		if item.ID == id {
			return item, true
		}
	}
	return application.TemplateSummary{}, false
}

func templatesHandler() *Handler {
	catalog := staticCatalog{items: []application.TemplateSummary{
		{ID: "xss-reflected", Name: "Reflected XSS", Severity: "high", Engine: "http", Tags: []string{"xss"}, PayloadCount: 4, Matchers: []string{"keyword", "regex"}},
		{ID: "sql-injection-error", Name: "SQL Injection (error based)", Severity: "critical", Engine: "http", Tags: []string{"sqli"}, PayloadCount: 6, Matchers: []string{"error_based"}},
	}}
	svc := application.NewScanService(nil, nil, nil, nil, nil).WithCatalog(catalog)
	return NewHandler(svc, nil, nil, nil, nil, nil)
}

func templateRequest(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	ctx := middleware.WithActor(r.Context(), policy.NewActor(1, entity.RoleViewer))
	return r.WithContext(ctx)
}

func TestListTemplatesHonoursFilterAndShape(t *testing.T) {
	h := templatesHandler()

	rec := httptest.NewRecorder()
	h.ListTemplates(rec, templateRequest("/api/templates?severity=critical"))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var body struct {
		Items []application.TemplateSummary `json:"items"`
		Total int                           `json:"total"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body.Total != 1 || len(body.Items) != 1 || body.Items[0].ID != "sql-injection-error" {
		t.Fatalf("unexpected body: %s", rec.Body.String())
	}
	if body.Items[0].PayloadCount != 6 {
		t.Fatalf("payload_count must describe the plugin, got %d", body.Items[0].PayloadCount)
	}
}

func TestGetTemplateByID(t *testing.T) {
	h := templatesHandler()

	rec := httptest.NewRecorder()
	r := templateRequest("/api/templates/xss-reflected")
	r = mux.SetURLVars(r, map[string]string{"id": "xss-reflected"})
	h.GetTemplate(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
	}
	var item application.TemplateSummary
	if err := json.Unmarshal(rec.Body.Bytes(), &item); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if item.ID != "xss-reflected" || item.Engine != "http" {
		t.Fatalf("unexpected template: %+v", item)
	}
}

func TestGetTemplateUnknownIs404(t *testing.T) {
	h := templatesHandler()

	rec := httptest.NewRecorder()
	r := templateRequest("/api/templates/nope")
	r = mux.SetURLVars(r, map[string]string{"id": "nope"})
	h.GetTemplate(rec, r)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d (%s)", rec.Code, rec.Body.String())
	}
}
