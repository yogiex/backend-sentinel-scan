package application

import (
	"context"
	"errors"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	apperr "github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/pkg/errors"
)

// fakeCatalog is a minimal TemplateCatalog for the filter/serving logic.
type fakeCatalog struct {
	items []TemplateSummary
}

func (f fakeCatalog) ResolveIDs(string) ([]string, error) { return nil, nil }
func (f fakeCatalog) List() []TemplateSummary             { return f.items }
func (f fakeCatalog) Get(id string) (TemplateSummary, bool) {
	for _, item := range f.items {
		if item.ID == id {
			return item, true
		}
	}
	return TemplateSummary{}, false
}

func testCatalog() fakeCatalog {
	return fakeCatalog{items: []TemplateSummary{
		{ID: "xss-reflected", Name: "Reflected XSS", Description: "Reflects a script tag", Severity: "high", Tags: []string{"xss", "injection"}},
		{ID: "sql-injection-error", Name: "SQL Injection (error based)", Description: "DBMS error patterns", Severity: "critical", Tags: []string{"sqli", "injection"}},
		{ID: "open-redirect", Name: "Open Redirect", Description: "Location header to another host", Severity: "medium", Tags: []string{"redirect"}},
	}}
}

func viewerActor() policy.Actor {
	return policy.NewActor(7, entity.RoleViewer)
}

func TestListTemplatesFiltersBySeverity(t *testing.T) {
	svc := NewScanService(nil, nil, nil, nil, nil).WithCatalog(testCatalog())

	items, err := svc.ListTemplates(context.Background(), viewerActor(), TemplateFilter{Severity: []string{"CRITICAL"}})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(items) != 1 || items[0].ID != "sql-injection-error" {
		t.Fatalf("expected only sql-injection-error, got %+v", items)
	}
}

func TestListTemplatesFiltersByTagAndSearch(t *testing.T) {
	svc := NewScanService(nil, nil, nil, nil, nil).WithCatalog(testCatalog())

	items, err := svc.ListTemplates(context.Background(), viewerActor(), TemplateFilter{Tag: "injection"})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(items) != 2 {
		t.Fatalf("expected 2 injection templates, got %d", len(items))
	}

	items, err = svc.ListTemplates(context.Background(), viewerActor(), TemplateFilter{Search: "location header"})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if len(items) != 1 || items[0].ID != "open-redirect" {
		t.Fatalf("expected open-redirect from description search, got %+v", items)
	}
}

func TestListTemplatesWithoutCatalogIsEmptyNotNil(t *testing.T) {
	svc := NewScanService(nil, nil, nil, nil, nil)
	items, err := svc.ListTemplates(context.Background(), viewerActor(), TemplateFilter{})
	if err != nil {
		t.Fatalf("ListTemplates: %v", err)
	}
	if items == nil {
		t.Fatal("expected an empty slice so the API serialises [], not null")
	}
	if len(items) != 0 {
		t.Fatalf("expected no items, got %d", len(items))
	}
}

func TestGetTemplateUnknownIsNotFound(t *testing.T) {
	svc := NewScanService(nil, nil, nil, nil, nil).WithCatalog(testCatalog())

	if _, err := svc.GetTemplate(context.Background(), viewerActor(), "does-not-exist"); !errors.Is(err, apperr.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestGetTemplateRequiresScanRead(t *testing.T) {
	svc := NewScanService(nil, nil, nil, nil, nil).WithCatalog(testCatalog())

	unknown := policy.NewActor(9, entity.Role("nobody"))
	if _, err := svc.GetTemplate(context.Background(), unknown, "xss-reflected"); !errors.Is(err, apperr.ErrForbidden) {
		t.Fatalf("expected ErrForbidden for an unknown role, got %v", err)
	}
}
