package orchestrator

import (
	"context"
	"errors"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/infrastructure/crawler"
)

// The scope filter is repeated at the merge point on purpose: it is the last
// place where a discovered URL can be stopped before it becomes a scan target.
// A provider bug must not be able to widen the scan to a third-party host.
func TestValidateDiscovered_DropsOutOfScopeURL(t *testing.T) {
	o := New(Config{})
	got := o.validateDiscovered(context.Background(), []crawler.DiscoveredURL{
		{URL: "https://target.example/page", Source: "link"},
		{URL: "https://elsewhere.invalid/collect", Source: "form"},
		{URL: "https://not-target.example/page", Source: "link"},
	}, crawler.ScopeSameDomain, []string{"https://target.example"})

	if len(got) != 1 || got[0] != "https://target.example/page" {
		t.Fatalf("expected only the in-scope URL, got %v", got)
	}
}

func TestValidateDiscovered_KeepsSubdomain(t *testing.T) {
	o := New(Config{})
	got := o.validateDiscovered(context.Background(), []crawler.DiscoveredURL{
		{URL: "https://api.target.example/v1", Source: "link"},
	}, crawler.ScopeSameDomain, []string{"https://target.example"})

	if len(got) != 1 {
		t.Fatalf("subdomain of the authorised domain should stay in scope, got %v", got)
	}
}

// A URL that is in scope but rejected by the SSRF policy is still dropped, and
// the validated (normalised) form is what reaches the queue.
func TestValidateDiscovered_SSRFStillRejectsInScopeURL(t *testing.T) {
	o := New(Config{
		ValidateTarget: func(_ context.Context, raw string) (string, error) {
			if raw == "https://target.example/private" {
				return "", errors.New("blocked")
			}
			return raw + "/normalised", nil
		},
	})
	got := o.validateDiscovered(context.Background(), []crawler.DiscoveredURL{
		{URL: "https://target.example/ok"},
		{URL: "https://target.example/private"},
	}, crawler.ScopeSameDomain, []string{"https://target.example"})

	if len(got) != 1 || got[0] != "https://target.example/ok/normalised" {
		t.Fatalf("expected only the validated URL, got %v", got)
	}
}
