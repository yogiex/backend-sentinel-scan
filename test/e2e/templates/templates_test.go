//go:build e2e

package templates

import (
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/test/e2e/testutil"
)

func TestListTemplates_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/templates")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}
