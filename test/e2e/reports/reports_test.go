//go:build e2e

package reports

import (
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/test/e2e/testutil"
)

func TestReportData_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/scans/1/report-data")
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}
