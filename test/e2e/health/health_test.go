//go:build e2e

package health

import (
	"net/http"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/test/e2e/testutil"
)

func TestHealthEndpoint_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/health")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var body map[string]string
	testutil.MustDecode(t, resp, &body)

	if body["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", body["status"])
	}
	if _, ok := body["timestamp"]; !ok {
		t.Error("Expected timestamp field in response")
	}
}
