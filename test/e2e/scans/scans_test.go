//go:build e2e

package scans

import (
	"net/http"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/test/e2e/testutil"
)

func TestCreateScan_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustPOST(t, server, "/api/scans", `{"targets":["http://example.com"]}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("Expected status 202, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	testutil.MustDecode(t, resp, &result)

	if result["status"] != "pending" && result["status"] != "completed" {
		t.Errorf("Expected scan status, got '%v'", result["status"])
	}
	if _, ok := result["id"]; !ok {
		t.Error("Expected scan ID in response")
	}
}

func TestCreateScan_InvalidBody_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustPOST(t, server, "/api/scans", "not-json")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid body, got %d", resp.StatusCode)
	}
}

func TestCreateScan_MissingTargets_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustPOST(t, server, "/api/scans", `{"targets":[]}`)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for empty targets, got %d", resp.StatusCode)
	}
}

func TestGetScan_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/scans/1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	testutil.MustDecode(t, resp, &result)

	if result["status"] != "completed" {
		t.Errorf("Expected status 'completed', got '%v'", result["status"])
	}
}

func TestGetScan_InvalidID_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/scans/abc")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("Expected status 400 for invalid ID, got %d", resp.StatusCode)
	}
}

func TestGetScanResults_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/scans/1/results")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var results []interface{}
	testutil.MustDecode(t, resp, &results)
	t.Logf("Got %d findings", len(results))
}
