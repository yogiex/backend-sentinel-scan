//go:build e2e

package credentials

import (
	"net/http"
	"strings"
	"testing"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/test/e2e/testutil"
)

func TestListCredentials_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/credentials")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	var body []interface{}
	testutil.MustDecode(t, resp, &body)
}

func TestCreateCredential_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	payload := `{"name":"test-cred","method":"cookie","config":{"cookies":[{"name":"sess","value":"abc"}]}}`
	resp := testutil.MustPOST(t, server, "/api/credentials", payload)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		t.Errorf("Expected status 201, got %d", resp.StatusCode)
	}

	var result map[string]interface{}
	testutil.MustDecode(t, resp, &result)
	if name, ok := result["name"]; ok {
		t.Logf("Created credential: %v", name)
	}
}

func TestGetCredential_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	resp := testutil.MustGET(t, server, "/api/credentials/1")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestUpdateCredential_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	payload := strings.NewReader(`{"name":"updated-cred"}`)
	req, err := http.NewRequest("PUT", server.URL+"/api/credentials/1", payload)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}
}

func TestDeleteCredential_E2E(t *testing.T) {
	server := testutil.NewTestServer(t)
	req, err := http.NewRequest("DELETE", server.URL+"/api/credentials/1", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		t.Errorf("Expected status 204, got %d", resp.StatusCode)
	}
}
