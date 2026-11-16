package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
)

func TestNewAuthRejectsShortSecret(t *testing.T) {
	if _, err := NewAuth("short", time.Minute); err == nil {
		t.Error("expected error for secret shorter than 32 characters")
	}
}

func TestRequireAcceptsValidToken(t *testing.T) {
	auth, err := NewAuth("0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	token, _, err := auth.Issue(&entity.User{ID: 42, Role: entity.RoleSecurityAnalyst})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	var got policy.Actor
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a, ok := ActorFrom(r.Context())
		if !ok {
			t.Error("actor missing from context")
		}
		got = policy.Actor{ID: a.ID, Role: a.Role}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	auth.Require(next).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got.ID != 42 || got.Role != entity.RoleSecurityAnalyst {
		t.Fatalf("actor = %+v, want id=42 role=security_analyst", got)
	}
}

func TestRequireRejectsBadTokens(t *testing.T) {
	auth, _ := NewAuth("0123456789abcdef0123456789abcdef", time.Minute)
	valid, _, _ := auth.Issue(&entity.User{ID: 1, Role: entity.RoleAdmin})

	cases := map[string]string{
		"missing":    "",
		"no bearer":  valid,
		"garbage":    "Bearer not-a-token",
		"tampered":   "Bearer " + valid + "x",
		"wrong alg":  "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0.",
	}
	for name, header := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/scans", nil)
		if header != "" {
			req.Header.Set("Authorization", header)
		}
		rec := httptest.NewRecorder()
		auth.Require(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			t.Errorf("%s: handler must not be called", name)
		})).ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status = %d, want 401", name, rec.Code)
		}
	}
}

func TestCORSAllowlist(t *testing.T) {
	h := CORS([]string{"http://localhost:5173"}, false)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Allowed origin gets the headers.
	req := httptest.NewRequest(http.MethodOptions, "/api/scans", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("allowed preflight status = %d, want 204", rec.Code)
	}
	if rec.Header().Get("Access-Control-Allow-Origin") != "http://localhost:5173" {
		t.Error("missing ACAO for allowed origin")
	}
	if rec.Header().Get("Vary") != "Origin" {
		t.Error("missing Vary: Origin")
	}

	// Suffix tricks and unknown origins are rejected.
	for _, origin := range []string{"http://localhost:5173.evil.com", "http://evil.com"} {
		req = httptest.NewRequest(http.MethodOptions, "/api/scans", nil)
		req.Header.Set("Origin", origin)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("origin %q status = %d, want 403", origin, rec.Code)
		}
		if rec.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("origin %q must not receive ACAO", origin)
		}
	}
}
