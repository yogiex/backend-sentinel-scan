package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
)

func TestQueryTokenAuthenticatesStreamRouteOnly(t *testing.T) {
	auth, err := NewAuth("0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	token, _, err := auth.Issue(&entity.User{ID: 5, Role: entity.RoleViewer})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := ActorFrom(r.Context()); !ok {
			t.Error("actor missing from context")
		}
		w.WriteHeader(http.StatusOK)
	})
	chain := QueryToken("/stream")(auth.Require(okHandler))

	cases := []struct {
		name string
		path string
		want int
	}{
		{"stream with query token", "/api/scans/7/stream?token=" + token, http.StatusOK},
		{"other route with query token", "/api/scans/7/results?token=" + token, http.StatusUnauthorized},
		{"stream without token", "/api/scans/7/stream", http.StatusUnauthorized},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			chain.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, tc.path, nil))
			if rec.Code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func TestQueryTokenDoesNotOverrideHeader(t *testing.T) {
	auth, err := NewAuth("0123456789abcdef0123456789abcdef", time.Minute)
	if err != nil {
		t.Fatalf("NewAuth: %v", err)
	}
	token, _, err := auth.Issue(&entity.User{ID: 1, Role: entity.RoleAdmin})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			t.Errorf("header was rewritten to %q", got)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/api/scans/7/stream?token=attacker", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	QueryToken("/stream")(next).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}
