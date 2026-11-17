package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/application"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/middleware"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/loginguard"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/security/passwd"
)

// authStateAdapter is the test-side equivalent of the adapter main.go installs:
// the middleware asks it for the current row on every request.
type authStateAdapter struct{ users userStore }

func (a authStateAdapter) AuthState(ctx context.Context, id uint) (middleware.UserState, error) {
	u, err := a.users.FindByID(ctx, id)
	if err != nil {
		return middleware.UserState{}, err
	}
	return middleware.UserState{Version: u.TokenVersion, Role: u.Role, Active: u.IsActive}, nil
}

type authHarness struct {
	router http.Handler
	users  userStore
	guard  *loginguard.Guard
}

func newAuthHarness(t *testing.T, guardCfg loginguard.Config) *authHarness {
	t.Helper()
	hash, err := passwd.Hash("correct-horse-battery")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	users := userStore{byID: map[uint]*entity.User{
		1: {
			ID:           1,
			Username:     "admin",
			Email:        "admin@sentinel.local",
			PasswordHash: hash,
			Role:         entity.RoleAdmin,
			IsActive:     true,
		},
	}}

	svc := application.NewAuthService(users)
	auth, err := middleware.NewAuth("0123456789abcdef0123456789abcdef", time.Hour)
	if err != nil {
		t.Fatalf("auth middleware: %v", err)
	}
	auth.WithUserState(authStateAdapter{users: users})
	guard := loginguard.New(guardCfg)

	handler := NewHandler(nil, nil, svc, nil, nil, nil).
		WithAuthIssuer(auth).
		WithLoginGuard(guard)
	// Same contract the router enforces: request paths are evaluated by the
	// public/private split, so the harness uses the real router.
	router := NewRouter(handler, RouterDeps{Auth: auth})
	return &authHarness{router: router, users: users, guard: guard}
}

func (h *authHarness) do(t *testing.T, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Content-Type", "application/json")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	h.router.ServeHTTP(rec, req)
	return rec
}

func (h *authHarness) login(t *testing.T, username, password string) *httptest.ResponseRecorder {
	t.Helper()
	return h.do(t, http.MethodPost, "/api/auth/login", "", map[string]string{
		"username": username,
		"password": password,
	})
}

func tokenFrom(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var body struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode login response: %v (%s)", err, rec.Body.String())
	}
	if body.Token == "" {
		t.Fatalf("login returned no token: %s", rec.Body.String())
	}
	return body.Token
}

func TestLoginIssuesToken(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 10, Window: time.Minute})

	rec := h.login(t, "admin", "correct-horse-battery")
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if tokenFrom(t, rec) == "" {
		t.Fatal("token must not be empty")
	}
}

func TestLoginRejectsWrongPassword(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 10, Window: time.Minute})

	rec := h.login(t, "admin", "wrong")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	// The message must not reveal whether the account exists.
	if !bytes.Contains(rec.Body.Bytes(), []byte("Invalid username or password")) {
		t.Fatalf("unexpected error body: %s", rec.Body.String())
	}
}

func TestLoginIsThrottled(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 3, Window: time.Minute})

	for i := 0; i < 3; i++ {
		if rec := h.login(t, "admin", "wrong"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, rec.Code)
		}
	}
	rec := h.login(t, "admin", "wrong")
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after the limit, got %d: %s", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Fatal("a 429 must tell the client when to retry")
	}
	// The correct password is refused too while the window is open: the limit
	// is on attempts, not on failures, so a guessing attacker gains nothing.
	if rec := h.login(t, "admin", "correct-horse-battery"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("throttled window must also refuse a valid password, got %d", rec.Code)
	}
}

func TestLogoutRevokesEveryToken(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 10, Window: time.Minute})

	token := tokenFrom(t, h.login(t, "admin", "correct-horse-battery"))
	if rec := h.do(t, http.MethodGet, "/api/auth/me", token, nil); rec.Code != http.StatusOK {
		t.Fatalf("token should work before logout, got %d", rec.Code)
	}

	if rec := h.do(t, http.MethodPost, "/api/auth/logout", token, nil); rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204 from logout, got %d: %s", rec.Code, rec.Body.String())
	}

	// The same token is now dead everywhere, not just on this endpoint.
	if rec := h.do(t, http.MethodGet, "/api/auth/me", token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token must be rejected, got %d", rec.Code)
	}
}

// Deactivating a user must end their session immediately. Before the state
// lookup existed, the token stayed valid until it expired.
func TestDeactivatedUserIsRejected(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 10, Window: time.Minute})
	token := tokenFrom(t, h.login(t, "admin", "correct-horse-battery"))

	user := h.users.byID[1]
	user.IsActive = false
	h.users.byID[1] = user

	if rec := h.do(t, http.MethodGet, "/api/auth/me", token, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("a deactivated user must not keep access, got %d", rec.Code)
	}
}

func TestLogoutRequiresAuthentication(t *testing.T) {
	h := newAuthHarness(t, loginguard.Config{MaxAttempts: 10, Window: time.Minute})
	if rec := h.do(t, http.MethodPost, "/api/auth/logout", "", nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", rec.Code)
	}
}
