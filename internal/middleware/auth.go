// Package middleware contains transport-level security: authentication,
// CORS, and defensive response headers.
package middleware

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/entity"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/domain/policy"
	"github.com/inkubasi-btp-cybersecurity/vulnerability-scanner/internal/httpx"
)

const (
	issuer = "sentinel-scan"
	// MinSecretLen is the minimum accepted HMAC secret length.
	MinSecretLen = 32
)

type actorKey struct{}

// ActorFrom returns the authenticated actor stored by Require.
func ActorFrom(ctx context.Context) (policy.Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(policy.Actor)
	return a, ok
}

// WithActor attaches an actor to ctx (used by tests and internal calls).
func WithActor(ctx context.Context, a policy.Actor) context.Context {
	return context.WithValue(ctx, actorKey{}, a)
}

// Claims is the JWT payload. Only the user ID and role are trusted; the
// permission set is always re-derived from the role on the server.
type Claims struct {
	Role entity.Role `json:"role"`
	jwt.RegisteredClaims
}

// Auth issues and verifies HS256 access tokens.
type Auth struct {
	key    []byte
	ttl    time.Duration
	parser *jwt.Parser
}

// NewAuth validates the secret and builds the parser with hardened options.
func NewAuth(secret string, ttl time.Duration) (*Auth, error) {
	if len(secret) < MinSecretLen {
		return nil, errors.New("JWT secret must be at least 32 characters")
	}
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	return &Auth{
		key: []byte(secret),
		ttl: ttl,
		parser: jwt.NewParser(
			jwt.WithValidMethods([]string{"HS256"}),
			jwt.WithIssuer(issuer),
			jwt.WithExpirationRequired(),
			jwt.WithLeeway(30*time.Second),
		),
	}, nil
}

// Issue mints an access token for u.
func (a *Auth) Issue(u *entity.User) (string, time.Time, error) {
	now := time.Now()
	expires := now.Add(a.ttl)
	claims := Claims{
		Role: u.Role,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   strconv.FormatUint(uint64(u.ID), 10),
			Issuer:    issuer,
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expires),
		},
	}
	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(a.key)
	if err != nil {
		return "", time.Time{}, err
	}
	return signed, expires, nil
}

// TTL exposes the configured token lifetime.
func (a *Auth) TTL() time.Duration { return a.ttl }

// Require rejects requests without a valid bearer token and injects the
// resulting actor into the request context.
func (a *Auth) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := r.Header.Get("Authorization")
		if !strings.HasPrefix(raw, "Bearer ") {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Missing bearer token")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(raw, "Bearer "))
		var claims Claims
		if _, err := a.parser.ParseWithClaims(token, &claims, func(t *jwt.Token) (any, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, errors.New("unexpected signing method")
			}
			return a.key, nil
		}); err != nil {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid or expired token")
			return
		}
		id, err := strconv.ParseUint(claims.Subject, 10, 32)
		if err != nil {
			httpx.Error(w, http.StatusUnauthorized, "UNAUTHORIZED", "Invalid token subject")
			return
		}
		actor := policy.NewActor(uint(id), claims.Role)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), actorKey{}, actor)))
	})
}
