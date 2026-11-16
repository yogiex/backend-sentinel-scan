// Package passwd hashes and verifies user passwords with bcrypt.
package passwd

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

// ErrMismatch is returned when a password does not match its hash.
var ErrMismatch = errors.New("password does not match")

const cost = 12

// dummyHash is compared against when a username does not exist, so the
// response time does not reveal account existence.
var dummyHash = []byte("$2a$12$C6UzMDM.H6dfI/f/IKcEe.5r5F9dM7yQ4G8Fq0n2fJm0hK6r7Q8Zu")

// Hash returns a bcrypt hash of password.
func Hash(password string) (string, error) {
	if len(password) < 8 || len(password) > 72 {
		return "", errors.New("password must be between 8 and 72 bytes")
	}
	b, err := bcrypt.GenerateFromPassword([]byte(password), cost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Verify returns nil when password matches hash.
func Verify(hash, password string) error {
	if hash == "" {
		_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return ErrMismatch
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

// Burn spends the same work as a real verification to keep timing uniform.
func Burn(password string) {
	_ = bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
}
