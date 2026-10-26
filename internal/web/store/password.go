package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"
)

const PasswordPrefix = "$argon2id$v=19$m=65536,t=3,p=4$"

func PasswordValid(password string) bool {
	return utf8.ValidString(password) && utf8.RuneCountInString(password) >= 12 && len(password) <= 256
}

func HashPassword(password string) (string, error) {
	if !PasswordValid(password) {
		return "", errors.New("PASSWORD_POLICY")
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return PasswordPrefix + base64.RawStdEncoding.EncodeToString(salt) + "$" + base64.RawStdEncoding.EncodeToString(key), nil
}

// Only our fixed, versioned policy is accepted. Corrupt hashes cannot request
// unbounded Argon2 allocations; migrations must explicitly handle policy changes.
func VerifyPassword(hash, password string) bool {
	if !strings.HasPrefix(hash, PasswordPrefix) || len(password) > 256 {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(hash, PasswordPrefix), "$")
	if len(parts) != 2 {
		return false
	}
	salt, e1 := base64.RawStdEncoding.DecodeString(parts[0])
	key, e2 := base64.RawStdEncoding.DecodeString(parts[1])
	if e1 != nil || e2 != nil || len(salt) != 16 || len(key) != 32 {
		return false
	}
	actual := argon2.IDKey([]byte(password), salt, 3, 64*1024, 4, 32)
	return subtle.ConstantTimeCompare(actual, key) == 1
}

func RandomToken() string {
	b := make([]byte, 32)
	// Go crypto/rand.Read does not return an error on supported Go versions.
	if _, err := rand.Read(b); err != nil {
		panic("secure randomness unavailable")
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func TokenHash(token string) []byte { sum := sha256.Sum256([]byte(token)); return sum[:] }
func Equal(a, b string) bool        { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }
