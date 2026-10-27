package store

// The store's public vocabulary, re-exported from the domain packages.
//
// The split moved the implementations into internal/control/store/<domain>.
// The HTTP and CLI layers keep one import — this package — so they read the
// same names they always have. Every declaration below is an alias or a
// one-line forwarder: it holds no behaviour, only the assembly of the public
// contract.
//
// A Code* constant whose literal moved into a domain package is re-exported as
// a variable: the error-code golden (internal/cli/upgrade) freezes the literal
// where it is declared — exactly once per value — and a const alias would hide
// the value from that scan. Nothing compares these values by identity.

import (
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

const (
	// CodeDatabaseUnavailable is the one "database unusable" code. The literal
	// lives in the versions leaf because the CLI, the core rule library and the
	// store all emit it.
	CodeDatabaseUnavailable = versions.CodeDatabaseUnavailable

	// SessionLifetime is the absolute lifetime of one authenticated session.
	SessionLifetime = common.SessionLifetime
	// OfflineAfter is the window after which a node that stopped contacting the
	// Hub is reported offline.
	OfflineAfter = common.OfflineAfter
	// PasswordPrefix is the stored Argon2id parameter prefix.
	PasswordPrefix = common.PasswordPrefix
)

// PublishVerifier checks assembled documents with the pinned kernels.
type PublishVerifier = common.PublishVerifier

// PublishGateConfig is the deployment configuration of the gate.
type PublishGateConfig = common.PublishGateConfig

// ErrorCodeOf returns the stable code segment of err.
func ErrorCodeOf(err error) string { return common.ErrorCodeOf(err) }

// NewPublishVerifier builds the fixed kernel gate.
func NewPublishVerifier(cfg PublishGateConfig, dir string) (PublishVerifier, error) {
	return common.NewPublishVerifier(cfg, dir)
}

// HashPassword derives one Argon2id hash.
func HashPassword(password string) (string, error) { return common.HashPassword(password) }

// VerifyPassword compares a password against one stored hash.
func VerifyPassword(hash, password string) bool { return common.VerifyPassword(hash, password) }

// PasswordValid reports whether a password satisfies the policy.
func PasswordValid(password string) bool { return common.PasswordValid(password) }

// RandomToken returns one URL-safe random token.
func RandomToken() string { return common.RandomToken() }

// TokenHash returns the stored digest of a bearer token.
func TokenHash(token string) []byte { return common.TokenHash(token) }

// Equal compares two secrets without leaking their length by timing.
func Equal(a, b string) bool { return common.Equal(a, b) }

// Itoa renders an integer for an operator message.
func Itoa(n int) string { return common.Itoa(n) }
