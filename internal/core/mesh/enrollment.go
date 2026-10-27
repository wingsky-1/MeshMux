package mesh

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The enrollment key lifetime of D1 is fixed at 15 minutes and is not a
// per-key preference: a key that outlives its window is a standing invitation
// to enroll a device nobody is watching.
const KeyTTL = 15 * time.Minute

const (
	keySecretBytes = 32
	keySecretChars = 43 // unpadded base64url of 32 bytes
)

// Additional stable codes for enrollment keys.
const (
	// CodeKeyIDInvalid: the key record id is not canonical.
	CodeKeyIDInvalid = "MESH_ENROLLMENT_KEY_ID_INVALID"
	// CodeKeyDeviceIDInvalid: the device the key enrolls is not canonical.
	CodeKeyDeviceIDInvalid = "MESH_ENROLLMENT_KEY_DEVICE_INVALID"
	// CodeKeyStateInvalid: the key state is not a defined value.
	CodeKeyStateInvalid = "MESH_ENROLLMENT_KEY_STATE_INVALID"
	// CodeKeyTransitionInvalid: the requested key edge is not in the transition
	// table, or a consumed/revoked/expired key was reused.
	CodeKeyTransitionInvalid = "MESH_ENROLLMENT_KEY_TRANSITION_INVALID"
	// CodeKeyExpired: the operation needed a live key but the window closed.
	CodeKeyExpired = "MESH_ENROLLMENT_KEY_EXPIRED"
	// CodeKeyNotExpired: expiry was requested before ExpiresAt. Withdrawing a
	// live key early is a revocation, not an expiry.
	CodeKeyNotExpired = "MESH_ENROLLMENT_KEY_NOT_EXPIRED"
	// CodeKeyDeviceMismatch: the key belongs to another device.
	CodeKeyDeviceMismatch = "MESH_ENROLLMENT_KEY_DEVICE_MISMATCH"
	// CodeKeyTTLInvalid: the recorded window is not the fixed 15-minute one.
	CodeKeyTTLInvalid = "MESH_ENROLLMENT_KEY_TTL_INVALID"
	// CodeKeyHashInvalid: the stored digest is not a SHA-256 digest.
	CodeKeyHashInvalid = "MESH_ENROLLMENT_KEY_HASH_INVALID"
	// CodeKeySecretInvalid: an untrusted key secret is not canonical.
	CodeKeySecretInvalid = "MESH_ENROLLMENT_KEY_SECRET_INVALID"
	// CodeKeyGenerationFailed: crypto/rand was unavailable, so no key exists.
	CodeKeyGenerationFailed = "MESH_ENROLLMENT_KEY_GENERATION_FAILED"
	// CodeKeyAlreadyActive: an unexpired issued key already exists for the
	// device, so a second one would break the single-active rule.
	CodeKeyAlreadyActive = "MESH_ENROLLMENT_KEY_ALREADY_ACTIVE"
)

// KeyState is the one-time mesh enrollment key state.
//
//	issued → consumed | expired | revoked
//
// consumed, expired and revoked are terminal: a consumed key can never be
// reissued or reused, an expired key is never revived (the operator issues a
// new one) and a revoked key is never reinstated. A same-state call is an
// idempotent no-op.
type KeyState string

const (
	// KeyIssued: the key was shown once to the operator and is not spent.
	KeyIssued KeyState = "issued"
	// KeyConsumed: the enrollment succeeded and the key is spent. Terminal.
	KeyConsumed KeyState = "consumed"
	// KeyExpired: the 15-minute window closed before enrollment. Terminal.
	KeyExpired KeyState = "expired"
	// KeyRevoked: the key was withdrawn before enrollment. Terminal.
	KeyRevoked KeyState = "revoked"
)

// Validate accepts only the four defined key states.
func (s KeyState) Validate() error {
	switch s {
	case KeyIssued, KeyConsumed, KeyExpired, KeyRevoked:
		return nil
	default:
		return failure(CodeKeyStateInvalid, "state must be issued, consumed, expired or revoked")
	}
}

// EnrollmentKey is the persisted record of one one-time mesh enrollment key.
// Only Hash is stored: the secret itself is returned once by
// NewEnrollmentKey, is never persisted and never logged (D1). The record is
// not a Headscale pre-auth key value written to disk; it is the Hub-side state
// that decides whether an enrollment may proceed.
type EnrollmentKey struct {
	ID         string
	DeviceID   string
	Hash       []byte
	State      KeyState
	IssuedAt   time.Time
	ExpiresAt  time.Time
	ConsumedAt time.Time
}

// NewEnrollmentKey mints a fresh key for a pending device and returns the
// record plus its plaintext secret once. issuedAt must come from the caller's
// clock so tests and the caller share one time source; the window is always
// KeyTTL from that instant.
func NewEnrollmentKey(deviceID string, issuedAt time.Time) (EnrollmentKey, string, error) {
	if err := subscription.ValidateID(deviceID); err != nil {
		return EnrollmentKey{}, "", failure(CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	if issuedAt.IsZero() {
		return EnrollmentKey{}, "", failure(CodeKeyTTLInvalid, "the issue time is required")
	}
	id, err := subscription.NewID()
	if err != nil {
		return EnrollmentKey{}, "", failure(CodeKeyGenerationFailed, "the enrollment key identity could not be generated")
	}
	secret, err := NewEnrollmentSecret()
	if err != nil {
		return EnrollmentKey{}, "", err
	}
	key := EnrollmentKey{
		ID:        id,
		DeviceID:  deviceID,
		Hash:      EnrollmentKeyHash(secret),
		State:     KeyIssued,
		IssuedAt:  issuedAt.UTC(),
		ExpiresAt: issuedAt.UTC().Add(KeyTTL),
	}
	if err := key.Validate(); err != nil {
		return EnrollmentKey{}, "", err
	}
	return key, secret, nil
}

// NewEnrollmentSecret returns a 43-character unpadded base64url secret carrying
// 256 bits from crypto/rand. A generation failure never falls back to a weaker
// source.
func NewEnrollmentSecret() (string, error) {
	var raw [keySecretBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", failure(CodeKeyGenerationFailed, "the enrollment key could not be generated")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ValidateEnrollmentSecret accepts only a canonical 43-character unpadded
// base64url secret that decodes to exactly 32 bytes.
func ValidateEnrollmentSecret(secret string) error {
	const detail = "need a canonical 43-character base64url key"
	if len(secret) != keySecretChars {
		return failure(CodeKeySecretInvalid, detail)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(secret)
	if err != nil || len(decoded) != keySecretBytes || base64.RawURLEncoding.EncodeToString(decoded) != secret {
		return failure(CodeKeySecretInvalid, detail)
	}
	return nil
}

// EnrollmentKeyHash returns the SHA-256 digest that persistence and lookup use.
// Only the digest leaves the enrollment boundary.
func EnrollmentKeyHash(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))
	return sum[:]
}

// Validate checks the key record and the fixed window, without a clock: it
// does not decide whether the key is still live. Use Expired for that.
func (k EnrollmentKey) Validate() error {
	if err := subscription.ValidateID(k.ID); err != nil {
		return failure(CodeKeyIDInvalid, "need 32 lowercase hex characters")
	}
	if err := subscription.ValidateID(k.DeviceID); err != nil {
		return failure(CodeKeyDeviceIDInvalid, "need 32 lowercase hex characters")
	}
	if len(k.Hash) != sha256.Size {
		return failure(CodeKeyHashInvalid, "need a 32-byte SHA-256 digest")
	}
	if err := k.State.Validate(); err != nil {
		return err
	}
	if k.IssuedAt.IsZero() {
		return failure(CodeKeyTTLInvalid, "the issue time is required")
	}
	if !k.ExpiresAt.Equal(k.IssuedAt.Add(KeyTTL)) {
		return failure(CodeKeyTTLInvalid, "the enrollment window must be exactly 15 minutes")
	}
	switch k.State {
	case KeyConsumed:
		if k.ConsumedAt.IsZero() || k.ConsumedAt.Before(k.IssuedAt) || k.ConsumedAt.After(k.ExpiresAt) {
			return failure(CodeKeyTTLInvalid, "a consumed key needs a consumption time inside its window")
		}
	default:
		if !k.ConsumedAt.IsZero() {
			return failure(CodeKeyTTLInvalid, "only a consumed key carries a consumption time")
		}
	}
	return nil
}

// Expired reports whether now is at or past ExpiresAt. A lapsed key may still
// carry the issued state until it is retired with Expire; it can never be
// consumed.
func (k EnrollmentKey) Expired(now time.Time) bool {
	return !now.Before(k.ExpiresAt)
}

// Active reports whether the key can still be consumed at now: issued and
// inside its window, including after IssuedAt.
func (k EnrollmentKey) Active(now time.Time) bool {
	return k.State == KeyIssued && !now.Before(k.IssuedAt) && !k.Expired(now)
}

// Consume spends an issued key for the matching device. It requires a live
// window (strictly before ExpiresAt) and a matching device id. The result is
// always the terminal consumed state, which no later call can undo; per D1 the
// caller deletes the record after recording the audit fact, so the one-time
// secret cannot be replayed.
func (k EnrollmentKey) Consume(deviceID string, now time.Time) (EnrollmentKey, error) {
	if err := k.Validate(); err != nil {
		return k, err
	}
	if deviceID != k.DeviceID {
		return k, failure(CodeKeyDeviceMismatch, "the key belongs to another device")
	}
	switch k.State {
	case KeyConsumed:
		return k, failure(CodeKeyTransitionInvalid, "a consumed key is spent and cannot be consumed again")
	case KeyExpired:
		return k, failure(CodeKeyExpired, "the enrollment window closed")
	case KeyRevoked:
		return k, failure(CodeKeyTransitionInvalid, "a revoked key cannot be consumed")
	}
	if k.Expired(now) {
		return k, failure(CodeKeyExpired, "the enrollment window closed")
	}
	if now.Before(k.IssuedAt) {
		return k, failure(CodeKeyTransitionInvalid, "the key is not valid yet")
	}
	k.State = KeyConsumed
	k.ConsumedAt = now.UTC()
	return k, nil
}

// Expire retires a lapsed key. It refuses before ExpiresAt, because an early
// withdrawal is a revocation and the two must not be reported as the same
// event. Expiring an already expired key is a no-op; a consumed or revoked key
// is refused, since each already reached a different terminal state and
// reporting it as expired would misstate what happened.
func (k EnrollmentKey) Expire(now time.Time) (EnrollmentKey, error) {
	if err := k.Validate(); err != nil {
		return k, err
	}
	switch k.State {
	case KeyExpired:
		return k, nil
	case KeyConsumed:
		return k, failure(CodeKeyTransitionInvalid, "a consumed key cannot expire")
	case KeyRevoked:
		return k, failure(CodeKeyTransitionInvalid, "a revoked key cannot expire")
	}
	if !k.Expired(now) {
		return k, failure(CodeKeyNotExpired, "the enrollment window is still open; revoke the key instead")
	}
	k.State = KeyExpired
	return k, nil
}

// Revoke withdraws an issued key before it is used. Revoking an already revoked
// key is a no-op. A consumed key is refused because it is spent, and an expired
// key is refused because its window already ended on its own; reporting either
// as revoked would misstate the audit trail.
func (k EnrollmentKey) Revoke() (EnrollmentKey, error) {
	if err := k.Validate(); err != nil {
		return k, err
	}
	switch k.State {
	case KeyRevoked:
		return k, nil
	case KeyConsumed:
		return k, failure(CodeKeyTransitionInvalid, "a consumed key cannot be revoked")
	case KeyExpired:
		return k, failure(CodeKeyTransitionInvalid, "an expired key cannot be revoked")
	case KeyIssued:
		k.State = KeyRevoked
		return k, nil
	default:
		return k, failure(CodeKeyStateInvalid, "state must be issued, consumed, expired or revoked")
	}
}
