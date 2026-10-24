package mesh

import (
	"crypto/sha256"
	"strings"
	"testing"
	"time"
)

var testIssuedAt = time.Date(2026, 10, 22, 9, 0, 0, 0, time.UTC)

const testDeviceID = "fedcba9876543210fedcba9876543210"

func newTestKey(t *testing.T) (EnrollmentKey, string) {
	t.Helper()
	key, secret, err := NewEnrollmentKey(testDeviceID, testIssuedAt)
	if err != nil {
		t.Fatalf("NewEnrollmentKey: %v", err)
	}
	return key, secret
}

func TestNewEnrollmentKeyHasFixedFifteenMinuteWindow(t *testing.T) {
	key, secret := newTestKey(t)
	if key.State != KeyIssued {
		t.Fatalf("new key state = %q, want issued", key.State)
	}
	if got := key.ExpiresAt.Sub(key.IssuedAt); got != 15*time.Minute {
		t.Fatalf("window = %v, want 15m", got)
	}
	if !key.ConsumedAt.IsZero() {
		t.Fatal("a new key already records a consumption time")
	}
	if err := ValidateEnrollmentSecret(secret); err != nil {
		t.Fatalf("generated secret rejected: %v", err)
	}
	if len(secret) != 43 {
		t.Fatalf("secret length = %d, want 43", len(secret))
	}
	sum := sha256.Sum256([]byte(secret))
	if string(key.Hash) != string(sum[:]) {
		t.Fatal("stored hash is not the SHA-256 of the secret")
	}
	if err := key.Validate(); err != nil {
		t.Fatalf("new key does not validate: %v", err)
	}
}

func TestEnrollmentSecretShapeAndReuse(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for range 64 {
		secret, err := NewEnrollmentSecret()
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateEnrollmentSecret(secret); err != nil {
			t.Fatalf("generated secret rejected: %v", err)
		}
		if strings.ContainsAny(secret, "=+/") {
			t.Fatalf("secret is not unpadded base64url: %q", secret)
		}
		if _, ok := seen[secret]; ok {
			t.Fatalf("duplicate secret: %q", secret)
		}
		seen[secret] = struct{}{}
	}
	for _, bad := range []string{
		"",
		"short",
		strings.Repeat("a", 42),
		strings.Repeat("a", 44),
		strings.Repeat("a", 43) + "=",
		strings.Repeat("a", 42) + "+",
		" " + strings.Repeat("a", 42),
	} {
		if err := ValidateEnrollmentSecret(bad); err == nil {
			t.Fatalf("invalid secret accepted: %q", bad)
		} else {
			assertCode(t, err, CodeKeySecretInvalid)
		}
	}
}

func TestKeyStateMatrix(t *testing.T) {
	states := []KeyState{KeyIssued, KeyConsumed, KeyExpired, KeyRevoked}
	terminal := map[KeyState]bool{KeyIssued: false, KeyConsumed: true, KeyExpired: true, KeyRevoked: true}
	for _, state := range states {
		if err := state.Validate(); err != nil {
			t.Fatalf("defined state rejected: %q: %v", state, err)
		}
		if got := state.Terminal(); got != terminal[state] {
			t.Fatalf("Terminal(%q) = %v, want %v", state, got, terminal[state])
		}
	}
	if KeyState("active").Validate() == nil {
		t.Fatal("undefined key state accepted")
	}
	if KeyState("active").Terminal() {
		t.Fatal("an undefined state reported itself terminal")
	}
}

func TestConsumeIsIrreversible(t *testing.T) {
	key, _ := newTestKey(t)
	now := testIssuedAt.Add(time.Minute)
	consumed, err := key.Consume(testDeviceID, now)
	if err != nil {
		t.Fatal(err)
	}
	if consumed.State != KeyConsumed || !consumed.ConsumedAt.Equal(now) {
		t.Fatalf("consume = %q at %v", consumed.State, consumed.ConsumedAt)
	}
	if !consumed.State.Terminal() {
		t.Fatal("consumed is not terminal")
	}
	if reuse, err := consumed.Consume(testDeviceID, now.Add(time.Minute)); err == nil {
		t.Fatalf("consumed key reused: %q", reuse.State)
	} else {
		assertCode(t, err, CodeKeyTransitionInvalid)
	}
	if _, err := consumed.Revoke(); err == nil {
		t.Fatal("consumed key revoked")
	}
	if _, err := consumed.Expire(testIssuedAt.Add(time.Hour)); err == nil {
		t.Fatal("consumed key expired")
	}
}

func TestConsumeRejectsOtherDevice(t *testing.T) {
	key, _ := newTestKey(t)
	other := strings.Repeat("1", 32)
	if _, err := key.Consume(other, testIssuedAt.Add(time.Minute)); err == nil {
		t.Fatal("key consumed for another device")
	} else {
		assertCode(t, err, CodeKeyDeviceMismatch)
	}
	if key.State != KeyIssued {
		t.Fatal("a mismatched consume changed the key state")
	}
}

func TestConsumeAtWindowEdges(t *testing.T) {
	key, _ := newTestKey(t)
	// One nanosecond before the deadline the key is still live.
	if _, err := key.Consume(testDeviceID, testIssuedAt.Add(15*time.Minute-time.Nanosecond)); err != nil {
		t.Fatalf("consume just before expiry refused: %v", err)
	}
	// At the deadline it is no longer live.
	if _, err := key.Consume(testDeviceID, testIssuedAt.Add(15*time.Minute)); err == nil {
		t.Fatal("consume at the expiry instant accepted")
	} else {
		assertCode(t, err, CodeKeyExpired)
	}
	// Before issue the key is not valid yet.
	if _, err := key.Consume(testDeviceID, testIssuedAt.Add(-time.Second)); err == nil {
		t.Fatal("consume before issue accepted")
	}
}

func TestConsumeOfRetiredKeys(t *testing.T) {
	key, _ := newTestKey(t)
	expired, err := key.Expire(testIssuedAt.Add(16 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := expired.Consume(testDeviceID, testIssuedAt.Add(16*time.Minute)); err == nil {
		t.Fatal("expired key consumed")
	} else {
		assertCode(t, err, CodeKeyExpired)
	}
	revoked, err := key.Revoke()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := revoked.Consume(testDeviceID, testIssuedAt.Add(time.Minute)); err == nil {
		t.Fatal("revoked key consumed")
	} else {
		assertCode(t, err, CodeKeyTransitionInvalid)
	}
}

func TestExpireRequiresAClosedWindow(t *testing.T) {
	key, _ := newTestKey(t)
	if _, err := key.Expire(testIssuedAt.Add(14 * time.Minute)); err == nil {
		t.Fatal("expire before the deadline accepted")
	} else {
		assertCode(t, err, CodeKeyNotExpired)
	}
	expired, err := key.Expire(testIssuedAt.Add(15 * time.Minute))
	if err != nil {
		t.Fatalf("expire at the deadline refused: %v", err)
	}
	if expired.State != KeyExpired {
		t.Fatalf("state = %q, want expired", expired.State)
	}
	// Expiring an expired key is a no-op, and an expired key never becomes usable.
	again, err := expired.Expire(testIssuedAt.Add(time.Hour))
	if err != nil || again.State != KeyExpired {
		t.Fatalf("repeated expire = %q, %v", again.State, err)
	}
	if _, err := expired.Consume(testDeviceID, testIssuedAt.Add(time.Hour)); err == nil {
		t.Fatal("expired key consumed")
	}
	if _, err := expired.Revoke(); err == nil {
		t.Fatal("expired key revoked")
	}
}

func TestRevokeIsIdempotentAndTerminal(t *testing.T) {
	key, _ := newTestKey(t)
	revoked, err := key.Revoke()
	if err != nil {
		t.Fatal(err)
	}
	if revoked.State != KeyRevoked {
		t.Fatalf("state = %q, want revoked", revoked.State)
	}
	again, err := revoked.Revoke()
	if err != nil || again.State != KeyRevoked {
		t.Fatalf("repeated revoke = %q, %v", again.State, err)
	}
	if _, err := revoked.Consume(testDeviceID, testIssuedAt.Add(time.Minute)); err == nil {
		t.Fatal("revoked key consumed")
	}
	if _, err := revoked.Expire(testIssuedAt.Add(time.Hour)); err == nil {
		t.Fatal("revoked key expired")
	}
}

func TestKeyRecordValidation(t *testing.T) {
	key, _ := newTestKey(t)

	bad := key
	bad.ExpiresAt = bad.IssuedAt.Add(30 * time.Minute)
	if err := bad.Validate(); err == nil {
		t.Fatal("a 30-minute window accepted")
	} else {
		assertCode(t, err, CodeKeyTTLInvalid)
	}

	bad = key
	bad.ConsumedAt = testIssuedAt.Add(time.Minute)
	if err := bad.Validate(); err == nil {
		t.Fatal("an issued key with a consumption time accepted")
	} else {
		assertCode(t, err, CodeKeyTTLInvalid)
	}

	bad = key
	bad.State = KeyConsumed
	if err := bad.Validate(); err == nil {
		t.Fatal("a consumed key without a consumption time accepted")
	}

	bad = key
	bad.State = KeyConsumed
	bad.ConsumedAt = testIssuedAt.Add(20 * time.Minute)
	if err := bad.Validate(); err == nil {
		t.Fatal("a consumption time outside the window accepted")
	}

	bad = key
	bad.Hash = bad.Hash[:16]
	if err := bad.Validate(); err == nil {
		t.Fatal("a truncated digest accepted")
	} else {
		assertCode(t, err, CodeKeyHashInvalid)
	}

	bad = key
	bad.ID = strings.ToUpper(bad.ID)
	if err := bad.Validate(); err == nil {
		t.Fatal("a non-canonical key id accepted")
	} else {
		assertCode(t, err, CodeKeyIDInvalid)
	}

	bad = key
	bad.DeviceID = "short"
	if err := bad.Validate(); err == nil {
		t.Fatal("a malformed device id accepted")
	} else {
		assertCode(t, err, CodeKeyDeviceIDInvalid)
	}

	if _, _, err := NewEnrollmentKey("short", testIssuedAt); err == nil {
		t.Fatal("NewEnrollmentKey accepted a malformed device id")
	}
	if _, _, err := NewEnrollmentKey(testDeviceID, time.Time{}); err == nil {
		t.Fatal("NewEnrollmentKey accepted a zero issue time")
	}
}

func TestKeyActiveWindow(t *testing.T) {
	key, _ := newTestKey(t)
	if !key.Active(testIssuedAt) {
		t.Fatal("a freshly issued key is not active")
	}
	if !key.Active(testIssuedAt.Add(15*time.Minute - time.Nanosecond)) {
		t.Fatal("a key just before the deadline is not active")
	}
	if key.Active(testIssuedAt.Add(15 * time.Minute)) {
		t.Fatal("a key at the deadline is active")
	}
	if key.Active(testIssuedAt.Add(-time.Nanosecond)) {
		t.Fatal("a key before its issue time is active")
	}
	revoked, err := key.Revoke()
	if err != nil {
		t.Fatal(err)
	}
	if revoked.Active(testIssuedAt) {
		t.Fatal("a revoked key is active")
	}
}

func TestKeyHashIsVerifiable(t *testing.T) {
	_, secret := newTestKey(t)
	hash := EnrollmentKeyHash(secret)
	if len(hash) != sha256.Size {
		t.Fatalf("hash length = %d", len(hash))
	}
	if string(EnrollmentKeyHash(secret)) != string(hash) {
		t.Fatal("hash is not deterministic")
	}
	if string(EnrollmentKeyHash(secret+"x")) == string(hash) {
		t.Fatal("different secrets collide")
	}
}
