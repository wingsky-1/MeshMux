package subscription

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewRealityKeyPairIsCanonicalX25519(t *testing.T) {
	seen := make(map[string]struct{}, 32)
	for i := 0; i < 32; i++ {
		pair, err := NewRealityKeyPair()
		if err != nil {
			t.Fatal(err)
		}
		for _, key := range []string{pair.PrivateKey, pair.PublicKey} {
			if len(key) != 43 {
				t.Fatalf("reality key is not 43 characters: %q", key)
			}
			raw, err := base64.RawURLEncoding.DecodeString(key)
			if err != nil || len(raw) != 32 {
				t.Fatalf("reality key is not 32 bytes: %v, %d", err, len(raw))
			}
		}
		if err = validateRealityKeyPair(pair.PrivateKey, pair.PublicKey); err != nil {
			t.Fatalf("generated pair does not match: %v", err)
		}
		if _, ok := seen[pair.PrivateKey]; ok {
			t.Fatal("duplicate REALITY private key")
		}
		seen[pair.PrivateKey] = struct{}{}
	}
}

func TestRealityKeyValidationRejectsMismatchAndZero(t *testing.T) {
	first, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	second, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err = validateRealityKeyPair(first.PrivateKey, second.PublicKey); err == nil {
		t.Fatal("mismatched REALITY key pair accepted")
	}
	zero := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	if err = validateRealityKeyPair(zero, zero); err == nil {
		t.Fatal("zero REALITY key accepted")
	}
	for _, key := range []string{
		"",
		first.PrivateKey[:42],
		first.PrivateKey + "=",
		first.PrivateKey[:42] + "+",
		first.PrivateKey[:42] + "/",
		strings.Repeat("A", 42),
	} {
		if err = validateRealityKeyPair(key, first.PublicKey); err == nil {
			t.Fatalf("malformed private key accepted: %q", key)
		}
		if err = validateRealityKeyPair(first.PrivateKey, key); err == nil {
			t.Fatalf("malformed public key accepted: %q", key)
		}
	}
}

func TestNewShortIDIsCanonicalAndUnique(t *testing.T) {
	seen := make(map[string]struct{}, 64)
	for i := 0; i < 64; i++ {
		shortID, err := NewShortID()
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateShortID(shortID); err != nil {
			t.Fatal(err)
		}
		if shortID != strings.ToLower(shortID) {
			t.Fatalf("short ID is not lowercase: %q", shortID)
		}
		if _, ok := seen[shortID]; ok {
			t.Fatal("duplicate short ID")
		}
		seen[shortID] = struct{}{}
	}
	for _, value := range []string{
		"",
		strings.Repeat("a", 15),
		strings.Repeat("a", 17),
		strings.Repeat("A", 16),
		strings.Repeat("g", 16),
		"0123456789abcde_",
	} {
		if err := ValidateShortID(value); err == nil {
			t.Fatalf("invalid short ID accepted: %q", value)
		}
	}
}
