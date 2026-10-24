package subscription

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestNewTokenHasFullEntropyShape(t *testing.T) {
	token, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 48 || strings.ContainsAny(token, "=+/") {
		t.Fatalf("token is not 48-character unpadded base64url (length %d)", len(token))
	}
	raw, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(raw) != 36 {
		t.Fatalf("token does not decode to 36 bytes: %v, %d", err, len(raw))
	}
	if err = ValidateToken(token); err != nil {
		t.Fatalf("generated token rejected: %v", err)
	}
	hash := TokenHash(token)
	sum := sha256.Sum256([]byte(token))
	if len(hash) != sha256.Size || !bytes.Equal(hash, sum[:]) {
		t.Fatal("TokenHash is not SHA-256 of the bearer")
	}
}

func TestValidateTokenRejectsMalformedBearers(t *testing.T) {
	valid, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	for _, token := range []string{
		"",
		valid[:47],
		valid + "A",
		valid[:47] + "=",
		valid[:47] + "+",
		valid[:47] + "/",
		valid[:47] + "\n",
		" " + valid[1:],
		strings.Repeat("A", 47),
	} {
		if err := ValidateToken(token); err == nil {
			t.Fatalf("malformed token accepted: %q", token)
		}
	}
}

func TestSubscriptionTokenValidation(t *testing.T) {
	subscriber, err := NewSubscriber("alice")
	if err != nil {
		t.Fatal(err)
	}
	record, _, err := NewSubscriptionToken(subscriber.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err = record.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*SubscriptionToken)
	}{
		{"bad record id", func(token *SubscriptionToken) { token.ID = "short" }},
		{"bad subscriber id", func(token *SubscriptionToken) { token.SubscriberID = strings.ToUpper(subscriber.ID) }},
		{"missing hash", func(token *SubscriptionToken) { token.Hash = nil }},
		{"short hash", func(token *SubscriptionToken) { token.Hash = token.Hash[:31] }},
		{"long hash", func(token *SubscriptionToken) { token.Hash = append(token.Hash, 0) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := record
			bad.Hash = append([]byte(nil), record.Hash...)
			tc.mutate(&bad)
			if err := bad.Validate(); err == nil {
				t.Fatal("invalid token record accepted")
			}
		})
	}
}
