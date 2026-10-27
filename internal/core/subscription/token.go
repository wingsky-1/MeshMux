package subscription

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

const (
	tokenBytes = 36
	tokenChars = 48
)

// SubscriptionToken is the persisted record for a subscription bearer. The
// bearer itself is returned once by NewSubscriptionToken and never stored
// here; Hash is the SHA-256 digest that persistence and lookup use. The token
// is deliberately separate from Credential.UUID.
type SubscriptionToken struct {
	ID           string
	SubscriberID string
	Hash         []byte
}

// NewToken returns a 48-character, unpadded base64url bearer carrying 288 bits
// from crypto/rand. Generation failure never falls back to a weaker source.
func NewToken() (string, error) {
	var raw [tokenBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("TOKEN_GENERATION_FAILED")
	}
	return base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

// ValidateToken accepts only a canonical 48-character unpadded base64url token
// that decodes to exactly 36 bytes.
func ValidateToken(token string) error {
	const invalid = "TOKEN_INVALID: need a canonical 48-character base64url bearer"
	if len(token) != tokenChars {
		return errors.New(invalid)
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(decoded) != tokenBytes || base64.RawURLEncoding.EncodeToString(decoded) != token {
		return errors.New(invalid)
	}
	return nil
}

// TokenHash returns the SHA-256 digest used to persist or look up a bearer.
// Call ValidateToken before accepting a token from an untrusted request.
func TokenHash(token string) []byte {
	sum := sha256.Sum256([]byte(token))
	return sum[:]
}

// NewSubscriptionToken creates a new token record and returns its plaintext
// bearer once. The caller must store only Hash and must not log the bearer.
func NewSubscriptionToken(subscriberID string) (SubscriptionToken, string, error) {
	if err := ValidateID(subscriberID); err != nil {
		return SubscriptionToken{}, "", errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	id, err := NewID()
	if err != nil {
		return SubscriptionToken{}, "", err
	}
	token, err := NewToken()
	if err != nil {
		return SubscriptionToken{}, "", err
	}
	record := SubscriptionToken{ID: id, SubscriberID: subscriberID, Hash: TokenHash(token)}
	if err = record.Validate(); err != nil {
		return SubscriptionToken{}, "", err
	}
	return record, token, nil
}

// Validate checks the record identity and the persisted digest shape.
func (t SubscriptionToken) Validate() error {
	if err := ValidateID(t.ID); err != nil {
		return errors.New("TOKEN_ID_INVALID: need 32 lowercase hex characters")
	}
	if err := ValidateID(t.SubscriberID); err != nil {
		return errors.New("TOKEN_SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	if len(t.Hash) != sha256.Size {
		return errors.New("TOKEN_HASH_INVALID: need a 32-byte SHA-256 digest")
	}
	return nil
}
