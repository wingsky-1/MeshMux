package subscription

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
)

const (
	realityKeyBytes = 32
	realityKeyChars = 43
	shortIDBytes    = 8
	shortIDChars    = 16
)

// RealityKeyPair is the canonical textual form of one X25519 key pair used by
// a REALITY transport. PrivateKey is secret and must not be logged.
type RealityKeyPair struct {
	PrivateKey string
	PublicKey  string
}

// NewRealityKeyPair generates an X25519 key pair and returns canonical
// unpadded base64url encodings of both keys.
func NewRealityKeyPair() (RealityKeyPair, error) {
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return RealityKeyPair{}, errors.New("REALITY_KEY_GENERATION_FAILED")
	}
	pair := RealityKeyPair{
		PrivateKey: base64.RawURLEncoding.EncodeToString(key.Bytes()),
		PublicKey:  base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes()),
	}
	if err = validateRealityKeyPair(pair.PrivateKey, pair.PublicKey); err != nil {
		return RealityKeyPair{}, errors.New("REALITY_KEY_GENERATION_FAILED")
	}
	return pair, nil
}

// NewShortID returns a random 16-character lowercase hexadecimal REALITY short
// ID (64 bits from crypto/rand).
func NewShortID() (string, error) {
	var raw [shortIDBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("SHORT_ID_GENERATION_FAILED")
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidateShortID accepts exactly 16 lowercase hexadecimal characters.
func ValidateShortID(value string) error {
	if len(value) != shortIDChars {
		return errors.New("SHORT_ID_INVALID: need 16 lowercase hex characters")
	}
	for i := 0; i < len(value); i++ {
		if !isLowerHex(value[i]) {
			return errors.New("SHORT_ID_INVALID: need 16 lowercase hex characters")
		}
	}
	return nil
}

func parseRealityKey(value string) ([]byte, error) {
	if len(value) != realityKeyChars {
		return nil, errors.New("REALITY_KEY_INVALID")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != realityKeyBytes || base64.RawURLEncoding.EncodeToString(decoded) != value || allZero(decoded) {
		return nil, errors.New("REALITY_KEY_INVALID")
	}
	return decoded, nil
}

// validateRealityKeyPair checks canonical encoding, non-zero keys and that the
// public key is the X25519 peer derived from the private key. A mismatched pair
// would produce a REALITY listener that no client could use.
func validateRealityKeyPair(privateKey, publicKey string) error {
	privateBytes, err := parseRealityKey(privateKey)
	if err != nil {
		return errors.New("LINE_PRIVATE_KEY_INVALID: need a canonical non-zero base64url X25519 key")
	}
	publicBytes, err := parseRealityKey(publicKey)
	if err != nil {
		return errors.New("LINE_PUBLIC_KEY_INVALID: need a canonical non-zero base64url X25519 key")
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return errors.New("LINE_PRIVATE_KEY_INVALID: need a canonical non-zero base64url X25519 key")
	}
	if !bytes.Equal(key.PublicKey().Bytes(), publicBytes) {
		return errors.New("LINE_KEY_PAIR_MISMATCH: private_key and public_key must be one X25519 pair")
	}
	return nil
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}
