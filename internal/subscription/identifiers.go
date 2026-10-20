package subscription

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
)

// NewID returns a random 32-character lowercase hexadecimal identifier.
// It is used for stable Subscriber, Credential and token-record identities.
func NewID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("ID_GENERATION_FAILED")
	}
	return hex.EncodeToString(raw[:]), nil
}

// ValidateID accepts exactly 32 lowercase hexadecimal characters.
func ValidateID(value string) error {
	if len(value) != 32 {
		return errors.New("ID_INVALID: need 32 lowercase hex characters")
	}
	for i := 0; i < len(value); i++ {
		if !isLowerHex(value[i]) {
			return errors.New("ID_INVALID: need 32 lowercase hex characters")
		}
	}
	return nil
}

// NewUUID returns a random canonical lowercase UUIDv4.
func NewUUID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("UUID_GENERATION_FAILED")
	}
	raw[6] = raw[6]&0x0f | 0x40
	raw[8] = raw[8]&0x3f | 0x80
	encoded := hex.EncodeToString(raw[:])
	return encoded[:8] + "-" + encoded[8:12] + "-" + encoded[12:16] + "-" + encoded[16:20] + "-" + encoded[20:], nil
}

// ValidateUUID accepts only a canonical lowercase UUIDv4, including the
// RFC 4122 version and variant bits.
func ValidateUUID(value string) error {
	const invalid = "UUID_INVALID: need a canonical lowercase UUIDv4"
	if len(value) != 36 {
		return errors.New(invalid)
	}
	for i := 0; i < len(value); i++ {
		switch i {
		case 8, 13, 18, 23:
			if value[i] != '-' {
				return errors.New(invalid)
			}
		default:
			if !isLowerHex(value[i]) {
				return errors.New(invalid)
			}
		}
	}
	if value[14] != '4' {
		return errors.New(invalid)
	}
	switch value[19] {
	case '8', '9', 'a', 'b':
		return nil
	default:
		return errors.New(invalid)
	}
}

func isLowerHex(value byte) bool {
	return value >= '0' && value <= '9' || value >= 'a' && value <= 'f'
}
