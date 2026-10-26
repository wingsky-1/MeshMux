package subscription

import (
	"crypto/rand"
	"encoding/hex"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
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

// ValidateID accepts exactly 32 lowercase hexadecimal characters. The spelling
// is the wire grammar's (protocol.ValidID): a credential id the Hub mints must
// be exactly what the node's candidate reader accepts.
func ValidateID(value string) error {
	if !protocol.ValidID(value) {
		return errors.New("ID_INVALID: need 32 lowercase hex characters")
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
// RFC 4122 version and variant bits. The spelling is the wire grammar's
// (protocol.ValidUUIDv4), so the Hub never mints a credential the Line's
// candidate reader would refuse.
func ValidateUUID(value string) error {
	if !protocol.ValidUUIDv4(value) {
		return errors.New("UUID_INVALID: need a canonical lowercase UUIDv4")
	}
	return nil
}
