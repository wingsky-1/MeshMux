package node

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
)

// OutLinkMethod is the pinned Shadowsocks method of the Line→Out double-hop.
// Under Ruling R7 the path is never bare VLESS on the public internet.
const OutLinkMethod = "2022-blake3-aes-128-gcm"

// outLinkKeyBytes is the raw length of one link key. The 128-gcm method
// requires exactly 16 bytes on the dial side: `sing-box check` refuses any
// other length with "bad key length, required 16". (Ruling R7 names 32 bytes,
// which the kernel's outbound gate rejects; the method pins the length.)
const outLinkKeyBytes = 16

// OutEgress is the Hub-issued dial body of one Line's "out" outbound: the
// selected Out node's address/port plus the SS link key.
//
// The endpoint is the Out the binding names, never the Line itself: rendering
// the Line address here would silently turn the Out path into a Line egress,
// the leak the fail-closed block stub exists to prevent. The key is a node
// secret in the same class as the per-Line VLESS UUIDs and the REALITY
// private key: it travels only over the authenticated Hub<->Agent channel
// (inside the immutable candidate document) and is never written to a public
// response, a subscription artifact or a generic log line.
//
// UUID is the void Task-2 shape (a VLESS client credential). Stored
// documents rendered before the SS switch keep decoding and rendering
// byte-identical VLESS bytes, so their pinned digests still verify; the void
// credential no longer authenticates anywhere because the Out side is
// SS-only. New issuances always carry Key. The two never mix.
type OutEgress struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
	Key    string `json:"key,omitempty"`
	UUID   string `json:"uuid,omitempty"`
}

// NewOutLinkKey issues one random link key: 16 bytes, base64-std encoded. It
// never derives from anything guessable; every transport set mints fresh
// entropy and an address update preserves it.
func NewOutLinkKey() (string, error) {
	var raw [outLinkKeyBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("OUT_LINK_KEY_FAILED: the link key could not be issued")
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

// ValidateOutLinkKey checks the encoded shape of one link key: canonical
// base64-std decoding to exactly the method's 16 bytes.
func ValidateOutLinkKey(key string) error {
	const invalid = "OUT_EGRESS_INVALID: out link key must be 16 random bytes in base64-std"
	if len(key) == 0 || len(key) > 64 {
		return errors.New(invalid)
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != outLinkKeyBytes || base64.StdEncoding.EncodeToString(raw) != key {
		return errors.New(invalid)
	}
	return nil
}

// Validate checks the egress shape: one IP address or lowercase DNS name, one
// bounded port, and exactly one credential — the SS link key for new
// egresses, the void VLESS UUID only for stored history.
func (e OutEgress) Validate() error {
	if !validRealityHost(e.Server) {
		return errors.New("OUT_EGRESS_INVALID: need one IP address or lowercase DNS name without scheme, path, port or credentials")
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("OUT_EGRESS_INVALID: out port must be 1-65535")
	}
	switch {
	case e.Key != "" && e.UUID != "":
		return errors.New("OUT_EGRESS_INVALID: out credential must be either the link key or the legacy UUID, never both")
	case e.Key != "":
		return ValidateOutLinkKey(e.Key)
	case e.UUID != "":
		if !uuidV4Pattern.MatchString(e.UUID) {
			return errors.New("OUT_EGRESS_INVALID: out credential must be a canonical lowercase UUIDv4")
		}
		return nil
	default:
		return errors.New("OUT_EGRESS_INVALID: out credential must be a Hub-issued link key")
	}
}
