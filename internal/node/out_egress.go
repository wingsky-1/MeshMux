package node

import "errors"

// OutEgress is the Hub-issued dial body of one Line's "out" outbound: the
// selected Out node's address/port plus the link credential the Hub signed.
//
// The endpoint is the Out the binding names, never the Line itself: rendering
// the Line address here would silently turn the Out path into a Line egress,
// the leak the fail-closed block stub exists to prevent. The credential is a
// node secret in the same class as the per-Line VLESS UUIDs and the REALITY
// private key: it travels only over the authenticated Hub<->Agent channel
// (inside the immutable candidate document) and is never written to a public
// response, a subscription artifact or a generic log line.
type OutEgress struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
	UUID   string `json:"uuid"`
}

// Validate checks the egress shape: one IP address or lowercase DNS name,
// one bounded port, one canonical UUIDv4 credential.
func (e OutEgress) Validate() error {
	if !validRealityHost(e.Server) {
		return errors.New("OUT_EGRESS_INVALID: need one IP address or lowercase DNS name without scheme, path, port or credentials")
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("OUT_EGRESS_INVALID: out port must be 1-65535")
	}
	if !uuidV4Pattern.MatchString(e.UUID) {
		return errors.New("OUT_EGRESS_INVALID: out credential must be a canonical lowercase UUIDv4")
	}
	return nil
}
