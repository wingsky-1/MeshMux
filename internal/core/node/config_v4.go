package node

import (
	"encoding/json"
	"errors"
)

// The v4 candidate document is the Out node's SS document: the frozen six
// fields plus the Hub-issued out egress that carries the link key. v1 stays
// the credential-free baseline for Out nodes without transport and for edge
// nodes without credentials; v4 is taken only when an Out has configured
// transport, so its Agent can render the SS guard instead of the VLESS
// baseline. v2 and v3 never carry an Out-role egress.
//
// v4 is strict like its siblings: exactly the seven frozen fields plus the
// required `out` object with the link key. An unknown, missing or malformed
// field is rejected instead of being reinterpreted.

const (
	// CandidateSchemaV4 is the strict v4 candidate schema identifier.
	CandidateSchemaV4 = "meshmux-node/v4"
)

// unmarshalV4 decodes the Out SS document: the frozen six fields plus the
// required out egress with the link key. No users, reality or route key may
// appear: those shapes belong to other schemas and other roles.
func (d *CandidateDocument) unmarshalV4(obj map[string]json.RawMessage) error {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version", "out"}
	if len(obj) != len(required) {
		return errors.New(malformed)
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return errors.New(malformed)
		}
	}

	var decoded CandidateDocument
	if err := decodeStringField(obj["schema"], &decoded.Schema); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if decoded.Schema != CandidateSchemaV4 {
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v4")
	}
	if err := decodeStringField(obj["node_id"], &decoded.NodeID); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	var role string
	if err := decodeStringField(obj["role"], &role); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	decoded.Role = Role(role)
	revision, err := decodePositiveInt64(obj["revision"])
	if err != nil {
		return errors.New("CANDIDATE_INVALID: revision must be a positive int64")
	}
	decoded.Revision = revision
	port, err := decodePositiveInt64(obj["vless_port"])
	if err != nil || port > 65535 {
		return errors.New("CANDIDATE_INVALID: VLESS port must be an integer")
	}
	decoded.VLESSPort = int(port)
	if err := decodeStringField(obj["kernel_version"], &decoded.KernelVersion); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	out, err := decodeOutEgress(obj["out"])
	if err != nil {
		return err
	}
	decoded.Out = out
	if err := decoded.Validate(); err != nil {
		return err
	}
	*d = decoded
	return nil
}
