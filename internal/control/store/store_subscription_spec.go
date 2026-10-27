package store

// The submitted selection is the store's external input boundary for the
// subscription wizard.
//
// Flow of every public entry that takes a SelectionSpec:
//
//	HTTP form (handler) -> SelectionSpec -> Normalize (shape + whitelist) ->
//	reference validation inside one transaction (existence + role + agreement)
//	-> draft/artifact assembly -> persistence
//
// Anti-corruption rules:
//   - the store never forwards the caller's struct: Normalize returns a fresh
//     canonical value, so a later caller mutation cannot change what is stored;
//   - every identifier must be the canonical 32-lowercase-hex shape;
//   - an Out is one of the two documented egress roles only (managed out,
//     external http) — any other node is refused rather than interpreted;
//   - rule revisions must be (stable_key, positive version) pairs; unknown
//     fields do not exist in this value type at all, and a JSON-facing caller
//     is required to decode with DisallowUnknownFields before it gets here.
//
// Normalize performs no I/O: existence, role and same-Line agreement are
// checked against the database in store_subscription_refs.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// RuleRevision is one pinned rule-library identity: rule_revision_id is exactly
// (StableKey, Version), the contract the rule library froze.
type RuleRevision struct {
	StableKey string
	Version   int
}

// SelectionSpec is one submitted selection: the four wizard groups.
type SelectionSpec struct {
	LineIDs    []string
	OutID      string
	Rules      []RuleRevision
	NetworkIDs []string
}

// Normalize validates the shape of one submitted selection and returns a
// canonical copy: trimmed identities, duplicates removed in first-seen order,
// dense positions implied by that order.
//
// It is the only place allowed to read caller slices, so no deeper function has
// to defend against a mutated or aliased request struct.
func (spec SelectionSpec) Normalize() (SelectionSpec, error) {
	lineIDs, err := normalizeLineSelection(spec.LineIDs)
	if err != nil {
		return SelectionSpec{}, err
	}
	ruleRevisions, err := normalizeRuleSelection(spec.Rules)
	if err != nil {
		return SelectionSpec{}, err
	}
	deviceIDs, err := normalizeDeviceSelection(spec.NetworkIDs)
	if err != nil {
		return SelectionSpec{}, err
	}
	outID, err := normalizeOutSelection(spec.OutID)
	if err != nil {
		return SelectionSpec{}, err
	}
	return SelectionSpec{LineIDs: lineIDs, OutID: outID, Rules: ruleRevisions, NetworkIDs: deviceIDs}, nil
}

// normalizeOutSelection accepts the empty slot or one canonical node id. The
// egress role whitelist (out, http) is enforced against the database, because
// only the stored row proves which role a node really has.
func normalizeOutSelection(raw string) (string, error) {
	outID := strings.TrimSpace(raw)
	if outID == "" {
		return "", nil
	}
	if err := subscription.ValidateID(outID); err != nil {
		return "", errors.New(CodeSelectionInvalid + ": out_id must be 32 lowercase hex characters")
	}
	return outID, nil
}

// selectionSpecDocument is the wire shape of one submitted selection. It is a
// separate type on purpose: the decoder below owns the field whitelist, so a
// request cannot reach SelectionSpec through an aliased struct.
type selectionSpecDocument struct {
	LineIDs    []string       `json:"line_ids"`
	OutID      string         `json:"out_id"`
	Rules      []ruleDocument `json:"rules"`
	NetworkIDs []string       `json:"network_ids"`
}

// ruleDocument is the wire shape of one pinned rule revision. Its fields match
// RuleRevision exactly, so the conversion below is a plain type conversion and
// the compiler keeps the two shapes in step.
type ruleDocument struct {
	StableKey string `json:"stable_key"`
	Version   int    `json:"version"`
}

// ParseSelectionSpec decodes one JSON selection body into a canonical
// SelectionSpec: unknown fields are refused, the body must be exactly one JSON
// object, and the result is Normalized before it is returned.
//
// A handler that accepts JSON for the wizard calls this instead of decoding into
// SelectionSpec directly, so the anti-corruption rules (shape, whitelist, no
// unknown field, no trailing document) hold even for a client that is not the
// Hub's own form.
func ParseSelectionSpec(raw []byte) (SelectionSpec, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return SelectionSpec{}, errors.New(CodeSelectionInvalid + ": the selection body is empty")
	}
	var document selectionSpecDocument
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return SelectionSpec{}, errors.New(CodeSelectionInvalid + ": the selection body must be the documented JSON")
	}
	if err := decoder.Decode(new(struct{})); err != io.EOF {
		return SelectionSpec{}, errors.New(CodeSelectionInvalid + ": the selection body must be one JSON object")
	}
	spec := SelectionSpec{LineIDs: document.LineIDs, OutID: document.OutID, NetworkIDs: document.NetworkIDs}
	for _, rule := range document.Rules {
		spec.Rules = append(spec.Rules, RuleRevision(rule))
	}
	return spec.Normalize()
}

// normalizeRuleSelection validates the identity shape and removes duplicates
// while keeping the caller's order.
func normalizeRuleSelection(revisions []RuleRevision) ([]RuleRevision, error) {
	if len(revisions) > maxSelectionRules {
		return nil, errors.New(CodeSelectionInvalid + ": select at most " + strconv.Itoa(maxSelectionRules) + " rules")
	}
	seen := make(map[string]struct{}, len(revisions))
	out := make([]RuleRevision, 0, len(revisions))
	for _, revision := range revisions {
		key := strings.TrimSpace(revision.StableKey)
		if key == "" || len(key) > 64 || revision.Version < 1 {
			return nil, errors.New(CodeSelectionInvalid + ": a rule needs a stable key and a positive version")
		}
		identity := key + "@" + strconv.Itoa(revision.Version)
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, RuleRevision{StableKey: key, Version: revision.Version})
	}
	return out, nil
}

// normalizeDeviceSelection validates the identity shape and removes duplicates
// while keeping the caller's order.
func normalizeDeviceSelection(deviceIDs []string) ([]string, error) {
	if len(deviceIDs) > maxSelectionDevices {
		return nil, errors.New(CodeSelectionInvalid + ": select at most " + strconv.Itoa(maxSelectionDevices) + " mesh devices")
	}
	seen := make(map[string]struct{}, len(deviceIDs))
	out := make([]string, 0, len(deviceIDs))
	for _, raw := range deviceIDs {
		deviceID := strings.TrimSpace(raw)
		if err := subscription.ValidateID(deviceID); err != nil {
			return nil, errMeshDeviceIDInvalid()
		}
		if _, duplicate := seen[deviceID]; duplicate {
			continue
		}
		seen[deviceID] = struct{}{}
		out = append(out, deviceID)
	}
	return out, nil
}
