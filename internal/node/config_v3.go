package node

// The v3 candidate document is the v2 REALITY document plus the resolved
// server route fragment of a Line. The fragment is non-secret policy output
// assembled by the Hub: matchers, pinned rule-set references and the final
// egress tag. It carries no credential, endpoint or key, and it is the only
// way a server route reaches the Line: the Agent compiles the immutable
// candidate, so a route that never enters the document would never be applied.
//
// v1 and v2 stay byte-identical. A v3 document is accepted only with the exact
// nine fields and a strictly validated route object; an unknown, missing or
// malformed field is rejected instead of being reinterpreted.

import (
	"bytes"
	"encoding/json"
	"errors"
)

const (
	// CandidateSchemaV3 is the strict v3 candidate schema identifier.
	CandidateSchemaV3 = "meshmux-node/v3"
	// maxCandidateRouteBytes bounds one route fragment. It is far below the
	// 1 MiB candidate body bound because a route is a few hundred bytes of
	// matchers; an oversized fragment is a Hub defect, not a policy.
	maxCandidateRouteBytes = 16 << 10
)

var candidateRouteKeys = map[string]struct{}{
	"rules":    {},
	"rule_set": {},
	"final":    {},
}

// validateCandidateRoute proves the fragment is one server route object: a
// required rules array, an optional rule_set array and one final egress tag. The Hub's sing-box check proves the kernel schema and the Hub's Out
// gate proves the egress contract; this check only refuses a shape that could
// smuggle a non-route field into the candidate document.
func validateCandidateRoute(raw []byte) error {
	invalid := errors.New("CANDIDATE_ROUTE_INVALID: the route must be one server route object")
	if len(raw) == 0 || len(raw) > maxCandidateRouteBytes {
		return invalid
	}
	obj, err := decodeExactObject(raw)
	if err != nil {
		return invalid
	}
	for key := range obj {
		if _, ok := candidateRouteKeys[key]; !ok {
			return invalid
		}
	}
	var final string
	if err = decodeStringField(obj["final"], &final); err != nil || final == "" || len(final) > 64 {
		return invalid
	}
	// An all-direct policy renders no rules, so an empty array is legal; the
	// key itself is required, because a fragment without it would leave the
	// kernel on its own default instead of the policy's final egress.
	rulesRaw, ok := obj["rules"]
	if !ok {
		return invalid
	}
	var rules []map[string]json.RawMessage
	if err = json.Unmarshal(rulesRaw, &rules); err != nil || rules == nil || len(rules) > 256 {
		return invalid
	}
	for _, rule := range rules {
		if err = validateRouteEntry(rule, "outbound", true); err != nil {
			return invalid
		}
	}
	if setRaw, ok := obj["rule_set"]; ok {
		var sets []map[string]json.RawMessage
		if err = json.Unmarshal(setRaw, &sets); err != nil || len(sets) > 64 {
			return invalid
		}
		for _, set := range sets {
			if err = validateRouteEntry(set, "", false); err != nil {
				return invalid
			}
		}
	}
	return nil
}

// validateRouteEntry checks one rules or rule_set element. Every value must be
// one bounded string or an array of bounded strings, so no nested object,
// number, null or oversized value enters the candidate document.
func validateRouteEntry(entry map[string]json.RawMessage, required string, outbound bool) error {
	invalid := errors.New("CANDIDATE_ROUTE_INVALID: malformed route entry")
	if len(entry) == 0 || len(entry) > 8 {
		return invalid
	}
	for key, value := range entry {
		if key == "" || len(key) > 32 || !isLowerSnake(key) {
			return invalid
		}
		if outbound && key == required {
			var tag string
			if json.Unmarshal(value, &tag) != nil || tag == "" || len(tag) > 64 {
				return invalid
			}
			continue
		}
		if err := validateRouteValue(value); err != nil {
			return invalid
		}
	}
	if outbound {
		if _, ok := entry[required]; !ok {
			return invalid
		}
	}
	return nil
}

func validateRouteValue(raw json.RawMessage) error {
	var scalar string
	if json.Unmarshal(raw, &scalar) == nil {
		if scalar == "" || len(scalar) > 512 {
			return errors.New("invalid")
		}
		return nil
	}
	var list []string
	if json.Unmarshal(raw, &list) != nil || len(list) == 0 || len(list) > 1024 {
		return errors.New("invalid")
	}
	for _, value := range list {
		if value == "" || len(value) > 512 {
			return errors.New("invalid")
		}
	}
	return nil
}

func isLowerSnake(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' {
			continue
		}
		return false
	}
	return true
}

// compactCandidateRoute validates the fragment and returns its compact form, so
// two equal routes always compare and hash equal regardless of whitespace.
func compactCandidateRoute(raw []byte) (json.RawMessage, error) {
	if err := validateCandidateRoute(raw); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := json.Compact(&out, raw); err != nil {
		return nil, errors.New("CANDIDATE_ROUTE_INVALID: the route is not valid JSON")
	}
	return json.RawMessage(out.Bytes()), nil
}

// unmarshalV3 decodes the v2 fields plus the route. It reuses the v2 decoder
// with a rewritten schema instead of duplicating the strict field decoding,
// then re-applies the v3 schema and the route check. The Hub-issued out
// egress rides the v2 half, so it is accepted here exactly as there.
func (d *CandidateDocument) unmarshalV3(obj map[string]json.RawMessage) error {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version", "users", "reality", "route"}
	if len(obj) != len(required) && (len(obj) != len(required)+1 || !hasOutField(obj)) {
		return errors.New(malformed)
	}
	base := make(map[string]json.RawMessage, len(required))
	for _, name := range required {
		value, ok := obj[name]
		if !ok {
			return errors.New(malformed)
		}
		if name != "route" {
			base[name] = value
		}
	}
	if hasOutField(obj) {
		base["out"] = obj["out"]
	}
	base["schema"] = json.RawMessage(`"` + CandidateSchemaV2 + `"`)
	if err := d.unmarshalV2(base); err != nil {
		return err
	}
	route, err := compactCandidateRoute(obj["route"])
	if err != nil {
		return err
	}
	d.Schema = CandidateSchemaV3
	d.Route = route
	return d.Validate()
}
