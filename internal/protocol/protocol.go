// Package protocol freezes the Hub <-> node management protocol for Issue #6.
// PR A (this change) freezes schema, identity model and allowlist only.
// Host apply, sing-box control and Out ACL belong to PR B and must not be
// added here. Upgrade/rollback kinds are reserved for Issue #11 and are
// explicitly rejected by ValidateTask.
package protocol

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Frozen protocol identifiers. Issue #11 reuses these without modification.
const (
	Schema  = "meshmux-agent/v1"
	Version = "1.0"
	// SingBoxVersion documents the only代理内核 expected by Phase 2B.
	// Enforcement (check/stage/apply/readback) lands in PR B.
	SingBoxVersion = "1.14.3"
	// PairingTTLSeconds bounds a one-time code lifetime. The Hub store
	// enforces expiry; this constant keeps docs and tests aligned.
	PairingTTLSeconds = 15 * 60
)

// Allowlisted task kinds. Anything else — including upgrade/rollback,
// arbitrary shell, URL or path operations — must be rejected.
const (
	KindConfigCheck    = "config.check"
	KindConfigStage    = "config.stage"
	KindConfigApply    = "config.apply"
	KindConfigReadback = "config.readback"
	KindHealthStatus   = "health.status"
	KindNodeStatus     = "node.status"
)

// Allowlist is the single source of truth for permitted remote behavior.
// Keep it private: callers must use ValidateTask instead of mutating a shared,
// process-wide map at runtime.
var allowlist = map[string]struct{}{
	KindConfigCheck:    {},
	KindConfigStage:    {},
	KindConfigApply:    {},
	KindConfigReadback: {},
	KindHealthStatus:   {},
	KindNodeStatus:     {},
}

// PublicationKinds is the fixed four-task publication chain of one candidate
// revision, in order. It mirrors the four config kinds already permitted by
// allowlist; it is exported only so chain producers and consumers share one
// source instead of repeating the same four literals.
var PublicationKinds = []string{
	KindConfigCheck,
	KindConfigStage,
	KindConfigApply,
	KindConfigReadback,
}

// Result statuses travel Hub -> Web and Agent -> Hub. partial/failed force
// explicit recovery; success is never inferred from delivery alone.
var resultStatuses = map[string]struct{}{
	"pending":     {},
	"applying":    {},
	"verifying":   {},
	"healthy":     {},
	"partial":     {},
	"failed":      {},
	"rolled_back": {},
}

var (
	hex32      = regexp.MustCompile(`^[a-f0-9]{32}$`)
	paramKey   = regexp.MustCompile(`^[a-z_]{1,32}$`)
	errorCode  = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	token43    = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	nodeRoleOK = map[string]struct{}{"edge": {}, "out": {}}
)

// Task is the frozen envelope. Every field is mandatory so Issue #11 can
// reuse operation_id/revision/idempotency without a protocol rewrite.
type Task struct {
	Schema         string          `json:"schema"`
	Version        string          `json:"version"`
	OperationID    string          `json:"operation_id"`
	Revision       int64           `json:"revision"`
	IdempotencyKey string          `json:"idempotency_key"`
	NodeID         string          `json:"node_id"`
	Kind           string          `json:"kind"`
	Params         json.RawMessage `json:"params"`
}

// TaskResult is reported by the Agent. Hub treats unknown operation IDs
// and unallowlisted statuses as rejections, not silent acceptance.
type TaskResult struct {
	OperationID string `json:"operation_id"`
	Status      string `json:"status"`
	ErrorCode   string `json:"error_code,omitempty"`
	Detail      string `json:"detail,omitempty"`
}

// PairingRequest is sent by the Agent over outbound HTTPS. The pairing code
// travels in the JSON body, never in argv, URL query or logs.
type PairingRequest struct {
	NodeID        string `json:"node_id"`
	Role          string `json:"role"`
	PairingCode   string `json:"pairing_code"`
	AgentVersion  string `json:"agent_version"`
	KernelVersion string `json:"kernel_version"`
}

// HeartbeatRequest is the strict typed heartbeat body. It carries only the
// agent and kernel versions; identity comes from the Bearer credential.
type HeartbeatRequest struct {
	AgentVersion  string `json:"agent_version"`
	KernelVersion string `json:"kernel_version"`
}

func (t *Task) UnmarshalJSON(data []byte) error {
	obj, err := decodeJSONObject(data, true)
	if err != nil {
		return errors.New("TASK_INVALID: malformed or overlapping fields")
	}
	if err := requireFields(obj, "schema", "version", "operation_id", "revision", "idempotency_key", "node_id", "kind", "params"); err != nil {
		return errors.New("TASK_INVALID: malformed or overlapping fields")
	}
	var decoded Task
	if err := decodeExactFields(obj, []fieldSpec{
		{"schema", &decoded.Schema},
		{"version", &decoded.Version},
		{"operation_id", &decoded.OperationID},
		{"revision", &decoded.Revision},
		{"idempotency_key", &decoded.IdempotencyKey},
		{"node_id", &decoded.NodeID},
		{"kind", &decoded.Kind},
		{"params", &decoded.Params},
	}); err != nil {
		return errors.New("TASK_INVALID: field type invalid")
	}
	*t = decoded
	return nil
}

func (r *TaskResult) UnmarshalJSON(data []byte) error {
	obj, err := decodeJSONObject(data, true)
	if err != nil {
		return errors.New("RESULT_INVALID: malformed or overlapping fields")
	}
	if err := allowFields(obj, "operation_id", "status", "error_code", "detail"); err != nil {
		return errors.New("RESULT_INVALID: malformed or overlapping fields")
	}
	if _, ok := obj["operation_id"]; !ok {
		return errors.New("RESULT_INVALID: missing operation_id")
	}
	var decoded TaskResult
	if err := decodeExactFields(obj, []fieldSpec{
		{"operation_id", &decoded.OperationID},
		{"status", &decoded.Status},
		{"error_code", &decoded.ErrorCode},
		{"detail", &decoded.Detail},
	}); err != nil {
		return errors.New("RESULT_INVALID: field type invalid")
	}
	*r = decoded
	return nil
}

func (r *PairingRequest) UnmarshalJSON(data []byte) error {
	obj, err := decodeJSONObject(data, true)
	if err != nil {
		return errors.New("PAIRING_INVALID: malformed or overlapping fields")
	}
	if err := requireFields(obj, "node_id", "role", "pairing_code", "agent_version", "kernel_version"); err != nil {
		return errors.New("PAIRING_INVALID: malformed or overlapping fields")
	}
	var decoded PairingRequest
	if err := decodeExactFields(obj, []fieldSpec{
		{"node_id", &decoded.NodeID},
		{"role", &decoded.Role},
		{"pairing_code", &decoded.PairingCode},
		{"agent_version", &decoded.AgentVersion},
		{"kernel_version", &decoded.KernelVersion},
	}); err != nil {
		return errors.New("PAIRING_INVALID: field type invalid")
	}
	*r = decoded
	return nil
}

func (r *HeartbeatRequest) UnmarshalJSON(data []byte) error {
	obj, err := decodeJSONObject(data, true)
	if err != nil {
		return errors.New("HEARTBEAT_INVALID: malformed or overlapping fields")
	}
	if err := requireFields(obj, "agent_version", "kernel_version"); err != nil {
		return errors.New("HEARTBEAT_INVALID: malformed or overlapping fields")
	}
	if bytes.Equal(bytes.TrimSpace(obj["agent_version"]), []byte("null")) ||
		bytes.Equal(bytes.TrimSpace(obj["kernel_version"]), []byte("null")) {
		return errors.New("HEARTBEAT_INVALID: field type invalid")
	}
	var decoded HeartbeatRequest
	if err := decodeExactFields(obj, []fieldSpec{
		{"agent_version", &decoded.AgentVersion},
		{"kernel_version", &decoded.KernelVersion},
	}); err != nil {
		return errors.New("HEARTBEAT_INVALID: field type invalid")
	}
	*r = decoded
	return nil
}

// Validate checks the two heartbeat versions without requiring pairing fields.
func (r HeartbeatRequest) Validate() error {
	if !validVersionString(r.AgentVersion) || !validVersionString(r.KernelVersion) {
		return errors.New("VERSION_INVALID: agent and kernel versions must be 1-64 printable characters")
	}
	return nil
}

// NewID returns an immutable 32-hex node or operation identifier.
func NewID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// NewSecret returns a 43-char URL-safe secret for pairing codes and node
// identity tokens (256-bit entropy, typable via paste into stdin).
func NewSecret() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// ValidateNodeInputs checks admin-supplied node fields before persistence.
func ValidateNodeInputs(role, displayName string, vlessPort, sshPort int) error {
	if _, ok := nodeRoleOK[role]; !ok {
		return errors.New("ROLE_INVALID: role must be edge or out")
	}
	if err := ValidateNodeDisplayName(displayName); err != nil {
		return err
	}
	if vlessPort < 1 || vlessPort > 65535 || sshPort < 1 || sshPort > 65535 {
		return errors.New("PORT_INVALID: VLESS and SSH ports must be 1-65535")
	}
	if vlessPort == sshPort {
		return errors.New("PORT_CONFLICT: VLESS and SSH ports must differ")
	}
	return nil
}

// ValidateNodeDisplayName checks the hub-visible label of one node. The HTTP
// proxy node (Ruling R11) has no ports, so its create path validates the name
// with this helper instead of the full agent-node input contract.
func ValidateNodeDisplayName(displayName string) error {
	name := strings.TrimSpace(displayName)
	if utf8.RuneCountInString(name) < 1 || utf8.RuneCountInString(name) > 64 {
		return errors.New("DISPLAY_NAME_INVALID: use 1-64 characters")
	}
	for _, r := range name {
		if !strconv.IsPrint(r) {
			return errors.New("DISPLAY_NAME_INVALID: non-printable characters rejected")
		}
	}
	return nil
}

// ValidatePairingRequest rejects wrong roles, malformed IDs and oversized
// version strings before any secret comparison happens.
func ValidatePairingRequest(req PairingRequest) error {
	if !hex32.MatchString(req.NodeID) {
		return errors.New("PAIRING_INVALID: unknown node")
	}
	if _, ok := nodeRoleOK[req.Role]; !ok {
		return errors.New("ROLE_MISMATCH: node role does not match pairing record")
	}
	if !token43.MatchString(req.PairingCode) {
		return errors.New("PAIRING_INVALID: pairing code rejected")
	}
	if !validVersionString(req.AgentVersion) || !validVersionString(req.KernelVersion) {
		return errors.New("VERSION_INVALID: agent and kernel versions must be 1-64 printable characters")
	}
	return nil
}

func validVersionString(s string) bool {
	if len(s) < 1 || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !strconv.IsPrint(r) {
			return false
		}
	}
	return true
}

// ValidateTask enforces the frozen allowlist. Upgrade/rollback are reserved
// for Issue #11 and rejected here so no caller can smuggle them in early.
func ValidateTask(t Task) error {
	if t.Schema != Schema {
		return errors.New("TASK_SCHEMA_INVALID: expected meshmux-agent/v1")
	}
	if t.Version != Version {
		return errors.New("TASK_VERSION_INVALID: expected 1.0")
	}
	if !hex32.MatchString(t.OperationID) {
		return errors.New("OPERATION_ID_INVALID: need 32 lowercase hex")
	}
	if t.Revision < 1 {
		return errors.New("REVISION_INVALID: revision must be a positive monotonic integer")
	}
	if !hex32.MatchString(t.IdempotencyKey) && !token43.MatchString(t.IdempotencyKey) {
		return errors.New("IDEMPOTENCY_INVALID: need 32 hex or 43-char secret")
	}
	if !hex32.MatchString(t.NodeID) {
		return errors.New("NODE_INVALID: unknown node")
	}
	if strings.HasPrefix(t.Kind, "upgrade.") || strings.HasPrefix(t.Kind, "rollback.") {
		return errors.New("UPGRADE_NOT_IMPLEMENTED: upgrade/rollback reserved for Issue #11")
	}
	if _, ok := allowlist[t.Kind]; !ok {
		return errors.New("TASK_KIND_REJECTED: kind is not in the fixed allowlist")
	}
	return validateParams(t.Kind, t.Params)
}

// decodeJSONObject ensures a value is exactly one JSON object and that every
// key appears once, including duplicate spellings created through escapes.
// Protocol keys are either lower_snake_case envelope names or param names.
func decodeJSONObject(raw json.RawMessage, exactKeys bool) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected JSON object")
	}
	obj := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("expected JSON object")
		}
		if exactKeys && !paramKey.MatchString(key) {
			return nil, errors.New("key is not lower_snake_case")
		}
		if _, exists := obj[key]; exists {
			return nil, errors.New("duplicate key")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		obj[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return obj, nil
}

func requireFields(obj map[string]json.RawMessage, names ...string) error {
	if len(obj) != len(names) {
		return errors.New("field count mismatch")
	}
	return allowFields(obj, names...)
}

func allowFields(obj map[string]json.RawMessage, names ...string) error {
	allowed := make(map[string]struct{}, len(names))
	for _, name := range names {
		allowed[name] = struct{}{}
	}
	for name := range obj {
		if _, ok := allowed[name]; !ok {
			return errors.New("unknown field")
		}
	}
	return nil
}

type fieldSpec struct {
	name string
	dst  any
}

// decodeExactFields avoids encoding/json's case-insensitive field matching
// after the object has been checked for exact keys.
func decodeExactFields(obj map[string]json.RawMessage, fields []fieldSpec) error {
	for _, field := range fields {
		value, ok := obj[field.name]
		if !ok {
			continue
		}
		if err := json.Unmarshal(value, field.dst); err != nil {
			return err
		}
	}
	return nil
}

// validateParams allowlists task parameters. No shell, URL, path, command or
// free-form script field exists by design; unknown keys are rejected.
func validateParams(kind string, raw json.RawMessage) error {
	if len(raw) > 4096 {
		return errors.New("PARAMS_TOO_LARGE: params limited to 4KiB")
	}
	if len(raw) == 0 {
		return errors.New("PARAMS_INVALID: params must be a JSON object")
	}
	obj, err := decodeParamsObject(raw)
	if err != nil {
		return err
	}
	for key, v := range obj {
		if key == allowedSourcesParam && configTaskKind(kind) {
			// Validated as an array below; every other config param stays a
			// scalar.
			continue
		}
		var s string
		var n float64
		var b bool
		switch {
		case json.Unmarshal(v, &s) == nil:
			if len(s) > 256 || strings.ContainsRune(s, 0) {
				return errors.New("PARAMS_INVALID: string value too long or contains NUL")
			}
		case json.Unmarshal(v, &n) == nil:
			// Numeric values accepted; kind-specific checks below bound them.
			if !isJSONNumber(v) {
				return errors.New("PARAMS_INVALID: numbers must be finite JSON numbers")
			}
		case json.Unmarshal(v, &b) == nil:
		default:
			return errors.New("PARAMS_INVALID: only string, number or boolean values allowed")
		}
	}
	switch kind {
	case KindHealthStatus, KindNodeStatus:
		if len(obj) != 0 {
			return errors.New("PARAMS_INVALID: status queries take no parameters")
		}
	case KindConfigCheck, KindConfigStage, KindConfigApply, KindConfigReadback:
		for key := range obj {
			if key != "revision" && key != allowedSourcesParam {
				return errors.New("PARAMS_INVALID: config tasks accept only revision and allowed_sources")
			}
		}
		if revRaw, ok := obj["revision"]; ok {
			if _, ok := parsePositiveInt64(revRaw); !ok {
				return errors.New("REVISION_INVALID: revision must be a positive integer")
			}
		}
		if sourcesRaw, ok := obj[allowedSourcesParam]; ok {
			if err := validateAllowedSources(sourcesRaw); err != nil {
				return err
			}
		}
	}
	return nil
}

// allowedSourcesParam is the one list-valued config parameter: the per-Line
// source allowlist the Hub authorizes for an Out revision. It is deliberately
// a bounded list of plain strings with no path, URL or shell meaning; the
// Agent re-validates every entry as an IP or CIDR before rendering a rule.
const allowedSourcesParam = "allowed_sources"

// maxAllowedSources bounds one allowlist envelope. The Agent renders at most
// one rule per entry, so the bound keeps params inside the frozen 4KiB body
// and the rendered table inside a single nft -f transaction.
const maxAllowedSources = 256

func configTaskKind(kind string) bool {
	switch kind {
	case KindConfigCheck, KindConfigStage, KindConfigApply, KindConfigReadback:
		return true
	}
	return false
}

// validateAllowedSources accepts one JSON array of source strings. Address
// semantics are checked where the ACL is rendered (ACL_SOURCE_INVALID); here
// only the envelope shape, count and length are bounded.
func validateAllowedSources(raw json.RawMessage) error {
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("PARAMS_INVALID: allowed_sources must be an array of strings")
	}
	var values []string
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&values); err != nil {
		return errors.New("PARAMS_INVALID: allowed_sources must be an array of strings")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("PARAMS_INVALID: allowed_sources must be an array of strings")
	}
	if len(values) > maxAllowedSources {
		return errors.New("PARAMS_INVALID: allowed_sources is too long")
	}
	for _, value := range values {
		if value == "" || len(value) > 64 || strings.ContainsRune(value, 0) {
			return errors.New("PARAMS_INVALID: allowed_sources entries must be 1-64 characters")
		}
	}
	return nil
}

// decodeParamsObject rejects invalid JSON, null/non-object values and duplicate
// keys. json.Unmarshal into a map would otherwise silently keep the last value
// for duplicate keys, including keys made equal through JSON escapes. Value
// shapes are checked by validateParams, which knows each kind's allowlist.
func decodeParamsObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	obj, err := decodeJSONObject(raw, true)
	if err != nil {
		return nil, errors.New("PARAMS_INVALID: params must be a JSON object")
	}
	return obj, nil
}

func isJSONNumber(raw json.RawMessage) bool {
	var n json.Number
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&n); err != nil {
		return false
	}
	if n.String() == "" {
		return false
	}
	var extra any
	return dec.Decode(&extra) == io.EOF
}

// parsePositiveInt64 accepts only a JSON integer token with a positive value.
// It deliberately rejects decimal or exponent spellings and checks the int64
// range before conversion.
func parsePositiveInt64(raw json.RawMessage) (int64, bool) {
	if !isJSONNumber(raw) {
		return 0, false
	}
	s := string(raw)
	if s == "" || s[0] == '-' || strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	rev, err := strconv.ParseInt(s, 10, 64)
	if err != nil || rev < 1 {
		return 0, false
	}
	return rev, true
}

// ValidateTaskResult rejects unknown statuses and malformed codes so partial
// and failed states stay explicit and queryable.
func ValidateTaskResult(res TaskResult) error {
	if !hex32.MatchString(res.OperationID) {
		return errors.New("OPERATION_ID_INVALID")
	}
	if _, ok := resultStatuses[res.Status]; !ok {
		return errors.New("STATUS_INVALID: unknown task status")
	}
	if res.ErrorCode != "" && !errorCode.MatchString(res.ErrorCode) {
		return errors.New("ERROR_CODE_INVALID")
	}
	if res.Status == "healthy" && res.ErrorCode != "" {
		return errors.New("ERROR_CODE_UNEXPECTED: healthy result cannot carry an error code")
	}
	if (res.Status == "partial" || res.Status == "failed") && res.ErrorCode == "" {
		return errors.New("ERROR_CODE_REQUIRED: partial and failed results require a stable error code")
	}
	if len(res.Detail) > 512 {
		return errors.New("DETAIL_TOO_LARGE")
	}
	for _, r := range res.Detail {
		if r < 0x20 && r != '\n' && r != '\t' || r == 0x7f {
			return errors.New("DETAIL_INVALID")
		}
	}
	return nil
}
