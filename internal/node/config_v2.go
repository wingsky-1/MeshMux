package node

import (
	"bytes"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strings"
)

// The v1 candidate document is a frozen, non-secret, six-field shape. The v2
// document keeps those six fields byte-identical and appends exactly two
// blocks: the per-Line VLESS users and the REALITY listener configuration.
//
// v2 carries node secrets (per-Line VLESS UUIDs and the REALITY private key),
// so it only travels over the authenticated Hub<->Agent channel and stays
// inside the node's private file boundary. It is never written to a public
// response, a subscription artifact or a generic log line.

const (
	// CandidateSchemaV2 is the strict v2 candidate schema identifier.
	CandidateSchemaV2 = "meshmux-node/v2"

	// maxCandidateUsers bounds the per-Line user set of one candidate.
	maxCandidateUsers = 1024
)

var (
	credentialIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	shortIDPattern      = regexp.MustCompile(`^[a-f0-9]{16}$`)
	uuidV4Pattern       = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
)

// VLESSUser is one per-Line VLESS credential carried by a v2 candidate.
// CredentialID is the stable subscription-domain record identity; UUID is the
// client credential itself and is a node secret.
type VLESSUser struct {
	CredentialID string `json:"credential_id"`
	UUID         string `json:"uuid"`
}

// RealityConfig is the REALITY listener configuration carried by a v2
// candidate. PrivateKey is a node secret and never leaves the authenticated
// Hub<->Agent channel.
type RealityConfig struct {
	ServerName      string `json:"server_name"`
	HandshakeServer string `json:"handshake_server"`
	HandshakePort   int    `json:"handshake_port"`
	PrivateKey      string `json:"private_key"`
	ShortID         string `json:"short_id"`
}

// Validate checks the shape of one VLESS user. Uniqueness across the whole
// candidate is checked by the candidate validation, not here.
func (u VLESSUser) Validate() error {
	if !credentialIDPattern.MatchString(u.CredentialID) {
		return errors.New("CREDENTIAL_ID_INVALID: need 32 lowercase hex characters")
	}
	if !uuidV4Pattern.MatchString(u.UUID) {
		return errors.New("CREDENTIAL_UUID_INVALID: need a canonical lowercase UUIDv4")
	}
	return nil
}

// Validate checks the REALITY listener configuration. The handshake target is
// one IP address or one lowercase DNS name without scheme, port, path or
// credentials; the server name is one DNS name; the private key is one
// canonical, non-zero X25519 key.
func (r RealityConfig) Validate() error {
	if !validDNSName(r.ServerName) {
		return errors.New("REALITY_SERVER_NAME_INVALID: need one lowercase DNS name without scheme, path, port or credentials")
	}
	if !validRealityHost(r.HandshakeServer) {
		return errors.New("REALITY_HANDSHAKE_SERVER_INVALID: need one IP address or lowercase DNS name without scheme, path, port or credentials")
	}
	if r.HandshakePort < 1 || r.HandshakePort > 65535 {
		return errors.New("REALITY_HANDSHAKE_PORT_INVALID: handshake_port must be 1-65535")
	}
	if err := validateRealityPrivateKey(r.PrivateKey); err != nil {
		return err
	}
	if !shortIDPattern.MatchString(r.ShortID) {
		return errors.New("REALITY_SHORT_ID_INVALID: need 16 lowercase hex characters")
	}
	return nil
}

// validateRealityPrivateKey accepts only the canonical unpadded base64url
// encoding of one non-zero 32-byte X25519 private key. A padded, truncated or
// non-canonical encoding would silently produce a different key.
func validateRealityPrivateKey(value string) error {
	const invalid = "REALITY_PRIVATE_KEY_INVALID: need a canonical non-zero base64url X25519 private key"
	if len(value) != 43 {
		return errors.New(invalid)
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(raw) != 32 || base64.RawURLEncoding.EncodeToString(raw) != value {
		return errors.New(invalid)
	}
	if allZeroBytes(raw) {
		return errors.New(invalid)
	}
	if _, err = ecdh.X25519().NewPrivateKey(raw); err != nil {
		return errors.New(invalid)
	}
	return nil
}

func allZeroBytes(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

// validRealityHost accepts one IP address or one lowercase DNS name. A URL, a
// host with a port, path or credentials, and an invalid IPv4 spelling are
// rejected instead of being reinterpreted as a DNS name.
func validRealityHost(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if strings.ContainsAny(value, " \t\r\n/\\:?#@[]") || strings.HasSuffix(value, ".") {
		return false
	}
	if numericDottedHost(value) {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// validDNSName accepts one lowercase DNS name. An IP address is not a valid
// server name.
func validDNSName(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return false
	}
	if strings.ContainsAny(value, " \t\r\n/\\:?#@[]") || strings.HasSuffix(value, ".") {
		return false
	}
	if numericDottedHost(value) {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if !dnsLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// numericDottedHost reports an all-numeric dotted value such as 999.1.1.1,
// which is not a valid IP address and must not be read as a DNS name.
func numericDottedHost(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if label == "" {
			return false
		}
		for i := 0; i < len(label); i++ {
			if label[i] < '0' || label[i] > '9' {
				return false
			}
		}
	}
	return true
}

// validateV2Fields validates the optional v2 blocks of a candidate. The v1
// baseline (no users and no REALITY block) stays valid, users require a
// REALITY block, and both blocks belong to edge nodes only.
func (c Candidate) validateV2Fields() error {
	if c.Reality == nil && len(c.Users) == 0 && len(c.Route) == 0 {
		return nil
	}
	if c.Role != RoleEdge {
		return errors.New("CANDIDATE_INVALID: users, reality and a route are only valid for edge nodes")
	}
	if c.Reality == nil {
		return errors.New("REALITY_REQUIRED: reality is required when users or a route are present")
	}
	if len(c.Route) > 0 {
		if err := validateCandidateRoute(c.Route); err != nil {
			return err
		}
	}
	if err := c.Reality.Validate(); err != nil {
		return err
	}
	if len(c.Users) > maxCandidateUsers {
		return errors.New("CANDIDATE_INVALID: at most 1024 users are allowed")
	}
	ids := make(map[string]struct{}, len(c.Users))
	uuids := make(map[string]struct{}, len(c.Users))
	for _, user := range c.Users {
		if err := user.Validate(); err != nil {
			return err
		}
		if _, exists := ids[user.CredentialID]; exists {
			return errors.New("CREDENTIAL_ID_DUPLICATE: credential ids must be unique")
		}
		ids[user.CredentialID] = struct{}{}
		if _, exists := uuids[user.UUID]; exists {
			return errors.New("CREDENTIAL_UUID_DUPLICATE: VLESS UUIDs must be unique")
		}
		uuids[user.UUID] = struct{}{}
	}
	return nil
}

// decodeUsers decodes the users array of a v2 document. The array itself, the
// null value and every element are strict: an element is one object with
// exactly credential_id and uuid, and unknown, duplicate and null fields are
// rejected.
func decodeUsers(raw json.RawMessage) ([]VLESSUser, error) {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return nil, errors.New(malformed)
	}
	var elements []json.RawMessage
	if err := json.Unmarshal(trimmed, &elements); err != nil {
		return nil, errors.New(malformed)
	}
	users := make([]VLESSUser, 0, len(elements))
	for _, element := range elements {
		user, err := decodeVLESSUser(element)
		if err != nil {
			return nil, err
		}
		users = append(users, user)
	}
	return users, nil
}

func decodeVLESSUser(raw json.RawMessage) (VLESSUser, error) {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	obj, err := decodeExactObject(raw)
	if err != nil {
		return VLESSUser{}, errors.New(malformed)
	}
	required := []string{"credential_id", "uuid"}
	if len(obj) != len(required) {
		return VLESSUser{}, errors.New(malformed)
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return VLESSUser{}, errors.New(malformed)
		}
	}
	var user VLESSUser
	if err := decodeStringField(obj["credential_id"], &user.CredentialID); err != nil {
		return VLESSUser{}, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if err := decodeStringField(obj["uuid"], &user.UUID); err != nil {
		return VLESSUser{}, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	return user, nil
}

// decodeReality decodes the REALITY block of a v2 document. The block is one
// object with exactly the five frozen fields; unknown, duplicate and null
// fields are rejected.
func decodeReality(raw json.RawMessage) (*RealityConfig, error) {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New(malformed)
	}
	obj, err := decodeExactObject(trimmed)
	if err != nil {
		return nil, errors.New(malformed)
	}
	required := []string{"server_name", "handshake_server", "handshake_port", "private_key", "short_id"}
	if len(obj) != len(required) {
		return nil, errors.New(malformed)
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return nil, errors.New(malformed)
		}
	}
	var reality RealityConfig
	if err := decodeStringField(obj["server_name"], &reality.ServerName); err != nil {
		return nil, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if err := decodeStringField(obj["handshake_server"], &reality.HandshakeServer); err != nil {
		return nil, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	port, err := decodePositiveInt64(obj["handshake_port"])
	if err != nil || port > 65535 {
		return nil, errors.New("CANDIDATE_INVALID: handshake_port must be an integer")
	}
	reality.HandshakePort = int(port)
	if err := decodeStringField(obj["private_key"], &reality.PrivateKey); err != nil {
		return nil, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if err := decodeStringField(obj["short_id"], &reality.ShortID); err != nil {
		return nil, errors.New("CANDIDATE_INVALID: field type invalid")
	}
	return &reality, nil
}
