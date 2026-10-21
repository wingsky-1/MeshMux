// Package node defines the fixed host layout and data contracts shared by the
// Hub, the node installer and the node runtime, and it also owns the runtime
// half that acts on them. The contract side lives in config.go (fixed paths
// such as AgentBinaryPath and the unit names) and in render.go and release.go
// (CompileCandidate, KernelReleaseFor).
//
// The package does perform host I/O. runtime.go creates and inspects the
// layout directories with os.Lstat and os.Mkdir, files.go writes managed files
// through writeAtomic (os.Rename), command.go runs subprocesses through
// exec.CommandContext and holds the shared runtime flock (AcquireRuntimeLock),
// and ReadbackLocal in runtime_readback.go reads the live data plane back.
//
// The dependency direction is one way: node imports only internal/protocol.
// internal/web and internal/install import node; node never imports either.
package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

const (
	AgentBinaryPath     = "/usr/local/libexec/meshmuxd"
	SingBoxBinaryPath   = "/usr/local/libexec/meshmux-sing-box"
	AgentConfigPath     = "/etc/meshmux/agent.json"
	IdentityPath        = "/var/lib/meshmux-agent/identity.json"
	RuntimeStatePath    = "/var/lib/meshmux-agent/state.json"
	ActiveCandidatePath = "/var/lib/meshmux-agent/active-candidate.json"
	ActiveConfigPath    = "/var/lib/meshmux-singbox/config.json"
	// ACLPath is the managed Out VLESS guard script: the exact table
	// replacement including the Hub-authorized source accept rules. It is
	// applied as one nft -f transaction and read back through nft -j.
	ACLPath = "/var/lib/meshmux-agent/out.nft"

	AgentUnit   = "meshmux-agent.service"
	SingBoxUnit = "meshmux-sing-box.service"
	ACLUnit     = "meshmux-out-acl.service"
	ACLTable    = "meshmux_out"
)

const (
	CandidateSchema     = "meshmux-node/v1"
	CurrentAgentVersion = "1.0.0-dev"
)

// Role is the installed node purpose. Line is represented by "edge".
type Role string

const (
	RoleEdge Role = "edge"
	RoleOut  Role = "out"
)

// Config is the installer-owned, non-secret Agent configuration. Installed
// release fields remain empty until the fixed binaries have been verified.
type Config struct {
	HubURL       string `json:"hub_url"`
	NodeID       string `json:"node_id"`
	Role         Role   `json:"role"`
	VLESSPort    int    `json:"vless_port"`
	SSHPort      int    `json:"ssh_port"`
	AgentVersion string `json:"agent_version,omitempty"`
	AgentSHA256  string `json:"agent_sha256,omitempty"`
	KernelSHA256 string `json:"kernel_sha256,omitempty"`
}

// Identity is stored only in the private identity file.
type Identity struct {
	NodeID        string `json:"node_id"`
	IdentityToken string `json:"identity_token"`
}

// Metadata binds a node's immutable enrollment identity to its listener ports.
type Metadata struct {
	NodeID    string `json:"node_id"`
	Role      Role   `json:"role"`
	VLESSPort int    `json:"vless_port"`
	SSHPort   int    `json:"ssh_port"`
}

// Candidate is the complete dynamic configuration input. The first five
// fields are the frozen v1 baseline. Users and Reality are the v2 blocks:
// they carry node secrets, so a candidate that uses them only travels over the
// authenticated Hub<->Agent channel and never enters a public response, a
// subscription artifact or a generic log line.
type Candidate struct {
	NodeID        string         `json:"node_id"`
	Role          Role           `json:"role"`
	Revision      int64          `json:"revision"`
	VLESSPort     int            `json:"vless_port"`
	KernelVersion string         `json:"kernel_version"`
	Users         []VLESSUser    `json:"users,omitempty"`
	Reality       *RealityConfig `json:"reality,omitempty"`
}

// CandidateDocument is the exact JSON document used for the mutable active
// candidate and immutable candidate transport. Schema is meshmux-node/v1 for
// the frozen six-field non-secret baseline and meshmux-node/v2 for the
// baseline plus the users and reality blocks.
type CandidateDocument struct {
	Schema        string         `json:"schema"`
	NodeID        string         `json:"node_id"`
	Role          Role           `json:"role"`
	Revision      int64          `json:"revision"`
	VLESSPort     int            `json:"vless_port"`
	KernelVersion string         `json:"kernel_version"`
	Users         []VLESSUser    `json:"users,omitempty"`
	Reality       *RealityConfig `json:"reality,omitempty"`
}

// NewCandidateDocument binds a candidate to a schema identifier. A candidate
// without users and without a reality block stays on the frozen v1 document;
// anything else is written as a v2 document.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	document := CandidateDocument{
		Schema:        CandidateSchema,
		NodeID:        candidate.NodeID,
		Role:          candidate.Role,
		Revision:      candidate.Revision,
		VLESSPort:     candidate.VLESSPort,
		KernelVersion: candidate.KernelVersion,
	}
	if candidate.Reality == nil && len(candidate.Users) == 0 {
		return document
	}
	document.Schema = CandidateSchemaV2
	document.Users = candidate.Users
	if document.Users == nil {
		document.Users = []VLESSUser{}
	}
	document.Reality = candidate.Reality
	return document
}

// Candidate returns the validated configuration input represented by the
// document after the caller has run Validate.
func (d CandidateDocument) Candidate() Candidate {
	return Candidate{
		NodeID:        d.NodeID,
		Role:          d.Role,
		Revision:      d.Revision,
		VLESSPort:     d.VLESSPort,
		KernelVersion: d.KernelVersion,
		Users:         d.Users,
		Reality:       d.Reality,
	}
}

// MarshalJSON writes the frozen v1 document byte for byte as before, or the
// v2 document with the users and reality blocks. The v1 shape never carries
// the new fields, so an existing v1 revision keeps its exact bytes.
//
// The document is validated first, so an unknown schema or a document whose
// schema does not match its own users and reality blocks fails closed instead
// of silently dropping credentials.
func (d CandidateDocument) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	if d.Schema == CandidateSchemaV2 {
		type v2Document struct {
			Schema        string         `json:"schema"`
			NodeID        string         `json:"node_id"`
			Role          Role           `json:"role"`
			Revision      int64          `json:"revision"`
			VLESSPort     int            `json:"vless_port"`
			KernelVersion string         `json:"kernel_version"`
			Users         []VLESSUser    `json:"users"`
			Reality       *RealityConfig `json:"reality"`
		}
		users := d.Users
		if users == nil {
			users = []VLESSUser{}
		}
		return json.Marshal(v2Document{
			Schema:        d.Schema,
			NodeID:        d.NodeID,
			Role:          d.Role,
			Revision:      d.Revision,
			VLESSPort:     d.VLESSPort,
			KernelVersion: d.KernelVersion,
			Users:         users,
			Reality:       d.Reality,
		})
	}
	type v1Document struct {
		Schema        string `json:"schema"`
		NodeID        string `json:"node_id"`
		Role          Role   `json:"role"`
		Revision      int64  `json:"revision"`
		VLESSPort     int    `json:"vless_port"`
		KernelVersion string `json:"kernel_version"`
	}
	return json.Marshal(v1Document{
		Schema:        d.Schema,
		NodeID:        d.NodeID,
		Role:          d.Role,
		Revision:      d.Revision,
		VLESSPort:     d.VLESSPort,
		KernelVersion: d.KernelVersion,
	})
}

// Equal reports whether two documents carry exactly the same content. It
// replaces the direct struct comparison, which no longer compiles once the
// document owns a user slice.
func (d CandidateDocument) Equal(other CandidateDocument) bool {
	if d.Schema != other.Schema {
		return false
	}
	return d.Candidate().Equal(other.Candidate())
}

// Equal reports whether two candidates carry exactly the same content,
// including the optional v2 blocks.
func (c Candidate) Equal(other Candidate) bool {
	if c.NodeID != other.NodeID || c.Role != other.Role || c.Revision != other.Revision ||
		c.VLESSPort != other.VLESSPort || c.KernelVersion != other.KernelVersion {
		return false
	}
	if len(c.Users) != len(other.Users) {
		return false
	}
	for i := range c.Users {
		if c.Users[i] != other.Users[i] {
			return false
		}
	}
	if c.Reality == nil || other.Reality == nil {
		return c.Reality == nil && other.Reality == nil
	}
	return *c.Reality == *other.Reality
}

// Readback contains only local evidence. Its fields deliberately cannot claim
// public reachability, a real protocol handshake or client usability.
//
// OutDefaultDeny is the observed_out_default_deny the Hub persists for an Out
// node. It means the live inet meshmux_out table was read back and proven to
// be the exact VLESS guard: the MeshMux table, the input chain at priority
// -10, both VLESS drops, and an accept set exactly equal to the applied
// source allowlist. An empty allowlist is still a passing guard — that is the
// fail-closed data plane. It never means "policy accept was seen".
type Readback struct {
	Architecture   string `json:"architecture"`
	AgentVersion   string `json:"agent_version"`
	AgentSHA256    string `json:"agent_sha256"`
	KernelVersion  string `json:"kernel_version"`
	KernelSHA256   string `json:"kernel_sha256"`
	ActiveRevision int64  `json:"active_revision"`
	ConfigSHA256   string `json:"config_sha256"`
	LocalActive    bool   `json:"local_active"`
	OutDefaultDeny bool   `json:"out_default_deny"`
}

var (
	nodeIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)
	sha256Pattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
	tokenPattern  = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)
	dnsLabel      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// Validate checks the enrollment data required before pairing.
func (c Config) Validate() error {
	if err := validateHubURL(c.HubURL); err != nil {
		return err
	}
	if !nodeIDPattern.MatchString(c.NodeID) {
		return errors.New("NODE_ID_INVALID: need 32 lowercase hex characters")
	}
	if !c.Role.valid() {
		return errors.New("ROLE_INVALID: role must be edge or out")
	}
	if err := validatePorts(c.VLESSPort, c.SSHPort); err != nil {
		return err
	}
	return nil
}

// ValidateInstalled additionally requires the exact MeshMux development
// version and verified binary digests. Protocol version 1.0 is not a program
// release version and is rejected here.
func (c Config) ValidateInstalled() error {
	if err := c.Validate(); err != nil {
		return err
	}
	if c.AgentVersion != CurrentAgentVersion {
		return errors.New("AGENT_VERSION_INVALID: installed Agent version is not the pinned build")
	}
	if !sha256Pattern.MatchString(c.AgentSHA256) {
		return errors.New("AGENT_SHA256_INVALID: need 64 lowercase hex characters")
	}
	if !sha256Pattern.MatchString(c.KernelSHA256) {
		return errors.New("KERNEL_SHA256_INVALID: need 64 lowercase hex characters")
	}
	return nil
}

// Metadata returns the immutable identity and port binding from Config.
func (c Config) Metadata() Metadata {
	return Metadata{NodeID: c.NodeID, Role: c.Role, VLESSPort: c.VLESSPort, SSHPort: c.SSHPort}
}

func (r Role) valid() bool {
	return r == RoleEdge || r == RoleOut
}

// ParseRole parses one install role argument into a node role. Hub is not a
// node role: a hub host is described by install.Config, so "hub" is rejected
// here and resolved on the install side instead.
func ParseRole(value string) (Role, error) {
	role := Role(value)
	if !role.valid() {
		return "", errors.New("ROLE_INVALID: role must be edge or out")
	}
	return role, nil
}

func validatePorts(vlessPort, sshPort int) error {
	if vlessPort < 1 || vlessPort > 65535 || sshPort < 1 || sshPort > 65535 {
		return errors.New("PORT_INVALID: VLESS and SSH ports must be 1-65535")
	}
	if vlessPort == sshPort {
		return errors.New("PORT_CONFLICT: VLESS and SSH ports must differ")
	}
	return nil
}

func validateHubURL(raw string) error {
	if raw == "" || len(raw) > 512 || strings.ContainsAny(raw, "\r\n\t #?") {
		return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Opaque != "" || u.Host == "" || u.Hostname() == "" ||
		u.User != nil || u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || u.String() != raw {
		return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip == nil {
		if len(host) > 253 || strings.HasSuffix(host, ".") {
			return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
		}
		for label := range strings.SplitSeq(host, ".") {
			if !dnsLabel.MatchString(label) {
				return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
			}
		}
	}
	if port := u.Port(); port != "" {
		if len(port) > 5 {
			return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
		}
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return errors.New("HUB_URL_INVALID: provide one HTTPS origin")
		}
	}
	return nil
}

// Validate checks that a private identity has the frozen field shapes.
func (i Identity) Validate() error {
	if !nodeIDPattern.MatchString(i.NodeID) {
		return errors.New("IDENTITY_INVALID: node identity does not match")
	}
	if !tokenPattern.MatchString(i.IdentityToken) {
		return errors.New("IDENTITY_INVALID: node identity does not match")
	}
	return nil
}

// ValidateFor checks that the identity belongs to this configured node.
func (i Identity) ValidateFor(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := i.Validate(); err != nil {
		return err
	}
	if i.NodeID != c.NodeID {
		return errors.New("IDENTITY_MISMATCH: node identity does not match")
	}
	return nil
}

// Validate checks the enrollment metadata without probing the host.
func (m Metadata) Validate() error {
	if !nodeIDPattern.MatchString(m.NodeID) {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	if !m.Role.valid() {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	if err := validatePorts(m.VLESSPort, m.SSHPort); err != nil {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	return nil
}

// ValidateFor rejects metadata for any node, role or port other than Config.
func (m Metadata) ValidateFor(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if m != c.Metadata() {
		return errors.New("METADATA_MISMATCH: node metadata does not match")
	}
	return nil
}

// Validate checks the frozen candidate fields and, when present, the optional
// v2 users and reality blocks.
func (c Candidate) Validate() error {
	if !nodeIDPattern.MatchString(c.NodeID) {
		return errors.New("CANDIDATE_INVALID: node identity does not match")
	}
	if !c.Role.valid() {
		return errors.New("CANDIDATE_INVALID: role must be edge or out")
	}
	if c.Revision < 1 {
		return errors.New("REVISION_INVALID: revision must be a positive int64")
	}
	if c.VLESSPort < 1 || c.VLESSPort > 65535 {
		return errors.New("CANDIDATE_INVALID: VLESS port must be 1-65535")
	}
	if c.KernelVersion != KernelVersion {
		return errors.New("KERNEL_VERSION_INVALID: candidate requires the pinned kernel version")
	}
	return c.validateV2Fields()
}

// ValidateFor binds a candidate to the configured node, role and VLESS port.
func (c Candidate) ValidateFor(config Config) error {
	if err := config.Validate(); err != nil {
		return err
	}
	if err := c.Validate(); err != nil {
		return err
	}
	if c.NodeID != config.NodeID || c.Role != config.Role || c.VLESSPort != config.VLESSPort {
		return errors.New("CANDIDATE_MISMATCH: candidate does not match the configured node")
	}
	return nil
}

// Validate checks the schema and immutable candidate constraints. Callers can
// use it before trusting a programmatically constructed document.
func (d CandidateDocument) Validate() error {
	switch d.Schema {
	case CandidateSchema:
		if d.Reality != nil || len(d.Users) > 0 {
			return errors.New("CANDIDATE_INVALID: users and reality are not allowed in meshmux-node/v1")
		}
	case CandidateSchemaV2:
		if d.Reality == nil {
			return errors.New("REALITY_REQUIRED: reality is required in meshmux-node/v2")
		}
		if d.Users == nil {
			return errors.New("CANDIDATE_INVALID: users must be an array in meshmux-node/v2")
		}
	default:
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1 or meshmux-node/v2")
	}
	return d.Candidate().Validate()
}

// ValidateFor binds the candidate document to the configured node.
func (d CandidateDocument) ValidateFor(c Config) error {
	if err := d.Validate(); err != nil {
		return err
	}
	return d.Candidate().ValidateFor(c)
}

// UnmarshalJSON accepts exactly one object with the schema and the candidate
// fields of that schema. It rejects unknown, duplicate, null and malformed
// values, and never mixes the v1 and v2 shapes.
func (d *CandidateDocument) UnmarshalJSON(data []byte) error {
	obj, err := decodeExactObject(data)
	if err != nil {
		return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
	}
	schema := new(string)
	if err := decodeStringField(obj["schema"], schema); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	switch *schema {
	case CandidateSchema:
		return d.unmarshalV1(obj)
	case CandidateSchemaV2:
		return d.unmarshalV2(obj)
	default:
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1 or meshmux-node/v2")
	}
}

// unmarshalV1 decodes the frozen six-field non-secret document. The v1 shape
// never carries the v2 blocks.
func (d *CandidateDocument) unmarshalV1(obj map[string]json.RawMessage) error {
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version"}
	if len(obj) != len(required) {
		return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
		}
	}

	var decoded CandidateDocument
	if err := decodeStringField(obj["schema"], &decoded.Schema); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if decoded.Schema != CandidateSchema {
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1")
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
	if err := decoded.Validate(); err != nil {
		return err
	}
	*d = decoded
	return nil
}

// unmarshalV2 decodes the v2 document: the frozen six fields plus exactly the
// users array and the reality block.
func (d *CandidateDocument) unmarshalV2(obj map[string]json.RawMessage) error {
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version", "users", "reality"}
	if len(obj) != len(required) {
		return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
	}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
		}
	}

	var decoded CandidateDocument
	if err := decodeStringField(obj["schema"], &decoded.Schema); err != nil {
		return errors.New("CANDIDATE_INVALID: field type invalid")
	}
	if decoded.Schema != CandidateSchemaV2 {
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v2")
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
	users, err := decodeUsers(obj["users"])
	if err != nil {
		return err
	}
	decoded.Users = users
	reality, err := decodeReality(obj["reality"])
	if err != nil {
		return err
	}
	decoded.Reality = reality
	if err := decoded.Validate(); err != nil {
		return err
	}
	*d = decoded
	return nil
}

func decodeExactObject(data []byte) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	obj := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok || key != strings.ToLower(key) || strings.Contains(key, "-") {
			return nil, errors.New("invalid key")
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

func decodeStringField(raw json.RawMessage, dst *string) error {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("null")
	}
	return json.Unmarshal(raw, dst)
}

func decodePositiveInt64(raw json.RawMessage) (int64, error) {
	if len(raw) == 0 || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return 0, errors.New("null")
	}
	s := string(bytes.TrimSpace(raw))
	if s == "" {
		return 0, errors.New("empty")
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errors.New("not an integer")
		}
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0, errors.New("not a positive int64")
	}
	return n, nil
}

// Validate checks local readback evidence and hash shapes without probing the
// host.
func (r Readback) Validate() error {
	if _, ok := KernelReleaseFor(r.Architecture); !ok {
		return errors.New("READBACK_INVALID: unsupported architecture")
	}
	if r.AgentVersion != CurrentAgentVersion {
		return errors.New("READBACK_INVALID: installed Agent version is not pinned")
	}
	if !sha256Pattern.MatchString(r.AgentSHA256) || !sha256Pattern.MatchString(r.KernelSHA256) ||
		!sha256Pattern.MatchString(r.ConfigSHA256) {
		return errors.New("READBACK_INVALID: digests must be 64 lowercase hex characters")
	}
	if r.KernelVersion != KernelVersion {
		return errors.New("READBACK_INVALID: kernel version is not pinned")
	}
	if r.ActiveRevision < 1 {
		return errors.New("READBACK_INVALID: active revision must be positive")
	}
	return nil
}
