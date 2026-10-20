// Package node defines the fixed host layout and data contracts shared by the
// node installer and runtime. It performs no host I/O.
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
	ACLPath             = "/var/lib/meshmux-agent/out.nft"

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

// Candidate is the complete, non-secret dynamic configuration input.
type Candidate struct {
	NodeID        string `json:"node_id"`
	Role          Role   `json:"role"`
	Revision      int64  `json:"revision"`
	VLESSPort     int    `json:"vless_port"`
	KernelVersion string `json:"kernel_version"`
}

// CandidateDocument is the exact JSON document used for the mutable active
// candidate and immutable candidate transport. Schema is always
// meshmux-node/v1 and the remaining fields are exactly Candidate's fields.
type CandidateDocument struct {
	Schema        string `json:"schema"`
	NodeID        string `json:"node_id"`
	Role          Role   `json:"role"`
	Revision      int64  `json:"revision"`
	VLESSPort     int    `json:"vless_port"`
	KernelVersion string `json:"kernel_version"`
}

// NewCandidateDocument binds a candidate to the frozen schema identifier.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return CandidateDocument{
		Schema:        CandidateSchema,
		NodeID:        candidate.NodeID,
		Role:          candidate.Role,
		Revision:      candidate.Revision,
		VLESSPort:     candidate.VLESSPort,
		KernelVersion: candidate.KernelVersion,
	}
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
	}
}

// Readback contains only local evidence. Its fields deliberately cannot claim
// public reachability, a real protocol handshake or client usability.
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
		for _, label := range strings.Split(host, ".") {
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

// Validate checks the frozen candidate fields.
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
	return nil
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
	if d.Schema != CandidateSchema {
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1")
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

// UnmarshalJSON accepts exactly one object with the schema and five frozen
// candidate fields. It rejects unknown, duplicate, null and malformed values.
func (d *CandidateDocument) UnmarshalJSON(data []byte) error {
	obj, err := decodeExactObject(data)
	if err != nil {
		return errors.New("CANDIDATE_INVALID: malformed candidate JSON")
	}
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
	if decoded.Revision, err = decodePositiveInt64(obj["revision"]); err != nil {
		return errors.New("CANDIDATE_INVALID: revision must be a positive int64")
	}
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
