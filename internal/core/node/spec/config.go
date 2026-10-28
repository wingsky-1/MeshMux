package spec

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

	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const (
	// AgentDataDir and ActiveConfigDir are the two host directories of the
	// Agent layout. Every path below and every runtime helper derives from them,
	// so the layout has one definition; the install side renders the same two
	// directories into its unit files.
	AgentDataDir    = "/var/lib/meshmux-agent"
	ActiveConfigDir = "/var/lib/meshmux-singbox"

	AgentBinaryPath     = "/usr/local/libexec/meshmuxd"
	SingBoxBinaryPath   = "/usr/local/libexec/meshmux-sing-box"
	AgentConfigPath     = "/etc/meshmux/agent.json"
	IdentityPath        = AgentDataDir + "/identity.json"
	RuntimeStatePath    = AgentDataDir + "/state.json"
	ActiveCandidatePath = AgentDataDir + "/active-candidate.json"
	ActiveConfigPath    = ActiveConfigDir + "/config.json"
	// ACLPath is the retired Out guard script: the exact, rule-free table
	// replacement. It is still applied as one nft -f transaction so a host
	// upgraded from an allowlist release flushes its stale rules; the readback
	// only asserts that the table exists and carries no rule.
	ACLPath = AgentDataDir + "/out.nft"

	AgentUnit   = "meshmux-agent.service"
	SingBoxUnit = "meshmux-sing-box.service"
	ACLUnit     = "meshmux-out-acl.service"
	ACLTable    = "meshmux_out"
)

const (
	// CandidateSchema is the only candidate document schema. The frozen v1
	// baseline is six required fields; users, reality, route and out are
	// optional fields on the same document.
	CandidateSchema = "meshmux-node/v1"
)

// Deprecated: the candidate document has a single schema, meshmux-node/v1.
// These names remain only so existing callers keep compiling; they must not
// be used to select or reject a document shape.
const (
	CandidateSchemaV2 = CandidateSchema
	CandidateSchemaV3 = CandidateSchema
	CandidateSchemaV4 = CandidateSchema
)

// CurrentAgentVersion is this build's Agent identity, projected read-only from
// the single source internal/buildinfo (#11d spec §5.3, N7).
//
// It is deliberately a function and not a variable. A writable package variable
// could be reassigned at runtime by any importing package, which would move the
// release manifest projection, the `database_versions` identity row and the
// upgrade confirmation together with no compile-time protection; a function
// returns a value no caller can assign. The release build injects the version
// once, with -ldflags -X .../internal/buildinfo.Version, so there is no second
// copy to keep in sync.
func CurrentAgentVersion() string { return buildinfo.Version }

// Role is the Hub-visible node purpose. Line is represented by "edge".
//
// RoleHTTP is an external HTTP proxy managed by the Hub only (Ruling R11): it
// has no Agent, no pairing, no candidate and no readback, so valid() (the
// agent/install role check) deliberately rejects it. Its status is always
// "external" and it is excluded from every convergence gate.
type Role string

const (
	RoleEdge Role = "edge"
	RoleOut  Role = "out"
	RoleHTTP Role = "http"
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

// Metadata binds a node's immutable enrollment identity to its listener ports
// and the newest published candidate revision.
//
// The revision is part of the binding so a fresh install applies the document
// the Hub currently publishes instead of assuming revision 1: an Out configured
// with its dial address before pairing carries the SS link key in a later
// candidate, and the first boot must run the guard that same candidate names.
// Zero means the caller did not report one (an older fixture); the installer
// falls back to the initial revision in that case.
type Metadata struct {
	NodeID         string `json:"node_id"`
	Role           Role   `json:"role"`
	VLESSPort      int    `json:"vless_port"`
	SSHPort        int    `json:"ssh_port"`
	ConfigRevision int64  `json:"config_revision"`
}

// Candidate is the complete dynamic configuration input. The first six fields
// are the frozen v1 baseline, byte-for-byte unchanged. Users, Reality, Route
// and Out are optional v1 fields: Users, Reality and Out carry node secrets, so
// a candidate that uses them only travels over the authenticated Hub<->Agent
// channel and never enters a public response, a subscription artifact or a
// generic log line.
type Candidate struct {
	NodeID        string         `json:"node_id"`
	Role          Role           `json:"role"`
	Revision      int64          `json:"revision"`
	VLESSPort     int            `json:"vless_port"`
	KernelVersion string         `json:"kernel_version"`
	Users         []VLESSUser    `json:"users,omitempty"`
	Reality       *RealityConfig `json:"reality,omitempty"`
	// Route is the resolved server route fragment of a Line. It is
	// non-secret policy output and an optional field of the v1 document.
	Route json.RawMessage `json:"route,omitempty"`
	// Out is the Hub-issued dial body of the Line's "out" outbound: the
	// selected Out node's address/port plus the SS link key. It is a
	// node secret in the same class as Users and Reality and travels only
	// over the authenticated Hub<->Agent channel. A nil Out with a route
	// that names "out" renders the fail-closed block stub.
	Out *OutEgress `json:"out,omitempty"`
}

// CandidateDocument is the exact JSON document used for the mutable active
// candidate and immutable candidate transport. Its only schema is
// meshmux-node/v1: the frozen six-field baseline plus optional users, reality,
// route and out fields. An absent optional field decodes as nil, so a producer
// that needs no block never emits it and a credential-free candidate keeps the
// exact frozen v1 bytes.
type CandidateDocument struct {
	Schema        string          `json:"schema"`
	NodeID        string          `json:"node_id"`
	Role          Role            `json:"role"`
	Revision      int64           `json:"revision"`
	VLESSPort     int             `json:"vless_port"`
	KernelVersion string          `json:"kernel_version"`
	Users         []VLESSUser     `json:"users,omitempty"`
	Reality       *RealityConfig  `json:"reality,omitempty"`
	Route         json.RawMessage `json:"route,omitempty"`
	Out           *OutEgress      `json:"out,omitempty"`
}

// NewCandidateDocument binds a candidate to the frozen v1 schema. There is no
// schema switch by content: users, reality, route and out are optional fields
// on the one document and stay unset when the candidate does not use them.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return CandidateDocument{
		Schema:        CandidateSchema,
		NodeID:        candidate.NodeID,
		Role:          candidate.Role,
		Revision:      candidate.Revision,
		VLESSPort:     candidate.VLESSPort,
		KernelVersion: candidate.KernelVersion,
		Users:         candidate.Users,
		Reality:       candidate.Reality,
		Route:         candidate.Route,
		Out:           candidate.Out,
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
		Users:         d.Users,
		Reality:       d.Reality,
		Route:         d.Route,
		Out:           d.Out,
	}
}

// MarshalJSON writes the single v1 document. The frozen baseline fields keep
// their exact bytes and order, and an absent optional block is omitted, so a
// credential-free candidate is byte-identical to the frozen v1 document. The
// document is validated first, so an invalid schema or an optional block that
// conflicts with the role fails closed instead of silently dropping
// credentials.
func (d CandidateDocument) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	type plain CandidateDocument
	return json.Marshal(plain(d))
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
// including the optional users, reality and route blocks and the Out egress.
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
		if c.Reality != nil || other.Reality != nil {
			return false
		}
	} else if *c.Reality != *other.Reality {
		return false
	}
	if c.Out == nil || other.Out == nil {
		if c.Out != nil || other.Out != nil {
			return false
		}
	} else if *c.Out != *other.Out {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(c.Route), bytes.TrimSpace(other.Route))
}

// Readback contains only local evidence. Its fields deliberately cannot claim
// public reachability, a real protocol handshake or client usability.
//
// OutDefaultDeny is the observed_out_default_deny field the Hub persists for
// an Out node. The name is historical: with the source allowlist retired it
// means the live inet meshmux_out table was read back and proven to be the
// neutral MeshMux table (the input chain at priority -10 with no rule), which
// is what flushes a legacy allowlist. It never claims a source was filtered
// or that public reachability was proven.
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

// dnsLabel is the only local pattern here: a single-label shape no other
// package owns. Identity, digest and token spellings come from protocol, the
// wire contract both sides of the Agent boundary share.
var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate checks the enrollment data required before pairing.
func (c Config) Validate() error {
	if err := validateHubURL(c.HubURL); err != nil {
		return err
	}
	if !protocol.ValidID(c.NodeID) {
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
	if c.AgentVersion != CurrentAgentVersion() {
		return errors.New("AGENT_VERSION_INVALID: installed Agent version is not the pinned build")
	}
	if !protocol.ValidSHA256(c.AgentSHA256) {
		return errors.New("AGENT_SHA256_INVALID: need 64 lowercase hex characters")
	}
	if !protocol.ValidSHA256(c.KernelSHA256) {
		return errors.New("KERNEL_SHA256_INVALID: need 64 lowercase hex characters")
	}
	return nil
}

// Metadata returns the immutable identity and port binding from Config.
func (c Config) Metadata() Metadata {
	return Metadata{NodeID: c.NodeID, Role: c.Role, VLESSPort: c.VLESSPort, SSHPort: c.SSHPort}
}

func (r Role) valid() bool {
	// Only an installed Agent role. RoleHTTP is a Hub-only external endpoint:
	// it never receives a Config, a Metadata document or a Candidate.
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
	if !protocol.ValidID(i.NodeID) {
		return errors.New("IDENTITY_INVALID: node identity does not match")
	}
	if !protocol.ValidToken43(i.IdentityToken) {
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
	if !protocol.ValidID(m.NodeID) {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	if !m.Role.valid() {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	if err := validatePorts(m.VLESSPort, m.SSHPort); err != nil {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	if m.ConfigRevision < 0 {
		return errors.New("METADATA_INVALID: node metadata does not match")
	}
	return nil
}

// ValidateFor rejects metadata for any node, role or port other than Config.
// The candidate revision is an observation, not part of the identity binding,
// so it never makes metadata from the right node invalid.
func (m Metadata) ValidateFor(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	if err := m.Validate(); err != nil {
		return err
	}
	if m.NodeID != c.NodeID || m.Role != c.Role || m.VLESSPort != c.VLESSPort || m.SSHPort != c.SSHPort {
		return errors.New("METADATA_MISMATCH: node metadata does not match")
	}
	return nil
}

// Validate checks the frozen candidate fields and, when present, the optional
// users and reality blocks.
func (c Candidate) Validate() error {
	if !protocol.ValidID(c.NodeID) {
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
	return c.validateOptionalFields()
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

// Validate checks the single v1 schema and the optional blocks. An absent
// optional block is the frozen baseline; a present one is validated against the
// role exactly as before, so the merged document cannot smuggle a credential or
// an egress into a shape that must not carry it.
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

// UnmarshalJSON accepts exactly one meshmux-node/v1 object. The six baseline
// fields are required; users, reality, route and out are optional. An absent
// optional field decodes as nil instead of being defaulted to an empty shape;
// an unknown, duplicate, null or malformed value is rejected.
func (d *CandidateDocument) UnmarshalJSON(data []byte) error {
	const malformed = "CANDIDATE_INVALID: malformed candidate JSON"
	obj, err := decodeExactObject(data)
	if err != nil {
		return errors.New(malformed)
	}
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version"}
	for _, name := range required {
		if _, ok := obj[name]; !ok {
			return errors.New(malformed)
		}
	}
	for name := range obj {
		switch name {
		case "schema", "node_id", "role", "revision", "vless_port", "kernel_version", "users", "reality", "route", "out":
		default:
			return errors.New(malformed)
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
	// Defaults for the optional blocks: an absent users block is an empty
	// list, matching the shape every producer and validator treats as "no
	// credentials"; reality, route and out stay nil when absent.
	decoded.Users = []VLESSUser{}
	if raw, ok := obj["users"]; ok {
		users, err := decodeUsers(raw)
		if err != nil {
			return err
		}
		decoded.Users = users
	}
	if raw, ok := obj["reality"]; ok {
		reality, err := decodeReality(raw)
		if err != nil {
			return err
		}
		decoded.Reality = reality
	}
	if raw, ok := obj["route"]; ok {
		route, err := compactCandidateRoute(raw)
		if err != nil {
			return err
		}
		decoded.Route = route
	}
	if raw, ok := obj["out"]; ok {
		out, err := decodeOutEgress(raw)
		if err != nil {
			return err
		}
		decoded.Out = out
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
	if r.AgentVersion != CurrentAgentVersion() {
		return errors.New("READBACK_INVALID: installed Agent version is not pinned")
	}
	if !protocol.ValidSHA256(r.AgentSHA256) || !protocol.ValidSHA256(r.KernelSHA256) ||
		!protocol.ValidSHA256(r.ConfigSHA256) {
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
