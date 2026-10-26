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

	"github.com/wingsky-1/MeshMux/internal/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/node/protocol"
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
	// ACLPath is the managed Out VLESS guard script: the exact table
	// replacement including the Hub-authorized source accept rules. It is
	// applied as one nft -f transaction and read back through nft -j.
	ACLPath = AgentDataDir + "/out.nft"

	AgentUnit   = "meshmux-agent.service"
	SingBoxUnit = "meshmux-sing-box.service"
	ACLUnit     = "meshmux-out-acl.service"
	ACLTable    = "meshmux_out"
)

const (
	CandidateSchema = "meshmux-node/v1"
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
	// Route is the resolved server route fragment of a Line. It is
	// non-secret policy output, present only in a meshmux-node/v3 document.
	Route json.RawMessage `json:"route,omitempty"`
	// Out is the Hub-issued dial body of the Line's "out" outbound: the
	// selected Out node's address/port plus the SS link key. It is a
	// node secret in the same class as Users and Reality and travels only
	// over the authenticated Hub<->Agent channel. A nil Out with a route
	// that names "out" renders the fail-closed block stub.
	Out *OutEgress `json:"out,omitempty"`
}

// CandidateDocument is the exact JSON document used for the mutable active
// candidate and immutable candidate transport. Schema is meshmux-node/v1 for
// the frozen six-field non-secret baseline, meshmux-node/v2 for the baseline
// plus the users and reality blocks, meshmux-node/v3 for v2 plus the resolved
// server route fragment of a Line, and meshmux-node/v4 for an Out node with
// configured transport (the baseline plus the link key for its SS guard).
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

// NewCandidateDocument binds a candidate to a schema identifier. A candidate
// without users, without a reality block, without a route and without an Out
// egress stays on the frozen v1 document; a route makes it v3 and users or
// reality make it v2. An Out-role candidate with an attached egress takes
// the v4 document so its Agent renders the SS guard; an Out without transport
// keeps the frozen v1 baseline. The route is compacted, so an equal route
// always yields equal bytes.
func NewCandidateDocument(candidate Candidate) CandidateDocument {
	document := CandidateDocument{
		Schema:        CandidateSchema,
		NodeID:        candidate.NodeID,
		Role:          candidate.Role,
		Revision:      candidate.Revision,
		VLESSPort:     candidate.VLESSPort,
		KernelVersion: candidate.KernelVersion,
	}
	if candidate.Reality == nil && len(candidate.Users) == 0 && len(candidate.Route) == 0 && candidate.Out == nil {
		return document
	}
	if candidate.Role == RoleOut && candidate.Out != nil {
		// The v4 branch keeps every field so Validate can refuse an Out
		// candidate that smuggles users, reality or a route instead of
		// silently dropping them.
		document.Schema = CandidateSchemaV4
		document.Users = candidate.Users
		document.Reality = candidate.Reality
		document.Route = candidate.Route
		document.Out = candidate.Out
		return document
	}
	if len(candidate.Route) > 0 {
		document.Schema = CandidateSchemaV3
		document.Route = candidate.Route
	} else {
		document.Schema = CandidateSchemaV2
	}
	document.Users = candidate.Users
	if document.Users == nil {
		document.Users = []VLESSUser{}
	}
	document.Reality = candidate.Reality
	document.Out = candidate.Out
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
		Route:         d.Route,
		Out:           d.Out,
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
	if d.Schema == CandidateSchemaV4 {
		type v4Document struct {
			Schema        string     `json:"schema"`
			NodeID        string     `json:"node_id"`
			Role          Role       `json:"role"`
			Revision      int64      `json:"revision"`
			VLESSPort     int        `json:"vless_port"`
			KernelVersion string     `json:"kernel_version"`
			Out           *OutEgress `json:"out"`
		}
		return json.Marshal(v4Document{
			Schema:        d.Schema,
			NodeID:        d.NodeID,
			Role:          d.Role,
			Revision:      d.Revision,
			VLESSPort:     d.VLESSPort,
			KernelVersion: d.KernelVersion,
			Out:           d.Out,
		})
	}
	if d.Schema == CandidateSchemaV3 {
		type v3Document struct {
			Schema        string          `json:"schema"`
			NodeID        string          `json:"node_id"`
			Role          Role            `json:"role"`
			Revision      int64           `json:"revision"`
			VLESSPort     int             `json:"vless_port"`
			KernelVersion string          `json:"kernel_version"`
			Users         []VLESSUser     `json:"users"`
			Reality       *RealityConfig  `json:"reality"`
			Route         json.RawMessage `json:"route"`
			Out           *OutEgress      `json:"out,omitempty"`
		}
		users := d.Users
		if users == nil {
			users = []VLESSUser{}
		}
		return json.Marshal(v3Document{
			Schema:        d.Schema,
			NodeID:        d.NodeID,
			Role:          d.Role,
			Revision:      d.Revision,
			VLESSPort:     d.VLESSPort,
			KernelVersion: d.KernelVersion,
			Users:         users,
			Reality:       d.Reality,
			Route:         d.Route,
			Out:           d.Out,
		})
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
			Out           *OutEgress     `json:"out,omitempty"`
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
			Out:           d.Out,
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
// including the optional v2 blocks, the v3 route and the Out egress.
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
		if d.Reality != nil || len(d.Users) > 0 || len(d.Route) > 0 || d.Out != nil {
			return errors.New("CANDIDATE_INVALID: users, reality, route and out are not allowed in meshmux-node/v1")
		}
	case CandidateSchemaV2:
		if d.Reality == nil {
			return errors.New("REALITY_REQUIRED: reality is required in meshmux-node/v2")
		}
		if d.Users == nil {
			return errors.New("CANDIDATE_INVALID: users must be an array in meshmux-node/v2")
		}
		if len(d.Route) > 0 {
			return errors.New("CANDIDATE_ROUTE_INVALID: a route document must use meshmux-node/v3")
		}
	case CandidateSchemaV3:
		if d.Reality == nil || d.Users == nil || len(d.Route) == 0 {
			return errors.New("CANDIDATE_INVALID: v3 requires reality, users and a route")
		}
		if err := validateCandidateRoute(d.Route); err != nil {
			return err
		}
	case CandidateSchemaV4:
		if d.Role != RoleOut {
			return errors.New("CANDIDATE_INVALID: v4 is only valid for out nodes")
		}
		if d.Reality != nil || len(d.Users) != 0 || len(d.Route) != 0 {
			return errors.New("CANDIDATE_INVALID: v4 carries only the link key, no users, reality or route")
		}
		if d.Out == nil || d.Out.Key == "" {
			return errors.New("CANDIDATE_INVALID: v4 requires the link key")
		}
	default:
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1, meshmux-node/v2, meshmux-node/v3 or meshmux-node/v4")
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
// values, and never mixes the v1, v2, v3 and v4 shapes.
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
	case CandidateSchemaV3:
		return d.unmarshalV3(obj)
	case CandidateSchemaV4:
		return d.unmarshalV4(obj)
	default:
		return errors.New("CANDIDATE_SCHEMA_INVALID: expected meshmux-node/v1, meshmux-node/v2, meshmux-node/v3 or meshmux-node/v4")
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
// users array and the reality block, with an optional Hub-issued out egress.
func (d *CandidateDocument) unmarshalV2(obj map[string]json.RawMessage) error {
	required := []string{"schema", "node_id", "role", "revision", "vless_port", "kernel_version", "users", "reality"}
	if len(obj) != len(required) && (len(obj) != len(required)+1 || !hasOutField(obj)) {
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
