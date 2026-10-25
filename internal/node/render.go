package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
)

type singBoxConfig struct {
	Log       singBoxLog        `json:"log"`
	Inbounds  []singBoxInbound  `json:"inbounds"`
	Outbounds []singBoxOutbound `json:"outbounds"`
	Route     json.RawMessage   `json:"route,omitempty"`
}

type singBoxLog struct {
	Disabled bool `json:"disabled"`
}

type singBoxInbound struct {
	Type       string            `json:"type"`
	Tag        string            `json:"tag"`
	Listen     string            `json:"listen"`
	ListenPort int               `json:"listen_port"`
	Users      []json.RawMessage `json:"users"`
}

type singBoxOutbound struct {
	Type string `json:"type"`
	Tag  string `json:"tag"`
	// Server, ServerPort and UUID carry the dial body of a real VLESS egress.
	// They are present only on the "out" outbound of a Line whose Out access
	// path attached an endpoint; every other outbound omits them.
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	UUID       string `json:"uuid,omitempty"`
}

// Server document egress tags. compiler.RenderServerRoute maps ActionDirect to
// "direct" and ActionOut to "out"; the candidate must declare every tag its
// route names, or the kernel document would reference an egress it does not
// carry.
const (
	singBoxDirectTag = "direct"
	singBoxOutTag    = "out"
	singBoxBlockTag  = "block"
)

// serverEgress is the set of egress tags one server route references.
type serverEgress struct {
	out   bool
	block bool
}

// serverOutbounds renders the outbound set of one server document.
//
// A route that selects the Out renders the fail-closed trio:
//
//   - "direct" keeps the Line egress for every rule that does not select the
//     Out;
//   - "out" is the tag the route names. While the Out access path owns the real
//     outbound body (its endpoint and Hub-issued credential), it is declared
//     as a VLESS outbound that dials the selected Out node, so AI traffic the
//     policy sends to the Out leaves through the Out instead of the Line
//     address. Until that body is attached — the Out is bound but its
//     transport is not configured yet — "out" stays a block stub, so the
//     traffic is refused instead of silently leaving from the Line address,
//     the leak the fail-closed rule exists to prevent. An Out that is
//     unavailable never reaches a published document (the Hub refuses it with
//     OUT_OFFLINE_FAIL_CLOSED); the stub is what keeps a document published
//     while the Out was healthy from silently turning into a Line egress if
//     the binding disappears later;
//   - "block" is the explicit never-route egress, so a document that refuses a
//     matched flow names a tag it actually carries.
//
// Without an Out the document keeps the single "direct" outbound: a route-free
// or direct-only candidate renders the frozen v1/v2 bytes, and a direct-only
// Line does not grow an unused tag.
func (e serverEgress) outbounds(out *OutEgress) []singBoxOutbound {
	if !e.out && !e.block {
		return []singBoxOutbound{{Type: singBoxDirectTag, Tag: singBoxDirectTag}}
	}
	outbounds := []singBoxOutbound{{Type: singBoxDirectTag, Tag: singBoxDirectTag}}
	if e.out {
		if out != nil {
			outbounds = append(outbounds, singBoxOutbound{
				Type: "vless", Tag: singBoxOutTag,
				Server: out.Server, ServerPort: out.Port, UUID: out.UUID,
			})
		} else {
			outbounds = append(outbounds, singBoxOutbound{Type: singBoxBlockTag, Tag: singBoxOutTag})
		}
	}
	outbounds = append(outbounds, singBoxOutbound{Type: singBoxBlockTag, Tag: singBoxBlockTag})
	return outbounds
}

// The v2 shapes are separate types on purpose: the frozen v1 document is
// byte-for-byte immutable, so it can never inherit a new field or a changed
// key order from the REALITY shape.

type singBoxConfigV2 struct {
	Log       singBoxLog         `json:"log"`
	Inbounds  []singBoxInboundV2 `json:"inbounds"`
	Outbounds []singBoxOutbound  `json:"outbounds"`
	Route     json.RawMessage    `json:"route,omitempty"`
}

type singBoxInboundV2 struct {
	Type       string             `json:"type"`
	Tag        string             `json:"tag"`
	Listen     string             `json:"listen"`
	ListenPort int                `json:"listen_port"`
	TLS        *singBoxTLS        `json:"tls"`
	Users      []singBoxVLESSUser `json:"users"`
}

type singBoxTLS struct {
	Enabled    bool           `json:"enabled"`
	ServerName string         `json:"server_name"`
	Reality    singBoxReality `json:"reality"`
}

type singBoxReality struct {
	Enabled    bool             `json:"enabled"`
	Handshake  singBoxHandshake `json:"handshake"`
	PrivateKey string           `json:"private_key"`
	ShortID    []string         `json:"short_id"`
}

type singBoxHandshake struct {
	Server     string `json:"server"`
	ServerPort int    `json:"server_port"`
}

// singBoxVLESSUser is one native VLESS credential. Name carries the stable
// credential id, UUID is the client secret and Flow is the exact XTLS flow
// token. The flow is spelled "xtls-rprx-vision" because sing-box rejects any
// other spelling.
type singBoxVLESSUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow"`
}

// vlessFlow is the exact flow token accepted by sing-box for VLESS.
const vlessFlow = "xtls-rprx-vision"

// CompileCandidate is a pure, deterministic renderer for the fixed native
// sing-box shape.
//
// Two shapes exist and they never mix:
//
//   - The frozen v1 baseline keeps its exact bytes, including the empty
//     "users" array and the revision-scoped "meshmux-vless-r<revision>" tag.
//     It is the non-secret baseline for Out nodes and for edge nodes that
//     have no credential yet.
//   - A candidate that carries a REALITY block renders the native edge
//     inbound with TLS, REALITY and the real credential users. Its tag is
//     "meshmux-vless-<node_id>", which is stable across revisions so a
//     user set change never rewrites the listener identity.
//
// The rendered bytes carry node secrets (the VLESS UUIDs and the REALITY
// private key). They only ever travel to the node's private file boundary;
// they are never written to a public response, a subscription artifact or a
// generic log line.
//
// A candidate that carries a route (a meshmux-node/v3 Line document) renders
// that route too: the Hub resolved the Out contract before it stored the
// fragment, and the Agent must apply exactly the published route instead of
// silently compiling a route-free kernel config. The outbound set follows the
// route: "out" and "block" are declared whenever the route names them. An
// "out" body is the real VLESS egress once the Hub attached the selected Out
// node's endpoint and the Hub-issued credential to the candidate, and the
// fail-closed block stub while it did not. `sing-box check` accepts a route
// tag with no matching outbound, so this renderer — not the kernel gate — is
// what keeps the document complete.
//
// The Out binding is deliberately not re-derived here: resolving "is an Out
// configured and healthy" needs Hub state the node does not have. A route that
// still names "out" only reaches this function through the Hub's own
// ResolveServerPolicy gate; the Agent proves the rest with sing-box check.
//
// The endpoint itself rides the candidate: the Hub attaches the selected Out
// node's address/port and the Hub-issued link credential to the Line
// candidate before it compiles, so the Hub and the Agent render byte-identical
// documents and the readback digest needs no second channel. A nil Out keeps
// the fail-closed block stub.
func CompileCandidate(c Candidate) ([]byte, error) {
	return compileCandidate(c, c.Route, len(c.Route) > 0)
}

// CompileCandidateWithRoute renders a Line candidate with the route fragment
// already produced by compiler.RenderServerRoute and the resolved Out fact.
// The fragment crosses as JSON because node must not import compiler: the
// subscription acceptance test imports node, which would close a test cycle.
// The caller must resolve the policy first; a fragment that references the
// "out" tag while no Out is configured is refused with OUT_BINDING_INVALID,
// never rendered as direct. The caller attaches the Out egress to the
// candidate when the binding names a configured Out: the fragment references
// "out" but the candidate carries its endpoint and credential.
func CompileCandidateWithRoute(c Candidate, route json.RawMessage, outConfigured bool) ([]byte, error) {
	return compileCandidate(c, route, outConfigured)
}

func compileCandidate(c Candidate, route json.RawMessage, outConfigured bool) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	route, egress, err := compileServerRoute(route, outConfigured)
	if err != nil {
		return nil, err
	}
	if c.Reality != nil {
		return compileRealityCandidate(c, route, egress)
	}
	config := singBoxConfig{
		Log: singBoxLog{Disabled: true},
		Inbounds: []singBoxInbound{{
			Type:       "vless",
			Tag:        fmt.Sprintf("meshmux-vless-r%d", c.Revision),
			Listen:     "0.0.0.0",
			ListenPort: c.VLESSPort,
			Users:      []json.RawMessage{},
		}},
		Outbounds: egress.outbounds(c.Out),
		Route:     route,
	}
	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("CANDIDATE_RENDER_FAILED")
	}
	return out, nil
}

// compileServerRoute embeds the route fragment; empty renders no route block.
//
// It returns the egress tags the fragment references, so the caller declares
// exactly those outbounds. Two refusals happen here, before any bytes exist:
//
//   - a tag this renderer cannot declare is CANDIDATE_ROUTE_INVALID, because a
//     published document that names an unknown egress would fail on the node
//     instead of at the Hub;
//   - an "out" reference while no Out is configured is OUT_BINDING_INVALID,
//     never a silent rewrite to the Line.
func compileServerRoute(fragment json.RawMessage, outConfigured bool) (json.RawMessage, serverEgress, error) {
	var egress serverEgress
	if len(fragment) == 0 {
		return nil, egress, nil
	}
	var route struct {
		Rules []struct {
			Outbound string `json:"outbound"`
		} `json:"rules"`
		Final string `json:"final"`
	}
	if err := json.Unmarshal(fragment, &route); err != nil {
		return nil, egress, errors.New("CANDIDATE_RENDER_FAILED")
	}
	tags := make([]string, 0, len(route.Rules)+1)
	tags = append(tags, route.Final)
	for _, rule := range route.Rules {
		tags = append(tags, rule.Outbound)
	}
	for _, tag := range tags {
		switch tag {
		case singBoxDirectTag:
		case singBoxOutTag:
			egress.out = true
		case singBoxBlockTag:
			egress.block = true
		default:
			return nil, egress, errors.New("CANDIDATE_ROUTE_INVALID: the route names an egress the candidate cannot render")
		}
	}
	if egress.out && !outConfigured {
		return nil, serverEgress{}, errors.New("OUT_BINDING_INVALID: the route references an Out that is not configured")
	}
	return fragment, egress, nil
}

// compileRealityCandidate renders the native edge inbound with the REALITY
// listener and the real credential users.
func compileRealityCandidate(c Candidate, route json.RawMessage, egress serverEgress) ([]byte, error) {
	config := singBoxConfigV2{
		Log: singBoxLog{Disabled: true},
		Inbounds: []singBoxInboundV2{{
			Type:       "vless",
			Tag:        fmt.Sprintf("meshmux-vless-%s", c.NodeID),
			Listen:     "0.0.0.0",
			ListenPort: c.VLESSPort,
			TLS: &singBoxTLS{
				Enabled:    true,
				ServerName: c.Reality.ServerName,
				Reality: singBoxReality{
					Enabled: true,
					Handshake: singBoxHandshake{
						Server:     c.Reality.HandshakeServer,
						ServerPort: c.Reality.HandshakePort,
					},
					PrivateKey: c.Reality.PrivateKey,
					ShortID:    []string{c.Reality.ShortID},
				},
			},
			Users: renderUsers(c.Users),
		}},
		Outbounds: egress.outbounds(c.Out),
		Route:     route,
	}
	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("CANDIDATE_RENDER_FAILED")
	}
	return out, nil
}

// renderUsers maps the candidate users onto the native VLESS user shape in a
// deterministic order. The credential id sorts the users, so two candidates
// that carry the same credentials always render the same bytes regardless of
// the order the Hub delivered them in.
//
// An empty user set is legal and renders as an empty array: removing the
// last credential leaves a listener that no client can use, which is the
// intended state of a Line whose last subscriber was deleted.
func renderUsers(users []VLESSUser) []singBoxVLESSUser {
	ordered := make([]VLESSUser, len(users))
	copy(ordered, users)
	slices.SortFunc(ordered, func(left, right VLESSUser) int {
		return strings.Compare(left.CredentialID, right.CredentialID)
	})
	rendered := make([]singBoxVLESSUser, 0, len(ordered))
	for _, user := range ordered {
		rendered = append(rendered, singBoxVLESSUser{
			Name: user.CredentialID,
			UUID: user.UUID,
			Flow: vlessFlow,
		})
	}
	return rendered
}

// maxACLSources bounds one rendered allowlist. The Hub derives at most one
// source per authorized Line, so this stays far above any real deployment and
// keeps the ACL file small enough to stay a single bounded nft -f script.
const maxACLSources = 256

// aclSource is one validated allowlist entry: the nft address family keyword
// plus the canonical masked prefix. The inet table carries both families, so
// one rule per source covers IPv4 and IPv6 without a second table.
type aclSource struct {
	family string
	prefix netip.Prefix
}

// CompileACL renders an exact table replacement for Out nodes. Edge nodes do
// not create the Out table. The caller must verify that inet meshmux_out is
// MeshMux-owned and feed the returned bytes to one nft -f transaction.
//
// The table is a narrow VLESS guard, not a host firewall: the base chain
// keeps policy accept so SSH, established return traffic and loopback stay
// with the host/filter rules, while the two VLESS drop rules deny the data
// plane by default. An empty allowlist therefore denies every unauthorized
// source. Each authorized source gets one accept rule ahead of the drops, so
// rule order carries the authorization decision: only the listed sources
// reach the VLESS port, everything else hits the drops.
//
// Every allowlist entry must be a valid IP or CIDR; anything else fails with
// ACL_SOURCE_INVALID instead of rendering a rule the kernel would reject or,
// worse, a broader rule than the Hub authorized. Entries are masked,
// de-duplicated and sorted, so the same authorization set always renders the
// same bytes and the readback comparison stays exact.
func CompileACL(c Candidate, allowed []string) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	// Sources are validated for every role: a malformed entry is a Hub defect
	// and must fail the task even on a node that does not render the table.
	sources, err := normalizeACLSources(allowed)
	if err != nil {
		return nil, err
	}
	// An Edge has no Out table, so an allowlist carries no meaning there and
	// renders nothing. Only Out creates the VLESS guard.
	if c.Role == RoleEdge {
		return nil, nil
	}
	if c.Role != RoleOut {
		return nil, errors.New("ROLE_INVALID: unsupported node role")
	}
	var script strings.Builder
	fmt.Fprintf(&script, "# Exact MeshMux-owned table replacement; apply as one nft -f transaction.\n")
	fmt.Fprintf(&script, "table inet %[1]s {}\n", ACLTable)
	fmt.Fprintf(&script, "delete table inet %[1]s\n", ACLTable)
	fmt.Fprintf(&script, "table inet %[1]s {\n", ACLTable)
	fmt.Fprintf(&script, "  chain input {\n")
	fmt.Fprintf(&script, "    type filter hook input priority -10; policy accept;\n")
	for _, source := range sources {
		fmt.Fprintf(&script, "    %s saddr %s tcp dport %d accept\n",
			source.family, source.prefix, c.VLESSPort)
	}
	fmt.Fprintf(&script, "    tcp dport %d drop\n", c.VLESSPort)
	fmt.Fprintf(&script, "    udp dport %d drop\n", c.VLESSPort)
	fmt.Fprintf(&script, "  }\n}\n")
	return []byte(script.String()), nil
}

// ParseACLAllowed parses the accept rules of one managed Out ACL script and
// then re-renders that set to confirm the file is a canonical MeshMux render
// rather than a hand-assembled table.
//
// This is an idempotency self-check, NOT an authorization proof: the input set
// is derived from the file being checked, so any edit that still sorts into the
// canonical order (for example an accept appended after the last authorized
// source) reproduces itself and passes. Callers must compare the result against
// an independent record of what the Hub authorized — the Agent's applied
// allowlist in state.json (AppliedAllowedSources) or the Hub-supplied task
// parameter — before treating the file as authorized.
func ParseACLAllowed(c Candidate, script []byte) ([]string, error) {
	invalid := errors.New("ACL_SCRIPT_INVALID: managed ACL is not the MeshMux render")
	allowed := make([]string, 0, 8)
	for line := range strings.SplitSeq(string(script), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 7 || (fields[0] != "ip" && fields[0] != "ip6") ||
			fields[1] != "saddr" || fields[3] != "tcp" || fields[4] != "dport" || fields[6] != "accept" {
			continue
		}
		if fields[5] != strconv.Itoa(c.VLESSPort) {
			continue
		}
		allowed = append(allowed, fields[2])
	}
	rendered, err := CompileACL(c, allowed)
	if err != nil || !bytes.Equal(rendered, script) {
		return nil, invalid
	}
	return allowed, nil
}

// normalizeACLSources validates, masks, de-duplicates and sorts one allowlist
// into the canonical rule order.
func normalizeACLSources(allowed []string) ([]aclSource, error) {
	if len(allowed) > maxACLSources {
		return nil, errors.New("ACL_SOURCE_INVALID: too many authorized sources")
	}
	seen := make(map[netip.Prefix]struct{}, len(allowed))
	sources := make([]aclSource, 0, len(allowed))
	for _, raw := range allowed {
		prefix, err := parseACLSource(raw)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seen[prefix]; duplicate {
			continue
		}
		seen[prefix] = struct{}{}
		family := "ip"
		if prefix.Addr().Is6() {
			family = "ip6"
		}
		sources = append(sources, aclSource{family: family, prefix: prefix})
	}
	slices.SortFunc(sources, func(left, right aclSource) int {
		return left.prefix.Compare(right.prefix)
	})
	return sources, nil
}

// parseACLSource accepts one bare IP or CIDR. The prefix is masked so the
// rendered rule and the readback comparison share one canonical spelling.
func parseACLSource(raw string) (netip.Prefix, error) {
	invalid := errors.New("ACL_SOURCE_INVALID: authorized source must be one IP or CIDR")
	if raw == "" || len(raw) > 64 || strings.TrimSpace(raw) != raw {
		return netip.Prefix{}, invalid
	}
	var (
		prefix netip.Prefix
		err    error
	)
	if prefix, err = netip.ParsePrefix(raw); err != nil {
		addr, addrErr := netip.ParseAddr(raw)
		// PrefixFrom silently drops a zone, so it is rejected on the
		// address itself; a scoped link-local source is not a Hub Line.
		if addrErr != nil || addr.Zone() != "" {
			return netip.Prefix{}, invalid
		}
		prefix = netip.PrefixFrom(addr, addr.BitLen())
	}
	addr := prefix.Addr()
	if !addr.IsValid() || addr.Zone() != "" || addr.Is4In6() {
		return netip.Prefix{}, invalid
	}
	// A zero-length prefix authorizes the whole internet, which would turn
	// the guard back into an allow-all rule. The Hub never derives one, so
	// it is a configuration error, not an authorization.
	if prefix.Bits() == 0 {
		return netip.Prefix{}, errors.New("ACL_SOURCE_INVALID: zero-length prefix would disable default deny")
	}
	return prefix.Masked(), nil
}
