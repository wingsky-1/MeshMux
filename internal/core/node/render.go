package node

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
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
	// Server, ServerPort, Method and Password carry the dial body of a real
	// Shadowsocks egress (or the ServerPort and optional Basic credentials of
	// an external HTTP proxy). They are present only on the "out" outbound of
	// a Line whose selected egress attached an endpoint; every other outbound
	// omits them. UUID is the void Task-2 shape: stored history keeps
	// rendering it byte-identically (see OutEgress), new writes never set it.
	Server     string `json:"server,omitempty"`
	ServerPort int    `json:"server_port,omitempty"`
	Method     string `json:"method,omitempty"`
	Password   string `json:"password,omitempty"`
	Username   string `json:"username,omitempty"`
	UUID       string `json:"uuid,omitempty"`
}

// singBoxSSInbound is the Out guard listener: Shadowsocks with the pinned
// 2022 method and the Hub-issued link key as password. The client-side chain
// model makes that key the only admission: the nft source allowlist around the
// listener is retired and the table is rendered rule-free.
type singBoxSSInbound struct {
	Type       string `json:"type"`
	Tag        string `json:"tag"`
	Listen     string `json:"listen"`
	ListenPort int    `json:"listen_port"`
	Method     string `json:"method"`
	Password   string `json:"password"`
}

// Server document egress tags. The values are owned by the wire contract in
// internal/node/protocol; policy.RenderServerRoute maps CompilerActionDirect to
// the direct tag and CompilerActionOut to the Out tag, and the candidate must
// declare every tag its route names, or the kernel document would reference an
// egress it does not carry.
const (
	singBoxDirectTag = protocol.OutboundDirectTag
	singBoxOutTag    = protocol.OutboundOutTag
	singBoxBlockTag  = protocol.OutboundBlockTag
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
//   - "out" is the tag the route names. While the egress slot owns the real
//     outbound body, it is declared as a Shadowsocks outbound that dials the
//     selected Out node (Ruling R7) or as an HTTP outbound that dials the
//     selected external HTTP proxy (Ruling R11), so traffic the policy sends
//     to the Out leaves through the selected egress instead of the Line
//     address. Until that body is attached — the egress is bound but its
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
// A stored document rendered before the SS switch keeps its byte-identical
// VLESS "out" body (see OutEgress): the pinned digest must still verify, and
// the void credential no longer authenticates anywhere because the Out side
// is SS-only.
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
		switch {
		case out != nil && out.Type == OutEgressHTTP:
			// Ruling R11: the egress slot may point at an external HTTP
			// proxy instead of a MeshMux Out. The kernel type is "http";
			// a credential-free proxy omits username and password because
			// both are omitempty.
			outbounds = append(outbounds, singBoxOutbound{
				Type: "http", Tag: singBoxOutTag,
				Server: out.Server, ServerPort: out.Port,
				Username: out.Username, Password: out.Password,
			})
		case out != nil && out.Key != "":
			outbounds = append(outbounds, singBoxOutbound{
				Type: "shadowsocks", Tag: singBoxOutTag,
				Server: out.Server, ServerPort: out.Port,
				Method: OutLinkMethod, Password: out.Key,
			})
		case out != nil && out.UUID != "":
			// Void history: reproduce the Task-2 VLESS bytes exactly so the
			// pinned digest verifies. New writes never take this path.
			outbounds = append(outbounds, singBoxOutbound{
				Type: "vless", Tag: singBoxOutTag,
				Server: out.Server, ServerPort: out.Port, UUID: out.UUID,
			})
		default:
			outbounds = append(outbounds, singBoxOutbound{Type: singBoxBlockTag, Tag: singBoxOutTag})
		}
	}
	outbounds = append(outbounds, singBoxOutbound{Type: singBoxBlockTag, Tag: singBoxBlockTag})
	return outbounds
}

// The v2 and v4 shapes are separate types on purpose: the frozen v1 document is
// byte-for-byte immutable, so it can never inherit a new field or a changed
// key order from the REALITY or SS shapes.

type singBoxConfigV2 struct {
	Log       singBoxLog         `json:"log"`
	Inbounds  []singBoxInboundV2 `json:"inbounds"`
	Outbounds []singBoxOutbound  `json:"outbounds"`
	Route     json.RawMessage    `json:"route,omitempty"`
}

// singBoxOutConfig is the v4 Out document: the SS guard inbound plus the
// direct outbound. It never carries a route, users or REALITY.
type singBoxOutConfig struct {
	Log       singBoxLog         `json:"log"`
	Inbounds  []singBoxSSInbound `json:"inbounds"`
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

// vlessFlow is the exact flow token accepted by sing-box for VLESS; the value
// is owned by the wire contract so the client document cannot spell another.
const vlessFlow = protocol.VLESSFlow

// CompileCandidate is a pure, deterministic renderer for the fixed native
// sing-box shape.
//
// Two shapes exist and they never mix:
//
//   - The frozen v1 baseline keeps its exact bytes, including the empty
//     "users" array and the revision-scoped "meshmux-vless-r<revision>" tag.
//     It is the non-secret baseline for Out nodes without transport and for
//     edge nodes that have no credential yet.
//   - A candidate that carries a REALITY block renders the native edge
//     inbound with TLS, REALITY and the real credential users. Its tag is
//     "meshmux-vless-<node_id>", which is stable across revisions so a
//     user set change never rewrites the listener identity.
//   - An Out candidate that carries the link key (a meshmux-node/v4 document)
//     renders the SS guard inbound with the pinned 2022 method instead of the
//     VLESS baseline. Its tag is "meshmux-ss-r<revision>".
//
// The rendered bytes carry node secrets (the VLESS UUIDs, the REALITY
// private key and the SS link key). They only ever travel to the node's
// private file boundary; they are never written to a public response, a
// subscription artifact or a generic log line.
//
// A candidate that carries a route (a meshmux-node/v3 Line document) renders
// that route too: the Hub resolved the Out contract before it stored the
// fragment, and the Agent must apply exactly the published route instead of
// silently compiling a route-free kernel config. The outbound set follows the
// route: "out" and "block" are declared whenever the route names them. An
// "out" body is the real Shadowsocks egress once the Hub attached the
// selected Out node's endpoint and the Hub-issued link key to the candidate,
// and the fail-closed block stub while it did not. `sing-box check` accepts
// a route tag with no matching outbound, so this renderer — not the kernel
// gate — is what keeps the document complete.
//
// The Out binding is deliberately not re-derived here: resolving "is an Out
// configured and healthy" needs Hub state the node does not have. A route that
// still names "out" only reaches this function through the Hub's own
// ResolveServerPolicy gate; the Agent proves the rest with sing-box check.
//
// The endpoint itself rides the candidate: the Hub attaches the selected Out
// node's address/port and the Hub-issued SS link key to the Line candidate
// before it compiles, so the Hub and the Agent render byte-identical
// documents and the readback digest needs no second channel. A nil Out keeps
// the fail-closed block stub.
func CompileCandidate(c Candidate) ([]byte, error) {
	return compileCandidate(c, c.Route, len(c.Route) > 0)
}

// CompileCandidateWithRoute renders a Line candidate with the route fragment
// already produced by policy.RenderServerRoute and the resolved Out fact.
// The fragment crosses as JSON because node must not import policy: the
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
	if c.Role == RoleOut && c.Out != nil && c.Out.Key != "" {
		return compileOutCandidate(c, route, egress)
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

// compileOutCandidate renders the Out guard listener: Shadowsocks with the
// pinned 2022 method and the Hub-issued link key, on the node's VLESS port.
// The tag stays revision-scoped like the v1 baseline it replaces
// ("meshmux-ss-r<revision>"). An Out without configured transport never
// reaches this renderer: it keeps the frozen v1 VLESS baseline, so its
// stored digest still verifies.
func compileOutCandidate(c Candidate, route json.RawMessage, egress serverEgress) ([]byte, error) {
	config := singBoxOutConfig{
		Log: singBoxLog{Disabled: true},
		Inbounds: []singBoxSSInbound{{
			Type:       "shadowsocks",
			Tag:        fmt.Sprintf("meshmux-ss-r%d", c.Revision),
			Listen:     "0.0.0.0",
			ListenPort: c.VLESSPort,
			Method:     OutLinkMethod,
			Password:   c.Out.Key,
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

// CompileACL renders the exact replacement script for the retired Out guard.
//
// The source allowlist is retired: an Out admits any client that presents the
// link key its own candidate publishes, so no nft rule may filter a source or
// the VLESS port any more. The table is kept as an empty, policy-accept shell
// so a host upgraded from an older release flushes its stale accept/drop rules
// on the next apply instead of keeping a guard that would deny every client
// the new model admits.
//
// The allowed argument stays in the signature only for the installer and older
// callers; it is ignored. An Edge never owns the table.
func CompileACL(c Candidate, _ []string) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Role == RoleEdge {
		return nil, nil
	}
	if c.Role != RoleOut {
		return nil, errors.New("ROLE_INVALID: unsupported node role")
	}
	var script strings.Builder
	fmt.Fprintf(&script, "# Exact MeshMux-owned table replacement; apply as one nft -f transaction.\n")
	fmt.Fprintf(&script, "# The Out source allowlist is retired; this table is intentionally rule-free.\n")
	fmt.Fprintf(&script, "table inet %[1]s {}\n", ACLTable)
	fmt.Fprintf(&script, "delete table inet %[1]s\n", ACLTable)
	fmt.Fprintf(&script, "table inet %[1]s {\n", ACLTable)
	fmt.Fprintf(&script, "  chain input {\n")
	fmt.Fprintf(&script, "    type filter hook input priority -10; policy accept;\n")
	fmt.Fprintf(&script, "  }\n}\n")
	return []byte(script.String()), nil
}

// ParseACLAllowed is retired with the source allowlist. The only canonical
// script is the empty table; it returns an empty set for that script and
// rejects every other file. A legacy allowlist is therefore never preserved
// across an install --repair: the repair rewrites the neutral table instead.
func ParseACLAllowed(c Candidate, script []byte) ([]string, error) {
	rendered, err := CompileACL(c, nil)
	if err != nil || bytes.Equal(script, nil) || !bytes.Equal(rendered, script) {
		return nil, errors.New("ACL_SCRIPT_INVALID: managed ACL is not the MeshMux render")
	}
	return []string{}, nil
}
