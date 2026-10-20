package node

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

type singBoxConfig struct {
	Log       singBoxLog        `json:"log"`
	Inbounds  []singBoxInbound  `json:"inbounds"`
	Outbounds []singBoxOutbound `json:"outbounds"`
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
}

// The v2 shapes are separate types on purpose: the frozen v1 document is
// byte-for-byte immutable, so it can never inherit a new field or a changed
// key order from the REALITY shape.

type singBoxConfigV2 struct {
	Log       singBoxLog         `json:"log"`
	Inbounds  []singBoxInboundV2 `json:"inbounds"`
	Outbounds []singBoxOutbound  `json:"outbounds"`
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
func CompileCandidate(c Candidate) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Reality != nil {
		return compileRealityCandidate(c)
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
		Outbounds: []singBoxOutbound{{Type: "direct", Tag: "direct"}},
	}
	out, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return nil, errors.New("CANDIDATE_RENDER_FAILED")
	}
	return out, nil
}

// compileRealityCandidate renders the native edge inbound with the REALITY
// listener and the real credential users.
func compileRealityCandidate(c Candidate) ([]byte, error) {
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
		Outbounds: []singBoxOutbound{{Type: "direct", Tag: "direct"}},
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

// CompileACL renders an exact table replacement for Out nodes. Edge nodes do
// not create the Out table. The caller must verify that inet meshmux_out is
// MeshMux-owned and feed the returned bytes to one nft -f transaction.
//
// The table is a narrow VLESS guard, not a host firewall: the base chain
// keeps policy accept so SSH, established return traffic and loopback stay
// with the host/filter rules, while the two VLESS drop rules deny the data
// plane by default while no Line is authorized. Per-Line source allowlists
// belong to a later stage and are applied ahead of the final drops.
func CompileACL(c Candidate) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if c.Role == RoleEdge {
		return nil, nil
	}
	if c.Role != RoleOut {
		return nil, errors.New("ROLE_INVALID: unsupported node role")
	}
	script := fmt.Sprintf(`# Exact MeshMux-owned table replacement; apply as one nft -f transaction.
table inet %[1]s {}
delete table inet %[1]s
table inet %[1]s {
  chain input {
    type filter hook input priority -10; policy accept;
    tcp dport %[2]d drop
    udp dport %[2]d drop
  }
}
`, ACLTable, c.VLESSPort)
	return []byte(script), nil
}
