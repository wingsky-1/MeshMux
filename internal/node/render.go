package node

import (
	"encoding/json"
	"errors"
	"fmt"
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

// CompileCandidate is a pure, deterministic renderer for the fixed native
// sing-box shape. Empty users intentionally provides no client credential.
func CompileCandidate(c Candidate) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
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
