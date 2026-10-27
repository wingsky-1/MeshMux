package common

// Role and kernel names the store compares against stored strings.
//
// The owner of a node role is the node domain (internal/node.Role). These are
// re-exported here so this package never spells the same literal twice; every
// comparison reads one of these constants, and a role added to the node domain
// is added here in the same change.
//
// The kernel names are the two binaries the publish gate runs. They are also
// the labels a receipt carries, so a query or a page that compares a label must
// use these values rather than its own copy.

import "github.com/wingsky-1/MeshMux/internal/core/node"

const (
	// NodeRoleEdge is a proxy Line node (the only role that serves VLESS).
	NodeRoleEdge = node.RoleEdge
	// NodeRoleOut is a managed Out node (an SS guard egress with an Agent).
	NodeRoleOut = node.RoleOut
	// NodeRoleHTTP is an external HTTP proxy egress (Hub-only, no Agent).
	NodeRoleHTTP = node.RoleHTTP

	// KernelSingBox is the required gate kernel and the label its evidence
	// carries.
	KernelSingBox = "sing-box"
	// KernelMihomo is the optional client gate kernel and its evidence label.
	KernelMihomo = "mihomo"
)
