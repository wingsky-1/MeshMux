// Package product contains deployment-domain contracts without runtime side effects.
package product

import "fmt"

// Role is the installed host's purpose. Mesh devices are not host roles.
type Role string

const (
	RoleHub  Role = "hub"
	RoleEdge Role = "edge"
	RoleOut  Role = "out"
)

func ParseRole(value string) (Role, error) {
	switch Role(value) {
	case RoleHub, RoleEdge, RoleOut:
		return Role(value), nil
	default:
		return "", fmt.Errorf("unsupported install role: %q", value)
	}
}
