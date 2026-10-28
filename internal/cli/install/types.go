package install

// Shared installer contract, re-exported from install/core: the domain
// configuration, the preflight/plan vocabulary and the operation identity.
//
// The aliases are not copies. A type alias is the same type, so an
// install.Config can be passed to a channel function and back without a
// conversion and without a second definition of the record shape.

import (
	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

const (
	// Ports are re-exported from the versions leaf through install/core: the
	// rendered units, the launcher and the restore probe read the same values.
	WebPort           = core.WebPort
	HeadscalePort     = core.HeadscalePort
	HeadscaleGRPCPort = core.HeadscaleGRPCPort
	STUNPort          = core.STUNPort
)

type Config = core.Config

// SameConfig reports whether two configurations describe the same install.
func SameConfig(a, b Config) bool { return core.SameConfig(a, b) }

type Check = core.Check
type Port = core.Port
type Component = core.Component
type Plan = core.Plan

// NewOperationID generates an ID without using environment or user data.
func NewOperationID() (string, error) { return core.NewOperationID() }

// Ports is the fixed port table the plan and the preflight report.
func Ports() []Port { return core.Ports() }

// BuildPlan assembles the read-only plan from preflight checks.
func BuildPlan(id string, c Config, architecture string, checks []Check, ssh []int) Plan {
	return core.BuildPlan(id, c, architecture, checks, ssh)
}
