package client

import "github.com/wingsky-1/MeshMux/internal/core/node/spec"

// The Agent client speaks the one node domain model. These aliases keep the
// domain vocabulary unqualified in this package without copying a type.
type (
	Candidate         = spec.Candidate
	CandidateDocument = spec.CandidateDocument
	Config            = spec.Config
	Identity          = spec.Identity
	Metadata          = spec.Metadata
	Role              = spec.Role
	StageTarget       = spec.StageTarget
)

const (
	KernelVersion = spec.KernelVersion
	RoleEdge      = spec.RoleEdge
	RoleOut       = spec.RoleOut
	RoleHTTP      = spec.RoleHTTP
)
