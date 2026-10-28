package render

import "github.com/wingsky-1/MeshMux/internal/core/node/spec"

// The renderer consumes the one node candidate document. These aliases keep
// the domain vocabulary unqualified in this package without copying a type or
// a constant.
type (
	Candidate         = spec.Candidate
	CandidateDocument = spec.CandidateDocument
	Config            = spec.Config
	KernelRelease     = spec.KernelRelease
	OutEgress         = spec.OutEgress
	VLESSUser         = spec.VLESSUser
	RealityConfig     = spec.RealityConfig
	Role              = spec.Role
)

const (
	OutLinkMethod     = spec.OutLinkMethod
	OutEgressHTTP     = spec.OutEgressHTTP
	RoleEdge          = spec.RoleEdge
	RoleOut           = spec.RoleOut
	RoleHTTP          = spec.RoleHTTP
	KernelVersion     = spec.KernelVersion
	CandidateSchema   = spec.CandidateSchema
	ACLTable          = spec.ACLTable
	MaxCandidateUsers = spec.MaxCandidateUsers
)
