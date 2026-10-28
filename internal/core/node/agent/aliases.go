package agent

import (
	"github.com/wingsky-1/MeshMux/internal/core/node/client"
	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// The Agent executes the one node domain model. These aliases keep the domain
// vocabulary unqualified in this package without copying a type or a constant.
type (
	Candidate         = spec.Candidate
	CandidateDocument = spec.CandidateDocument
	Config            = spec.Config
	Identity          = spec.Identity
	Metadata          = spec.Metadata
	Readback          = spec.Readback
	Role              = spec.Role
	VLESSUser         = spec.VLESSUser
	RealityConfig     = spec.RealityConfig
	OutEgress         = spec.OutEgress
	KernelRelease     = spec.KernelRelease
	StageTarget       = spec.StageTarget
	ClientError       = client.ClientError
)

const (
	AgentDataDir        = spec.AgentDataDir
	ActiveConfigDir     = spec.ActiveConfigDir
	AgentBinaryPath     = spec.AgentBinaryPath
	SingBoxBinaryPath   = spec.SingBoxBinaryPath
	AgentConfigPath     = spec.AgentConfigPath
	IdentityPath        = spec.IdentityPath
	RuntimeStatePath    = spec.RuntimeStatePath
	ActiveCandidatePath = spec.ActiveCandidatePath
	ActiveConfigPath    = spec.ActiveConfigPath
	ACLPath             = spec.ACLPath
	AgentUnit           = spec.AgentUnit
	SingBoxUnit         = spec.SingBoxUnit
	ACLUnit             = spec.ACLUnit
	ACLTable            = spec.ACLTable
	KernelVersion       = spec.KernelVersion
	CandidateSchema     = spec.CandidateSchema
	RoleEdge            = spec.RoleEdge
	RoleOut             = spec.RoleOut
	RoleHTTP            = spec.RoleHTTP
	OutLinkMethod       = spec.OutLinkMethod
	OutEgressHTTP       = spec.OutEgressHTTP
	MaxCandidateUsers   = spec.MaxCandidateUsers
)
