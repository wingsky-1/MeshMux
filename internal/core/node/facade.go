package node

// This file re-exports every public name of the node subpackages, so callers
// keep importing internal/core/node while the implementation stays navigable.

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/wingsky-1/MeshMux/internal/core/node/agent"
	"github.com/wingsky-1/MeshMux/internal/core/node/client"
	"github.com/wingsky-1/MeshMux/internal/core/node/render"
	"github.com/wingsky-1/MeshMux/internal/core/node/spec"
)

// Domain types.
type (
	Candidate         = spec.Candidate
	CandidateDocument = spec.CandidateDocument
	Config            = spec.Config
	Identity          = spec.Identity
	KernelRelease     = spec.KernelRelease
	Metadata          = spec.Metadata
	OutEgress         = spec.OutEgress
	Readback          = spec.Readback
	RealityConfig     = spec.RealityConfig
	Role              = spec.Role
	StageTarget       = spec.StageTarget
	VLESSUser         = spec.VLESSUser
)

// Agent runtime types.
type (
	CommandRunner            = agent.CommandRunner
	Controller               = agent.Controller
	ExecRunner               = agent.ExecRunner
	HandoffClaim             = agent.HandoffClaim
	HandoffConvergenceWriter = agent.HandoffConvergenceWriter
	RunOption                = agent.RunOption
	Runtime                  = agent.Runtime
	RuntimeOptions           = agent.RuntimeOptions
	Spawner                  = agent.Spawner
	StageTargetSource        = agent.StageTargetSource
	UpgradeConfirmer         = agent.UpgradeConfirmer
	UpgradeReverter          = agent.UpgradeReverter
)

// Outbound Hub client types.
type (
	Client        = client.Client
	ClientError   = client.ClientError
	ManifestBytes = client.ManifestBytes
)

// Host layout, schema and role vocabulary.
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
	CandidateSchema     = spec.CandidateSchema
	RoleEdge            = spec.RoleEdge
	RoleOut             = spec.RoleOut
	RoleHTTP            = spec.RoleHTTP
	KernelVersion       = spec.KernelVersion
	OutLinkMethod       = spec.OutLinkMethod
	OutEgressHTTP       = spec.OutEgressHTTP
)

// Agent host and publish contracts.
const (
	RuntimeLockPath       = agent.RuntimeLockPath
	MihomoVersion         = agent.MihomoVersion
	SingBoxPublishVersion = agent.SingBoxPublishVersion
	// The publish gate values stay literal in the facade because the
	// error-code golden scans this package's Code* constants for string
	// literals. facade_test.go pins them to the agent declarations.
	CodePublishCheckSingBox   = "PUBLISH_CHECK_SINGBOX_FAILED"
	CodePublishCheckMihomo    = "PUBLISH_CHECK_MIHOMO_FAILED"
	CodePublishSingBoxMissing = "PUBLISH_SINGBOX_UNAVAILABLE"
	CodePublishMihomoMissing  = "PUBLISH_MIHOMO_UNAVAILABLE"
	CodePublishMihomoVersion  = "PUBLISH_MIHOMO_VERSION_INVALID"
)

// Pure domain functions.
func CurrentAgentVersion() string { return spec.CurrentAgentVersion() }

func KernelReleaseFor(architecture string) (KernelRelease, bool) {
	return spec.KernelReleaseFor(architecture)
}

func NewCandidateDocument(candidate Candidate) CandidateDocument {
	return spec.NewCandidateDocument(candidate)
}

func NewOutLinkKey() (string, error) { return spec.NewOutLinkKey() }

func ParseHTTPProxyURL(raw string) (OutEgress, error) { return spec.ParseHTTPProxyURL(raw) }

func ParseRole(value string) (Role, error) { return spec.ParseRole(value) }

func ValidateOutLinkKey(key string) error { return spec.ValidateOutLinkKey(key) }

// Candidate rendering.
func CompileCandidate(c Candidate) ([]byte, error) { return render.CompileCandidate(c) }

func CompileCandidateWithRoute(c Candidate, route json.RawMessage, outConfigured bool) ([]byte, error) {
	return render.CompileCandidateWithRoute(c, route, outConfigured)
}

func CompileACL(c Candidate, sources []string) ([]byte, error) {
	return render.CompileACL(c, sources)
}

func ParseACLAllowed(c Candidate, script []byte) ([]string, error) {
	return render.ParseACLAllowed(c, script)
}

// Agent runtime and publish gates.
func AcquireRuntimeLock(ctx context.Context, root string) (io.Closer, error) {
	return agent.AcquireRuntimeLock(ctx, root)
}

func CheckMihomoDocument(ctx context.Context, runner CommandRunner, binary, configPath, dataDir string) (string, error) {
	return agent.CheckMihomoDocument(ctx, runner, binary, configPath, dataDir)
}

func CheckSingBoxDocument(ctx context.Context, runner CommandRunner, binary, configPath string) error {
	return agent.CheckSingBoxDocument(ctx, runner, binary, configPath)
}

func NewRuntime(cfg Config, identity Identity, opts RuntimeOptions) (*Runtime, error) {
	return agent.NewRuntime(cfg, identity, opts)
}

func NewRuntimeContext(ctx context.Context, cfg Config, identity Identity, opts RuntimeOptions) (*Runtime, error) {
	return agent.NewRuntimeContext(ctx, cfg, identity, opts)
}

func ReadbackLocal(ctx context.Context, cfg Config, root string, runner CommandRunner) (Readback, error) {
	return agent.ReadbackLocal(ctx, cfg, root, runner)
}

func RunCommand(args []string, stderr io.Writer, options ...RunOption) int {
	return agent.RunCommand(args, stderr, options...)
}

func TransientReadback(err error) bool { return agent.TransientReadback(err) }

func VerifyOutACLDocument(output []byte, port int, sources []string) error {
	return agent.VerifyOutACLDocument(output, port, sources)
}

func VerifyOutACLShapeDocument(output []byte, port int) error {
	return agent.VerifyOutACLShapeDocument(output, port)
}

func WithHandoffConvergence(writer HandoffConvergenceWriter) RunOption {
	return agent.WithHandoffConvergence(writer)
}

func WithUpgradeConfirmation(confirmer UpgradeConfirmer) RunOption {
	return agent.WithUpgradeConfirmation(confirmer)
}

func WithUpgradeRevert(reverter UpgradeReverter) RunOption {
	return agent.WithUpgradeRevert(reverter)
}

// NewClient builds the outbound Hub client.
func NewClient(config Config, identity Identity, httpClient *http.Client) (*Client, error) {
	return client.NewClient(config, identity, httpClient)
}
