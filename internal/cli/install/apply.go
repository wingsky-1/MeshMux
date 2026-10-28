package install

// The forwarded entry points below are the whole public surface: a caller
// imports install and never a channel package.

import (
	"context"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/install/hub"
	"github.com/wingsky-1/MeshMux/internal/cli/install/node"
	"github.com/wingsky-1/MeshMux/internal/cli/install/snapshot"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// Engine and channel entry points, forwarded to the package that owns them.

// install/core
type SharedBinary = core.SharedBinary
type InstallState = core.InstallState
type InstallResult = core.InstallResult
type InstallError = core.InstallError
type CommandRunner = core.CommandRunner
type ExecRunner = core.ExecRunner
type ApplyOptions = core.ApplyOptions

func ReadState(root string) (InstallState, bool, error)     { return core.ReadState(root) }
func EncodeState(state InstallState) ([]byte, error)        { return core.EncodeState(state) }
func ReadNodeState(root string) (InstallState, bool, error) { return core.ReadNodeState(root) }
func ReadLocalLineState(root string) (InstallState, bool, error) {
	return core.ReadLocalLineState(root)
}

type NodeApplyOptions = core.NodeApplyOptions

func SameNodeConfig(a, b corenode.Config) bool { return core.SameNodeConfig(a, b) }

// install/hub
func InstallHub(ctx context.Context, c Config, operationID string, repair bool, opts ApplyOptions) (InstallResult, error) {
	return hub.InstallHub(ctx, c, operationID, repair, opts)
}
func DiskAvailable(path string, minimum uint64) error { return core.DiskAvailable(path, minimum) }
func SSHPorts(ctx context.Context) ([]int, error)     { return core.SSHPorts(ctx) }
func CanBind(protocol, address string) error          { return core.CanBind(protocol, address) }
func PreflightWithMode(ctx context.Context, c Config, allowManagedListeners bool) ([]Check, []int) {
	return hub.PreflightWithMode(ctx, c, allowManagedListeners)
}
func CandidateFiles(c Config, ssh []int) (map[string]string, error) {
	return hub.CandidateFiles(c, ssh)
}

// install/node
func InstallNode(ctx context.Context, cfg corenode.Config, operationID string, repair bool, pairingCode string, opts NodeApplyOptions) (InstallResult, error) {
	return node.InstallNode(ctx, cfg, operationID, repair, pairingCode, opts)
}
func ConvergeHandoffConfig(root, operationID, expectedSHA256 string) error {
	return node.ConvergeHandoffConfig(root, operationID, expectedSHA256)
}

const CodeFail2banBaselineInvalid = node.CodeFail2banBaselineInvalid
const CodeFail2banRepairFailed = node.CodeFail2banRepairFailed

type Fail2banBaselineRepair = node.Fail2banBaselineRepair

const Fail2banRepairRsyslog = node.Fail2banRepairRsyslog
const Fail2banRepairSystemdBackend = node.Fail2banRepairSystemdBackend

func RepairNodeFail2banBaseline(ctx context.Context, root, operationID string, repair Fail2banBaselineRepair, runner CommandRunner) error {
	return node.RepairNodeFail2banBaseline(ctx, root, operationID, repair, runner)
}

type NodePlan = node.NodePlan

func PreflightNode(ctx context.Context, cfg corenode.Config, allowManaged bool) ([]Check, []int) {
	return node.PreflightNode(ctx, cfg, allowManaged)
}
func BuildNodePlanForRoot(root, id string, cfg corenode.Config, architecture string, checks []Check, ssh []int) NodePlan {
	return node.BuildNodePlanForRoot(root, id, cfg, architecture, checks, ssh)
}
func RenderNodeAgentConfig(cfg corenode.Config) ([]byte, error) {
	return node.RenderNodeAgentConfig(cfg)
}

// install/snapshot
const UpgradeSourceDir = snapshot.UpgradeSourceDir
const SnapshotManifestName = snapshot.SnapshotManifestName
const SnapshotSchema = snapshot.SnapshotSchema

type RestoreMode = snapshot.RestoreMode

const RestoreModeNone = snapshot.RestoreModeNone
const RestoreModeBinaryOnly = snapshot.RestoreModeBinaryOnly
const RestoreModeFull = snapshot.RestoreModeFull

type SnapshotEntry = snapshot.SnapshotEntry
type SnapshotManifest = snapshot.SnapshotManifest
type RestoreAnchors = snapshot.RestoreAnchors
type RestoreReport = snapshot.RestoreReport

func ReadUpgradeSource(root string) (string, error)    { return snapshot.ReadUpgradeSource(root) }
func UpgradeSourceCurrent(root string) bool            { return snapshot.UpgradeSourceCurrent(root) }
func UpgradeSourceAgentSHA(root string) (string, bool) { return snapshot.UpgradeSourceAgentSHA(root) }
func ReadSnapshotManifest(dir string) (SnapshotManifest, error) {
	return snapshot.ReadSnapshotManifest(dir)
}
func WriteSnapshotManifest(dir string, manifest SnapshotManifest) error {
	return snapshot.WriteSnapshotManifest(dir, manifest)
}
func RestoreNodeSnapshot(ctx context.Context, opts NodeApplyOptions, snapshotDir string, anchors RestoreAnchors) (RestoreReport, error) {
	return snapshot.RestoreNodeSnapshot(ctx, opts, snapshotDir, anchors)
}
func AdoptRestoredRelease(root, operationID string) error {
	return snapshot.AdoptRestoredRelease(root, operationID)
}
func StartRestoredNode(ctx context.Context, runner CommandRunner, root string) error {
	return snapshot.StartRestoredNode(ctx, runner, root)
}
func RefreshUpgradeSource(root string) error { return snapshot.RefreshUpgradeSource(root) }
