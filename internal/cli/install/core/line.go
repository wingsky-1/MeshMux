package core

import (
	"context"
	"errors"
	"path/filepath"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// The co-located Line layout is derived entirely from the host's own
// recorded state. No caller, CLI flag, user input or remote request can
// select a ledger path, a binary path or a service name here: every value
// below is an internal constant or comes from a MeshMux-written ledger.

const (
	// sharedAgentKey names the Hub-owned MeshMux runtime binary inside a
	// ledger's shared-binary map.
	SharedAgentKey = "meshmuxd"
	// hubSSHJailName is the Fail2ban jail the Hub owns.
	HubSSHJailName = "meshmux-sshd"
	// nodeSSHJailName is the Fail2ban jail a standalone Line owns.
	NodeSSHJailName = "meshmux-node-sshd"
	// hubSSHJailPath is the Fail2ban jail file the Hub owns.
	HubSSHJailPath = Fail2banJailDir + "/" + SSHJailFileName
	// nodeSSHJailPath is the Fail2ban jail file a standalone Line owns.
	NodeSSHJailPath = Fail2banJailDir + "/meshmux-node-ssh.local"
)

// nodeLayout describes where a Node operation keeps its ledger and which
// host resources it shares with an already installed Hub.
type NodeLayout struct {
	// StatePath is the fixed ledger path of this Node operation.
	StatePath string
	// OperationDir is the journal root of this Node operation.
	OperationDir string
	// StageRoot is the staging cache root of this Node operation.
	StageRoot string
	// SharedAgent is the Hub-owned MeshMux runtime binary this Line reuses
	// verbatim, or "" when the Line owns its own copy.
	SharedAgent string
	// SharedAgentSHA256 is the pinned digest of the reused binary.
	SharedAgentSHA256 string
	// ReuseHubSSHJail reports that the Hub's Fail2ban SSH jail already
	// covers the same listeners and must not be duplicated.
	ReuseHubSSHJail bool
	// CoLocated reports that this host also runs the Hub.
	CoLocated bool
	// HubHost reports that this host records a Hub layout, even when the
	// Hub does not yet publish a reusable runtime binary.
	HubHost bool
	// HubState is the recorded Hub ledger of this host.
	HubState InstallState
}

// standaloneNodeLayout is the layout of a Node that owns the host. It keeps
// the historical single ledger, journal and staging locations.
func StandaloneNodeLayout() NodeLayout {
	return NodeLayout{
		StatePath:    InstallerStatePath,
		OperationDir: versions.InstallerRoot + "/operations",
		StageRoot:    "/var/cache/meshmux-installer",
	}
}

// hubOriginFor renders the exact public management origin of a recorded Hub
// layout. A Line that shares the host with the Hub must point at it.
func HubOriginFor(state InstallState) string {
	if state.Config.ManagementDomain == "" {
		return ""
	}
	return "https://" + state.Config.ManagementDomain
}

// resolveNodeLayout selects the ledger, journal and shared-binary policy for
// a Node operation from the host's own recorded state.
//
// A host that already runs the Hub hosts exactly one co-located Line with
// its own ledger; every other host keeps the single-ledger behavior
// byte-for-byte.
//
// A Hub that does not publish a reusable runtime binary yet cannot host a
// Line: the Line would have to install a second, possibly different,
// MeshMux binary on the same host. Such a host is still reported as a Hub
// host, so the caller refuses it with the stable layout conflict code
// instead of proceeding.
func ResolveNodeLayout(root string) (NodeLayout, error) {
	hubState, hasHub, err := ReadState(root)
	if err != nil {
		return NodeLayout{}, &InstallError{Stage: "preflight", Code: CodeInstallStateInvalid,
			Recovery: "Inspect the recorded installer state; do not delete MeshMux data or Headscale keys."}
	}
	standalone := StandaloneNodeLayout()
	if !hasHub || hubState.Node != nil {
		// No Hub on this host, or the recorded ledger is a standalone Line.
		return standalone, nil
	}
	if hubState.Config.ManagementDomain == "" && hubState.Config.SubscriptionDomain == "" &&
		hubState.Config.HeadscaleDomain == "" {
		return standalone, nil
	}
	layout := NodeLayout{
		StatePath:    LocalLineStatePath,
		OperationDir: versions.InstallerRoot + "/local-line/operations",
		StageRoot:    "/var/cache/meshmux-installer/local-line",
		HubHost:      true,
		HubState:     hubState,
	}
	// Only an installed Hub may host a co-located Line, and only a Hub that
	// publishes its runtime build can hand a verified binary to the Line.
	shared, ok := hubState.SharedBinaries[SharedAgentKey]
	if hubState.Status == "installed" && ok && shared.Path == node.AgentBinaryPath &&
		ValidDigest.MatchString(shared.SHA256) {
		layout.CoLocated = true
		layout.SharedAgent = shared.Path
		layout.SharedAgentSHA256 = shared.SHA256
		layout.ReuseHubSSHJail = true
	}
	return layout, nil
}

// nodeOwnershipUnverified is the stable preflight code returned when the
// effective Node ledger of this host cannot authorize a managed listener.
//
// The ledger is the only ownership proof MeshMux accepts for a listener that
// is already bound. A missing ledger, a ledger that records another Hub
// origin, Node ID, role or port set, or a ledger without a verified kernel
// digest must never be reported as PORT_CONFLICT: that would either blame a
// third party for a MeshMux listener or let an unverified process pass as
// MeshMux-owned. The code is stable because operators and the CLI branch on
// it; the recovery text explains the concrete repair.
const NodeOwnershipUnverified = "NODE_OWNERSHIP_UNVERIFIED"

func NodeOwnershipError(recovery string) error {
	return &InstallError{Stage: "preflight", Code: NodeOwnershipUnverified, Recovery: recovery}
}

// effectiveNodeStateError preserves a stable installer code from the layout
// resolver and never downgrades a ledger read failure to "no ledger".
func effectiveNodeStateError(err error) error {
	var ie *InstallError
	if errors.As(err, &ie) {
		return ie
	}
	return &InstallError{Stage: "preflight", Code: CodeInstallStateInvalid,
		Recovery: "Inspect the recorded installer state; do not delete MeshMux data."}
}

// ReadNodeState returns the effective Node ledger of this host.
//
// On a host that also runs the Hub, that is the co-located Line's own
// fixed ledger. On every other host it is the historical single ledger at
// /var/lib/meshmux-installer/state.json. The path is always an internal
// constant selected from the host's own recorded state.
//
// A host that records a Hub layout which cannot host a co-located Line (the
// Hub does not publish a pinned reusable runtime) has no effective Node
// ledger. Such a host fails closed instead of falling back to the Hub ledger,
// whose Node record is nil by construction and therefore can never prove
// Node ownership.
func ReadNodeState(root string) (InstallState, bool, error) {
	layout, err := ResolveNodeLayout(root)
	if err != nil {
		return InstallState{}, false, effectiveNodeStateError(err)
	}
	if layout.HubHost && !layout.CoLocated {
		return InstallState{}, false, NodeOwnershipError(
			"This host records a Hub layout that cannot host a co-located Line because the Hub does not publish a pinned reusable MeshMux runtime. Repair the Hub layout first; a Line never falls back to the Hub ledger.")
	}
	return ReadNodeStateAt(root, layout)
}

// effectiveNodeState resolves the Node ledger that belongs to this host and
// proves that it describes cfg.
//
// The ledger must exist and must record the same Hub origin, Node ID, role,
// VLESS port and SSH port as cfg (SameNodeConfig). Every failure is a stable
// ownership/state error, never a bare PORT_CONFLICT, and a ledger read error
// is propagated instead of being treated as "no managed listener".
func effectiveNodeState(root string, cfg node.Config) (NodeLayout, InstallState, error) {
	layout, err := ResolveNodeLayout(root)
	if err != nil {
		return NodeLayout{}, InstallState{}, effectiveNodeStateError(err)
	}
	if layout.HubHost && !layout.CoLocated {
		return layout, InstallState{}, NodeOwnershipError(
			"This host records a Hub layout that cannot host a co-located Line because the Hub does not publish a pinned reusable MeshMux runtime. Repair the Hub layout first; a Line never falls back to the Hub ledger.")
	}
	state, hasState, err := ReadNodeStateAt(root, layout)
	if err != nil {
		return layout, InstallState{}, &InstallError{Stage: "preflight", Code: CodeInstallStateInvalid,
			Recovery: "Inspect the effective Node ledger; do not delete MeshMux state."}
	}
	if !hasState || state.Node == nil {
		return layout, state, NodeOwnershipError(
			"No effective Node ledger records this Line. A missing ledger cannot prove that a bound listener belongs to MeshMux; install or repair the recorded Node layout first.")
	}
	if !SameNodeConfig(*state.Node, cfg) {
		return layout, state, NodeOwnershipError(
			"The effective Node ledger records a different Hub origin, Node ID, role or port set. Repair only supports the exact recorded Node configuration.")
	}
	return layout, state, nil
}

// effectiveNodeKernelDigest returns the kernel digest recorded by the
// effective Node ledger of this host.
//
// Only a digest that is bound to the recorded Node and is a valid SHA-256 is
// ever adopted. The caller-supplied cfg digest is never used as ownership
// evidence: the ledger is the record MeshMux itself wrote. An empty or
// malformed digest is an ownership failure, not a port conflict.
func EffectiveNodeKernelDigest(root string, cfg node.Config) (string, error) {
	_, state, err := effectiveNodeState(root, cfg)
	if err != nil {
		return "", err
	}
	if !ValidDigest.MatchString(state.Node.KernelSHA256) {
		return "", NodeOwnershipError(
			"The effective Node ledger has no verified kernel digest. A bound listener is never adopted as MeshMux-owned without the recorded digest; complete the Node install or re-enroll the Node.")
	}
	return state.Node.KernelSHA256, nil
}

// nodeLedgerBindsConfig reports whether the effective Node ledger of this
// host records exactly cfg. A missing ledger or a read error is false; the
// caller decides the stable code it reports.
func NodeLedgerBindsConfig(root string, cfg node.Config) (bool, error) {
	_, state, err := effectiveNodeState(root, cfg)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) && ie.Code == NodeOwnershipUnverified {
			return false, nil
		}
		return false, err
	}
	return state.Node != nil, nil
}

// readNodeState reads the ledger that belongs to this Node operation: the
// Hub ledger for a standalone host, the dedicated local Line ledger for a
// co-located host. The path is always an internal constant.
func ReadNodeStateAt(root string, layout NodeLayout) (InstallState, bool, error) {
	if layout.CoLocated {
		return ReadStateAt(root, LocalLineStatePath)
	}
	return ReadState(root)
}

// writeNodeState persists the ledger that belongs to this Node operation.
func WriteNodeState(root string, layout NodeLayout, state InstallState) error {
	if layout.CoLocated {
		return WriteLocalLineState(root, state)
	}
	return WriteState(root, state)
}

// readLocalLineState reads the co-located Line ledger from its fixed path.
func readLocalLineState(root string) (InstallState, bool, error) {
	return ReadStateAt(root, LocalLineStatePath)
}

// ReadLocalLineState is the exported read point for the privileged Hub upgrade
// executor (#11d Task 6): it must re-pin the Line ledger whose path is a private
// install constant, never a caller-selected path.
func ReadLocalLineState(root string) (InstallState, bool, error) {
	return readLocalLineState(root)
}

// writeLocalLineState persists the co-located Line ledger to its fixed path.
func WriteLocalLineState(root string, state InstallState) error {
	if err := EnsureDirectory(Rooted(root, filepath.Dir(LocalLineStatePath)), 0700); err != nil {
		return err
	}
	return WriteStateAt(root, LocalLineStatePath, state)
}

// sharedAgentMatches reports whether the Hub-owned runtime binary on disk is
// still exactly the build that was pinned. A mismatch means the Hub and the
// Line would run different MeshMux builds on one host, so the Line fails
// closed instead of continuing.
func SharedAgentMatches(root, path, expected string) bool {
	if path == "" || !ValidDigest.MatchString(expected) {
		return false
	}
	digest, err := SHA256File(Rooted(root, path))
	if err != nil {
		return false
	}
	return digest == expected
}

// checkLocalLineSharedBinary fails closed when a co-located Line pins a
// MeshMux runtime build that differs from the candidate build.
//
// The coordinated Web upgrade that moves the Hub and the Line to a new
// build together is Issue #11. This profile only refuses the unsafe
// single-sided change: a mismatch is never applied silently.
//
// The check is a no-op when this host has no co-located Line, so a standalone
// Hub never pays for the extra read.
func CheckLocalLineSharedBinary(root, candidateHash string) error {
	lineState, hasLine, err := ReadStateAt(root, LocalLineStatePath)
	if err != nil {
		return &InstallError{Stage: "preflight", Code: "LOCAL_LINE_STATE_INVALID",
			Recovery: "Inspect /var/lib/meshmux-installer/local-line/state.json; do not delete it before the co-located Line is repaired."}
	}
	if !hasLine {
		return nil
	}
	pin, ok := lineState.SharedBinaries[SharedAgentKey]
	if !ok || pin.SHA256 == "" {
		return nil
	}
	if !ValidDigest.MatchString(candidateHash) || pin.SHA256 != candidateHash {
		return &InstallError{Stage: "preflight", Code: "SHARED_BINARY_MISMATCH",
			Recovery: "The co-located Line pins a different MeshMux runtime build. Restore the matching build on both layouts, or use the validated coordinated Web upgrade from Issue #11 once it is available."}
	}
	return nil
}

// checkLocalLineSharedBinaryForExecutable performs the same check during
// the Hub preflight, using the executable the Hub would install. The check
// runs before any target ownership or drift check so a conflicting build is
// refused before the Hub starts replacing files.
func CheckLocalLineSharedBinaryForExecutable(root string, opts ApplyOptions) error {
	lineState, hasLine, err := ReadStateAt(root, LocalLineStatePath)
	if err != nil {
		return &InstallError{Stage: "preflight", Code: "LOCAL_LINE_STATE_INVALID",
			Recovery: "Inspect /var/lib/meshmux-installer/local-line/state.json; do not delete it before the co-located Line is repaired."}
	}
	if !hasLine {
		return nil
	}
	pin, ok := lineState.SharedBinaries[SharedAgentKey]
	if !ok || pin.SHA256 == "" {
		return nil
	}
	candidateHash, err := SHA256File(referenceExecutablePath(opts))
	if err != nil {
		return &InstallError{Stage: "preflight", Code: "MESHMUX_BINARY_INVALID",
			Recovery: "Run the installer from a regular, readable MeshMux executable and retry."}
	}
	return CheckLocalLineSharedBinary(root, candidateHash)
}

// hubSSHJailCovers reports whether the recorded Hub layout owns a Fail2ban
// SSH jail that covers exactly the detected SSH listeners. A co-located
// Line reuses that jail instead of installing a second one for the same
// ports, so the reuse must be provable from the Hub ledger.
func hubSSHJailCovers(hubState InstallState, sshPorts []int) bool {
	if _, ok := hubState.ManagedFiles[HubSSHJailPath]; !ok {
		return false
	}
	if len(hubState.SSHPorts) == 0 || len(sshPorts) == 0 {
		return false
	}
	return EqualIntSets(hubState.SSHPorts, sshPorts)
}

// checkLocalLineSSHJailReuse fails closed when a co-located Line cannot
// prove that the Hub's Fail2ban SSH jail already covers the detected SSH
// listeners.
//
// The fixed behavior is reuse, never duplication: a second jail for the
// same listeners would double-ban and duplicate the nftables rules. But
// reuse is only safe when the Hub's jail really covers this host's SSH
// ports. When it does not, the Line refuses instead of silently leaving
// its SSH listener unprotected or installing a duplicate jail.
func CheckLocalLineSSHJailReuse(layout NodeLayout, sshPorts []int) error {
	if !layout.CoLocated {
		return nil
	}
	if hubSSHJailCovers(layout.HubState, sshPorts) {
		return nil
	}
	return &InstallError{Stage: "preflight", Code: "SSH_JAIL_REUSE_CONFLICT",
		Recovery: "The Hub's Fail2ban SSH jail does not cover this host's actual SSH listeners. Repair the Hub so its jail matches, then install the Line."}
}

// resolveNodeAgent returns the Agent binary this Node runs and its verified
// digest.
//
// A co-located Line reuses the Hub-owned runtime binary verbatim: it never
// stages a replacement, never overwrites the file and never snapshots or
// rolls it back. The Line only proves that the shared build is still the
// pinned one.
func ResolveNodeAgent(ctx context.Context, opts NodeApplyOptions, layout NodeLayout, stageDir string) (string, string, error) {
	if !layout.CoLocated {
		executable := opts.Executable
		if executable == "" {
			executable = "/proc/self/exe"
		}
		agentPath := filepath.Join(stageDir, "meshmuxd")
		agentHash, err := CopyExecutable(executable, agentPath)
		if err != nil {
			return "", "", &InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID",
				Recovery: "Run the installer from a regular MeshMux executable and retry."}
		}
		if err := VerifyAgentBinary(ctx, opts, agentPath, agentHash); err != nil {
			return "", "", &InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID",
				Recovery: "Run the installer from the exact MeshMux build being installed; external Agent binaries are rejected."}
		}
		return agentPath, agentHash, nil
	}
	if !SharedAgentMatches(opts.Root, layout.SharedAgent, layout.SharedAgentSHA256) {
		return "", "", &InstallError{Stage: "stage", Code: "SHARED_BINARY_MISMATCH",
			Recovery: "The Hub-owned MeshMux runtime on this host no longer matches the recorded digest. Repair the Hub and the Line together; the Line never replaces the shared binary."}
	}
	if err := verifySharedAgentVersion(ctx, opts, layout.SharedAgent); err != nil {
		return "", "", err
	}
	return layout.SharedAgent, layout.SharedAgentSHA256, nil
}

// verifySharedAgentVersion proves that the Hub-owned runtime binary is the
// pinned MeshMux Agent build. The output must equal the pinned version
// exactly; substring matches and extra output are rejected.
func verifySharedAgentVersion(ctx context.Context, opts NodeApplyOptions, logicalPath string) error {
	path := Rooted(opts.Root, logicalPath)
	out, err := opts.Runner.Run(ctx, path, "__internal-agent-version")
	if err != nil {
		return &InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID",
			Recovery: "The Hub-owned MeshMux runtime did not answer the version probe; repair the Hub first."}
	}
	if strings.TrimSpace(string(out)) != node.CurrentAgentVersion() {
		return &InstallError{Stage: "stage", Code: "MESHMUX_BINARY_INVALID",
			Recovery: "The Hub-owned MeshMux runtime is not the pinned build; repair the Hub and the Line together."}
	}
	return nil
}

// referenceExecutablePath is the executable an installer run copies for its
// own runtime binary. It is never user supplied.
func referenceExecutablePath(opts ApplyOptions) string {
	if opts.Executable == "" {
		return "/proc/self/exe"
	}
	return opts.Executable
}

// removeTarget drops one logical path from a target list. It is used to keep
// the Hub-owned shared binary out of the Line's snapshot and rollback set.
func RemoveTarget(targets []string, drop string) []string {
	if drop == "" {
		return targets
	}
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		if target == drop {
			continue
		}
		out = append(out, target)
	}
	return out
}
