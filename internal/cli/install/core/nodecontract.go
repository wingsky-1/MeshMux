package core

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// The Node channel's options and the shared Node-state helpers that the
// installer engine owns because more than one package needs them: the snapshot
// restore path and the co-located Line layout inspect and rewrite Node state,
// the Node channel verifies its staged Agent, and the revert executor rolls
// Node files back.

// NodeApplyOptions is shared by the install CLI and isolated VM acceptance.
// The production defaults are wired by InstallNode.
type NodeApplyOptions struct {
	Root             string
	Runner           CommandRunner
	HTTPClient       *http.Client
	Executable       string
	Preflight        func(context.Context, node.Config, bool) ([]Check, []int)
	DownloadArtifact func(context.Context, Artifact, string) (string, error)

	// NonInteractive marks a Web-driven handoff: the operation must never wait
	// for an operator, so a path that would need a prompt is refused with
	// UPDATE_INTERACTIVE_REFUSED instead.
	NonInteractive bool

	// FromRecordedState marks the hidden handoff family
	// (`install <role> --repair --non-interactive --from-recorded-state
	// --operation-id <op>`): every configuration value and the identity come
	// from the recorded ledger, so a lost identity is terminal
	// (UPDATE_REENROLL_REQUIRED) instead of a prompt. It is never a second
	// install mode: the public `install` surface cannot set it.
	FromRecordedState bool

	// LockWait bounds how long an unattended operation retries the host-wide
	// install lock before UPDATE_RETRY_EXHAUSTED. Zero uses installLockWait
	// (60s, spec §4.9 / D7) for a non-interactive run and no wait at all for
	// an interactive one. Tests set a short bound.
	LockWait time.Duration

	// Test-only seams. Root != "/" is required to use either override.
	Artifacts []Artifact
	Verify    func(context.Context, node.Config, CommandRunner, node.Readback) error
	Pair      func(context.Context, node.Config, string) (node.Identity, error)
	Metadata  func(context.Context, node.Config, node.Identity) (node.Metadata, error)
	Candidate func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error)
	Readback  func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error)
	// VerifyAgent is a test-only seam for an isolated root. Production
	// verification requires the staged Agent to be byte-identical to the
	// running installer.
	VerifyAgent func(string, string) error
}

func SameNodeConfig(a, b node.Config) bool {
	return a.HubURL == b.HubURL && a.NodeID == b.NodeID && a.Role == b.Role &&
		a.VLESSPort == b.VLESSPort && a.SSHPort == b.SSHPort
}

func CloneNodeConfig(cfg *node.Config) *node.Config {
	if cfg == nil {
		return nil
	}
	copyCfg := *cfg
	return &copyCfg
}

func EqualIntSets(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	sortedA, sortedB := append([]int(nil), a...), append([]int(nil), b...)
	sort.Ints(sortedA)
	sort.Ints(sortedB)
	for i := range sortedA {
		if sortedA[i] != sortedB[i] {
			return false
		}
	}
	return true
}

// NodeAgentReference resolves which executable the staged Agent binary must
// be a copy of: the running installer itself, or the explicit Executable
// the install was launched from (the VM harness stages /tmp/meshmux while
// driving the install from install.test).
func NodeAgentReference(executable string) string {
	if executable == "" {
		return "/proc/self/exe"
	}
	return executable
}

func VerifyAgentBinary(ctx context.Context, opts NodeApplyOptions, stagedPath, stagedHash string) error {
	if opts.VerifyAgent != nil {
		return opts.VerifyAgent(stagedPath, stagedHash)
	}
	if opts.Root != "/" {
		return errors.New("AGENT_VERIFIER_REQUIRED")
	}
	// The staged Agent must be a copy of the exact executable being
	// installed. That is /proc/self/exe for a real install, or the explicit
	// Executable (the VM harness stages /tmp/meshmux while driving the
	// install from install.test).
	reference := NodeAgentReference(opts.Executable)
	selfHash, err := SHA256File(reference)
	if err != nil || selfHash != stagedHash {
		return errors.New("AGENT_NOT_SELF_COPY")
	}
	// Exact zero-arg version probe: output must equal the pinned Agent
	// version after trimming surrounding whitespace. Substring matches,
	// extra output or echoed arguments are rejected.
	out, err := opts.Runner.Run(ctx, stagedPath, "__internal-agent-version")
	if err != nil {
		return errors.New("AGENT_VERSION_PROBE_FAILED")
	}
	if strings.TrimSpace(string(out)) != node.CurrentAgentVersion() {
		return errors.New("AGENT_VERSION_MISMATCH")
	}
	return nil
}

// clearNodeUpgradeClaim removes the record once agent.json names the same
// binary. A missing record is success: the crash window is closed either way.
func ClearNodeUpgradeClaim(root string) error {
	if err := os.Remove(Rooted(root, NodeUpgradeClaimPath)); err != nil && !os.IsNotExist(err) {
		return errors.New("UPGRADE_CLAIM_CLEAR_FAILED")
	}
	return nil
}

func RollbackNodeFiles(ctx context.Context, opts NodeApplyOptions, snapshots []FileSnapshot, restoreRunning bool) bool {
	for _, unit := range []string{node.AgentUnit, node.SingBoxUnit, node.ACLUnit} {
		_, _ = opts.Runner.Run(ctx, "systemctl", "stop", unit)
	}
	ok := RestoreFileSnapshots(opts.Root, snapshots)
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		ok = false
	}
	if restoreRunning && ok {
		for _, unit := range []string{node.SingBoxUnit, node.AgentUnit} {
			if _, err := opts.Runner.Run(ctx, "systemctl", "start", unit); err != nil {
				ok = false
			}
		}
	}
	return ok
}
