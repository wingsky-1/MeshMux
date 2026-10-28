package node

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/user"
	"strconv"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// Verify-tail data-plane helpers: activate the ACL and kernel units, install
// the dynamic candidate, poll native readback and prove the recorded LKG and
// Out guard. node_verify_tail.go owns the ordering and the failure ledger.

func activateNodeUnit(ctx context.Context, runner core.CommandRunner, unit string, repair bool) error {
	if repair {
		_, err := runner.Run(ctx, "systemctl", "restart", unit)
		return err
	}
	_, err := runner.Run(ctx, "systemctl", "enable", "--now", unit)
	return err
}

func currentNodeCandidate(root string, cfg corenode.Config) (corenode.CandidateDocument, bool) {
	candidateData, err := os.ReadFile(core.Rooted(root, corenode.ActiveCandidatePath))
	if err != nil {
		return corenode.CandidateDocument{}, false
	}
	var document corenode.CandidateDocument
	if err := json.Unmarshal(candidateData, &document); err != nil || document.ValidateFor(cfg) != nil {
		return corenode.CandidateDocument{}, false
	}
	return document, true
}

func nodeValidLKG(root string, cfg corenode.Config) (string, bool) {
	active, ok := currentNodeCandidate(root, cfg)
	if !ok {
		return "", false
	}
	candidatePath := core.Rooted(root, corenode.ActiveCandidatePath)
	candidateInfo, err := os.Lstat(candidatePath)
	if err != nil || !candidateInfo.Mode().IsRegular() || candidateInfo.Mode()&os.ModeSymlink != 0 || candidateInfo.Mode().Perm() != 0600 {
		return "", false
	}
	configPath := core.Rooted(root, corenode.ActiveConfigPath)
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 {
		return "", false
	}
	if root == "/" && !nodeFileOwnedBy(configPath, 0, "meshmux-singbox") {
		return "", false
	}
	actual, err := os.ReadFile(configPath)
	if err != nil {
		return "", false
	}
	expected, err := corenode.CompileCandidate(active.Candidate())
	if err != nil || !bytes.Equal(actual, expected) {
		return "", false
	}
	if cfg.Role == corenode.RoleOut {
		// The Out ACL unit applies this file before the kernel starts. The
		// source allowlist is retired, so the only valid file is the neutral,
		// rule-free MeshMux render. A legacy guard is not LKG: repair rewrites
		// the neutral table instead of preserving a stale source filter.
		aclPath := core.Rooted(root, corenode.ACLPath)
		aclInfo, err := os.Lstat(aclPath)
		if err != nil || !aclInfo.Mode().IsRegular() || aclInfo.Mode()&os.ModeSymlink != 0 || aclInfo.Mode().Perm() != 0600 {
			return "", false
		}
		aclActual, err := os.ReadFile(aclPath)
		if err != nil {
			return "", false
		}
		if _, err := corenode.ParseACLAllowed(active.Candidate(), aclActual); err != nil {
			return "", false
		}
	}
	digest := sumBytes(actual)
	return digest, digest == sumBytes(expected)
}

// pollNodeReadback re-reads the live data plane until it validates or the
// deadline hits. The kernel needs a moment after (re)start before its
// process, listeners and nft state are observable, especially under QEMU
// software emulation. Only startup-transient failures are retried; a
// deterministic config or ownership failure still fails fast so a broken
// data plane is never mistaken for a slow one.
func pollNodeReadback(ctx context.Context, opts core.NodeApplyOptions, cfg corenode.Config) (corenode.Readback, error) {
	deadline := time.Now().Add(60 * time.Second)
	for {
		readback, err := opts.Readback(ctx, cfg, opts.Root, opts.Runner)
		if err == nil {
			return readback, nil
		}
		if !corenode.TransientReadback(err) || time.Now().After(deadline) {
			return corenode.Readback{}, err
		}
		select {
		case <-ctx.Done():
			return corenode.Readback{}, ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
}

// nodeFileOwnedBy checks exact UID and group ownership. It is only used for
// production-root readbacks; isolated test roots keep whatever UID the test
// runner has, so ownership is not asserted there.
func nodeFileOwnedBy(path string, uid uint32, group string) bool {
	info, err := os.Lstat(path)
	if err != nil {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	if stat.Uid != uid {
		return false
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return false
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil || gid < 0 {
		return false
	}
	return stat.Gid == uint32(gid)
}

func installNodeDynamic(ctx context.Context, opts core.NodeApplyOptions, candidate corenode.CandidateDocument, compiled []byte, role corenode.Role, preserveAuthorizedACL bool) error {
	dir := core.Rooted(opts.Root, nodeKernelDataDir)
	if err := core.EnsureDirectory(dir, 0750); err != nil {
		return err
	}
	if err := core.WriteBytesAtomic(core.Rooted(opts.Root, corenode.ActiveConfigPath), compiled, 0640); err != nil {
		return err
	}
	if opts.Root == "/" {
		// The active kernel configuration must stay readable by the
		// meshmux-singbox service account. writeBytesAtomic leaves a
		// root-owned file behind, so the ownership is fixed explicitly.
		if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-singbox", corenode.ActiveConfigPath); err != nil {
			return &core.InstallError{Code: "FILE_OWNERSHIP_FAILED", Recovery: "The sing-box service account cannot read the active configuration; inspect ownership and run --repair."}
		}
	}
	candidateBody, err := jsonMarshal(candidate)
	if err != nil {
		return err
	}
	if err := core.WriteBytesAtomic(core.Rooted(opts.Root, corenode.ActiveCandidatePath), candidateBody, 0600); err != nil {
		return err
	}
	if role == corenode.RoleOut {
		// The Out source allowlist is retired. A first install and a repair
		// both write the neutral, rule-free table; the only thing a repair
		// preserves is an already canonical neutral file, so an existing
		// legacy allowlist is flushed instead of re-applied.
		aclPath := core.Rooted(opts.Root, corenode.ACLPath)
		acl, err := corenode.CompileACL(candidate.Candidate(), nil)
		if err != nil {
			return err
		}
		if preserveAuthorizedACL {
			if existing, readErr := os.ReadFile(aclPath); readErr == nil {
				if _, parseErr := corenode.ParseACLAllowed(candidate.Candidate(), existing); parseErr == nil {
					return nil
				}
			}
		}
		if err := core.WriteBytesAtomic(aclPath, acl, 0600); err != nil {
			return err
		}
	}
	return nil
}

// verifyNodeInstall asserts the installer-visible evidence of an installed
// Node. For an Out, OutDefaultDeny is the observed_out_default_deny the Hub
// stores: it is true only when the live inet meshmux_out table was proven to
// be the exact VLESS guard (both drops present, accept set exactly the
// applied allowlist). A bare `policy accept` table is not evidence and never
// sets it, so a host with no guard fails install instead of looking healthy.
func verifyNodeInstall(ctx context.Context, cfg corenode.Config, runner core.CommandRunner, rb corenode.Readback) error {
	if rb.AgentSHA256 == "" || rb.KernelSHA256 == "" || !rb.LocalActive {
		return errors.New("NODE_READBACK_INCOMPLETE")
	}
	if cfg.Role == corenode.RoleOut && !rb.OutDefaultDeny {
		return errors.New("OUT_DEFAULT_DENY_MISSING")
	}
	return nil
}
