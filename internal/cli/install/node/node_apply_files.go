package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// The apply-phase file transaction: target ownership checks, snapshots, the
// ordered atomic replace of every managed file (including the Agent binary
// crash-window claim) and the per-file ledger writes. InstallNode orchestrates
// these steps; node_apply_verify.go drives them.

func applyNodeFiles(ctx context.Context, opts core.NodeApplyOptions, layout core.NodeLayout, state core.InstallState, managed map[string]nodeManagedFile, files map[string]string, backupDir string) error {
	keys := make([]string, 0, len(files))
	for path := range files {
		keys = append(keys, path)
	}
	sort.Strings(keys)
	applyOne := func(target string) (string, error) {
		mode, owner := os.FileMode(0644), "root:root"
		if file, ok := managed[target]; ok {
			mode, owner = os.FileMode(file.Mode), file.Owner
		} else if target == corenode.AgentBinaryPath || target == corenode.SingBoxBinaryPath {
			mode = 0755
		} else if target == corenode.IdentityPath {
			mode = 0600
		}
		if err := core.CopyAtomic(files[target], core.Rooted(opts.Root, target), mode); err != nil {
			return "", &core.InstallError{Code: "FILE_APPLY_FAILED", Recovery: "No Agent was started; inspect the operation journal and run --repair."}
		}
		if opts.Root == "/" {
			if _, err := opts.Runner.Run(ctx, "chown", owner, target); err != nil {
				return "", &core.InstallError{Code: "FILE_OWNERSHIP_FAILED", Recovery: "No Agent was started; inspect service-account ownership and run --repair."}
			}
		}
		digest, err := core.SHA256File(core.Rooted(opts.Root, target))
		if err != nil {
			return "", &core.InstallError{Code: "FILE_READBACK_FAILED", Recovery: "Readback failed after an atomic write; inspect the target filesystem."}
		}
		if file, ok := managed[target]; ok && file.Static {
			state.ManagedFiles[target] = digest
		} else if target == corenode.AgentBinaryPath || target == corenode.SingBoxBinaryPath {
			// Staged binaries are hash-verified before apply. Recording them
			// lets a later repair recognize its own binaries instead of
			// rejecting them as third-party files; drift still fails closed
			// as MANAGED_FILE_DRIFT.
			state.ManagedFiles[target] = digest
		}
		if err := core.WriteNodeState(opts.Root, layout, state); err != nil {
			return "", &core.InstallError{Code: "INSTALL_STATE_WRITE_FAILED", Recovery: "The file ledger failed to persist; preserve the journal and run --repair."}
		}
		return digest, nil
	}

	// The Agent binary is renamed first so the one real crash window (spec
	// §4.8) is covered by the claim record: binary rename, claim write, then
	// agent.json. A crash after the binary but before agent.json is reclaimed
	// by the boot self-check; a crash before the claim still fails closed.
	_, replacesAgent := files[corenode.AgentBinaryPath]
	if replacesAgent {
		digest, err := applyOne(corenode.AgentBinaryPath)
		if err != nil {
			return err
		}
		if err := writeNodeUpgradeClaim(opts.Root, state.OperationID, digest); err != nil {
			return &core.InstallError{Code: "UPGRADE_CLAIM_WRITE_FAILED", Recovery: "The Agent binary was replaced but the crash-window record could not be written; restore the previous binary or run --repair before restarting the Agent."}
		}
	}
	for _, target := range keys {
		if replacesAgent && target == corenode.AgentBinaryPath {
			continue
		}
		if _, err := applyOne(target); err != nil {
			return err
		}
		// agent.json now names the same binary; the recovery window is closed.
		// A crash after this point boots with a matching pair and never reads
		// the claim record.
		if replacesAgent && target == corenode.AgentConfigPath {
			if err := core.ClearNodeUpgradeClaim(opts.Root); err != nil {
				return &core.InstallError{Code: "UPGRADE_CLAIM_CLEAR_FAILED", Recovery: "The Agent pair is consistent but the crash-window record could not be removed; inspect /var/lib/meshmux-agent and run --repair."}
			}
		}
	}
	return nil
}

func snapshotNodeTargets(root string, targets []string, state core.InstallState, hasState bool, backupDir string) ([]core.FileSnapshot, error) {
	var snapshots []core.FileSnapshot
	for _, target := range targets {
		path := core.Rooted(root, target)
		info, err := os.Lstat(path)
		snapshot := core.FileSnapshot{Target: path, Logical: target, Backup: filepath.Join(backupDir, strings.TrimPrefix(strings.ReplaceAll(target, "/", "_"), "_"))}
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return snapshots, &core.InstallError{Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the target; symlinks and non-regular files are never replaced."}
		}
		if !hasState {
			return snapshots, &core.InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The target exists without MeshMux ownership state."}
		}
		if target == corenode.IdentityPath && !stateOwnsNodeState(state) {
			return snapshots, &core.InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The private identity appeared after it was created by this operation; inspect concurrent access."}
		}
		if _, recorded := state.ManagedFiles[target]; !recorded {
			if target == corenode.IdentityPath || target == corenode.ActiveConfigPath || target == corenode.ActiveCandidatePath {
				// These are protected dynamic/private paths. A repair may
				// snapshot them, but only the identity is reused and the
				// dynamic LKG is never overwritten merely to repair layout.
			} else {
				return snapshots, &core.InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The target is not recorded as MeshMux-managed."}
			}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return snapshots, errors.New("TARGET_OWNER_UNKNOWN")
		}
		if err := core.CopyAtomic(path, snapshot.Backup, info.Mode().Perm()); err != nil {
			return snapshots, err
		}
		snapshot.Exists, snapshot.Mode, snapshot.UID, snapshot.GID = true, info.Mode(), int(st.Uid), int(st.Gid)
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func stateOwnsNodeState(state core.InstallState) bool {
	return state.Node != nil && state.Schema == 1 && core.OperationIDPattern.MatchString(state.OperationID)
}

// checkNodeTargets verifies that the paths this Node operation will write
// are either free or recorded as MeshMux-managed by this Node's own ledger.
//
// A co-located Line does not own the Hub's runtime binary: the shared
// binary is verified separately against the digest the Hub published, and
// it is never adopted into the Line's own managed-file ledger.
func checkNodeTargets(root string, cfg corenode.Config, ssh []int, state core.InstallState, hasState bool, layout core.NodeLayout) error {
	paths := []string{
		corenode.AgentBinaryPath, corenode.SingBoxBinaryPath, corenode.AgentConfigPath,
		core.UnitPath(corenode.AgentUnit), core.UnitPath(corenode.SingBoxUnit),
	}
	if !layout.ReuseHubSSHJail {
		paths = append(paths, core.NodeSSHJailPath)
	}
	// The host-level journald quota is the standalone Line's own file; a
	// co-located Line reuses the Hub-owned copy.
	if !layout.CoLocated {
		paths = append(paths, core.JournaldDropInPath)
	}
	if cfg.Role == corenode.RoleOut {
		paths = append(paths, core.UnitPath(corenode.ACLUnit))
	}
	if layout.CoLocated {
		// The Hub owns the shared runtime. The Line verifies the recorded
		// digest instead of claiming ownership of the file.
		paths = core.RemoveTarget(paths, layout.SharedAgent)
	}
	if err := core.CheckTargetOwnership(root, paths, state, hasState); err != nil {
		return err
	}
	if layout.CoLocated {
		if !core.SharedAgentMatches(root, layout.SharedAgent, layout.SharedAgentSHA256) {
			return &core.InstallError{Stage: "preflight", Code: "SHARED_BINARY_MISMATCH",
				Recovery: "The Hub-owned MeshMux runtime on this host no longer matches the recorded digest. Repair the Hub and the Line together; the Line never replaces the shared binary."}
		}
	}
	if cfg.Role == corenode.RoleOut {
		if err := checkDynamicNodeTarget(root, corenode.ACLPath, state, hasState); err != nil {
			return err
		}
	}
	for _, dir := range []string{nodeAgentStateDir, nodeKernelDataDir} {
		info, err := os.Lstat(core.Rooted(root, dir))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &core.InstallError{Stage: "preflight", Code: "DATA_PATH_UNSAFE", Recovery: "Inspect the fixed Node data directory; symlinks are rejected."}
		}
		if !hasState {
			entries, readErr := os.ReadDir(core.Rooted(root, dir))
			if readErr != nil || len(entries) > 0 {
				return &core.InstallError{Stage: "preflight", Code: "DATA_STATE_CONFLICT", Recovery: "Data exists without a Node installer record; preserve and inspect it manually."}
			}
		}
	}
	return nil
}

func ensureNodeAccounts(ctx context.Context, runner core.CommandRunner, root string, hasState bool) error {
	for _, account := range []struct {
		name, home string
	}{
		{"meshmux-agent", nodeAgentStateDir},
		{"meshmux-singbox", nodeKernelDataDir},
	} {
		out, err := runner.Run(ctx, "getent", "passwd", account.name)
		if err == nil && strings.TrimSpace(string(out)) != "" {
			continue
		}
		if _, err := runner.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", account.home, "--no-create-home", "--shell", "/usr/sbin/nologin", account.name); err != nil {
			return err
		}
	}
	return nil
}

func ensureNodeDirectories(ctx context.Context, opts core.NodeApplyOptions) error {
	agentDir := core.Rooted(opts.Root, nodeAgentStateDir)
	if err := ensurePrivateNodeDirectory(agentDir); err != nil {
		return err
	}
	kernelDir := core.Rooted(opts.Root, nodeKernelDataDir)
	if err := core.EnsureDirectory(kernelDir, 0750); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-agent", nodeAgentStateDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chmod", "0700", nodeAgentStateDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chown", "root:meshmux-singbox", nodeKernelDataDir); err != nil {
		return err
	}
	if _, err := opts.Runner.Run(ctx, "chmod", "0750", nodeKernelDataDir); err != nil {
		return err
	}
	return nil
}

func nodeStaticTargets(files map[string]nodeManagedFile) []string {
	var out []string
	for path, file := range files {
		if file.Static {
			out = append(out, path)
		}
	}
	sort.Strings(out)
	return out
}

func nodeUnitPaths(root string, cfg corenode.Config) []string {
	units := []string{core.Rooted(root, core.UnitPath(corenode.AgentUnit)), core.Rooted(root, core.UnitPath(corenode.SingBoxUnit))}
	if cfg.Role == corenode.RoleOut {
		units = append(units, core.Rooted(root, core.UnitPath(corenode.ACLUnit)))
	}
	return units
}

func verifyNodeTableOwnershipAfterInstall(ctx context.Context, root string, runner core.CommandRunner, cfg corenode.Config, hasState bool) error {
	result := nodeTableOwnership(ctx, root, runner, cfg, hasState)
	if result.Kind == tableAbsent ||
		(result.Kind == tableManaged && tableOwnedByLedger(cfg, hasState)) {
		return nil
	}
	check := result.checkName("out_acl_table")
	return &core.InstallError{Code: check.Code, Recovery: check.Recovery}
}

func tableOwnedByLedger(cfg corenode.Config, hasState bool) bool {
	return hasState && cfg.Role == corenode.RoleOut
}

func checkDynamicNodeTarget(root, target string, state core.InstallState, hasState bool) error {
	info, err := os.Lstat(core.Rooted(root, target))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return &core.InstallError{Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the dynamic MeshMux file; symlinks and non-private files are rejected."}
	}
	if !hasState {
		return &core.InstallError{Code: "MANAGED_PATH_CONFLICT", Recovery: "The dynamic file exists without a Node installer ledger."}
	}
	return nil
}
