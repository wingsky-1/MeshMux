package install

// Self-describing rollback snapshots (#11c-3 Task 4, spec §4.1/§4.7/§4.18).
//
// Every successful Node install leaves a durable snapshot of the release it
// just verified under /var/lib/meshmux-agent/upgrade-source. The NEXT upgrade
// promotes that tree into its 0700 rollback store, so a revert restores the
// release the host was actually running — not a hand-picked file list.
//
// The snapshot is a manifest ("snapshot.json") plus a "payload/" tree copied
// 0600/0700. The manifest names, for every managed file, its absolute target,
// its payload path, whether it existed, its mode, owner and SHA-256. Revert
// rebuilds []fileSnapshot from those entries and reuses rollbackNodeFiles; no
// second rename-back implementation exists (spec §4.7). The record schema is
// untouched: the manifest lives inside the payload tree, so a schema bump is
// not needed.
//
// The same manifest drives the graded selection: restore only the Agent binary
// when that is the whole observed change set and the kernel still matches its
// recorded digest; every other change (config, unit, ACL, LKG, or a kernel SHA
// mismatch) restores the full recorded set. The 11c-3 rule is deliberately
// conservative: a kernel change is never hidden by a binary-only fast path
// (spec §4.18).

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/versions"
)

const (
	// UpgradeSourceDir is the durable snapshot of the installed release. It is
	// private (0700/0600, root-owned) and contains secrets (the LKG bytes and
	// the active sing-box config), so it never leaves the host.
	UpgradeSourceDir = versions.AgentRoot + "/upgrade-source"
	// SnapshotManifestName is the self-description of one payload tree.
	SnapshotManifestName = "snapshot.json"
	// SnapshotSchema is the manifest schema. It is independent of the backup
	// record schema: the record keeps schema 1 and this manifest rides inside
	// the payload it already hashes.
	SnapshotSchema = 1

	snapshotPayloadDir = "payload"
	snapshotPartSuffix = ".part"
	snapshotMaxBytes   = 4 << 20
)

// RestoreMode is the graded selection of one revert.
type RestoreMode string

const (
	// RestoreModeNone means the live tree already matches the recorded release;
	// nothing is stopped, rewritten or restarted.
	RestoreModeNone RestoreMode = "none"
	// RestoreModeBinaryOnly restores just the Agent binary.
	RestoreModeBinaryOnly RestoreMode = "binary_only"
	// RestoreModeFull restores the whole recorded file set.
	RestoreModeFull RestoreMode = "full"
)

// SnapshotEntry is one managed file of a recorded release.
type SnapshotEntry struct {
	// Target is the absolute installed path. Restore re-roots it under the
	// caller's root, so the same manifest restores a fixture tree.
	Target string `json:"target"`
	// Payload is the clean relative path of the copied bytes inside the
	// snapshot directory.
	Payload string `json:"payload"`
	// Exists records whether the target existed. A false entry restores the
	// absence of a file the upgrade created.
	Exists bool `json:"exists"`
	// Mode is the permission set to re-apply (no setuid/setgid/sticky bits).
	Mode uint32 `json:"mode"`
	// UID and GID are the recorded owner. The installer restores them only on
	// a real root.
	UID int `json:"uid"`
	GID int `json:"gid"`
	// SHA256 is the digest of the payload bytes; empty for an absent target.
	SHA256 string `json:"sha256"`
}

// SnapshotManifest is the self-description of one rollback payload tree.
type SnapshotManifest struct {
	Schema int             `json:"schema"`
	Files  []SnapshotEntry `json:"files"`
}

// RestoreAnchors are the old-package trust anchors of a revert. The payload's
// Agent bytes must hash to FromAgentSHA256; on a Node the package and the Agent
// binary are the same artifact, so FromPackageSHA256 must agree when present.
type RestoreAnchors struct {
	FromAgentSHA256   string
	FromPackageSHA256 string
}

// RestoreReport is the observable outcome of one graded restore.
type RestoreReport struct {
	Mode     RestoreMode
	Restored []string
	// KernelSHA256 is the recorded kernel digest when the manifest names one.
	KernelSHA256 string
}

// ReadUpgradeSource returns the durable snapshot directory of this host after
// proving it is a private, manifest-backed tree that names the Agent binary. A
// missing or incomplete source is a refusal: an upgrade must never be handed
// an empty rollback source.
func ReadUpgradeSource(root string) (string, error) {
	dir := rooted(root, UpgradeSourceDir)
	info, err := os.Lstat(dir)
	if os.IsNotExist(err) {
		return "", &InstallError{Stage: "revert", Code: CodeRollbackSourceMissing,
			Recovery: "The host has no retained rollback snapshot. Run one interactive repair to record the installed release before upgrading."}
	}
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", &InstallError{Stage: "revert", Code: CodeRollbackSourceInvalid,
			Recovery: "Inspect /var/lib/meshmux-agent/upgrade-source; a symlink or non-directory is never used."}
	}
	if info.Mode().Perm() != 0700 || !snapshotOwnedByEUID(info) {
		return "", &InstallError{Stage: "revert", Code: CodeRollbackSourceInvalid,
			Recovery: "The retained rollback snapshot must be 0700 and owned by root."}
	}
	manifest, err := ReadSnapshotManifest(dir)
	if err != nil {
		return "", err
	}
	if _, ok := snapshotAgentEntry(manifest); !ok {
		return "", &InstallError{Stage: "revert", Code: CodeRollbackSourceInvalid,
			Recovery: "The retained rollback snapshot does not describe the Agent binary; run one interactive repair."}
	}
	return dir, nil
}

// UpgradeSourceCurrent reports whether the durable snapshot already describes
// the live release and carries the Agent's runtime state (the LKG pair). A
// snapshot that names the right binary but predates the Agent's first boot is
// still stale: its LKG bytes are missing.
func UpgradeSourceCurrent(root string) bool {
	manifest, err := ReadSnapshotManifest(rooted(root, UpgradeSourceDir))
	if err != nil {
		return false
	}
	entry, ok := snapshotAgentEntry(manifest)
	if !ok {
		return false
	}
	live, err := sha256File(rooted(root, node.AgentBinaryPath))
	if err != nil || live != entry.SHA256 {
		return false
	}
	for _, file := range manifest.Files {
		if file.Target == node.RuntimeStatePath && file.Exists {
			return true
		}
	}
	return false
}

// UpgradeSourceAgentSHA reports the Agent digest the durable snapshot names.
// The confirmer uses it to avoid rewriting the (large) snapshot on every
// accepted readback: only a snapshot that still names another release is
// stale.
func UpgradeSourceAgentSHA(root string) (string, bool) {
	dir := rooted(root, UpgradeSourceDir)
	manifest, err := ReadSnapshotManifest(dir)
	if err != nil {
		return "", false
	}
	entry, ok := snapshotAgentEntry(manifest)
	return entry.SHA256, ok
}

// ReadSnapshotManifest reads and validates one manifest without following a
// symlink. It is pure: no target and no payload is touched beyond the manifest
// file itself.
func ReadSnapshotManifest(dir string) (SnapshotManifest, error) {
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != 0700 ||
		!snapshotOwnedByEUID(info) {
		return SnapshotManifest{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot directory must be a private 0700 directory."}
	}
	path := filepath.Join(dir, SnapshotManifestName)
	fileInfo, err := os.Lstat(path)
	if err != nil || fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() ||
		fileInfo.Mode().Perm() != 0600 || !snapshotOwnedByEUID(fileInfo) || fileInfo.Size() > snapshotMaxBytes {
		return SnapshotManifest{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest must be a private 0600 regular file."}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SnapshotManifest{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest could not be read."}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var manifest SnapshotManifest
	if err := decoder.Decode(&manifest); err != nil {
		return SnapshotManifest{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest is not valid JSON."}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return SnapshotManifest{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest carries trailing data."}
	}
	if err := validateSnapshotManifest(manifest); err != nil {
		return SnapshotManifest{}, err
	}
	return manifest, nil
}

// WriteSnapshotManifest validates and publishes one manifest atomically. It is
// exported for the snapshot writer and for fixtures that prove the contract.
func WriteSnapshotManifest(dir string, manifest SnapshotManifest) error {
	if err := validateSnapshotManifest(manifest); err != nil {
		return err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest could not be encoded."}
	}
	if err := writeBytesAtomic(filepath.Join(dir, SnapshotManifestName), append(data, '\n'), 0600); err != nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot manifest could not be written."}
	}
	return nil
}

// RestoreNodeSnapshot restores one recorded release into opts.Root. It reuses
// rollbackNodeFiles for the actual file replacement, stops the three Node units
// first, and leaves starting them to the caller (the revert executor must
// reconcile the ledger before the Agent restarts). A no-op selection touches
// nothing at all.
func RestoreNodeSnapshot(ctx context.Context, opts NodeApplyOptions, snapshotDir string, anchors RestoreAnchors) (RestoreReport, error) {
	if opts.Runner == nil {
		return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackRestoreFailed,
			Recovery: "The revert has no command runner; no file was restored."}
	}
	manifest, err := ReadSnapshotManifest(snapshotDir)
	if err != nil {
		return RestoreReport{}, err
	}
	agent, ok := snapshotAgentEntry(manifest)
	if !ok {
		return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
			Recovery: "The rollback snapshot does not describe the Agent binary."}
	}
	type candidate struct {
		entry   SnapshotEntry
		snap    fileSnapshot
		changed bool
	}
	candidates := make([]candidate, 0, len(manifest.Files))
	for _, entry := range manifest.Files {
		payloadPath := filepath.Join(snapshotDir, filepath.FromSlash(entry.Payload))
		if !snapshotPayloadInside(snapshotDir, payloadPath) || ensureNoSymlinkAncestors(payloadPath) != nil {
			return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
				Recovery: "The rollback snapshot names a payload outside its own directory."}
		}
		target := rooted(opts.Root, entry.Target)
		snap := fileSnapshot{Target: target, Logical: entry.Target, Backup: payloadPath,
			Exists: entry.Exists, Mode: os.FileMode(entry.Mode), UID: entry.UID, GID: entry.GID}
		changed := false
		currentInfo, statErr := os.Lstat(target)
		switch {
		case !entry.Exists:
			if statErr == nil {
				changed = true
			} else if !os.IsNotExist(statErr) {
				return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackRestoreFailed,
					Recovery: "A recorded target could not be inspected; no file was restored."}
			}
		case statErr != nil:
			if !os.IsNotExist(statErr) {
				return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackRestoreFailed,
					Recovery: "A recorded target could not be inspected; no file was restored."}
			}
			changed = true
		case currentInfo.Mode()&os.ModeSymlink != 0 || !currentInfo.Mode().IsRegular():
			changed = true
		default:
			currentDigest, digestErr := sha256File(target)
			if digestErr != nil {
				return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackRestoreFailed,
					Recovery: "A recorded target could not be read; no file was restored."}
			}
			changed = currentDigest != entry.SHA256 || currentInfo.Mode().Perm() != os.FileMode(entry.Mode)
		}
		if entry.Exists {
			payloadInfo, payloadErr := os.Lstat(payloadPath)
			if payloadErr != nil || payloadInfo.Mode()&os.ModeSymlink != 0 || !payloadInfo.Mode().IsRegular() {
				return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
					Recovery: "A rollback payload entry is missing, a symlink or not a regular file."}
			}
			digest, digestErr := sha256File(payloadPath)
			if digestErr != nil || digest != entry.SHA256 {
				return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid,
					Recovery: "A rollback payload entry does not match the manifest digest."}
			}
		}
		candidates = append(candidates, candidate{entry: entry, snap: snap, changed: changed})
	}

	// The payload tree is verified before the anchors are compared: a damaged
	// copy is ROLLBACK_SNAPSHOT_INVALID even when its manifest claims the right
	// old-package digest.
	if anchors.FromAgentSHA256 != agent.SHA256 {
		return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackAnchorMismatch,
			Recovery: "The rollback payload's Agent binary does not match from_agent_sha256; the old package is not trusted."}
	}
	if anchors.FromPackageSHA256 != "" && anchors.FromPackageSHA256 != anchors.FromAgentSHA256 {
		return RestoreReport{}, &InstallError{Stage: "revert", Code: CodeRollbackAnchorMismatch,
			Recovery: "The rollback record names two different old packages; no revert is possible from this record."}
	}
	report := RestoreReport{KernelSHA256: snapshotKernelDigest(manifest)}
	var changed []candidate
	for _, item := range candidates {
		if item.changed {
			changed = append(changed, item)
		}
	}
	if len(changed) == 0 {
		report.Mode = RestoreModeNone
		return report, nil
	}
	kernelRecorded, kernelChanged := false, false
	for _, item := range candidates {
		if item.entry.Target == node.SingBoxBinaryPath && item.entry.Exists {
			kernelRecorded = true
			kernelChanged = item.changed
		}
	}
	// Binary-only is allowed only when the Agent binary is the whole observed
	// change AND the co-located kernel is recorded and still matches. A missing
	// kernel entry cannot prove the change set is binary-only, so it falls back
	// to the full set.
	binaryOnly := len(changed) == 1 && changed[0].entry.Target == node.AgentBinaryPath &&
		kernelRecorded && !kernelChanged
	selected := candidates
	if binaryOnly {
		selected = changed
		report.Mode = RestoreModeBinaryOnly
	} else {
		report.Mode = RestoreModeFull
	}
	snapshots := make([]fileSnapshot, 0, len(selected))
	for _, item := range selected {
		snapshots = append(snapshots, item.snap)
		report.Restored = append(report.Restored, item.entry.Target)
	}
	if !rollbackNodeFiles(ctx, opts, snapshots, false) {
		return report, &InstallError{Stage: "revert", Code: CodeRollbackRestoreFailed,
			Recovery: "The recorded files could not all be restored. Do not delete identity or kernel data; inspect the operation journal and restore only recorded MeshMux files."}
	}
	return report, nil
}

// AdoptRestoredRelease reconciles the installer ledger with the restored
// release after a revert (spec §4.17 deliberate path). A failed upgrade may
// legitimately leave ledger/agent.json disagreeing; the revert restores both
// files and then records the restored identity instead of refusing the host
// with CONFIG_CONFLICT. The user configuration (Hub, node, role, ports) must
// still agree, and the crash-window claim is cleared so the restored Agent does
// not adopt the failed target.
func AdoptRestoredRelease(root, operationID string) error {
	if !operationIDPattern.MatchString(operationID) {
		return &InstallError{Stage: "revert", Code: CodeOperationIDInvalid, Recovery: "Carry the failed upgrade chain's operation ID."}
	}
	restored, err := readSnapshotNodeConfig(root)
	if err != nil {
		return err
	}
	layout, err := resolveNodeLayout(root)
	if err != nil {
		var ie *InstallError
		if errors.As(err, &ie) {
			return ie
		}
		return &InstallError{Stage: "revert", Code: CodeRollbackLedgerInvalid,
			Recovery: "The recorded installer state could not be read; keep the restored files and repair state manually."}
	}
	state, exists, err := readNodeState(root, layout)
	if err != nil || !exists || state.Node == nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackLedgerInvalid,
			Recovery: "The host records no Node ledger to reconcile; do not delete identity or data, repair state manually."}
	}
	if !SameNodeConfig(*state.Node, restored) {
		return &InstallError{Stage: "revert", Code: CodeConfigConflict,
			Recovery: "The restored agent.json names another Hub, node, role or port set than the ledger. Inspect both and run one interactive repair."}
	}
	state.Node = cloneNodeConfig(&restored)
	state.Status, state.Stage, state.ErrorCode, state.Recovery = "installed", "verify", "", ""
	state.OperationID, state.LastOperation = operationID, operationID
	state.UpdatedAt = time.Now().UTC()
	if err := writeNodeState(root, layout, state); err != nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackLedgerFailed,
			Recovery: "The restored files are in place but the ledger could not be updated; repair state before the Agent starts."}
	}
	if err := clearNodeUpgradeClaim(root); err != nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackClaimClearFailed,
			Recovery: "The crash-window claim could not be cleared; remove it manually before the restored Agent starts."}
	}
	return nil
}

// StartRestoredNode restarts the restored data plane after the revert has
// reconciled the ledger. It uses restart, not start: the failed new release may
// still be running, and `systemctl start` would leave it in place. Order
// matters: the Out ACL unit applies the restored ACL before the kernel starts,
// and the Agent starts last. The revert unit lives outside the Agent's cgroup,
// so restarting the Agent cannot kill it.
func StartRestoredNode(ctx context.Context, runner CommandRunner, root string) error {
	if runner == nil {
		return &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
			Recovery: "The revert has no command runner; the restored services were not started."}
	}
	cfg, err := readSnapshotNodeConfig(root)
	if err != nil {
		return err
	}
	if cfg.Role == node.RoleOut {
		if info, statErr := os.Lstat(rooted(root, node.ACLPath)); statErr == nil && info.Mode().IsRegular() {
			if _, runErr := runner.Run(ctx, "systemctl", "restart", node.ACLUnit); runErr != nil {
				return &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
					Recovery: "The restored Out ACL unit did not start; inspect only that unit."}
			}
		}
	}
	for _, unit := range []string{node.SingBoxUnit, node.AgentUnit} {
		if _, runErr := runner.Run(ctx, "systemctl", "restart", unit); runErr != nil {
			return &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
				Recovery: "A restored Node unit did not start; inspect the unit and the operation journal."}
		}
	}
	return nil
}

// RefreshUpgradeSource re-records the running release as the next upgrade's
// rollback source. The Agent calls it after an accepted readback confirmed an
// upgrade (the LKG bytes and the active candidate/config are only trustworthy
// after that boot), so the durable snapshot names exactly what the host runs.
func RefreshUpgradeSource(root string) error {
	if UpgradeSourceCurrent(root) {
		return nil
	}
	layout, err := resolveNodeLayout(root)
	if err != nil {
		return err
	}
	state, exists, err := readNodeState(root, layout)
	if err != nil || !exists || state.Node == nil {
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceInvalid,
			Recovery: "The host records no Node ledger; the rollback snapshot cannot be refreshed."}
	}
	return writeUpgradeSnapshot(root, layout, state, state.Node.Role, true)
}

// writeUpgradeSnapshot records the just-verified release. It is best-effort at
// the call site's discretion; the function itself is fail-closed.
func writeUpgradeSnapshot(root string, layout nodeLayout, state InstallState, role node.Role, includeRuntimeState bool) error {
	parent := rooted(root, filepath.Dir(UpgradeSourceDir))
	if err := ensureDirectory(parent, 0700); err != nil {
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The private Agent directory could not hold the rollback snapshot; check disk space and permissions."}
	}
	part := rooted(root, UpgradeSourceDir+snapshotPartSuffix)
	final := rooted(root, UpgradeSourceDir)
	if err := os.RemoveAll(part); err != nil {
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The previous partial rollback snapshot could not be cleared."}
	}
	if err := os.MkdirAll(filepath.Join(part, snapshotPayloadDir), 0700); err != nil {
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The rollback snapshot directory could not be created; check disk space."}
	}
	targets := upgradeSnapshotTargets(state, layout, role, includeRuntimeState)
	manifest := SnapshotManifest{Schema: SnapshotSchema}
	for _, target := range targets {
		if !snapshotAbsoluteTarget(target) {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "The ledger names a target that is not a clean absolute path; inspect the installer state."}
		}
		path := rooted(root, target)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "A managed path is a symlink or a non-regular file; inspect it before retrying."}
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "A managed path has no owner information; inspect the filesystem."}
		}
		relative := strings.TrimPrefix(filepath.Clean(target), "/")
		payload := filepath.Join(snapshotPayloadDir, relative)
		if err := os.MkdirAll(filepath.Join(part, filepath.Dir(payload)), 0700); err != nil {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "The rollback snapshot payload directory could not be created."}
		}
		if err := copyAtomic(path, filepath.Join(part, payload), 0600); err != nil {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "A managed file could not be copied into the rollback snapshot."}
		}
		digest, err := sha256File(filepath.Join(part, payload))
		if err != nil {
			_ = os.RemoveAll(part)
			return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
				Recovery: "A copied rollback file could not be hashed."}
		}
		manifest.Files = append(manifest.Files, SnapshotEntry{
			Target: target, Payload: filepath.ToSlash(payload), Exists: true,
			Mode: uint32(info.Mode().Perm()), UID: int(st.Uid), GID: int(st.Gid), SHA256: digest,
		})
	}
	if _, ok := snapshotAgentEntry(manifest); !ok {
		_ = os.RemoveAll(part)
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The rollback snapshot does not contain the Agent binary; the next upgrade would have no verified rollback source."}
	}
	if err := WriteSnapshotManifest(part, manifest); err != nil {
		_ = os.RemoveAll(part)
		return err
	}
	// Publishing the snapshot is RemoveAll(final) + Rename(part, final), not one
	// atomic replace: POSIX rename cannot replace a non-empty directory. The
	// window is fail-closed — the part tree is already complete, so the only
	// observable states are the old complete tree, the new complete tree, or
	// (between the two calls) no tree at all. A caller that finds no tree gets
	// ROLLBACK_SOURCE_MISSING and the next upgrade/refresh rewrites it; a
	// half-written tree is never visible under the final name. Callers must not
	// read the source concurrently with this replacement.
	if err := os.RemoveAll(final); err != nil {
		_ = os.RemoveAll(part)
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The previous rollback snapshot could not be replaced."}
	}
	if err := os.Rename(part, final); err != nil {
		_ = os.RemoveAll(part)
		return &InstallError{Stage: "verify", Code: CodeRollbackSourceFailed,
			Recovery: "The rollback snapshot could not be published."}
	}
	return nil
}

func upgradeSnapshotTargets(state InstallState, layout nodeLayout, role node.Role, includeRuntimeState bool) []string {
	seen := map[string]bool{}
	add := func(path string) {
		if path == "" || seen[path] {
			return
		}
		seen[path] = true
	}
	for path := range state.ManagedFiles {
		add(path)
	}
	for _, path := range []string{
		node.AgentBinaryPath, node.SingBoxBinaryPath,
		node.ActiveCandidatePath, node.ActiveConfigPath,
	} {
		add(path)
	}
	if includeRuntimeState {
		// The install seed deliberately omits state.json: at that moment the
		// file still belongs to the previous release. Only the post-readback
		// refresh (RefreshUpgradeSource) captures the live LKG bytes.
		add(node.RuntimeStatePath)
	}
	if role == node.RoleOut {
		add(node.ACLPath)
	}
	if layout.CoLocated {
		// The shared Hub runtime is never snapshotted or restored by a Line.
		delete(seen, layout.SharedAgent)
	}
	targets := make([]string, 0, len(seen))
	for path := range seen {
		targets = append(targets, path)
	}
	sort.Strings(targets)
	return targets
}

func snapshotAgentEntry(manifest SnapshotManifest) (SnapshotEntry, bool) {
	for _, entry := range manifest.Files {
		if entry.Target == node.AgentBinaryPath && entry.Exists {
			return entry, true
		}
	}
	return SnapshotEntry{}, false
}

func snapshotKernelDigest(manifest SnapshotManifest) string {
	for _, entry := range manifest.Files {
		if entry.Target == node.SingBoxBinaryPath && entry.Exists {
			return entry.SHA256
		}
	}
	return ""
}

func validateSnapshotManifest(manifest SnapshotManifest) error {
	failInvalid := func(detail string) error {
		return &InstallError{Stage: "revert", Code: CodeRollbackSnapshotInvalid, Recovery: detail}
	}
	if manifest.Schema != SnapshotSchema {
		return failInvalid("The rollback snapshot manifest names an unknown schema.")
	}
	if len(manifest.Files) == 0 {
		return failInvalid("The rollback snapshot manifest is empty.")
	}
	targets := map[string]bool{}
	payloads := map[string]bool{}
	for _, entry := range manifest.Files {
		if !snapshotAbsoluteTarget(entry.Target) {
			return failInvalid("A rollback target is not a clean absolute path.")
		}
		if targets[entry.Target] {
			return failInvalid("The rollback manifest names one target twice.")
		}
		targets[entry.Target] = true
		if !snapshotRelativePayload(entry.Payload) {
			return failInvalid("A rollback payload path is not a clean relative path.")
		}
		if payloads[entry.Payload] {
			return failInvalid("The rollback manifest names one payload twice.")
		}
		payloads[entry.Payload] = true
		if entry.Mode&^uint32(0777) != 0 || entry.UID < 0 || entry.GID < 0 {
			return failInvalid("A rollback entry has an invalid mode or owner.")
		}
		if entry.Exists {
			if !validDigest.MatchString(entry.SHA256) || entry.Mode == 0 {
				return failInvalid("A present rollback entry has no digest or mode.")
			}
		} else if entry.SHA256 != "" {
			return failInvalid("An absent rollback entry carries a digest.")
		}
	}
	return nil
}

func snapshotAbsoluteTarget(target string) bool {
	if target == "" || target == "/" || !filepath.IsAbs(target) || filepath.Clean(target) != target ||
		strings.ContainsAny(target, "\x00\n\r") {
		return false
	}
	return true
}

func snapshotRelativePayload(payload string) bool {
	if payload == "" || filepath.IsAbs(payload) || filepath.Clean(payload) != payload {
		return false
	}
	if payload == "." || payload == ".." || strings.HasPrefix(payload, ".."+string(filepath.Separator)) {
		return false
	}
	return !strings.ContainsAny(payload, "\x00\n\r")
}

func snapshotPayloadInside(dir, path string) bool {
	relative, err := filepath.Rel(dir, path)
	if err != nil {
		return false
	}
	return relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func snapshotOwnedByEUID(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

// readSnapshotNodeConfig reads the restored agent.json for the start step. It
// is the same private 0600/owner rule the Agent and the installer use.
func readSnapshotNodeConfig(root string) (node.Config, error) {
	path := rooted(root, node.AgentConfigPath)
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		return node.Config{}, &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
			Recovery: "The restored agent.json is missing or not a private 0600 regular file."}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return node.Config{}, &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
			Recovery: "The restored agent.json could not be read."}
	}
	var cfg node.Config
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.Validate() != nil {
		return node.Config{}, &InstallError{Stage: "revert", Code: CodeRollbackStartFailed,
			Recovery: "The restored agent.json is not a valid Node configuration."}
	}
	return cfg, nil
}
