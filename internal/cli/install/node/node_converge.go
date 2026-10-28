package node

// The outside-sandbox half of the crash-window recovery (#11c-2, spec §4.2
// amended / §4.8).
//
// The Agent's unit keeps /etc read-only, so the Agent never rewrites
// agent.json: after an in-memory adoption it keeps the claim and asks a writer
// outside its mount namespace to publish the config. That writer is the hidden
// `__internal-update-converge` command below, run from a one-shot transient
// unit. It is driven by the claim record the installer wrote, and it refuses
// everything the claim does not prove:
//
//   - the claim must exist and name a valid operation and digest;
//   - the Agent binary on disk must hash to the claimed digest (never publish a
//     config for bytes that are not there);
//   - the current agent.json must be a usable installed configuration;
//   - the written pair must read back as the claimed digest and version.
//
// It does not clear the claim: only the Agent's pair readback may do that, so a
// converged-but-unobserved write stays repeatable.

import (
	"encoding/json"
	"errors"
	"os"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// ConvergeHandoffConfig publishes the claimed Agent release into agent.json.
// It is the body of the hidden convergence command and the installer-side
// equivalent of the Agent's in-memory adoption: after it succeeds, the on-disk
// pair (binary + config) names the running build, so the Agent can clear the
// claim on its next readback.
func ConvergeHandoffConfig(root, operationID, expectedSHA256 string) error {
	if !core.OperationIDPattern.MatchString(operationID) {
		return errors.New(core.CodeOperationIDInvalid)
	}
	if !core.ValidDigest.MatchString(expectedSHA256) {
		return errors.New("HANDOFF_CONVERGE_INVALID")
	}
	claim, ok, err := readNodeUpgradeClaim(root)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("HANDOFF_CONVERGE_NO_CLAIM")
	}
	if claim.OperationID != operationID || claim.NewSHA256 != expectedSHA256 {
		return errors.New("HANDOFF_CONVERGE_CLAIM_MISMATCH")
	}
	disk, err := core.SHA256File(core.Rooted(root, corenode.AgentBinaryPath))
	if err != nil || disk != expectedSHA256 {
		return errors.New("HANDOFF_CONVERGE_BINARY_MISMATCH")
	}
	cfg, err := readAgentConfig(root)
	if err != nil {
		return err
	}
	cfg.AgentVersion = corenode.CurrentAgentVersion()
	cfg.AgentSHA256 = expectedSHA256
	if err := cfg.ValidateInstalled(); err != nil {
		return errors.New("HANDOFF_CONVERGE_CONFIG_INVALID")
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return errors.New("HANDOFF_CONVERGE_ENCODE_FAILED")
	}
	body = append(body, '\n')
	if err := core.WriteBytesAtomic(core.Rooted(root, corenode.AgentConfigPath), body, 0600); err != nil {
		return errors.New("HANDOFF_CONVERGE_WRITE_FAILED")
	}
	// Readback is the post-condition: a converged file is only useful if it
	// names the running binary and validates as an installed configuration.
	written, err := readAgentConfig(root)
	if err != nil || written.AgentSHA256 != expectedSHA256 ||
		written.AgentVersion != corenode.CurrentAgentVersion() || written.ValidateInstalled() != nil {
		return errors.New("HANDOFF_CONVERGE_READBACK_FAILED")
	}
	return nil
}

// readNodeUpgradeClaim reads the installer's crash-window record. A missing
// record is (zero, false, nil); anything unsafe or malformed is a refusal.
func readNodeUpgradeClaim(root string) (nodeUpgradeClaim, bool, error) {
	path := core.Rooted(root, core.NodeUpgradeClaimPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nodeUpgradeClaim{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return nodeUpgradeClaim{}, false, errors.New("UPGRADE_CLAIM_UNSAFE")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nodeUpgradeClaim{}, false, errors.New("UPGRADE_CLAIM_UNSAFE")
	}
	var claim nodeUpgradeClaim
	if json.Unmarshal(data, &claim) != nil ||
		!core.OperationIDPattern.MatchString(claim.OperationID) || !core.ValidDigest.MatchString(claim.NewSHA256) {
		return nodeUpgradeClaim{}, false, errors.New("UPGRADE_CLAIM_INVALID")
	}
	return claim, true, nil
}

// readAgentConfig reads the recorded Agent configuration with the same
// private-file rule the installer applies to every Agent-owned file.
func readAgentConfig(root string) (corenode.Config, error) {
	path := core.Rooted(root, corenode.AgentConfigPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return corenode.Config{}, errors.New(core.CodeAgentConfigUnavailable)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return corenode.Config{}, errors.New(core.CodeAgentConfigUnavailable)
	}
	var cfg corenode.Config
	if json.Unmarshal(data, &cfg) != nil {
		return corenode.Config{}, errors.New(core.CodeAgentConfigUnavailable)
	}
	return cfg, nil
}
