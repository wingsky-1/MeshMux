package install

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

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// ConvergeHandoffConfig publishes the claimed Agent release into agent.json.
// It is the body of the hidden convergence command and the installer-side
// equivalent of the Agent's in-memory adoption: after it succeeds, the on-disk
// pair (binary + config) names the running build, so the Agent can clear the
// claim on its next readback.
func ConvergeHandoffConfig(root, operationID, expectedSHA256 string) error {
	if !operationIDPattern.MatchString(operationID) {
		return errors.New(CodeOperationIDInvalid)
	}
	if !validDigest.MatchString(expectedSHA256) {
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
	disk, err := sha256File(rooted(root, node.AgentBinaryPath))
	if err != nil || disk != expectedSHA256 {
		return errors.New("HANDOFF_CONVERGE_BINARY_MISMATCH")
	}
	cfg, err := readAgentConfig(root)
	if err != nil {
		return err
	}
	cfg.AgentVersion = node.CurrentAgentVersion()
	cfg.AgentSHA256 = expectedSHA256
	if err := cfg.ValidateInstalled(); err != nil {
		return errors.New("HANDOFF_CONVERGE_CONFIG_INVALID")
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return errors.New("HANDOFF_CONVERGE_ENCODE_FAILED")
	}
	body = append(body, '\n')
	if err := writeBytesAtomic(rooted(root, node.AgentConfigPath), body, 0600); err != nil {
		return errors.New("HANDOFF_CONVERGE_WRITE_FAILED")
	}
	// Readback is the post-condition: a converged file is only useful if it
	// names the running binary and validates as an installed configuration.
	written, err := readAgentConfig(root)
	if err != nil || written.AgentSHA256 != expectedSHA256 ||
		written.AgentVersion != node.CurrentAgentVersion() || written.ValidateInstalled() != nil {
		return errors.New("HANDOFF_CONVERGE_READBACK_FAILED")
	}
	return nil
}

// readNodeUpgradeClaim reads the installer's crash-window record. A missing
// record is (zero, false, nil); anything unsafe or malformed is a refusal.
func readNodeUpgradeClaim(root string) (nodeUpgradeClaim, bool, error) {
	path := rooted(root, nodeUpgradeClaimPath)
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
		!operationIDPattern.MatchString(claim.OperationID) || !validDigest.MatchString(claim.NewSHA256) {
		return nodeUpgradeClaim{}, false, errors.New("UPGRADE_CLAIM_INVALID")
	}
	return claim, true, nil
}

// readAgentConfig reads the recorded Agent configuration with the same
// private-file rule the installer applies to every Agent-owned file.
func readAgentConfig(root string) (node.Config, error) {
	path := rooted(root, node.AgentConfigPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return node.Config{}, errors.New(CodeAgentConfigUnavailable)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return node.Config{}, errors.New(CodeAgentConfigUnavailable)
	}
	var cfg node.Config
	if json.Unmarshal(data, &cfg) != nil {
		return node.Config{}, errors.New(CodeAgentConfigUnavailable)
	}
	return cfg, nil
}
