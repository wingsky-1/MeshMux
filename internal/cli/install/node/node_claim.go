package node

// The crash-window claim of the self-replacing install (#11c-2, spec §4.8).
// The Agent binary and agent.json are two atomic renames, and a crash between
// them leaves the new binary running against a config that names the old
// digest. The installer writes this small record after the binary rename and
// before the agent.json rename; the Agent's boot self-check consumes it exactly
// once. The record is not the handoff marker (the Agent remains its only
// writer) and it is not a second protocol: two fixed fields, 0600, a fixed path.

import (
	"encoding/json"
	"errors"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

type nodeUpgradeClaim struct {
	NewSHA256   string `json:"new_sha256"`
	OperationID string `json:"operation_id"`
}

// writeNodeUpgradeClaim records the just-renamed Agent binary for boot
// recovery. It is called only between the binary apply and the agent.json
// apply, so its presence always means "the binary may be newer than the
// config".
func writeNodeUpgradeClaim(root, operationID, newSHA256 string) error {
	if !core.OperationIDPattern.MatchString(operationID) || !core.ValidDigest.MatchString(newSHA256) {
		return errors.New("UPGRADE_CLAIM_INVALID")
	}
	data, err := json.MarshalIndent(nodeUpgradeClaim{
		NewSHA256: newSHA256, OperationID: operationID,
	}, "", "  ")
	if err != nil {
		return errors.New("UPGRADE_CLAIM_ENCODE_FAILED")
	}
	data = append(data, '\n')
	if err := core.WriteBytesAtomic(core.Rooted(root, core.NodeUpgradeClaimPath), data, 0600); err != nil {
		return errors.New("UPGRADE_CLAIM_WRITE_FAILED")
	}
	return nil
}
