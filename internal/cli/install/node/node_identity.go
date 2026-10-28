package node

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// nodeIdentityErrors carries the exact identity-phase failure templates. The
// Line recovery wording must stay verbatim and guard-checked, so InstallNode
// owns every literal and this phase only selects the applicable entry.
type nodeIdentityErrors struct {
	identityInvalid       *core.InstallError
	pairingFailedRepair   *core.InstallError
	pairingRequired       *core.InstallError
	pairingMetadataRepair *core.InstallError
	pairingMetadataFresh  *core.InstallError
	identityMissing       *core.InstallError
	pairingCodeRequired   *core.InstallError
	pairingFailedFresh    *core.InstallError
	agentStateUnsafe      *core.InstallError
	identityPersistFailed *core.InstallError
	stateWriteFailed      *core.InstallError
}

// nodeIdentityResolved reports the identity work of the pairing phase. The
// pairing-pending outcome is a separate field on purpose: that branch has
// already written the ledger and the journal, so it must not travel the
// ordinary failure path. Mutable operation state is updated through pointers.
type nodeIdentityResolved struct {
	identity       corenode.Identity
	candidate      corenode.CandidateDocument
	pairingPending bool
}

// nodeResolveIdentityAndCandidate loads the recorded Agent identity or pairs a
// fresh one, fetches the Hub metadata and candidate document, and validates
// both. A missing pairing code ends the operation as a pending pairing request
// after the ledger and journal are updated, exactly in the original order.
func nodeResolveIdentityAndCandidate(ctx context.Context, result *core.InstallResult, state *core.InstallState, opts *core.NodeApplyOptions, layout core.NodeLayout, record func(string, string, string) error, installedCfg corenode.Config, repair bool, pairingCode string, failures nodeIdentityErrors) (nodeIdentityResolved, error) {
	fail := func(failure *core.InstallError) (nodeIdentityResolved, error) {
		res, err := failNodePartial(*result, *state, *opts, layout, record, failure.Stage, failure.Code, failure.Recovery)
		*result = res
		return nodeIdentityResolved{}, err
	}
	identity, identityLoaded, err := loadNodeIdentity(opts.Root, installedCfg)
	if err != nil {
		return fail(failures.identityInvalid)
	}
	var metadata corenode.Metadata
	var candidate corenode.CandidateDocument
	if identityLoaded {
		if repair {
			if pairingCode != "" {
				fresh, pairErr := opts.Pair(ctx, installedCfg, pairingCode)
				if pairErr == nil {
					pairErr = fresh.ValidateFor(installedCfg)
				}
				if pairErr == nil {
					pairErr = persistNodeIdentity(opts.Root, fresh)
				}
				if pairErr != nil {
					return fail(failures.pairingFailedRepair)
				}
				identity = fresh
			}
			metadata, err = opts.Metadata(ctx, installedCfg, identity)
			if err == nil {
				candidate, err = opts.Candidate(ctx, installedCfg, identity, metadata.ConfigRevision)
			}
			if err == nil && metadata.NodeID != "" {
				err = metadata.ValidateFor(installedCfg)
			}
			if err == nil && candidate.Schema != "" {
				err = candidate.ValidateFor(installedCfg)
			}
			if err != nil {
				if clientUnauthorized(err) {
					return fail(failures.pairingRequired)
				}
				return fail(failures.pairingMetadataRepair)
			}
		}
	} else {
		if repair {
			return fail(failures.identityMissing)
		}
		if pairingCode == "" {
			state.Stage = "pairing"
			state.Status = "partial"
			state.ErrorCode, state.Recovery = failures.pairingCodeRequired.Code, failures.pairingCodeRequired.Recovery
			state.UpdatedAt = time.Now().UTC()
			_ = core.WriteNodeState(opts.Root, layout, *state)
			result.Stage, result.Status, result.ErrorCode, result.Recovery = "pairing", "partial", state.ErrorCode, state.Recovery
			_ = record("pairing", "waiting", state.ErrorCode)
			return nodeIdentityResolved{pairingPending: true}, nil
		}
		identity, err = opts.Pair(ctx, installedCfg, pairingCode)
		if err == nil {
			err = identity.ValidateFor(installedCfg)
		}
		if err != nil {
			return fail(failures.pairingFailedFresh)
		}
		if err := ensurePrivateNodeDirectory(core.Rooted(opts.Root, nodeAgentStateDir)); err != nil {
			return fail(failures.agentStateUnsafe)
		}
		if err := persistNodeIdentity(opts.Root, identity); err != nil {
			return fail(failures.identityPersistFailed)
		}
		state.Node = core.CloneNodeConfig(&installedCfg)
		if err := core.WriteNodeState(opts.Root, layout, *state); err != nil {
			return fail(failures.stateWriteFailed)
		}
		metadata, err = opts.Metadata(ctx, installedCfg, identity)
		if err == nil {
			candidate, err = opts.Candidate(ctx, installedCfg, identity, metadata.ConfigRevision)
		}
		if err == nil && metadata.NodeID != "" {
			err = metadata.ValidateFor(installedCfg)
		}
		if err == nil && candidate.Schema != "" {
			err = candidate.ValidateFor(installedCfg)
		}
		if err != nil {
			return fail(failures.pairingMetadataFresh)
		}
	}
	return nodeIdentityResolved{identity: identity, candidate: candidate}, nil
}

// clientUnauthorized reports whether a Hub client failure is an identity
// rejection (revoked or replaced identity) rather than a transport or data
// problem. Only revocation may prompt the operator for a fresh pairing code.
func clientUnauthorized(err error) bool {
	var ce *corenode.ClientError
	if errors.As(err, &ce) {
		return ce.StatusCode == 401
	}
	return false
}

func ensurePrivateNodeDirectory(path string) error {
	if err := core.EnsureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, 0700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return errors.New("AGENT_STATE_UNSAFE")
	}
	return nil
}

func loadNodeIdentity(root string, cfg corenode.Config) (corenode.Identity, bool, error) {
	path := core.Rooted(root, corenode.IdentityPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return corenode.Identity{}, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		return corenode.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return corenode.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	var identity corenode.Identity
	if err := jsonUnmarshal(data, &identity); err != nil {
		return corenode.Identity{}, false, errors.New("IDENTITY_INVALID")
	}
	if err := identity.ValidateFor(cfg); err != nil {
		return corenode.Identity{}, false, errors.New("IDENTITY_MISMATCH")
	}
	return identity, true, nil
}

func persistNodeIdentity(root string, identity corenode.Identity) error {
	if err := ensurePrivateNodeDirectory(core.Rooted(root, nodeAgentStateDir)); err != nil {
		return err
	}
	data, err := jsonMarshal(identity)
	if err != nil {
		return err
	}
	return core.WriteBytesAtomic(core.Rooted(root, corenode.IdentityPath), data, 0600)
}
