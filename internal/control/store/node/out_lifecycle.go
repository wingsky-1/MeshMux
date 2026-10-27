package node

// Out lifecycle after Ruling R9: deleting an Out is a real delete.
//
// The action used to be "remove the routing intent, keep the node". R9 rejects
// that: an operator who deletes an Out means the Out is gone, so the node row, its
// dial parameters and the Hub-issued link key all go with it. Two consequences
// follow, and both are deliberate:
//
//   - the whole thing is guarded before anything is destroyed: an Out that a
//     subscription still selects is refused with the subscription names (the
//     operator migrates those first), and an Out with a chain in flight is refused
//     so no task is left pointing at a node that no longer exists;
//   - the ACL is brought back to default-deny before the row disappears. The empty
//     authorization is published and read back in the same transaction, so the host
//     that is about to be forgotten cannot keep accepting the old sources. Only
//     then is the node deleted, which also drops out_settings (dial address + link
//     key) and every candidate/task row through the schema's cascades.
//
// Lines that used to egress through the deleted Out are NOT silently turned into
// direct egress. Their route is re-derived by the existing drain chain, and the
// policy package's own fail-closed rule refuses a policy that names an Out the Hub no
// longer has (OUT_BINDING_INVALID; a requirement of an unavailable Out is
// OUT_OFFLINE_FAIL_CLOSED). See RepublishLineAuthorizations.

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	candidatepkg "github.com/wingsky-1/MeshMux/internal/control/store/candidate"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

// DeleteOutAt is the request-clock variant used by the Web handler, so the
// refusal check, the ACL publication and the readback share one timestamp.
//
// Order of operations (all in one transaction):
//
//  1. Validate the node is an Out, so a Line or a typo can never reach the delete.
//  2. Refuse a live subscription reference, naming the subscriptions.
//  3. Refuse an Out with an unfinished chain: a task addressed to a node that is
//     about to be deleted could never be reported, and the Agent would keep the
//     guard of a Host the Hub has forgotten.
//  4. Publish the explicit empty authorization and read it back.
//  5. Delete the node row; out_settings, candidates, tasks, identities and pairing
//     rows go with it through ON DELETE CASCADE.
//
// A failure at any step rolls the whole thing back: there is no half-deleted Out.
func (s *Store) DeleteOutAt(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return common.ErrOutIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return common.ErrOutNotFound
	}
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(common.NodeRoleOut) && role != string(common.NodeRoleHTTP) {
		return errors.New("OUT_ROLE_INVALID: only out and http egress nodes can be deleted")
	}
	// A subscription that selects this Out is a live reference: the client document
	// names an egress that is about to disappear, so the operator migrates those
	// subscriptions first. The used-by list names them.
	//
	// The read must share the delete's transaction: the store runs on a single
	// connection, so a second DB-level query here would wait on the open
	// transaction forever.
	usedBy, err := s.Subscribers.OutUsedByTx(tx, outID)
	if err != nil {
		return err
	}
	if len(usedBy) > 0 {
		return errors.New(s.Subscribers.OutReferencedCode() + ": out " + outID + " is still selected by " + strings.Join(usedBy, "、") + "; migrate those subscriptions first")
	}
	// An unfinished chain is a host that has not finished applying the guard. Deleting
	// the node now would strand that chain: no result could be recorded for it, and the
	// host would keep whatever ACL it last applied. The operator retries after it
	// settles (the same bounded rule the rest of the Out synchronization uses).
	//
	// The refusal is joined with ErrOutCleanupPending so every caller classifies it the
	// same way as the offline/deferred case: a refusal that deleted nothing, never a
	// half-success. Without the sentinel the handler fell through to the generic mapping,
	// which used to answer 202 "route cleaned" for a delete that destroyed nothing.
	unfinished, err := candidatepkg.LineUnfinishedTasksTx(tx, outID)
	if err != nil {
		return err
	}
	if unfinished != 0 {
		return errors.Join(errors.New(CodeOutSyncPending+": the out still has an unfinished chain; retry after it settles"), ErrOutCleanupPending)
	}
	// Publish the explicit empty authorization before the node is gone. An Out that
	// never published a chain has no host state to clear.
	deferred, deferredErr := s.clearOutACLBeforeDeleteTx(tx, outID, now)
	if deferred {
		// The host cannot drop its guard yet: a chain is still applying, or it stopped
		// reporting. Deleting anyway would leave a host accepting the old sources with no
		// node row left to retry from, so nothing is destroyed and the caller sees the
		// deferral. The intent is durable, so the next Out event completes the cleanup and
		// the operator can delete again.
		return errors.Join(deferredErr, ErrOutCleanupPending)
	}
	// Delete the node. Everything keyed to it (out_settings with the dial address and
	// link key, node_candidates, agent_tasks, node_identities, node_pairing) cascades.
	// The candidate immutability trigger only guards a live parent: its WHEN clause
	// skips the cascade (schema 15), so history of a deleted node is removed with it
	// instead of blocking the delete.
	if _, err := tx.Exec(`DELETE FROM nodes WHERE id=?`, outID); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	if err := tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	// The Out is gone, so any policy that still names it must be re-derived for every
	// Line: the policy resolver refuses an Out reference the Hub cannot justify, so the Line's
	// next publication fails closed instead of silently becoming direct.
	s.RepublishLineAuthorizations(now)
	return nil
}

// clearOutACLBeforeDeleteTx publishes the explicit empty authorization of one Out and
// verifies the newest chain carries it.
//
// The boolean reports a deferral: the chain could not be published (offline Out or a
// competing in-flight chain) or the readback does not show the empty set. A caller
// that is about to delete the node must treat that as a refusal, not as a reason to
// continue.
func (s *Store) clearOutACLBeforeDeleteTx(tx *sql.Tx, outID string, now time.Time) (bool, error) {
	revision, digest, _, published, err := candidatepkg.LatestPublishedTx(tx, outID)
	if err != nil {
		return false, err
	}
	if !published {
		// Nothing was ever published: no host state exists to clear.
		return false, nil
	}
	clean, confirmed, err := s.OutACLCleanTx(tx, outID, revision, digest)
	if err != nil {
		return false, err
	}
	if !clean || !confirmed {
		// A host that is not reporting cannot apply or prove the cleanup. Publishing the
		// chain anyway would leave an unreachable host on the old allowlist while the node
		// row disappears, so the delete defers instead.
		offline, offlineErr := SubscriberLineNodeOfflineTx(tx, outID, now)
		if offlineErr != nil {
			return false, offlineErr
		}
		if offline {
			return true, errors.New("OUT_OFFLINE: out is offline; the acl cleanup stays pending")
		}
		// The delete must publish an EMPTY authorization, and the ordinary drain would
		// publish the current membership set instead (the Out is still enrolled at this
		// point). So the cleanup chain is published here explicitly, with an empty
		// allowlist, through the same fixed four-task publication as every other revision.
		if unfinished, countErr := candidatepkg.LineUnfinishedTasksTx(tx, outID); countErr != nil {
			return false, countErr
		} else if unfinished != 0 {
			return true, errors.New(CodeOutSyncPending + ": the out still has an unfinished chain")
		}
		revision, nextErr := candidatepkg.NextCandidateRevisionTx(tx, outID)
		if nextErr != nil {
			return false, nextErr
		}
		candidate, buildErr := BuildLineCandidateTx(tx, outID, revision)
		if buildErr != nil {
			return false, buildErr
		}
		if _, err := candidatepkg.PublishOutTx(tx, outID, candidate, now, []string{}); err != nil {
			return false, err
		}
	}
	// Read the cleanup back. Publishing happened in this transaction, so the anchor is
	// exact: the newest chain must name the empty set explicitly.
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, outID)
	if err != nil {
		return false, err
	}
	if !found {
		return false, nil
	}
	clean, _, err = s.OutACLCleanTx(tx, outID, revision, digest)
	if err != nil {
		return false, err
	}
	if !clean {
		return true, errors.New(CodeOutSyncPending + ": the out acl cleanup was not published")
	}
	return false, nil
}

// ErrOutCleanupPending is retained for the callers that classify a deferred cleanup.
// A successful delete no longer returns it: under Ruling R9 an Out that cannot be
// cleaned up is refused instead of reported as "route gone, host pending".
var ErrOutCleanupPending = errors.New(CodeOutSyncPending + ": the out acl cleanup is queued behind an in-flight or offline out; retry the out synchronization")
