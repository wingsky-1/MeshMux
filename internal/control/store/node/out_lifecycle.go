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
//   - the deletion itself is total: out_settings (dial address + link key),
//     candidates, tasks, identities and pairing rows go with the row through the
//     schema's cascades. There is no source allowlist to clear any more: an Out
//     admitted clients by link key, and the key is deleted with the node.
//
// Lines that used to egress through the deleted Out are NOT silently turned into
// direct egress. Their client document is recomposed on the next download, and the
// policy layer's own fail-closed rule refuses a policy that names an Out the Hub no
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
// refusal check and the delete share one timestamp.
//
// Order of operations (all in one transaction):
//
//  1. Validate the node is an Out or an HTTP proxy, so a Line or a typo can never
//     reach the delete.
//  2. Refuse a live subscription reference, naming the subscriptions.
//  3. Refuse an Out with an unfinished chain: a task addressed to a node that is
//     about to be deleted could never be reported, and the Agent would keep
//     applying a configuration the Hub has forgotten.
//  4. Delete the node row; out_settings, candidates, tasks, identities, pairing
//     rows and the private proxy row go with it through ON DELETE CASCADE.
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
	// An unfinished chain is a host that has not finished applying its link-key
	// listener. Deleting the node now would strand that chain: no result could be
	// recorded for it, and the host would keep whatever configuration it last
	// applied. The operator retries after it settles (the same bounded rule the
	// rest of the Out synchronization uses).
	//
	// The refusal is joined with ErrOutCleanupPending so every caller classifies
	// it the same way: a refusal that deleted nothing, never a half-success.
	unfinished, err := candidatepkg.LineUnfinishedTasksTx(tx, outID)
	if err != nil {
		return err
	}
	if unfinished != 0 {
		return errors.Join(errors.New(CodeOutSyncPending+": the out still has an unfinished chain; retry after it settles"), ErrOutCleanupPending)
	}
	// Delete the node. Everything keyed to it (out_settings with the dial address and
	// link key, node_candidates, agent_tasks, node_identities, node_pairing) cascades.
	// For role http there is no out_settings, candidate or task row to cascade: the
	// private proxy row (URL + credentials) goes with the node through its own
	// ON DELETE CASCADE. The candidate immutability trigger only guards a live parent:
	// its WHEN clause skips the cascade (schema 15), so history of a deleted node is
	// removed with it instead of blocking the delete.
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

// ErrOutCleanupPending is the refusal sentinel of a delete that destroyed
// nothing because the Out still has an unfinished chain. The name is kept for
// the Web handler's 409 mapping; there is no ACL cleanup left to wait for.
var ErrOutCleanupPending = errors.New(CodeOutSyncPending + ": the out still has an unfinished chain; retry the out synchronization")
