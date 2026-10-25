package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// OutBinding is the Hub-side record that binds one optional Out node to one
// edge Line. LineID is empty when the Out has been unbound: the empty value is
// a preserved audit row, not a deleted record, so an operator can always tell
// that the Out was once configured. Enabled is only authoritative together
// with a non-empty LineID; the schema enforces that pair.
type OutBinding struct {
	OutID     string `json:"out_id"`
	LineID    string `json:"line_id"`
	Enabled   bool   `json:"enabled"`
	UpdatedAt int64  `json:"updated_at"`
}

// OutBindingPreview is a read-only projection of the egress that a binding
// would produce. It never mutates the binding, the subscriber credentials or
// any Line state.
type OutBindingPreview struct {
	// Mode is one of:
	//   no-out-direct - no Out is configured at all, Lines egress directly
	//   line-direct   - the selected Out is not enabled for a Line
	//   out-disabled  - a binding exists but is disabled
	//   out-bound     - the Line would egress through the Out
	Mode string `json:"mode"`
	// OutID and LineID describe the proposed or current binding.
	OutID  string `json:"out_id"`
	LineID string `json:"line_id"`
	// Enabled is true when the preview describes an active Out egress.
	Enabled bool `json:"enabled"`
	// AffectedLines counts the Lines whose egress would change. A single
	// binding affects at most one Line.
	AffectedLines int `json:"affected_lines"`
	// AffectedPolicies counts the active subscriber credentials on those
	// Lines. One credential is one published per-subscriber policy.
	AffectedPolicies int `json:"affected_policies"`
	// AffectedSubscribers counts the distinct Subscribers behind the
	// affected policies.
	AffectedSubscribers int `json:"affected_subscribers"`
	// EgressState and EgressCode report whether the Out path of the previewed
	// Line is authorized. A proposal is never healthy: nothing has been
	// published yet, so a preview can only report direct, pending or partial.
	// A policy that depends on an unauthorized Out egress is not publishable,
	// which is why the preview refuses to describe it as an established path.
	EgressState string `json:"egress_state"`
	EgressCode  string `json:"egress_code,omitempty"`
}

// migrateSchema5 adds the Out binding table. It is additive: every schema-4
// table and row stays untouched, so a rollback to the previous binary can
// still read the database (the new table is simply ignored).
func migrateSchema5(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE out_bindings (
  out_id TEXT PRIMARY KEY REFERENCES nodes(id) ON DELETE CASCADE,
  line_id TEXT REFERENCES nodes(id),
  enabled INTEGER NOT NULL DEFAULT 0 CHECK(enabled IN (0,1)),
  updated_at INTEGER NOT NULL,
  CHECK(enabled=0 OR line_id IS NOT NULL)
);
CREATE INDEX out_bindings_line ON out_bindings(line_id);
PRAGMA user_version=5;
`); err != nil {
		return err
	}
	return nil
}

// validBindingNodeID accepts exactly the canonical node identity shape that
// the rest of the domain uses (32 lowercase hex characters).
func validBindingNodeID(id string) bool {
	return subscription.ValidateID(id) == nil
}

// ListOutBindings returns every binding row, including preserved unbind rows.
// The order is stable so callers can render a deterministic list.
func (s *Store) ListOutBindings() ([]OutBinding, error) {
	rows, err := s.DB.Query(`SELECT out_id, line_id, enabled, updated_at FROM out_bindings ORDER BY updated_at ASC, out_id ASC`)
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []OutBinding{}
	for rows.Next() {
		var (
			binding OutBinding
			lineID  sql.NullString
			enabled int
		)
		if err := rows.Scan(&binding.OutID, &lineID, &enabled, &binding.UpdatedAt); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		if lineID.Valid {
			binding.LineID = lineID.String
		}
		binding.Enabled = enabled == 1
		out = append(out, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// GetOutBinding reads one binding. A row that was explicitly unbound is
// returned with an empty LineID and Enabled=false; a missing row is
// OUT_BINDING_NOT_FOUND so a caller never mistakes "never configured" for
// "deliberately direct".
func (s *Store) GetOutBinding(outID string) (OutBinding, error) {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return OutBinding{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	binding := OutBinding{OutID: outID}
	var (
		lineID  sql.NullString
		enabled int
	)
	err := s.DB.QueryRow(`SELECT line_id, enabled, updated_at FROM out_bindings WHERE out_id=?`, outID).
		Scan(&lineID, &enabled, &binding.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return OutBinding{}, errors.New("OUT_BINDING_NOT_FOUND: the out has no binding record")
	}
	if err != nil {
		return OutBinding{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if lineID.Valid {
		binding.LineID = lineID.String
	}
	binding.Enabled = enabled == 1
	return binding, nil
}

// SetOutBinding stores one binding. Both ends must exist with the immutable
// roles out and edge. Enabling an Out additionally requires a configured Line
// and a current non-revoked identity on both ends: an Out that was never
// paired (or whose identity was revoked) can never become a live egress.
//
// An empty LineID is rejected here; unbinding is an explicit ClearOutBinding
// so a typo can never silently remove an active egress path.
//
// The store owns the timestamp: UpdatedAt on the input is ignored and the
// stored value always comes from this store's clock.
func (s *Store) SetOutBinding(binding OutBinding) error {
	return s.SetOutBindingAt(binding, time.Now())
}

// setOutBindingAt is the request-clock variant used by the Web handler, so one
// request records one timestamp. The caller's UpdatedAt is ignored: a request
// body can never choose the audit time.
func (s *Store) SetOutBindingAt(binding OutBinding, now time.Time) error {
	binding.OutID = strings.TrimSpace(binding.OutID)
	binding.LineID = strings.TrimSpace(binding.LineID)
	if !validBindingNodeID(binding.OutID) || !validBindingNodeID(binding.LineID) {
		return errors.New("OUT_BINDING_INVALID: out_id and line_id must be 32 lowercase hex characters")
	}
	stamp := now.Unix()
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var outRole string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, binding.OutID).Scan(&outRole)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if outRole != "out" {
		return errors.New("OUT_ROLE_INVALID: only out nodes can carry an out binding")
	}
	var lineRole string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, binding.LineID).Scan(&lineRole)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("LINE_NOT_FOUND: unknown line node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if lineRole != "edge" {
		return errors.New("LINE_ROLE_INVALID: only edge nodes can be bound to an out")
	}
	if binding.Enabled {
		// A binding may only enable an egress for a Line that already has a
		// stored transport. An edge node without line_settings can never
		// serve a client configuration, so it cannot anchor an Out path.
		var configured int
		if err = tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, binding.LineID).Scan(&configured); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if configured == 0 {
			return errors.New("LINE_NOT_CONFIGURED: configure the line transport before enabling an out binding")
		}
		for _, nodeID := range []string{binding.OutID, binding.LineID} {
			var identities int
			if err = tx.QueryRow(`SELECT count(*) FROM node_identities WHERE node_id=? AND revoked=0`, nodeID).Scan(&identities); err != nil {
				return errors.New("DATABASE_UNAVAILABLE")
			}
			if identities != 1 {
				return errors.New("OUT_NOT_AUTHORIZED: both ends need a current paired identity before the out can be enabled")
			}
		}
	}
	enabled := 0
	if binding.Enabled {
		enabled = 1
	}
	if _, err = tx.Exec(`INSERT INTO out_bindings(out_id, line_id, enabled, updated_at) VALUES(?,?,?,?)
 ON CONFLICT(out_id) DO UPDATE SET line_id=excluded.line_id, enabled=excluded.enabled, updated_at=excluded.updated_at`,
		binding.OutID, binding.LineID, enabled, stamp); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	// The binding is the authorization intent: enabling it publishes the Out
	// allowlist and disabling it republishes the Out with an explicit empty
	// list. The drain owns its own transaction and never fails the mutation;
	// the next Out event retries it.
	s.drainOutNode(binding.OutID, now)
	return nil
}

// DeleteOut removes one Out from the Hub's routing model in one transaction:
// the binding route is deleted first, then the Out authorization is republished
// as an explicit empty allowlist by the same reclaim drain that OnLineRetired
// uses, so a deleted Out can never keep a stale accept rule that the Hub still
// believes in.
//
// The readback anchor of the delete is the newest published chain of the Out:
// it must carry the key present and empty. An omitted key would mean "no Hub
// expectation", which is the shape-only degradation the guard must never fall
// back to, so the whole delete is rolled back instead.
//
// An Out that is offline or has a chain in flight cannot apply the cleanup yet.
// Its routing intent is still removed (the derivation is empty and fail-closed
// from that moment on), and the call returns OUT_SYNC_PENDING joined with the
// real deferral reason instead of claiming a cleaned host. The next Out event
// republishes the empty authorization on its own.
//
// Deleting the routing model is not the same as revoking the node identity: an
// identity revocation in the same transaction would fail the very cleanup chain
// this call publishes, leaving an unreachable host with a stale guard while the
// Hub reports success. Credential revocation therefore stays the explicit
// revokeIdentity action. The node row and its immutable candidate history stay
// as the audit trail; only the binding row is deleted, so a deleted Out is
// "never configured" again rather than a preserved unbind row.
func (s *Store) DeleteOut(outID string) error {
	return s.DeleteOutAt(outID, time.Now())
}

// deleteOutAt is the request-clock variant used by the Web handler, so the
// deletion, the cleanup publication and the readback share one timestamp.
func (s *Store) DeleteOutAt(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return errors.New("OUT_ROLE_INVALID: only out nodes can carry an out binding")
	}
	// The Lines are read before the route disappears: after the delete there is
	// no row left to tell which Lines have to be released from the Out gate.
	lines, err := queryIDsTx(tx, `SELECT line_id FROM out_bindings
 WHERE out_id=? AND line_id IS NOT NULL ORDER BY line_id ASC`, outID)
	if err != nil {
		return err
	}
	// 1. Delete the route. From this statement on every derivation of this
	// Out's authorization is empty, so a concurrent publish cannot resurrect
	// the deleted Line either.
	if _, err = tx.Exec(`DELETE FROM out_bindings WHERE out_id=?`, outID); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	// 2. Clear the ACL. An Out that never published a chain has no host state
	// to clear; otherwise the shared reclaim drain republishes the explicit
	// empty authorization (it also refuses to race an in-flight chain and
	// leaves an offline Out's intent durable).
	//
	// A repeated delete is idempotent: when the newest chain already names the
	// explicit empty set and the node confirmed it, there is nothing left to
	// publish and no operator action is needed.
	revision, digest, _, published, err := LatestPublishedCandidateTx(tx, outID)
	if err != nil {
		return err
	}
	deferred := false
	var deferredErr error
	if published {
		clean, confirmed, err := outACLCleanTx(tx, outID, revision, digest)
		if err != nil {
			return err
		}
		if !clean || !confirmed {
			outcome, drainErr := DrainOutNodeIntentTx(tx, outID, now, true)
			if outcome == outDrainDeferred {
				deferred = true
				deferredErr = drainErr
			} else if drainErr != nil {
				return drainErr
			}
		}
	}
	// 3. Read the cleanup back. Publishing happens in this transaction, so the
	// anchor is exact: the newest chain must name the empty set explicitly.
	if !deferred && published {
		revision, digest, _, found, err := LatestPublishedCandidateTx(tx, outID)
		if err != nil {
			return err
		}
		if found {
			clean, _, err := outACLCleanTx(tx, outID, revision, digest)
			if err != nil {
				return err
			}
			if !clean {
				return errors.New(CodeOutSyncPending + ": the out acl cleanup was not published; the delete is rolled back")
			}
		}
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if deferred {
		// The routing model is already clean and fail-closed; only the host
		// cleanup waits. Report both facts instead of a fabricated success.
		return errors.Join(deferredErr, ErrOutCleanupPending)
	}
	// The Lines no longer have an enabled Out, so a Line that was gated may
	// publish again. Each drain owns its own transaction and never fails the
	// delete: the next Line event retries it.
	for _, lineID := range lines {
		s.drainSubscriberNode(lineID, now)
	}
	return nil
}

// ErrOutCleanupPending marks a delete whose routing cleanup succeeded but whose
// host cleanup could not be delivered yet. It is a sentinel so the caller can
// report "route gone, host pending" as one explicit outcome instead of matching
// error text.
var ErrOutCleanupPending = errors.New(CodeOutSyncPending + ": the out acl cleanup is queued behind an in-flight or offline out; retry the out synchronization")

// outACLCleanTx reports whether the newest published chain of one Out already
// names an explicit empty authorization, and whether the node confirmed that
// exact revision. "Clean" needs the key present and empty: an omitted key means
// "no Hub expectation" and would hide a stale guard behind a shape-only check.
func outACLCleanTx(tx *sql.Tx, outID string, revision int64, digest string) (bool, bool, error) {
	allowed, present, err := OutReadbackAllowlistTx(tx, outID, revision)
	if err != nil {
		return false, false, err
	}
	if !present || len(allowed) != 0 {
		return false, false, nil
	}
	confirmed, err := subscriberLineReadbackConfirmedTx(tx, outID, revision, digest)
	if err != nil {
		return false, false, err
	}
	return true, confirmed, nil
}

// ClearOutBinding unbinds one Out. The row is preserved with an empty LineID
// and Enabled=false, so the deliberate change keeps an audit trail while the
// egress returns to the direct Line path. Repeating the call is idempotent for
// an existing Out node.
//
// An Out that never had a binding row is a no-op: unbinding must not fabricate
// an audit row, because that would change a Hub-level "never configured"
// (no-out-direct) into "deliberately direct" (line-direct).
func (s *Store) ClearOutBinding(outID string) error {
	return s.ClearOutBindingAt(outID, time.Now())
}

// clearOutBindingAt is the request-clock variant used by the Web handler.
func (s *Store) ClearOutBindingAt(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	var role string
	err = tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return errors.New("OUT_ROLE_INVALID: only out nodes can carry an out binding")
	}
	res, err := tx.Exec(`UPDATE out_bindings SET line_id=NULL, enabled=0, updated_at=? WHERE out_id=?`, now.Unix(), outID)
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if affected == 0 {
		// No row existed: keep it that way. Commit the read-only transaction
		// so the no-op is explicit rather than a silent rollback.
		if err = tx.Commit(); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		return nil
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	// The unbound Out has to stop authorizing the Line: the drain republishes
	// it with an explicit empty allowlist. It owns its own transaction and never
	// fails the mutation; the next Out event retries it.
	s.drainOutNode(outID, now)
	return nil
}

// PreviewOutBinding projects the effect of a binding without changing anything.
//
// With no arguments it summarizes the whole Hub and reports no-out-direct when
// no Out is enabled, which is the guarantee that an Out-free deployment keeps
// using the direct Line egress. With an out_id it previews that Out's current
// binding, or a proposed line_id when one is supplied. Counts are read from the
// active subscriber credentials of the affected Lines; no subscriber identity,
// UUID or token is returned.
func (s *Store) PreviewOutBinding(outID, lineID string) (OutBindingPreview, error) {
	return s.PreviewOutBindingAt(outID, lineID, time.Now())
}

// previewOutBindingAt is the request-clock variant of the read-only preview, so
// the egress projection and the affected-policy counts share one clock.
func (s *Store) PreviewOutBindingAt(outID, lineID string, now time.Time) (OutBindingPreview, error) {
	outID = strings.TrimSpace(outID)
	lineID = strings.TrimSpace(lineID)
	if outID == "" {
		if lineID != "" {
			return OutBindingPreview{}, errors.New("OUT_BINDING_INVALID: a line preview needs an out_id")
		}
		return s.previewAllOutBindings()
	}
	if !validBindingNodeID(outID) {
		return OutBindingPreview{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	var role string
	err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutBindingPreview{}, errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return OutBindingPreview{}, errors.New("OUT_ROLE_INVALID: only out nodes can carry an out binding")
	}
	preview := OutBindingPreview{OutID: outID}
	if lineID != "" {
		if !validBindingNodeID(lineID) {
			return OutBindingPreview{}, errors.New("OUT_BINDING_INVALID: line_id must be 32 lowercase hex characters")
		}
		var lineRole string
		err = s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&lineRole)
		if errors.Is(err, sql.ErrNoRows) {
			return OutBindingPreview{}, errors.New("LINE_NOT_FOUND: unknown line node")
		}
		if err != nil {
			return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if lineRole != "edge" {
			return OutBindingPreview{}, errors.New("LINE_ROLE_INVALID: only edge nodes can be bound to an out")
		}
		// A proposal preview mirrors the enable gate: a Line without a stored
		// transport can never anchor an Out path, so the preview must not
		// claim an egress that SetOutBinding would reject.
		var configured int
		if err = s.DB.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, lineID).Scan(&configured); err != nil {
			return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if configured == 0 {
			return OutBindingPreview{}, errors.New("LINE_NOT_CONFIGURED: configure the line transport before enabling an out binding")
		}
		preview.LineID = lineID
		preview.Enabled = true
		preview.Mode = "out-bound"
	} else {
		binding, bindingErr := s.GetOutBinding(outID)
		switch {
		case bindingErr == nil:
			preview.LineID = binding.LineID
			preview.Enabled = binding.Enabled
			switch {
			case binding.LineID == "":
				preview.Mode = "line-direct"
			case binding.Enabled:
				preview.Mode = "out-bound"
			default:
				preview.Mode = "out-disabled"
			}
		case strings.HasPrefix(bindingErr.Error(), "OUT_BINDING_NOT_FOUND"):
			preview.Mode = "line-direct"
		default:
			return OutBindingPreview{}, bindingErr
		}
	}
	if preview.LineID != "" {
		preview.AffectedLines = 1
		if err = s.DB.QueryRow(`SELECT count(*), count(DISTINCT subscriber_id) FROM proxy_credentials
 WHERE node_id=? AND active=1`, preview.LineID).Scan(&preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
			return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	// The egress state is what the preview must not overstate. A proposal is
	// always pending: the Out has not even been asked to authorize the Line. An
	// existing binding reports the real Hub-side state, so a caller can tell an
	// established path from one whose policy would still be refused at publish.
	if preview.LineID != "" {
		if lineID != "" {
			// A proposal has published nothing: the Out was never asked to
			// authorize the Line, so a policy that depends on it is not
			// publishable yet. Reporting the same code the publish gate uses
			// keeps the preview and the gate from disagreeing.
			preview.EgressState, preview.EgressCode = LineEgressPendingPreview, CodeOutNotAuthorized
		} else {
			tx, err := s.DB.Begin()
			if err != nil {
				return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
			}
			state, code, egressErr := LineOutEgressStatusTx(tx, preview.LineID, now)
			_ = tx.Rollback()
			if egressErr != nil {
				return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
			}
			preview.EgressState, preview.EgressCode = state, code
		}
	}
	return preview, nil
}

// LineEgressPendingPreview is the projection of a proposed egress: the Hub has
// recorded the intent but has not authorized or confirmed it yet.
const LineEgressPendingPreview = "pending"

// CodeOutNotAuthorized is the single refusal code of a policy that depends on an
// Out egress the Hub cannot vouch for yet. The preview and the publish gate both
// report it, so an operator never sees "preview says fine, publish says no".
const CodeOutNotAuthorized = "OUT_NOT_AUTHORIZED"

// previewAllOutBindings summarizes every enabled binding in one read-only
// query. A deployment with no binding rows reports no-out-direct, preserving
// the Out-free direct egress behavior.
//
// A Line may be the egress of more than one Out, so the credentials join
// fans out. Every aggregate therefore deduplicates by identity: one active
// credential is one policy no matter how many enabled Out rows point at its
// Line, and the Hub totals match the single-binding preview.
func (s *Store) previewAllOutBindings() (OutBindingPreview, error) {
	preview := OutBindingPreview{Mode: "no-out-direct"}
	var rows, enabled int
	if err := s.DB.QueryRow(`SELECT count(*), COALESCE(SUM(enabled),0) FROM out_bindings`).Scan(&rows, &enabled); err != nil {
		return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if rows > 0 && enabled == 0 {
		preview.Mode = "line-direct"
	}
	if enabled == 0 {
		return preview, nil
	}
	preview.Mode = "out-bound"
	preview.Enabled = true
	if err := s.DB.QueryRow(`SELECT count(DISTINCT ob.line_id),
 COALESCE(COUNT(DISTINCT pc.id),0),
 COUNT(DISTINCT pc.subscriber_id)
 FROM out_bindings ob
 LEFT JOIN proxy_credentials pc ON pc.node_id=ob.line_id AND pc.active=1
 WHERE ob.enabled=1 AND ob.line_id IS NOT NULL`).
		Scan(&preview.AffectedLines, &preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
		return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return preview, nil
}
