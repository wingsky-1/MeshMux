package web

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
func (s *store) ListOutBindings() ([]OutBinding, error) {
	rows, err := s.db.Query(`SELECT out_id, line_id, enabled, updated_at FROM out_bindings ORDER BY updated_at ASC, out_id ASC`)
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
func (s *store) GetOutBinding(outID string) (OutBinding, error) {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return OutBinding{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	binding := OutBinding{OutID: outID}
	var (
		lineID  sql.NullString
		enabled int
	)
	err := s.db.QueryRow(`SELECT line_id, enabled, updated_at FROM out_bindings WHERE out_id=?`, outID).
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
// roles out and edge. Enabling an Out additionally requires a current
// non-revoked identity on both ends: an Out that was never paired (or whose
// identity was revoked) can never become a live egress.
//
// An empty LineID is rejected here; unbinding is an explicit ClearOutBinding
// so a typo can never silently remove an active egress path.
func (s *store) SetOutBinding(binding OutBinding) error {
	return s.setOutBindingAt(binding, time.Now())
}

// setOutBindingAt is the request-clock variant used by the Web handler, so one
// request records one timestamp.
func (s *store) setOutBindingAt(binding OutBinding, now time.Time) error {
	binding.OutID = strings.TrimSpace(binding.OutID)
	binding.LineID = strings.TrimSpace(binding.LineID)
	if !validBindingNodeID(binding.OutID) || !validBindingNodeID(binding.LineID) {
		return errors.New("OUT_BINDING_INVALID: out_id and line_id must be 32 lowercase hex characters")
	}
	if binding.UpdatedAt <= 0 {
		binding.UpdatedAt = now.Unix()
	}
	tx, err := s.db.Begin()
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
		binding.OutID, binding.LineID, enabled, binding.UpdatedAt); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	return nil
}

// ClearOutBinding unbinds one Out. The row is preserved with an empty LineID
// and Enabled=false, so the deliberate change keeps an audit trail while the
// egress returns to the direct Line path. Repeating the call is idempotent for
// an existing Out node.
func (s *store) ClearOutBinding(outID string) error {
	return s.clearOutBindingAt(outID, time.Now())
}

// clearOutBindingAt is the request-clock variant used by the Web handler.
func (s *store) clearOutBindingAt(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validBindingNodeID(outID) {
		return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
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
	if _, err = tx.Exec(`INSERT INTO out_bindings(out_id, line_id, enabled, updated_at) VALUES(?,NULL,0,?)
 ON CONFLICT(out_id) DO UPDATE SET line_id=NULL, enabled=0, updated_at=excluded.updated_at`,
		outID, now.Unix()); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if err = tx.Commit(); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
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
func (s *store) PreviewOutBinding(outID, lineID string) (OutBindingPreview, error) {
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
	err := s.db.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
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
		err = s.db.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&lineRole)
		if errors.Is(err, sql.ErrNoRows) {
			return OutBindingPreview{}, errors.New("LINE_NOT_FOUND: unknown line node")
		}
		if err != nil {
			return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if lineRole != "edge" {
			return OutBindingPreview{}, errors.New("LINE_ROLE_INVALID: only edge nodes can be bound to an out")
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
		if err = s.db.QueryRow(`SELECT count(*), count(DISTINCT subscriber_id) FROM proxy_credentials
 WHERE node_id=? AND active=1`, preview.LineID).Scan(&preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
			return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	return preview, nil
}

// previewAllOutBindings summarizes every enabled binding in one read-only
// query. A deployment with no binding rows reports no-out-direct, preserving
// the Out-free direct egress behavior.
func (s *store) previewAllOutBindings() (OutBindingPreview, error) {
	preview := OutBindingPreview{Mode: "no-out-direct"}
	var rows, enabled int
	if err := s.db.QueryRow(`SELECT count(*), COALESCE(SUM(enabled),0) FROM out_bindings`).Scan(&rows, &enabled); err != nil {
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
	if err := s.db.QueryRow(`SELECT count(DISTINCT ob.line_id),
 COALESCE(SUM(CASE WHEN pc.id IS NULL THEN 0 ELSE 1 END),0),
 count(DISTINCT pc.subscriber_id)
 FROM out_bindings ob
 LEFT JOIN proxy_credentials pc ON pc.node_id=ob.line_id AND pc.active=1
 WHERE ob.enabled=1 AND ob.line_id IS NOT NULL`).
		Scan(&preview.AffectedLines, &preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
		return OutBindingPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return preview, nil
}
