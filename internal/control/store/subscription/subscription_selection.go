package subscription

// Subscription selection persistence (ADR-0008 §1–§3).
//
// The four edge tables are the subscription's side of every reference:
//
//	subscription_lines(subscriber_id, node_id, position)
//	subscription_outs(subscriber_id, out_id, position)          -- 1.0: one row
//	subscription_rules(subscriber_id, rule_stable_key, rule_version, position)
//	subscription_networks(subscriber_id, device_id, position)
//
// `position` is unique inside its group, so the wizard order survives a
// reopen, and every reference is a real foreign key with ON DELETE CASCADE:
// deleting a subscriber clears its own edges, and no other delete can leave a
// dangling reference (the rule library refuses a referenced delete before the
// row is reached; see internal/policy).
//
// `subscription_snapshots` stores the selection identity and the approved
// artifact digest — never a rendered byte. The artifact itself is always
// re-derived by the pure composer, which is what makes a download verifiable.
//
// `proxy_credentials` keeps its role: it is the materialized VLESS identity per
// (subscriber, Line). The edge table decides *which* Lines a subscription
// selects; the credential row is the credential that serves the selected Line.
// Both are written in one transaction so they cannot disagree.
//
// This file is persistence only. Shape validation is SelectionSpec.Normalize
// (store_subscription_spec.go), reference validation is
// store_subscription_refs.go, and draft/approval orchestration is
// store_subscription_compose.go.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// Stable selection refusals. Only the code (before ": ") is stable.
const (
	// CodeOutSelectionConflict: another subscription that already serves one
	// of the selected Lines chose a different Out (including "no Out"). The
	// Line publishes one route, so two subscriptions cannot disagree.
	CodeOutSelectionConflict = "SUBSCRIPTION_OUT_CONFLICT"
	// CodeOutReferenced: an Out is still selected by subscriptions.
	CodeOutReferenced = "OUT_REFERENCED_BY_SUBSCRIPTIONS"
	// CodeSelectionInvalid: the submitted selection is not a canonical set.
	CodeSelectionInvalid = "SUBSCRIPTION_SELECTION_INVALID"
	// CodeArtifactDrift: the recomposed artifact no longer matches the approved
	// digest, so serving it would publish bytes nobody approved.
	CodeArtifactDrift = "SUBSCRIPTION_ARTIFACT_DRIFT"
	// CodeArtifactNotApproved: a selection was saved but never gated, so there
	// is no approved artifact to download.
	CodeArtifactNotApproved = "SUBSCRIPTION_ARTIFACT_NOT_APPROVED"
)

// MigrateSchema13 adds the subscription edge tables and the selection snapshot.
//
// It is purely additive: one new table per group plus one snapshot table, no
// existing table, row or index changes. A rollback only needs to drop the new
// tables and set user_version back, so an older binary keeps reading the
// database (it ignores the tables it does not know).
//
// Version note: 11 belongs to 11d and 12 to the rule library, so this leg runs
// from 12 (or from 11/10 through the earlier legs) and bumps to 13. The DDL is
// idempotent so a replayed migration cannot fail on its own earlier write.
func MigrateSchema13(tx *sql.Tx) error {
	if _, err := tx.Exec(`
CREATE TABLE IF NOT EXISTS subscription_lines (
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  node_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position>=0),
  line_revision INTEGER NOT NULL DEFAULT 0 CHECK(line_revision>=0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(subscriber_id, node_id),
  UNIQUE(subscriber_id, position)
);
CREATE INDEX IF NOT EXISTS subscription_lines_node ON subscription_lines(node_id);
CREATE TABLE IF NOT EXISTS subscription_outs (
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  out_id TEXT NOT NULL REFERENCES nodes(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position=0),
  out_revision INTEGER NOT NULL DEFAULT 0 CHECK(out_revision>=0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(subscriber_id),
  UNIQUE(subscriber_id, position)
);
CREATE INDEX IF NOT EXISTS subscription_outs_out ON subscription_outs(out_id);
CREATE TABLE IF NOT EXISTS subscription_rules (
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  rule_stable_key TEXT NOT NULL,
  rule_version INTEGER NOT NULL CHECK(rule_version>0),
  position INTEGER NOT NULL CHECK(position>=0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(subscriber_id, rule_stable_key, rule_version),
  UNIQUE(subscriber_id, position)
);
CREATE INDEX IF NOT EXISTS subscription_rules_revision ON subscription_rules(rule_stable_key, rule_version);
CREATE TABLE IF NOT EXISTS subscription_networks (
  subscriber_id TEXT NOT NULL REFERENCES subscribers(id) ON DELETE CASCADE,
  device_id TEXT NOT NULL REFERENCES mesh_devices(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position>=0),
  created_at INTEGER NOT NULL,
  PRIMARY KEY(subscriber_id, device_id),
  UNIQUE(subscriber_id, position)
);
CREATE INDEX IF NOT EXISTS subscription_networks_device ON subscription_networks(device_id);
CREATE TABLE IF NOT EXISTS subscription_snapshots (
  subscriber_id TEXT PRIMARY KEY REFERENCES subscribers(id) ON DELETE CASCADE,
  version INTEGER NOT NULL CHECK(version>0),
  selection_id TEXT NOT NULL,
  selection_json TEXT NOT NULL,
  artifact_id TEXT NOT NULL DEFAULT '',
  artifact_approved INTEGER NOT NULL DEFAULT 0 CHECK(artifact_approved IN (0,1)),
  artifact_at INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL
);
PRAGMA user_version=13;
`); err != nil {
		return err
	}
	return nil
}

// SaveSubscriptionSelection replaces the four-group selection of one active
// subscriber in a single transaction: edges (and their credentials for a new
// Line), then the snapshot with an empty artifact digest.
//
// Flow: Normalize (shape) -> draft builder inside one transaction (references,
// same-Line Out agreement, credentials) -> one write transaction. It is the
// direct edge save; the wizard uses the explicit Draft/Preview/Approve/Save
// steps instead, and both share the same builder and writer so they cannot
// drift.
func (s *Store) SaveSubscriptionSelection(subscriberID string, spec SelectionSpec, now time.Time) (coredomain.Selection, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return coredomain.Selection{}, err
	}
	draft, err := s.DraftSubscriptionSelection(subscriberID, "", spec)
	if err != nil {
		return coredomain.Selection{}, err
	}
	if _, err := s.SaveSubscriptionDraft(draft, "", now); err != nil {
		return coredomain.Selection{}, err
	}
	return draft.Selection, nil
}

// writeSelectionEdgesTx replaces every edge group of one subscriber. The
// groups are rewritten as a whole so a dropped Line, rule or device cannot
// survive a save.
func writeSelectionEdgesTx(tx *sql.Tx, selection coredomain.Selection, now time.Time) error {
	for _, table := range []string{"subscription_lines", "subscription_outs", "subscription_rules", "subscription_networks"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE subscriber_id=?`, selection.SubscriberID); err != nil {
			return errors.New(common.CodeDatabaseUnavailable)
		}
	}
	for _, line := range selection.Lines {
		if _, err := tx.Exec(`INSERT INTO subscription_lines(subscriber_id, node_id, position, line_revision, created_at) VALUES(?,?,?,?,?)`,
			selection.SubscriberID, line.NodeID, line.Position, line.LineRevision, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the line selection was not stored")
		}
	}
	if selection.Out != nil {
		if _, err := tx.Exec(`INSERT INTO subscription_outs(subscriber_id, out_id, position, out_revision, created_at) VALUES(?,?,?,?,?)`,
			selection.SubscriberID, selection.Out.OutID, selection.Out.Position, selection.Out.OutRevision, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the out selection was not stored")
		}
	}
	for _, revision := range selection.Rules {
		if _, err := tx.Exec(`INSERT INTO subscription_rules(subscriber_id, rule_stable_key, rule_version, position, created_at) VALUES(?,?,?,?,?)`,
			selection.SubscriberID, revision.StableKey, revision.Version, revision.Position, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the rule selection was not stored")
		}
	}
	for _, device := range selection.Networks {
		if _, err := tx.Exec(`INSERT INTO subscription_networks(subscriber_id, device_id, position, created_at) VALUES(?,?,?,?)`,
			selection.SubscriberID, device.DeviceID, device.Position, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the network selection was not stored")
		}
	}
	return nil
}

// writeSnapshotTx records the selection identity and the approved artifact
// digest. An empty artifactID stores a saved-but-unapproved selection, which the
// download refuses; a changed selection always replaces the previous digest, so
// a download can never serve bytes composed from an older choice.
func writeSnapshotTx(tx *sql.Tx, selection coredomain.Selection, artifactID string, now time.Time) error {
	encoded, err := json.Marshal(selection)
	if err != nil {
		return errors.New("SUBSCRIPTION_SNAPSHOT_FAILED")
	}
	approved, approvedAt := 0, int64(0)
	if artifactID != "" {
		approved, approvedAt = 1, now.Unix()
	}
	if _, err := tx.Exec(`INSERT INTO subscription_snapshots(subscriber_id, version, selection_id, selection_json, artifact_id, artifact_approved, artifact_at, updated_at)
	  VALUES(?,?,?,?,?,?,?,?)
	  ON CONFLICT(subscriber_id) DO UPDATE SET
	   version=excluded.version,
	   selection_id=excluded.selection_id,
	   selection_json=excluded.selection_json,
	   artifact_id=excluded.artifact_id,
	   artifact_approved=excluded.artifact_approved,
	   artifact_at=excluded.artifact_at,
	   updated_at=excluded.updated_at`,
		selection.SubscriberID, selection.Version, selection.SnapshotID(), string(encoded), artifactID, approved, approvedAt, now.Unix()); err != nil {
		return errors.New("SUBSCRIPTION_SNAPSHOT_FAILED")
	}
	return nil
}

// storedSelectionVersionTx reads the snapshot version of one subscriber, or zero
// when it never saved a selection. The save path increments it so every save is a
// new identity.
func storedSelectionVersionTx(tx *sql.Tx, subscriberID string) (int64, error) {
	var stored int64
	err := tx.QueryRow(`SELECT version FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).Scan(&stored)
	switch {
	case err == nil:
		return stored, nil
	case errors.Is(err, sql.ErrNoRows):
		return 0, nil
	default:
		return 0, errors.New(common.CodeDatabaseUnavailable)
	}
}

// readSelectionTx reads one subscriber's edges back into the snapshot model.
// The version is the stored snapshot version, or zero when the subscriber never
// saved a selection.
func readSelectionTx(tx *sql.Tx, subscriberID string) (coredomain.Selection, error) {
	selection := coredomain.Selection{SubscriberID: subscriberID}
	stored, err := storedSelectionVersionTx(tx, subscriberID)
	if err != nil {
		return coredomain.Selection{}, err
	}
	selection.Version = stored

	rows, err := tx.Query(`SELECT node_id, position, line_revision FROM subscription_lines WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	for rows.Next() {
		var line coredomain.SelectionLine
		if err := rows.Scan(&line.NodeID, &line.Position, &line.LineRevision); err != nil {
			rows.Close()
			return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
		}
		selection.Lines = append(selection.Lines, line)
	}
	if err := rows.Close(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := rows.Err(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}

	var out coredomain.SelectionOut
	err = tx.QueryRow(`SELECT out_id, position, out_revision FROM subscription_outs WHERE subscriber_id=?`, subscriberID).
		Scan(&out.OutID, &out.Position, &out.OutRevision)
	switch {
	case err == nil:
		selection.Out = &out
	case errors.Is(err, sql.ErrNoRows):
	default:
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}

	rows, err = tx.Query(`SELECT rule_stable_key, rule_version, position FROM subscription_rules WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	for rows.Next() {
		var rule coredomain.SelectionRule
		if err := rows.Scan(&rule.StableKey, &rule.Version, &rule.Position); err != nil {
			rows.Close()
			return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
		}
		selection.Rules = append(selection.Rules, rule)
	}
	if err := rows.Close(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := rows.Err(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}

	rows, err = tx.Query(`SELECT device_id, position FROM subscription_networks WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	for rows.Next() {
		var device coredomain.SelectionNetwork
		if err := rows.Scan(&device.DeviceID, &device.Position); err != nil {
			rows.Close()
			return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
		}
		selection.Networks = append(selection.Networks, device)
	}
	if err := rows.Close(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := rows.Err(); err != nil {
		return coredomain.Selection{}, errors.New(common.CodeDatabaseUnavailable)
	}
	return selection, nil
}

// SubscriptionSelection reads the saved selection of one subscriber. The
// boolean is false when the subscriber never saved one, so the wizard can tell
// "no selection yet" from "an empty selection".
func (s *Store) SubscriptionSelection(subscriberID string) (coredomain.Selection, bool, error) {
	if err := coredomain.ValidateID(subscriberID); err != nil {
		return coredomain.Selection{}, false, common.ErrSubscriberIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return coredomain.Selection{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return coredomain.Selection{}, false, err
	}
	selection, err := readSelectionTx(tx, subscriberID)
	if err != nil {
		return coredomain.Selection{}, false, err
	}
	saved := len(selection.Lines) > 0 || len(selection.Rules) > 0 || len(selection.Networks) > 0 || selection.Out != nil
	return selection, saved, nil
}

// LineUsedBy names the subscriptions that select one Line. It is the used-by
// edge of the reference graph, read by the delete guard and the page.
func (s *Store) LineUsedBy(nodeID string) ([]string, error) {
	return s.SelectionUsedByTx(nil, `SELECT s.display_name FROM subscription_lines l
	  JOIN subscribers s ON s.id=l.subscriber_id
	  WHERE l.node_id=? ORDER BY s.display_name, s.id`, nodeID)
}

// OutUsedBy names the subscriptions that select one Out.
func (s *Store) OutUsedBy(outID string) ([]string, error) {
	return s.SelectionUsedByTx(nil, `SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	  WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
}

// outUsedByTx is the transaction-scoped variant of OutUsedBy. The store has one
// connection, so a delete that must check its own references has to use this
// one instead of opening a second query on the pool.
func (s *Store) OutUsedByTx(tx *sql.Tx, outID string) ([]string, error) {
	return selectionUsedByTx(tx, `SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	  WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
}

// OutReferencedCode is the node port's spelling of the refusal code for an
// egress a subscription still selects.
func (s *Store) OutReferencedCode() string { return CodeOutReferenced }

// MeshDeviceUsedBy names the subscriptions that record one mesh device.
func (s *Store) MeshDeviceUsedBy(deviceID string) ([]string, error) {
	return s.SelectionUsedByTx(nil, `SELECT s.display_name FROM subscription_networks n
	  JOIN subscribers s ON s.id=n.subscriber_id
	  WHERE n.device_id=? ORDER BY s.display_name, s.id`, deviceID)
}

// selectionUsedByTx is the transaction-scoped used-by reader. A missing edge
// table is honest emptiness (a database that has not reached schema 13 yet);
// any other read error is DATABASE_UNAVAILABLE.
func selectionUsedByTx(tx *sql.Tx, query, id string) ([]string, error) {
	rows, err := tx.Query(query, id)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []string{}, nil
		}
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanNameRows(rows)
}

// selectionUsedBy runs one used-by query. A missing edge table is honest
// emptiness (a database that has not reached schema 13 yet); any other read
// error is DATABASE_UNAVAILABLE, never "nobody references this".
func (s *Store) SelectionUsedByTx(tx *sql.Tx, query, id string) ([]string, error) {
	// A transaction-scoped caller passes its transaction so the reference check
	// and the delete it guards see the same rows; a page read passes nil and
	// runs on the pool.
	var (
		rows *sql.Rows
		err  error
	)
	if tx != nil {
		rows, err = tx.Query(query, id)
	} else {
		rows, err = s.DB.Query(query, id)
	}
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []string{}, nil
		}
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanNameRows(rows)
}

// scanNameRows drains one display-name result set. It is the single reader of
// the used-by shape, so the three used-by projections cannot disagree about
// error mapping.
func scanNameRows(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}
