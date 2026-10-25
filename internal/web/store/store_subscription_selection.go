package store

// Subscription selection persistence for the aggregation rebuild (Task 4,
// ADR-0008 §1–§3).
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

import (
	"database/sql"
	"encoding/json"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
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

// RuleRevision is one pinned rule-library identity: rule_revision_id is exactly
// (StableKey, Version), the contract Task 3 froze.
type RuleRevision struct {
	StableKey string
	Version   int
}

// SelectionSpec is one submitted selection: the four wizard groups.
type SelectionSpec struct {
	LineIDs    []string
	OutID      string
	Rules      []RuleRevision
	NetworkIDs []string
}

// migrateSchema13 adds the subscription edge tables and the selection snapshot.
//
// It is purely additive: one new table per group plus one snapshot table, no
// existing table, row or index changes. A rollback only needs to drop the new
// tables and set user_version back, so an older binary keeps reading the
// database (it ignores the tables it does not know).
//
// Version note: 11 belongs to 11d and 12 to the rule library, so this leg runs
// from 12 (or from 11/10 through the earlier legs) and bumps to 13. The DDL is
// idempotent so a replayed migration cannot fail on its own earlier write.
func migrateSchema13(tx *sql.Tx) error {
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
// subscriber in a single transaction: edges, credentials and the snapshot row.
//
// The save is strict (layer 2 of the preview contract): every identity must be
// canonical and exist, the Out must be a configured Out node, the rules must be
// stored revisions, the devices must be mesh devices, and the 1.0 single-Out
// plus same-Line-Out rules are enforced here, not only in the UI.
//
// A Line that stays selected keeps its credential; a newly selected Line gets a
// fresh one; a dropped Line is only deactivated (its UUID stays auditable). The
// credential write is the same rule SelectLines follows, so a save can never
// mint a second UUID for one Line.
func (s *Store) SaveSubscriptionSelection(subscriberID string, spec SelectionSpec, now time.Time) (subscription.Selection, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return subscription.Selection{}, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	// One writer: the same draft builder the wizard uses, saved without an
	// approved artifact. A direct edge save therefore keeps every strict check
	// (identity shape, reference existence, the single-Out rule and the
	// same-Line Out agreement) and cannot drift from the wizard path.
	draft, err := s.DraftSubscriptionSelection(subscriberID, "", spec)
	if err != nil {
		return subscription.Selection{}, err
	}
	if _, err := s.SaveSubscriptionDraft(draft, "", now); err != nil {
		return subscription.Selection{}, err
	}
	return draft.Selection, nil
}

// normalizeRuleSelection validates the identity shape and removes duplicates
// while keeping the caller's order, then assigns dense positions.
func normalizeRuleSelection(revisions []RuleRevision) ([]RuleRevision, error) {
	if len(revisions) > 64 {
		return nil, errors.New(CodeSelectionInvalid + ": select at most 64 rules")
	}
	seen := make(map[string]struct{}, len(revisions))
	out := make([]RuleRevision, 0, len(revisions))
	for _, revision := range revisions {
		key := strings.TrimSpace(revision.StableKey)
		if key == "" || len(key) > 64 || revision.Version < 1 {
			return nil, errors.New(CodeSelectionInvalid + ": a rule needs a stable key and a positive version")
		}
		identity := key + "@" + strconv.Itoa(revision.Version)
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		out = append(out, RuleRevision{StableKey: key, Version: revision.Version})
	}
	return out, nil
}

// normalizeDeviceSelection validates the identity shape and removes duplicates
// while keeping the caller's order.
func normalizeDeviceSelection(deviceIDs []string) ([]string, error) {
	if len(deviceIDs) > 64 {
		return nil, errors.New(CodeSelectionInvalid + ": select at most 64 mesh devices")
	}
	seen := make(map[string]struct{}, len(deviceIDs))
	out := make([]string, 0, len(deviceIDs))
	for _, raw := range deviceIDs {
		deviceID := strings.TrimSpace(raw)
		if err := subscription.ValidateID(deviceID); err != nil {
			return nil, errors.New("MESH_DEVICE_ID_INVALID: need 32 lowercase hex characters")
		}
		if _, duplicate := seen[deviceID]; duplicate {
			continue
		}
		seen[deviceID] = struct{}{}
		out = append(out, deviceID)
	}
	return out, nil
}

// validateSelectionOutTx checks that a selected egress is a usable endpoint:
// a managed Out with configured transport, or an external HTTP proxy
// (Ruling R11) with a stored proxy row. The proxy is not an Agent node, so the
// out_settings requirement applies to role "out" only. An egress without a
// dial body would render a route that names an egress nobody can reach.
func validateSelectionOutTx(tx *sql.Tx, outID string) error {
	if outID == "" {
		return nil
	}
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	switch role {
	case "out":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM out_settings WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if configured == 0 {
			return errors.New("OUT_NOT_CONFIGURED: configure the out transport before selecting it")
		}
	case "http":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM node_http_proxy WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if configured == 0 {
			return errors.New("OUT_NOT_CONFIGURED: configure the http proxy before selecting it")
		}
	default:
		return errors.New("OUT_ROLE_INVALID: only out and http nodes can be selected as an egress")
	}
	return nil
}

// validateRuleRevisionTx checks that a selected rule revision exists. The row
// is immutable, so a pinned revision never changes under a subscription.
func validateRuleRevisionTx(tx *sql.Tx, revision RuleRevision) error {
	var count int
	if err := tx.QueryRow(`SELECT count(*) FROM policy_rules WHERE stable_key=? AND version=?`,
		revision.StableKey, revision.Version).Scan(&count); err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	if count == 0 {
		return errors.New("RULE_NOT_FOUND: the selected rule revision does not exist")
	}
	return nil
}

// validateSelectionDeviceTx checks that a selected device is a live mesh
// device. A revoked device is history and cannot be newly selected.
func validateSelectionDeviceTx(tx *sql.Tx, deviceID string) error {
	var status string
	err := tx.QueryRow(`SELECT status FROM mesh_devices WHERE id=?`, deviceID).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return errors.New("MESH_DEVICE_NOT_FOUND: unknown mesh device")
	}
	if err != nil {
		return errors.New("DATABASE_UNAVAILABLE")
	}
	switch status {
	case "revoked", "revoking", "expired", "failed":
		return errors.New("MESH_DEVICE_STATUS_INVALID: the device is no longer selectable")
	}
	return nil
}

// enforceSameLineOutTx refuses a selection that disagrees with an existing
// subscription on the same Line. The Line publishes one server route, so two
// subscriptions cannot ask for different egresses; the refusal names the
// conflicting subscriptions and the Line.
func enforceSameLineOutTx(tx *sql.Tx, subscriberID string, lineIDs []string, outID string) error {
	for _, nodeID := range lineIDs {
		rows, err := tx.Query(`SELECT DISTINCT s.display_name, COALESCE(o.out_id,'')
		  FROM subscription_lines l
		  JOIN subscribers s ON s.id=l.subscriber_id
		  LEFT JOIN subscription_outs o ON o.subscriber_id=l.subscriber_id
		  WHERE l.node_id=? AND l.subscriber_id<>? ORDER BY s.display_name, s.id`, nodeID, subscriberID)
		if err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		conflicts := []string{}
		for rows.Next() {
			var name, selected string
			if err := rows.Scan(&name, &selected); err != nil {
				rows.Close()
				return errors.New("DATABASE_UNAVAILABLE")
			}
			if selected != outID {
				conflicts = append(conflicts, name)
			}
		}
		if err := rows.Close(); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if err := rows.Err(); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if len(conflicts) > 0 {
			sort.Strings(conflicts)
			return errors.New(CodeOutSelectionConflict + ": line " + nodeID +
				" is already served with another out choice by " + strings.Join(conflicts, "、") +
				"; all subscriptions on one line must select the same out")
		}
	}
	return nil
}

// writeSelectionEdgesTx replaces every edge group of one subscriber. The
// groups are rewritten as a whole so a dropped Line, rule or device cannot
// survive a save.
func writeSelectionEdgesTx(tx *sql.Tx, subscriberID string, lineIDs []string, outID string, rules []RuleRevision, devices []string, now time.Time) error {
	for _, table := range []string{"subscription_lines", "subscription_outs", "subscription_rules", "subscription_networks"} {
		if _, err := tx.Exec(`DELETE FROM `+table+` WHERE subscriber_id=?`, subscriberID); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
	}
	for position, nodeID := range lineIDs {
		var lineRevision int64
		// The candidate revision is informational only: a Line's transport is
		// not versioned by the subscription. A Line with no candidate yet keeps
		// zero, which the snapshot records honestly.
		if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, nodeID).Scan(&lineRevision); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if _, err := tx.Exec(`INSERT INTO subscription_lines(subscriber_id, node_id, position, line_revision, created_at) VALUES(?,?,?,?,?)`,
			subscriberID, nodeID, position, lineRevision, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the line selection was not stored")
		}
	}
	if outID != "" {
		var outRevision int64
		if err := tx.QueryRow(`SELECT COALESCE(MAX(revision),0) FROM node_candidates WHERE node_id=?`, outID).Scan(&outRevision); err != nil {
			return errors.New("DATABASE_UNAVAILABLE")
		}
		if _, err := tx.Exec(`INSERT INTO subscription_outs(subscriber_id, out_id, position, out_revision, created_at) VALUES(?,?,0,?,?)`,
			subscriberID, outID, outRevision, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the out selection was not stored")
		}
	}
	for position, revision := range rules {
		if _, err := tx.Exec(`INSERT INTO subscription_rules(subscriber_id, rule_stable_key, rule_version, position, created_at) VALUES(?,?,?,?,?)`,
			subscriberID, revision.StableKey, revision.Version, position, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the rule selection was not stored")
		}
	}
	for position, deviceID := range devices {
		if _, err := tx.Exec(`INSERT INTO subscription_networks(subscriber_id, device_id, position, created_at) VALUES(?,?,?,?)`,
			subscriberID, deviceID, position, now.Unix()); err != nil {
			return errors.New(CodeSelectionInvalid + ": the network selection was not stored")
		}
	}
	return nil
}

// writeSnapshotTx records the selection identity and the approved artifact
// digest. An empty artifactID stores a saved-but-unapproved selection, which the
// download refuses; a changed selection always replaces the previous digest, so
// a download can never serve bytes composed from an older choice.
func writeSnapshotTx(tx *sql.Tx, selection subscription.Selection, artifactID string, now time.Time) error {
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

// readSelectionTx reads one subscriber's edges back into the snapshot model.
// The version is the stored snapshot version, or zero when the subscriber never
// saved a selection; the save path increments it so every save is a new
// identity.
func readSelectionTx(tx *sql.Tx, subscriberID string) (subscription.Selection, error) {
	selection := subscription.Selection{SubscriberID: subscriberID}
	var stored int64
	err := tx.QueryRow(`SELECT version FROM subscription_snapshots WHERE subscriber_id=?`, subscriberID).Scan(&stored)
	switch {
	case err == nil:
		selection.Version = stored
	case errors.Is(err, sql.ErrNoRows):
	default:
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	rows, err := tx.Query(`SELECT node_id, position, line_revision FROM subscription_lines WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	for rows.Next() {
		var line subscription.SelectionLine
		if err := rows.Scan(&line.NodeID, &line.Position, &line.LineRevision); err != nil {
			rows.Close()
			return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
		}
		selection.Lines = append(selection.Lines, line)
	}
	if err := rows.Close(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := rows.Err(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	var out subscription.SelectionOut
	err = tx.QueryRow(`SELECT out_id, position, out_revision FROM subscription_outs WHERE subscriber_id=?`, subscriberID).
		Scan(&out.OutID, &out.Position, &out.OutRevision)
	switch {
	case err == nil:
		selection.Out = &out
	case errors.Is(err, sql.ErrNoRows):
	default:
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	rows, err = tx.Query(`SELECT rule_stable_key, rule_version, position FROM subscription_rules WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	for rows.Next() {
		var rule subscription.SelectionRule
		if err := rows.Scan(&rule.StableKey, &rule.Version, &rule.Position); err != nil {
			rows.Close()
			return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
		}
		selection.Rules = append(selection.Rules, rule)
	}
	if err := rows.Close(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := rows.Err(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	rows, err = tx.Query(`SELECT device_id, position FROM subscription_networks WHERE subscriber_id=? ORDER BY position ASC`, subscriberID)
	if err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	for rows.Next() {
		var device subscription.SelectionNetwork
		if err := rows.Scan(&device.DeviceID, &device.Position); err != nil {
			rows.Close()
			return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
		}
		selection.Networks = append(selection.Networks, device)
	}
	if err := rows.Close(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if err := rows.Err(); err != nil {
		return subscription.Selection{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return selection, nil
}

// SubscriptionSelection reads the saved selection of one subscriber. The
// boolean is false when the subscriber never saved one, so the wizard can tell
// "no selection yet" from "an empty selection".
func (s *Store) SubscriptionSelection(subscriberID string) (subscription.Selection, bool, error) {
	if err := subscription.ValidateID(subscriberID); err != nil {
		return subscription.Selection{}, false, errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return subscription.Selection{}, false, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	if _, err := getSubscriberTx(tx, subscriberID); err != nil {
		return subscription.Selection{}, false, err
	}
	selection, err := readSelectionTx(tx, subscriberID)
	if err != nil {
		return subscription.Selection{}, false, err
	}
	saved := len(selection.Lines) > 0 || len(selection.Rules) > 0 || len(selection.Networks) > 0 || selection.Out != nil
	return selection, saved, nil
}

// LineUsedBy names the subscriptions that select one Line. It is the used-by
// edge of the reference graph, read by the delete guard and the page.
func (s *Store) LineUsedBy(nodeID string) ([]string, error) {
	return s.selectionUsedBy(`SELECT s.display_name FROM subscription_lines l
	  JOIN subscribers s ON s.id=l.subscriber_id
	  WHERE l.node_id=? ORDER BY s.display_name, s.id`, nodeID)
}

// OutUsedBy names the subscriptions that select one Out.
func (s *Store) OutUsedBy(outID string) ([]string, error) {
	return s.selectionUsedBy(`SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	  WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
}

// outUsedByTx is the transaction-scoped variant of OutUsedBy. The store has one
// connection, so a delete that must check its own references has to use this
// one instead of opening a second query on the pool.
func outUsedByTx(tx *sql.Tx, outID string) ([]string, error) {
	return selectionUsedByTx(tx, `SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	  WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
}

// MeshDeviceUsedBy names the subscriptions that record one mesh device.
func (s *Store) MeshDeviceUsedBy(deviceID string) ([]string, error) {
	return s.selectionUsedBy(`SELECT s.display_name FROM subscription_networks n
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
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}

// selectionUsedBy runs one used-by query. A missing edge table is honest
// emptiness (a database that has not reached schema 13 yet); any other read
// error is DATABASE_UNAVAILABLE, never "nobody references this".
func (s *Store) selectionUsedBy(query, id string) ([]string, error) {
	rows, err := s.DB.Query(query, id)
	if err != nil {
		if strings.Contains(err.Error(), "no such table") {
			return []string{}, nil
		}
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.New("DATABASE_UNAVAILABLE")
		}
		out = append(out, name)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	return out, nil
}
