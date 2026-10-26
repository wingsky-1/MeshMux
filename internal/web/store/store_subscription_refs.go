package store

// Reference validation for one draft selection, inside the caller's
// transaction.
//
// Every function here is read-only and reports a stable code:
//
//	validateSelectionOutTx        -> OUT_NOT_FOUND / OUT_NOT_CONFIGURED / OUT_ROLE_INVALID
//	validateRuleRevisionTx        -> RULE_NOT_FOUND
//	validateSelectionDeviceTx     -> MESH_DEVICE_NOT_FOUND / MESH_DEVICE_STATUS_INVALID
//	enforceSameLineOutTx          -> SUBSCRIPTION_OUT_CONFLICT
//
// The same-Line refusal is also offered as plain conflict data
// (lineOutConflictsTx) so the impact preview can report it before anything is
// written, without duplicating the query.

import (
	"database/sql"
	"errors"
	"sort"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/mesh"
)

// validateSelectionOutTx checks that a selected egress is a usable endpoint:
// a managed Out with configured transport, or an external HTTP proxy (Ruling
// R11) with a stored proxy row. The proxy is not an Agent node, so the
// out_settings requirement applies to role "out" only. An egress without a
// dial body would render a route that names an egress nobody can reach.
//
// The switch is the egress-role whitelist: any other node kind is refused
// rather than reinterpreted.
func validateSelectionOutTx(tx *sql.Tx, outID string) error {
	if outID == "" {
		return nil
	}
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return errOutNotFound
	}
	if err != nil {
		return errors.New(CodeDatabaseUnavailable)
	}
	switch role {
	case "out":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM out_settings WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New(CodeDatabaseUnavailable)
		}
		if configured == 0 {
			return errors.New("OUT_NOT_CONFIGURED: configure the out transport before selecting it")
		}
	case "http":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM node_http_proxy WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New(CodeDatabaseUnavailable)
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
		return errors.New(CodeDatabaseUnavailable)
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
		return errors.New(CodeDatabaseUnavailable)
	}
	switch mesh.Status(status) {
	case mesh.StatusRevoked, mesh.StatusRevoking, mesh.StatusExpired, mesh.StatusFailed:
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
		conflicts, err := lineOutConflictsTx(tx, subscriberID, nodeID, outID)
		if err != nil {
			return err
		}
		if len(conflicts) > 0 {
			return errors.New(CodeOutSelectionConflict + ": line " + nodeID +
				" is already served with another out choice by " + strings.Join(conflicts, "、") +
				"; all subscriptions on one line must select the same out")
		}
	}
	return nil
}

// lineOutConflictsTx names the other subscriptions that serve one Line with a
// different Out choice (including "no Out"). The result is sorted and never
// contains the caller's own subscriber.
func lineOutConflictsTx(tx *sql.Tx, subscriberID, lineID, outID string) ([]string, error) {
	rows, err := tx.Query(`SELECT DISTINCT s.display_name
	  FROM subscription_lines l
	  JOIN subscribers s ON s.id=l.subscriber_id
	  LEFT JOIN subscription_outs o ON o.subscriber_id=l.subscriber_id
	  WHERE l.node_id=? AND l.subscriber_id<>? AND COALESCE(o.out_id,'')<>?
	  ORDER BY s.display_name, s.id`, lineID, subscriberID, outID)
	if err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	defer rows.Close()
	conflicts := []string{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		conflicts = append(conflicts, name)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(CodeDatabaseUnavailable)
	}
	sort.Strings(conflicts)
	return conflicts, nil
}

// lineSubscribersTx names the other active subscriptions that reference any of
// the given Lines. It answers "whose Line publication changes" without reading
// a single rendered byte.
func lineSubscribersTx(tx *sql.Tx, subscriberID string, lineIDs []string) ([]string, error) {
	seen := map[string]struct{}{}
	names := []string{}
	for _, lineID := range lineIDs {
		rows, err := tx.Query(`SELECT DISTINCT s.display_name
		  FROM subscription_lines l
		  JOIN subscribers s ON s.id=l.subscriber_id
		  WHERE l.node_id=? AND l.subscriber_id<>? AND s.state='active'
		  ORDER BY s.display_name, s.id`, lineID, subscriberID)
		if err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return nil, errors.New(CodeDatabaseUnavailable)
			}
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
		if err := rows.Close(); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
		if err := rows.Err(); err != nil {
			return nil, errors.New(CodeDatabaseUnavailable)
		}
	}
	sort.Strings(names)
	return names, nil
}
