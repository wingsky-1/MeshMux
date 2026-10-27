package subscription

// Reference validation for one draft selection, inside the caller's
// transaction.
//
// Every function here is read-only and reports a stable code:
//
//	validateSelectionOutTx        -> OUT_NOT_FOUND / OUT_NOT_CONFIGURED / OUT_ROLE_INVALID
//	validateRuleRevisionTx        -> RULE_NOT_FOUND
//	validateSelectionDeviceTx     -> MESH_DEVICE_NOT_FOUND / MESH_DEVICE_STATUS_INVALID
//
// There is no same-Line Out agreement here: the client chains itself to the
// Out its own subscription names, so two subscriptions on one Line may choose
// different egresses without disagreeing about any server-side route.

import (
	"database/sql"
	"errors"
	"sort"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
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
		return common.ErrOutNotFound
	}
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	switch role {
	case "out":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM out_settings WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New(common.CodeDatabaseUnavailable)
		}
		if configured == 0 {
			return errors.New("OUT_NOT_CONFIGURED: configure the out transport before selecting it")
		}
	case "http":
		var configured int
		if err := tx.QueryRow(`SELECT count(*) FROM node_http_proxy WHERE node_id=?`, outID).Scan(&configured); err != nil {
			return errors.New(common.CodeDatabaseUnavailable)
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
		return errors.New(common.CodeDatabaseUnavailable)
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
		return errors.New(common.CodeDatabaseUnavailable)
	}
	switch mesh.Status(status) {
	case mesh.StatusRevoked, mesh.StatusRevoking, mesh.StatusExpired, mesh.StatusFailed:
		return errors.New("MESH_DEVICE_STATUS_INVALID: the device is no longer selectable")
	}
	return nil
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
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return nil, errors.New(common.CodeDatabaseUnavailable)
			}
			if _, duplicate := seen[name]; duplicate {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
		if err := rows.Close(); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		if err := rows.Err(); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
	}
	sort.Strings(names)
	return names, nil
}
