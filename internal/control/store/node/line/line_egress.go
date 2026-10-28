package line

// The egress slot of one Line.
//
// A Line's server-side configuration carries its listener and its user set; the
// egress is a routing choice the client document carries. The status of the slot
// is still a Line fact: it is the answer to "what does this Line's selection
// name?", which the Line layer derives and the Out projection reads back.
//
// These helpers are exported because the Out layer is built on this package. A
// second derivation would be a second answer: the Out projection asks exactly
// the same questions about the selected egress and about the dial body the
// client document has to name.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// ValidNodeID accepts exactly the canonical node identity shape that the rest of
// the domain uses (32 lowercase hex characters).
func ValidNodeID(id string) bool {
	return subscription.ValidateID(id) == nil
}

// NodeRoleTx reads one node's immutable role, mapping a missing row to a stable
// refusal.
func NodeRoleTx(tx *sql.Tx, nodeID string) (string, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return "", common.ErrNodeNotFoundDetail
	}
	if err != nil {
		return "", errors.New(common.CodeDatabaseUnavailable)
	}
	return role, nil
}

// OutEgressTx is the single derivation of one Out's dial body for candidate
// rendering: the configured server/port plus the Hub-issued link key. The
// boolean is false when the Out has no transport yet; callers render the frozen
// baseline in that case instead of inventing an endpoint.
//
// The read lives at this layer because the candidate builder needs it and the
// Out lifecycle imports the builder: a read the other way round would invert the
// dependency of the node domain.
func OutEgressTx(tx *sql.Tx, outID string) (coredomain.OutEgress, bool, error) {
	var egress coredomain.OutEgress
	err := tx.QueryRow(`SELECT server, port, link_key FROM out_settings WHERE node_id=?`, outID).
		Scan(&egress.Server, &egress.Port, &egress.Key)
	if errors.Is(err, sql.ErrNoRows) {
		return coredomain.OutEgress{}, false, nil
	}
	if err != nil {
		return coredomain.OutEgress{}, false, errors.New(common.CodeDatabaseUnavailable)
	}
	if err := egress.Validate(); err != nil {
		return coredomain.OutEgress{}, false, errors.New("OUT_TRANSPORT_CORRUPT: the stored out transport is invalid")
	}
	return egress, true, nil
}

// SelectedEgressIDsForLineTx returns every egress the Line's selection names:
// managed Out nodes and external HTTP proxies (Ruling R11). The 1.0 slot holds
// one egress per subscriber, so a caller sees one distinct id per subscription;
// the query does not rely on that to stay correct.
func SelectedEgressIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return QueryIDsTx(tx, `SELECT DISTINCT o.out_id
	  FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id AND s.state='active'
	  JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
	 WHERE l.node_id=?
	 ORDER BY o.out_id ASC`, lineID)
}

// LineOutEgressStatusTx reports the routing state of one Line's egress slot.
//
// It reads the subscription selection only: an Out admits clients by the link
// key its candidate publishes, so there is no per-Line authorization to
// converge and no publication gate to satisfy. A Line that no active
// subscription pairs with an egress egresses directly; an HTTP proxy slot is the
// operator's declaration; a managed Out slot is healthy because the client
// document carries the key that Out accepts.
//
// The clock is accepted for the caller's symmetry; the routing state is derived
// from the persisted selection and needs no time comparison.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	selected, err := SelectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return LineEgressPartial, common.CodeDatabaseUnavailable, err
	}
	if len(selected) == 0 {
		return LineEgressDirect, "", nil
	}
	role, err := NodeRoleTx(tx, selected[0])
	if err != nil {
		return LineEgressPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	switch role {
	case string(common.NodeRoleOut):
		// The Out admits by link key, so the only thing that can still be
		// missing is the dial body the client document has to name.
		if _, configured, err := OutEgressTx(tx, selected[0]); err != nil {
			return LineEgressPartial, common.SanitizeSyncCode(err.Error()), nil
		} else if !configured {
			return LineEgressPartial, CodeOutSyncPending, nil
		}
		return LineEgressHealthy, "", nil
	case string(common.NodeRoleHTTP):
		return LineEgressExternal, CodeLineEgressExternalDeclared, nil
	default:
		return LineEgressPartial, "OUT_ROLE_INVALID", nil
	}
}
