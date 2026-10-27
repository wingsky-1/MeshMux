package node

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// OutEgressFactsTx is the transaction-scoped Out projection of one Line. It is
// the single derivation both the read-only OutEgressFacts projection and the
// route resolver use, so the publish gate, the composer and an implicit route
// publication can never disagree about whether the Out is usable.
func (s *Store) OutEgressFactsTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	return OutEgressFactsTxTx(tx, lineID, now)
}

// OutEgressFactsTxTx is the handle-free spelling of OutEgressFactsTx: the
// projection reads only tables, so a caller with no assembled handle can use it.
func OutEgressFactsTxTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutEgressFacts{}, common.ErrLineNotFound
	}
	if err != nil {
		return OutEgressFacts{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(coredomain.RoleEdge) {
		return OutEgressFacts{}, errors.New("LINE_ROLE_INVALID: only edge nodes carry an ai egress")
	}
	facts := OutEgressFacts{LineID: lineID}
	selected, err := selectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressFacts{}, err
	}
	if len(selected) == 0 {
		// No egress is the configured direct egress. This is the only path that
		// is allowed to send AI traffic down the Line without an explicit
		// administrator decision.
		return facts, nil
	}
	facts.Configured = true
	facts.OutID = selected[0]
	outs, err := enabledOutIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressFacts{}, err
	}
	if len(outs) == 0 {
		// The slot holds an external HTTP proxy (Ruling R11). It has no ACL,
		// no Agent and no readback, so there is no Hub-side fact to wait for:
		// the policy may keep the out tag, and the availability is the
		// operator's external endpoint.
		facts.Available = true
		return facts, nil
	}
	// An Out that stopped reporting cannot apply or prove the authorization.
	// The synchronization projection alone would call a confirmed chain
	// healthy, so the offline window is checked separately and reported as
	// OUT_OFFLINE instead of a stale healthy.
	for _, outID := range outs {
		offline, err := SubscriberLineNodeOfflineTx(tx, outID, now)
		if err != nil {
			return OutEgressFacts{}, err
		}
		if offline {
			facts.Code = "OUT_OFFLINE"
			return facts, nil
		}
	}
	state, code, err := LineOutEgressStatusTxTx(tx, lineID, now)
	if err != nil {
		return OutEgressFacts{}, err
	}
	switch state {
	case LineEgressHealthy:
		facts.Available = true
		facts.Code = ""
	case LineEgressDirect:
		// The bindings are enabled but the projection reports direct, which
		// cannot happen for a real enabled binding. Fail closed rather than
		// claiming a healthy Ai path the Out never confirmed.
		facts.Code = CodeOutSyncPending
	default:
		facts.Available = false
		facts.Code = firstStableCode(code, CodeOutSyncPending)
	}
	return facts, nil
}
