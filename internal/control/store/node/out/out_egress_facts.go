package out

// The egress facts of one Line.
//
// A Line's server-side configuration carries its listener and user set only: the
// egress lives in the client document the subscriber downloads. These facts are
// therefore a routing projection, not a publish gate:
//
//   - no egress selected: the Line's clients egress directly, which is a
//     configured state (the Out-free deployment), not a degradation;
//   - a managed Out selected: available by link-key admission. The Hub publishes
//     the Out's dial body and key in its own candidate; the client presents the
//     key, so there is no per-Line authorization to prove;
//   - an external HTTP proxy selected: available as the operator's declaration,
//     never as a proven egress (Ruling R11);
//   - a selected egress without a dial body: unavailable with a stable code,
//     because the client document could not name an endpoint.
//
// This file only reads.

import (
	"database/sql"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	storeline "github.com/wingsky-1/MeshMux/internal/control/store/node/line"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
)

// OutEgressFacts is the read-only Out half of one egress decision. It carries no
// address, allowlist entry or credential.
type OutEgressFacts struct {
	LineID string `json:"line_id"`
	// OutID is the selected egress, empty when the Line's clients egress
	// directly.
	OutID string `json:"out_id,omitempty"`
	// Configured is true when at least one subscription selects an egress for
	// this Line. A false value means "direct by configuration", never "the Out
	// broke".
	Configured bool `json:"configured"`
	// Available is true when the client document can name a usable endpoint: a
	// managed Out with configured transport (link-key admission), or an external
	// HTTP proxy the operator declared. The external case is a declaration, not
	// a proof; ExternalDeclared and Code distinguish the two.
	Available bool `json:"available"`
	// ExternalDeclared is true only for the external HTTP proxy egress: the Hub
	// has no Agent and no readback for it, so "available" is the operator's own
	// endpoint. Code carries CodeLineEgressExternalDeclared in that state.
	ExternalDeclared bool `json:"external_declared,omitempty"`
	// Code is the stable reason when Configured is true and Available is false:
	// OUT_SYNC_PENDING (the selected egress has no dial body) or the declaration
	// code for an external proxy.
	Code string `json:"code,omitempty"`
}

// OutEgressFactsTx is the transaction-scoped egress projection of one Line. It
// is the single derivation both the read-only projection and the policy layer
// consume, so a projection can never disagree with the client artifact about
// which egress the selection names.
func OutEgressFactsTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	if !storeline.ValidNodeID(lineID) {
		return OutEgressFacts{}, common.ErrLineIDInvalid()
	}
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutEgressFacts{}, common.ErrLineNotFound
	}
	if err != nil {
		return OutEgressFacts{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(coredomain.RoleEdge) {
		return OutEgressFacts{}, errors.New("LINE_ROLE_INVALID: only edge nodes carry an egress")
	}
	facts := OutEgressFacts{LineID: lineID}
	selected, err := storeline.SelectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressFacts{}, err
	}
	if len(selected) == 0 {
		// No egress is the configured direct egress. This is the only path that
		// is allowed to send traffic down the Line without an explicit
		// administrator decision.
		return facts, nil
	}
	facts.Configured = true
	facts.OutID = selected[0]
	egressRole, err := storeline.NodeRoleTx(tx, selected[0])
	if err != nil {
		return OutEgressFacts{}, err
	}
	switch egressRole {
	case string(common.NodeRoleOut):
		// The Out admits by link key; the only thing the client document still
		// needs is a dial body to name.
		if _, configured, err := storeline.OutEgressTx(tx, selected[0]); err != nil {
			return OutEgressFacts{}, err
		} else if configured {
			facts.Available = true
		} else {
			facts.Code = storeline.CodeOutSyncPending
		}
	case string(common.NodeRoleHTTP):
		// The egress is the operator's declared proxy (Ruling R11). There is no
		// Agent and no readback, so the state is the declaration itself.
		facts.Available = true
		facts.ExternalDeclared = true
		facts.Code = storeline.CodeLineEgressExternalDeclared
	default:
		return OutEgressFacts{}, errors.New("OUT_ROLE_INVALID: only out and http nodes can be selected as an egress")
	}
	return facts, nil
}

// ProjectOutEgressFacts projects one Line's egress preconditions at one clock.
//
// The Line must exist with the immutable edge role; a wrong role or an unknown
// id is rejected instead of being reported as "no Out", because silently
// treating an Out node as a Line would hide an operator mistake behind a
// healthy-looking direct egress.
func ProjectOutEgressFacts(db *sql.DB, lineID string, now time.Time) (OutEgressFacts, error) {
	tx, err := db.Begin()
	if err != nil {
		return OutEgressFacts{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	return OutEgressFactsTx(tx, lineID, now)
}
