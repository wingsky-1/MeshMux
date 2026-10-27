package policy

// The server route of one Line, derived from the active policy revision and the
// current Out facts.
//
// A published route is rendered output, not intent. Copying the newest
// candidate's route into a later revision freezes whatever the Out binding and
// the active policy revision happened to be at that moment, so an Out that was
// unbound, deleted or went offline afterwards keeps being named by every
// subscriber change and every upgrade approval, and a revised or revoked server
// policy keeps being enforced from a stale copy.
//
// The single source of truth is the active server policy revision plus the
// Line's current egress facts, exactly the pair the publication path renders.
// Every implicit publisher (subscriber synchronization and upgrade approval)
// calls LineServerRouteTx, so a route can never enter a candidate without
// passing coredomain.ResolveServerPolicy again.
//
// Fail-closed is unchanged and is not relaxed for these implicit publications:
// they carry no operator opt-in and no operation id, so an Out-selecting policy
// whose Out is unbound, deleted or unavailable is refused with the policy
// package's own stable code and the previous revision stays live. A policy
// that does not select the Out renders in any Out state.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"

	"github.com/wingsky-1/MeshMux/internal/core/node"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/policy"
)

// LineServerRouteTx returns the route fragment a Line must publish now, or nil
// when the Hub holds no route intent for it.
//
// The fragment is produced by the same Validate -> ResolveServerPolicy ->
// RenderServerRoute chain as the publication path:
//
//   - only an Edge with stored Line transport carries a route; an Out node and
//     an unconfigured Edge never do;
//   - no active server policy revision means no route intent, so the candidate
//     stays route-free instead of preserving a revoked policy;
//   - an active policy that needs an Out the Line cannot use is a refusal
//     (OUT_BINDING_INVALID / OUT_OFFLINE_FAIL_CLOSED), never a silent direct
//     render and never a stale "out" reference.
func (s *Store) LineServerRouteTx(tx *sql.Tx, nodeID string, now time.Time) (json.RawMessage, error) {
	return LineServerRouteTx(tx, nodeID, now)
}

// LineServerRouteTx is the handle-free spelling of the route derivation. It
// reads the active server revision and the Line's egress facts from the tables
// directly, so a caller with no assembled handle can still derive a route.
func LineServerRouteTx(tx *sql.Tx, nodeID string, now time.Time) (json.RawMessage, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, common.ErrNodeNotFoundDetail
	}
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if node.Role(role) != node.RoleEdge {
		return nil, nil
	}
	var settings int
	if err := tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&settings); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	if settings == 0 {
		return nil, nil
	}
	record, intent, err := ActivePolicyIntentTx(tx, PolicyLayerServer)
	if err != nil {
		if IsNotFound(err) {
			// No active server revision: the Hub holds no route intent, so the
			// candidate must not inherit the one an earlier revision carried.
			return nil, nil
		}
		return nil, err
	}
	pins, err := DecodePins(record.Pins)
	if err != nil {
		return nil, err
	}
	facts, err := storenode.OutEgressFactsTx(tx, nodeID, now)
	if err != nil {
		return nil, err
	}
	// Implicit publications take no Line fallback: they have no operation id,
	// so an unavailable Out must stay a refusal instead of becoming an
	// unaudited direct egress.
	serverIntent := coredomain.ServerPolicy{
		Default:       intent.Default,
		Rules:         intent.Rules,
		OutConfigured: facts.Configured,
		OutAvailable:  facts.Available,
	}
	resolved, err := coredomain.ResolveServerPolicy(serverIntent)
	if err != nil {
		return nil, err
	}
	if err := pins.Validate(resolved.Rules); err != nil {
		return nil, err
	}
	fragment, err := coredomain.RenderServerRoute(resolved, pins)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(fragment), nil
}

// ActivePolicyIntentTx is the transaction-scoped reader of one layer's active
// revision. It is the same single reader as ActivePolicyIntent, so a page, a
// publication and an implicit route derivation can never disagree about which
// revision is live.
func ActivePolicyIntentTx(tx *sql.Tx, layer PolicyLayer) (RoutePolicy, RoutePolicyPayload, error) {
	record, err := scanRoutePolicy(tx.QueryRow(routePolicySelect+` WHERE p.layer=? AND p.status=?`, layer, PolicyActive))
	return activePolicyIntentOf(record, err)
}

// activePolicyIntentOf decodes a stored active revision into its intent payload,
// forwarding a read error unchanged.
func activePolicyIntentOf(record RoutePolicy, err error) (RoutePolicy, RoutePolicyPayload, error) {
	if err != nil {
		return record, RoutePolicyPayload{}, err
	}
	intent, err := decodeActivePolicyIntent(record)
	return record, intent, err
}

// decodeActivePolicyIntent is the one decoder of a stored active payload. It
// is strict: schema 17 rewrote every legacy payload, so an unknown key means
// the row escaped the migration or was written by hand, and silently ignoring
// it would resurrect the retired exceptions/ssids behaviour. Either way the
// answer is POLICY_CORRUPT, never a partial intent.
func decodeActivePolicyIntent(record RoutePolicy) (RoutePolicyPayload, error) {
	var intent RoutePolicyPayload
	decoder := json.NewDecoder(bytes.NewReader(record.Payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&intent); err != nil {
		return RoutePolicyPayload{}, errors.New(codePolicyCorrupt + ": the active payload is not valid intent JSON")
	}
	return intent, nil
}
