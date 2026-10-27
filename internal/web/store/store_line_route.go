package store

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
// calls lineServerRouteTx, so a route can never enter a candidate without
// passing policy.ResolveServerPolicy again.
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

	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/policy"
)

// lineServerRouteTx returns the route fragment a Line must publish now, or nil
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
func LineServerRouteTx(tx *sql.Tx, nodeID string, now time.Time) (json.RawMessage, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("NODE_NOT_FOUND: unknown node")
	}
	if err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	if node.Role(role) != node.RoleEdge {
		return nil, nil
	}
	var settings int
	if err := tx.QueryRow(`SELECT count(*) FROM line_settings WHERE node_id=?`, nodeID).Scan(&settings); err != nil {
		return nil, errors.New("DATABASE_UNAVAILABLE")
	}
	if settings == 0 {
		return nil, nil
	}
	record, intent, err := activePolicyIntentTx(tx, PolicyLayerServer)
	if err != nil {
		if isPolicyNotFound(err) {
			// No active server revision: the Hub holds no route intent, so the
			// candidate must not inherit the one an earlier revision carried.
			return nil, nil
		}
		return nil, err
	}
	pins, err := decodePolicyPins(record.Pins)
	if err != nil {
		return nil, err
	}
	facts, err := outEgressFactsTx(tx, nodeID, now)
	if err != nil {
		return nil, err
	}
	// Implicit publications take no Line fallback: they have no operation id,
	// so an unavailable Out must stay a refusal instead of becoming an
	// unaudited direct egress.
	serverIntent := policy.ServerPolicy{
		Default:       intent.Default,
		Rules:         intent.Rules,
		OutConfigured: facts.Configured,
		OutAvailable:  facts.Available,
	}
	resolved, err := policy.ResolveServerPolicy(serverIntent)
	if err != nil {
		return nil, err
	}
	if err := pins.Validate(resolved.Rules); err != nil {
		return nil, err
	}
	fragment, err := policy.RenderServerRoute(resolved, pins)
	if err != nil {
		return nil, err
	}
	return json.RawMessage(fragment), nil
}

// activePolicyIntentTx is the transaction-scoped reader of one layer's active
// revision. It is the same single reader as activePolicyIntent, so a page, a
// publication and an implicit route derivation can never disagree about which
// revision is live.
func activePolicyIntentTx(tx *sql.Tx, layer PolicyLayer) (RoutePolicy, RoutePolicyPayload, error) {
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
		return RoutePolicyPayload{}, errors.New("POLICY_CORRUPT: the active payload is not valid intent JSON")
	}
	return intent, nil
}

// outEgressFactsTx is the transaction-scoped Out projection of one Line. It is
// the single derivation both the read-only OutEgressFacts projection and the
// route resolver use, so the publish gate, the composer and an implicit route
// publication can never disagree about whether the Out is usable.
func outEgressFactsTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutEgressFacts{}, errors.New("LINE_NOT_FOUND: unknown line node")
	}
	if err != nil {
		return OutEgressFacts{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != string(node.RoleEdge) {
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
		// The slot holds an external HTTP proxy (Ruling R11). It has no ACL, no
		// Agent, no readback and no machine controller that could apply or prove
		// one, so there is no Hub-side fact to wait for. The out tag stays
		// available, but only as the operator's declaration: ExternalDeclared is
		// set and Code names the declaration so no caller can read this as a
		// proven managed egress. The egress body is the stored http outbound.
		facts.Available = true
		facts.ExternalDeclared = true
		facts.Code = CodeLineEgressExternalDeclared
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
	state, code, err := LineOutEgressStatusTx(tx, lineID, now)
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
