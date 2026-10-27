package policy

// Active policy intent readers.
//
// A stored revision is the deployment's record of what the operator configured.
// The readers below are the single decoder of that record, so the page and the
// publication cannot disagree about which revision is live. Nothing here
// renders a route: the server publishes proxy ports and credentials only, and
// every routing decision is made by the client from the document it downloads
// (iron rule ① of the client-chain design).

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
)

// ActivePolicyIntentTx is the transaction-scoped reader of one layer's active
// revision. It is the same single reader as ActivePolicyIntent, so a page, a
// publication and a preview can never disagree about which revision is live.
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
