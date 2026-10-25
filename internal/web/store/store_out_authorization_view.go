package store

// Out authorization projection for the nodes page (Task 5).
//
// After the authorization migration the question "what does this Out do?" has one
// answer per Line, derived from node membership (Ruling R10):
//
//	the Hub has no Out          -> no-out-direct (the Out-free deployment)
//	no Line is a member         -> line-direct (nothing to accept)
//	at least one member Line    -> out-selected, with the derived sources
//
// The projection is read-only and never returns a credential, a link key or a
// subscriber identity: it names counts and stable states only. Under Ruling R10 the
// line set is membership, so the projection answers "which enrolled Lines this Out
// accepts" and reports subscribers separately as the delete guard's used-by names.

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// The Out pool modes the projection reports.
const (
	// OutPoolNoOutDirect: the Hub has no Out node at all, so every Line egresses
	// directly. This is the Out-free deployment, not a degradation.
	OutPoolNoOutDirect = "no-out-direct"
	// OutPoolLineDirect: the Out exists but the projected Line set is empty or narrowed
	// to one Line, so the answer describes no accepted Line.
	OutPoolLineDirect = "line-direct"
	// OutPoolBound: the Out accepts at least one enrolled Line (Ruling R10).
	OutPoolBound = "out-selected"
)

// OutAuthorizationPreview is a read-only projection of the egress a selection
// would produce. It never mutates a subscription, a credential or any Line state.
type OutAuthorizationPreview struct {
	// Mode is one of OutPoolNoOutDirect, OutPoolLineDirect or OutPoolBound.
	Mode string `json:"mode"`
	// OutID is the Out the projection describes, empty for the hub summary.
	OutID string `json:"out_id,omitempty"`
	// LineIDs are the Lines the Out is selected for, in node-id order.
	LineIDs []string `json:"line_ids"`
	// Subscribers are the display names of the subscriptions that select it.
	// Never an identity, a token or a credential.
	Subscribers []string `json:"subscribers"`
	// Sources is the derived allowlist: exactly the set the Agent would be
	// authorized to accept. An empty list is the default-deny answer.
	Sources []string `json:"sources"`
	// AffectedLines counts the Lines whose egress depends on this Out.
	AffectedLines int `json:"affected_lines"`
	// AffectedPolicies counts the active credentials on those Lines. One
	// credential is one published per-subscriber policy.
	AffectedPolicies int `json:"affected_policies"`
	// AffectedSubscribers counts the distinct subscribers behind the policies.
	AffectedSubscribers int `json:"affected_subscribers"`
	// EgressState and EgressCode report whether the Out path of the selected
	// Lines is authorized. A proposal is never healthy: nothing has been
	// published for it yet.
	EgressState string `json:"egress_state"`
	EgressCode  string `json:"egress_code,omitempty"`
	// SyncState and SyncCode are the Out's own authorization state
	// (healthy/pending/verifying/partial), so an operator can tell "authorized"
	// from "authorized and proven".
	SyncState string `json:"sync_state"`
	SyncCode  string `json:"sync_code,omitempty"`
}

// PreviewOutAuthorization projects one Out's subscription-derived authorization.
//
// With no out_id it summarizes the whole hub: whether any subscription selects an
// Out at all, which is the guarantee that an Out-free deployment keeps using the
// direct Line egress. With an out_id it projects that Out, and an optional line_id
// restricts the counts to one Line.
//
// A proposal (an out_id with a line_id the Out is not selected for yet) is reported
// as pending with the publish gate's own code, so the preview and the gate can never
// disagree. It is never reported as an established path.
func (s *Store) PreviewOutAuthorization(outID, lineID string) (OutAuthorizationPreview, error) {
	return s.PreviewOutAuthorizationAt(outID, lineID, time.Now())
}

// PreviewOutAuthorizationAt is the request-clock variant so the egress projection
// and the affected-policy counts share one clock.
func (s *Store) PreviewOutAuthorizationAt(outID, lineID string, now time.Time) (OutAuthorizationPreview, error) {
	outID = strings.TrimSpace(outID)
	lineID = strings.TrimSpace(lineID)
	if outID == "" {
		if lineID != "" {
			return OutAuthorizationPreview{}, errors.New("OUT_BINDING_INVALID: a line projection needs an out_id")
		}
		return s.previewOutPool()
	}
	if !validNodeID(outID) {
		return OutAuthorizationPreview{}, errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
	}
	var role string
	err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutAuthorizationPreview{}, errors.New("OUT_NOT_FOUND: unknown out node")
	}
	if err != nil {
		return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if role != "out" {
		return OutAuthorizationPreview{}, errors.New("OUT_ROLE_INVALID: only out nodes carry a source authorization")
	}
	if lineID != "" {
		if !validNodeID(lineID) {
			return OutAuthorizationPreview{}, errors.New("OUT_BINDING_INVALID: line_id must be 32 lowercase hex characters")
		}
		var lineRole string
		err = s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&lineRole)
		if errors.Is(err, sql.ErrNoRows) {
			return OutAuthorizationPreview{}, errors.New("LINE_NOT_FOUND: unknown line node")
		}
		if err != nil {
			return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
		if lineRole != "edge" {
			return OutAuthorizationPreview{}, errors.New("LINE_ROLE_INVALID: only edge nodes can be selected with an out")
		}
	}

	preview := OutAuthorizationPreview{OutID: outID, LineIDs: []string{}, Subscribers: []string{}, Sources: []string{}}
	// Every read shares one transaction: the store runs on a single connection, so
	// a DB-level query issued while a transaction is open would wait on itself.
	tx, err := s.DB.Begin()
	if err != nil {
		return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	// Under the membership model (Ruling R10) the authorized Lines are the enrolled
	// pool, not a subscription choice: this projection answers "which Lines may this
	// Out accept", which is the same for every Out.
	members, err := OutAuthorizedLineIDsTx(tx, outID)
	if err != nil {
		return OutAuthorizationPreview{}, err
	}
	selected := members
	if lineID != "" {
		selected = keepLine(members, lineID)
		preview.Mode = OutPoolLineDirect
		preview.EgressState = LineEgressPendingPreview
		preview.EgressCode = CodeOutNotAuthorized
	} else if len(members) == 0 {
		preview.Mode = OutPoolLineDirect
	} else {
		preview.Mode = OutPoolBound
	}
	preview.LineIDs = selected

	sources, err := outAuthorizationTx(tx, outID)
	if err != nil {
		// A Line the Hub cannot vouch for is reported, not hidden: the caller
		// sees the same code the publication would fail with.
		preview.EgressState = LineEgressPartial
		preview.EgressCode = SanitizeSubscriberSyncCode(err.Error())
	} else {
		preview.Sources = sources
	}
	state, code, err := outSyncStatusTx(tx, outID, now)
	if err != nil {
		return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	preview.SyncState, preview.SyncCode = state, code
	if lineID == "" {
		switch {
		case len(members) == 0:
			// An Out enrolled on a Hub with no Line has nothing to accept, which is
			// a real state of the pool, not a degraded one.
			preview.EgressState, preview.EgressCode = LineEgressDirect, ""
		case preview.EgressState == LineEgressPartial:
			// Keep the derivation refusal reported above.
		case state == OutSyncHealthy:
			preview.EgressState, preview.EgressCode = LineEgressHealthy, ""
		default:
			preview.EgressState, preview.EgressCode = LineEgressVerifying, firstStableCode(code, CodeOutSyncInProgress)
		}
	}

	// Subscribers are a selection projection for the delete guard, not an
	// authorization input: they name who would have to migrate before this Out
	// disappears.
	subscribers, err := queryIDsTx(tx, `SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	 WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
	if err != nil {
		return OutAuthorizationPreview{}, err
	}
	preview.Subscribers = subscribers
	preview.AffectedLines = len(selected)
	if preview.AffectedLines > 0 {
		if err := tx.QueryRow(`SELECT count(DISTINCT c.id), count(DISTINCT c.subscriber_id)
		  FROM proxy_credentials c
		  JOIN subscribers s ON s.id=c.subscriber_id AND s.state='active'
		 WHERE c.active=1 AND c.node_id IN (SELECT id FROM nodes WHERE role='edge')`).
			Scan(&preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
			return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
		}
	}
	return preview, nil
}

// keepLine narrows a Line list to one entry without inventing an order.
func keepLine(lines []string, lineID string) []string {
	for _, entry := range lines {
		if entry == lineID {
			return []string{entry}
		}
	}
	return []string{}
}

// LineEgressPendingPreview is the projection of a proposed egress: the Hub has
// recorded the intent but has not authorized or confirmed it yet.
const LineEgressPendingPreview = "pending"

// previewOutPool summarizes the hub pool: no Out means the Out-free deployment,
// and otherwise the whole membership is the set every Out accepts.
//
// The counts are the pool's, not a subscription's: under Ruling R10 an Out accepts
// every enrolled Line, so the "affected" numbers describe what the pool covers.
func (s *Store) previewOutPool() (OutAuthorizationPreview, error) {
	preview := OutAuthorizationPreview{
		Mode: OutPoolNoOutDirect, LineIDs: []string{}, Subscribers: []string{}, Sources: []string{},
	}
	var outs int
	if err := s.DB.QueryRow(`SELECT count(*) FROM nodes WHERE role='out'`).Scan(&outs); err != nil {
		return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	if outs == 0 {
		return preview, nil
	}
	preview.Mode = OutPoolBound
	if err := s.DB.QueryRow(`SELECT
	  (SELECT count(*) FROM nodes WHERE role='edge'),
	  (SELECT COUNT(DISTINCT c.id) FROM proxy_credentials c
	     JOIN subscribers sub ON sub.id=c.subscriber_id AND sub.state='active'
	    WHERE c.active=1),
	  (SELECT COUNT(DISTINCT c.subscriber_id) FROM proxy_credentials c
	     JOIN subscribers sub ON sub.id=c.subscriber_id AND sub.state='active'
	    WHERE c.active=1)`).
		Scan(&preview.AffectedLines, &preview.AffectedPolicies, &preview.AffectedSubscribers); err != nil {
		return OutAuthorizationPreview{}, errors.New("DATABASE_UNAVAILABLE")
	}
	return preview, nil
}
