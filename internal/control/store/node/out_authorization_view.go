package node

// Out projection for the nodes page.
//
// Under the client-side chain model the question "what does this Out accept?"
// no longer has a per-Line answer: the Out admits any client that presents the
// link key its own candidate publishes. The projection therefore reports the
// pool's shape and the subscriptions that *select* the Out, never an
// authorization:
//
//	the Hub has no Out          -> no-out-direct (the Out-free deployment)
//	no subscription selects it  -> line-direct (nobody routes through it yet)
//	at least one selects it     -> out-selected, with the selecting Lines
//
// The projection is read-only and never returns a credential, a link key or a
// subscriber identity: it names counts, identifiers and stable states only.

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

// The Out pool modes the projection reports.
const (
	// OutPoolNoOutDirect: the Hub has no Out node at all, so every Line egresses
	// directly. This is the Out-free deployment, not a degradation.
	OutPoolNoOutDirect = "no-out-direct"
	// OutPoolLineDirect: the Out exists but no subscription selects it, so the
	// projection describes no routed Line.
	OutPoolLineDirect = "line-direct"
	// OutPoolBound: at least one subscription selects the Out.
	OutPoolBound = "out-selected"
)

// OutAuthorizationPreview is a read-only projection of the egress a selection
// would produce. It never mutates a subscription, a credential or any Line
// state.
type OutAuthorizationPreview struct {
	// Mode is one of OutPoolNoOutDirect, OutPoolLineDirect or OutPoolBound.
	Mode string `json:"mode"`
	// OutID is the Out the projection describes, empty for the hub summary.
	OutID string `json:"out_id,omitempty"`
	// LineIDs are the Lines whose active subscriptions select the Out, in
	// node-id order.
	LineIDs []string `json:"line_ids"`
	// Subscribers are the display names of the subscriptions that select it.
	// Never an identity, a token or a credential.
	Subscribers []string `json:"subscribers"`
	// Sources is retired with the source allowlist and is always empty: the Out
	// admits by link key, so no address list describes its admission. The field
	// stays in the JSON shape so an older page does not break.
	Sources []string `json:"sources"`
	// AffectedLines counts the Lines whose subscriptions select this Out.
	AffectedLines int `json:"affected_lines"`
	// AffectedPolicies counts the active credentials on those Lines. One
	// credential is one published per-subscriber policy.
	AffectedPolicies int `json:"affected_policies"`
	// AffectedSubscribers counts the distinct subscribers behind the policies.
	AffectedSubscribers int `json:"affected_subscribers"`
	// EgressState and EgressCode report the routing state of the selected
	// Lines' egress slot. A proposal (an Out that nothing selects yet) is
	// reported as pending, never as an established path.
	EgressState string `json:"egress_state"`
	EgressCode  string `json:"egress_code,omitempty"`
	// SyncState and SyncCode are the Out's own chain state
	// (healthy/pending/verifying/partial), so an operator can tell
	// "published" from "published and proven".
	SyncState string `json:"sync_state"`
	SyncCode  string `json:"sync_code,omitempty"`
}

// PreviewOutAuthorization projects one Out's subscription-driven state.
//
// With no out_id it summarizes the whole hub: whether any subscription selects
// an Out at all, which is the guarantee that an Out-free deployment keeps using
// the direct Line egress. With an out_id it projects that Out, and an optional
// line_id restricts the counts to one Line.
func (s *Store) PreviewOutAuthorization(outID, lineID string) (OutAuthorizationPreview, error) {
	return s.PreviewOutAuthorizationAt(outID, lineID, time.Now())
}

// PreviewOutAuthorizationAt is the request-clock variant so the egress
// projection and the affected-policy counts share one clock.
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
		return OutAuthorizationPreview{}, common.ErrOutIDInvalid()
	}
	var role string
	err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return OutAuthorizationPreview{}, common.ErrOutNotFound
	}
	if err != nil {
		return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if role != string(common.NodeRoleOut) && role != string(common.NodeRoleHTTP) {
		return OutAuthorizationPreview{}, common.ErrOutRoleInvalidSource
	}
	if lineID != "" {
		if !validNodeID(lineID) {
			return OutAuthorizationPreview{}, errors.New("OUT_BINDING_INVALID: line_id must be 32 lowercase hex characters")
		}
		var lineRole string
		err = s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, lineID).Scan(&lineRole)
		if errors.Is(err, sql.ErrNoRows) {
			return OutAuthorizationPreview{}, common.ErrLineNotFound
		}
		if err != nil {
			return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
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
		return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	selected, err := queryIDsTx(tx, `SELECT DISTINCT l.node_id
	  FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id AND s.state='active'
	  JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
	 WHERE o.out_id=?
	 ORDER BY l.node_id ASC`, outID)
	if err != nil {
		return OutAuthorizationPreview{}, err
	}
	if lineID != "" {
		selected = keepLine(selected, lineID)
	}
	preview.LineIDs = selected
	if lineID != "" || len(selected) == 0 {
		preview.Mode = OutPoolLineDirect
		preview.EgressState = LineEgressPendingPreview
		preview.EgressCode = CodeOutNotAuthorized
	} else {
		preview.Mode = OutPoolBound
	}

	state, code, err := outSyncStatusTx(tx, outID, now)
	if err != nil {
		return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
	}
	preview.SyncState, preview.SyncCode = state, code
	if lineID == "" {
		switch {
		case len(selected) == 0:
			// An Out no subscription selects yet is a real state of the pool, not
			// a degraded one.
			preview.EgressState, preview.EgressCode = LineEgressDirect, ""
		case state == OutSyncHealthy:
			preview.EgressState, preview.EgressCode = LineEgressHealthy, ""
		default:
			preview.EgressState, preview.EgressCode = LineEgressVerifying, firstStableCode(code, CodeOutSyncInProgress)
		}
	}

	// Subscribers are a selection projection for the delete guard: they name who
	// would have to migrate before this Out disappears.
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
			return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
		}
	}
	return preview, nil
}

// OutAuthorizedSubscribers names the subscriptions that select one Out,
// ordered by display name. The name is kept for the Web delete guard, which
// still has to say who would migrate before the Out disappears; it is a
// selection projection, not an authorization input. It never returns a
// credential or a token.
func (s *Store) OutAuthorizedSubscribers(outID string) ([]string, error) {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return nil, common.ErrOutIDInvalid()
	}
	return s.Subscribers.SelectionUsedByTx(nil, `SELECT s.display_name FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id
	 WHERE o.out_id=? ORDER BY s.display_name, s.id`, outID)
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

// LineEgressPendingPreview is the projection of a proposed egress: the
// subscription records the intent but the Out's own chain is not confirmed yet.
const LineEgressPendingPreview = "pending"

// previewOutPool summarizes the hub pool: no Out means the Out-free deployment,
// and otherwise the pooled Out nodes and the subscriptions that select them.
func (s *Store) previewOutPool() (OutAuthorizationPreview, error) {
	preview := OutAuthorizationPreview{
		Mode: OutPoolNoOutDirect, LineIDs: []string{}, Subscribers: []string{}, Sources: []string{},
	}
	var outs int
	if err := s.DB.QueryRow(`SELECT count(*) FROM nodes WHERE role='out'`).Scan(&outs); err != nil {
		return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
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
		return OutAuthorizationPreview{}, errors.New(common.CodeDatabaseUnavailable)
	}
	return preview, nil
}
