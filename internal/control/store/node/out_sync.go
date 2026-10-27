package node

// Out synchronization after the client-side chain rebuild.
//
// The Out is an ordinary Shadowsocks endpoint now. Its guard listener accepts
// any client that presents the Hub-issued link key, so the credential *is* the
// admission: there is no source allowlist to derive, publish, read back or
// gate. The `inet meshmux_out` nft table is retired as a write target (its
// definition stays in the Agent renderer so an existing host keeps a valid
// file), no Hub task carries `allowed_sources` any more, and no Hub code
// compares one.
//
// What is left is what the Hub can still prove about an Out:
//
//   - its own immutable candidate chain (dial body + link key) is published and
//     read back by its Agent;
//   - an Out lifecycle event republishes that chain when its content changed,
//     and never automatically repeats an unchanged unconfirmed snapshot;
//   - a Line's egress is a routing choice the *client* document carries, so a
//     Line publication never waits for an Out state and an Out never waits for
//     a subscription.
//
// Evidence levels stay narrow: "the Hub published this Out revision" is the
// immutable candidate plus the task envelope; "the Agent applied it" is a
// healthy readback of that revision with the same compiled digest. Nothing here
// claims an Out is reachable from the internet, and nothing claims a client
// chose the Out — the download is where that choice is made.

import (
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	candidatepkg "github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The Out states the Hub can prove about its own chain.
const (
	// OutSyncHealthy: the published chain is the desired one and the Agent
	// readback confirmed it for the current revision.
	OutSyncHealthy = "healthy"
	// OutSyncVerifying: a chain is in flight.
	OutSyncVerifying = "verifying"
	// OutSyncPending: the desired chain has not been published yet.
	OutSyncPending = "pending"
	// OutSyncPartial: the last chain ended in a terminal failure, or the Hub
	// cannot build the Out's candidate at all.
	OutSyncPartial = "partial"
)

// The Line egress states derived from the subscription selection.
const (
	// LineEgressDirect: no active subscription selects an egress for this Line,
	// so its clients egress directly. This is a routing state, not a defect.
	LineEgressDirect = "direct"
	// LineEgressExternal: the Line's egress slot holds an external HTTP proxy.
	// The proxy is not a managed host: there is no Agent, no readback and no
	// machine controller, so this state is the operator's declaration, never a
	// proven egress. It always carries CodeLineEgressExternalDeclared, so a
	// projection or a log line can tell the declaration apart from a managed
	// Out.
	LineEgressExternal = "external"
	// LineEgressHealthy: the Line's selection names a managed Out. The Out
	// admits clients by the link key its own candidate publishes, so the Hub has
	// no per-Line authorization left to prove; the Line's inbound snapshot is
	// reported separately by the convergence view.
	LineEgressHealthy = "healthy"
	// LineEgressVerifying: reserved for a projection that still waits on an Out
	// chain. The current Line derivation never produces it; the constant stays
	// because the Web projection and the sync vocabulary name it.
	LineEgressVerifying = "verifying"
	// LineEgressPartial: the selection names an egress the Hub cannot resolve.
	LineEgressPartial = "partial"
)

// OutAclSourceMismatchCode is the Agent readback code of the retired source
// allowlist. It stays declared because an older Agent may still report it; the
// Hub no longer publishes an allowlist and no longer interprets the code.
const OutAclSourceMismatchCode = "OUT_ACL_SOURCE_MISMATCH"

// The stable codes the Hub itself reports for a Line egress.
const (
	// CodeLineEgressUnverified is retired with the source allowlist: the Hub no
	// longer needs a verifiable source address, because the Out admits by key.
	// It stays declared so a stored diagnosis row and the frozen error-code
	// vocabulary keep resolving.
	CodeLineEgressUnverified = "LINE_EGRESS_UNVERIFIED"
	// CodeLineNotAuthorized is retired with the source allowlist.
	CodeLineNotAuthorized = "LINE_NOT_AUTHORIZED"
	// CodeOutSyncInProgress and CodeOutSyncPending are the transition codes.
	CodeOutSyncInProgress = "OUT_SYNC_IN_PROGRESS"
	CodeOutSyncPending    = "OUT_SYNC_PENDING"
	// CodeOutNotAuthorized marks a projected egress that is not established
	// yet. It is a projection-only code: nothing gates a Line publication on it
	// any more.
	CodeOutNotAuthorized = "OUT_NOT_AUTHORIZED"
	// CodeLineEgressExternalDeclared marks the LineEgressExternal state: the
	// egress is an external HTTP proxy the operator declared, and the Hub
	// deliberately holds no proof of it (no readback, no controller). The code
	// is informational and never blocks a publication; it exists so a readback,
	// a log line and the UI can say "declared" instead of "healthy".
	CodeLineEgressExternalDeclared = "LINE_EGRESS_EXTERNAL_DECLARED"
	// CodeOutSyncNotApplicable marks an operation that has no meaning for an
	// external HTTP proxy: there is no Agent, no candidate and no readback to
	// publish or retry. The action reports it explicitly instead of a silent
	// success, so an operator never believes a chain was sent.
	CodeOutSyncNotApplicable = "OUT_SYNC_NOT_APPLICABLE"
)

// outDrainOutcome classifies what one Out drain attempt did. It lets the caller
// tell "nothing to publish" apart from "publish is blocked", which the operator
// has to see.
type outDrainOutcome int

const (
	// outDrainNoop: the published chain already equals the desired one and is
	// confirmed, or an unchanged unconfirmed snapshot waits for an explicit
	// retry.
	outDrainNoop outDrainOutcome = iota
	// outDrainPublished: a new immutable revision and its fixed chain were
	// enqueued in the caller's transaction.
	outDrainPublished
	// outDrainDeferred: a publish is required but cannot happen yet (a chain is
	// in flight, or the Out is offline). The change stays pending.
	outDrainDeferred
	// outDrainNotApplicable: the egress is an external HTTP proxy (Ruling R11).
	// It has no Agent, no candidate and no readback, so there is no out-side
	// chain to publish at all. The caller reports this explicitly instead of a
	// silent no-op.
	outDrainNotApplicable
)

// OutEgressReadback is the Hub-side readback of one Line that names an egress.
// It never mutates state and never returns a secret.
type OutEgressReadback struct {
	LineID string `json:"line_id"`
	OutID  string `json:"out_id"`
	// Allowlist is the routing state of the Line's egress slot: direct, external
	// (the operator's declared HTTP proxy) or healthy (a managed Out, which
	// admits by link key). The field and its JSON key keep their historical
	// names because a stored diagnosis log and the Web projection read them; the
	// source allowlist they used to carry is retired.
	Allowlist string `json:"allowlist"`
	// AllowlistCode is the stable reason when Allowlist is not a plain healthy
	// Out.
	AllowlistCode string `json:"allowlist_code,omitempty"`
	// Inbound is the Line inbound readback: the Line proved the exact desired
	// snapshot, which includes its listener and user set.
	Inbound string `json:"inbound"`
	// InboundCode is the stable reason when Inbound is not healthy.
	InboundCode string `json:"inbound_code,omitempty"`
	// Reality is true only when the confirmed Line candidate carries the
	// REALITY transport block that its stored Line settings describe.
	Reality bool `json:"reality"`
	// FinalEgress is healthy only when the egress state and the inbound are
	// both usable. An external HTTP proxy is never reported as healthy: it is
	// the operator's declaration, so the pair reports the declaration.
	FinalEgress string `json:"final_egress"`
	// FinalEgressCode is the stable reason when FinalEgress is not healthy.
	FinalEgressCode string `json:"final_egress_code,omitempty"`
	// ConfirmedRevision and ConfirmedDigest are the Hub-side rollback pointer:
	// the newest revision whose chain the node fully confirmed for the Line.
	// Zero means nothing was ever confirmed, so a rollback has no target yet.
	ConfirmedRevision int64  `json:"confirmed_revision"`
	ConfirmedDigest   string `json:"confirmed_digest,omitempty"`
	// RetryPending is the retry pointer: true only when the pair is in a
	// terminal failure that an explicit retry can resolve. The retry affordance
	// is the existing node retry route (POST /nodes/{nodeID}/retry).
	//
	// A transition in progress (verifying) is deliberately NOT retry-pending:
	// a chain is still applying, and republishing on top of it would race two
	// apply steps on one host. An automatic poll never retries either; only the
	// explicit action does.
	RetryPending bool `json:"retry_pending"`
}

// validNodeID accepts exactly the canonical node identity shape that the rest of
// the domain uses (32 lowercase hex characters).
func validNodeID(id string) bool {
	return subscription.ValidateID(id) == nil
}

// selectedEgressIDsForLineTx returns every egress the Line's selection names:
// managed Out nodes and external HTTP proxies (Ruling R11). The 1.0 slot holds
// one egress per subscriber, so a caller sees one distinct id per subscription;
// the query does not rely on that to stay correct.
func selectedEgressIDsForLineTx(tx *sql.Tx, lineID string) ([]string, error) {
	return queryIDsTx(tx, `SELECT DISTINCT o.out_id
	  FROM subscription_outs o
	  JOIN subscribers s ON s.id=o.subscriber_id AND s.state='active'
	  JOIN subscription_lines l ON l.subscriber_id=o.subscriber_id
	 WHERE l.node_id=?
	 ORDER BY o.out_id ASC`, lineID)
}

// nodeRoleTx reads one node's immutable role, mapping a missing row to a stable
// refusal.
func nodeRoleTx(tx *sql.Tx, nodeID string) (string, error) {
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

// LineOutEgressStatusTx reports the routing state of one Line's egress slot.
//
// It reads the subscription selection only: an Out admits clients by the link
// key its candidate publishes, so there is no per-Line authorization to
// converge and no publication gate to satisfy. A Line that no active
// subscription pairs with an egress egresses directly; an HTTP proxy slot is the
// operator's declaration; a managed Out slot is healthy because the client
// document carries the key that Out accepts.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	selected, err := selectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return LineEgressPartial, common.CodeDatabaseUnavailable, err
	}
	if len(selected) == 0 {
		return LineEgressDirect, "", nil
	}
	role, err := nodeRoleTx(tx, selected[0])
	if err != nil {
		return LineEgressPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	switch role {
	case string(common.NodeRoleOut):
		// The Out admits by link key, so the only thing that can still be
		// missing is the dial body the client document has to name.
		if _, configured, err := outEgressTx(tx, selected[0]); err != nil {
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

// outEgressReadbackTx is the Hub-side readback of one Line.
//
// Each fact is derived independently and reported with its own stable code, so a
// partially converged Line can never be summarized as healthy: the egress
// routing state, the Line inbound snapshot, the REALITY block of that snapshot,
// and the resulting final egress.
func (s *Store) outEgressReadbackTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressReadback, error) {
	readback := OutEgressReadback{LineID: lineID}
	selected, err := selectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressReadback{}, err
	}
	if len(selected) > 0 {
		readback.OutID = selected[0]
	}
	state, code, err := LineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		return OutEgressReadback{}, err
	}
	readback.Allowlist, readback.AllowlistCode = state, code
	// The Line side facts come from the Line's own confirmed snapshot, which is
	// what proves its inbound listener, user set and REALITY transport.
	inbound, inboundCode, inboundErr := s.Subscribers.LineSyncViewTx(tx, lineID, now)
	if inboundErr != nil {
		return OutEgressReadback{}, errors.New(common.CodeDatabaseUnavailable)
	}
	readback.Inbound, readback.InboundCode = inbound, inboundCode
	// REALITY is reported as its own fact because an operator must be able to
	// see it, and it is derived independently from the confirmed Line
	// candidate. For a configured Line a healthy inbound already implies it: the
	// desired digest is built from the stored transport, so the only snapshot
	// that can confirm carries the REALITY block. The extra conjunction below is
	// therefore a redundancy guard against a future change to the inbound
	// projection, not a currently reachable distinction; it never lets the pair
	// be reported healthy while the fact is false.
	readback.Reality = lineRealityConfirmedTx(tx, lineID)
	readback.ConfirmedRevision, readback.ConfirmedDigest = confirmedLineRevisionTx(tx, lineID)
	switch {
	case readback.Allowlist == LineEgressDirect:
		readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
	case readback.Allowlist == LineEgressExternal:
		// The egress is the operator's external HTTP proxy (Ruling R11): no
		// readback and no controller can prove it. A converged Line proves only
		// its own inbound half, so the pair is reported as the declaration it is
		// instead of a healthy egress the Hub never demonstrated.
		if inbound == common.SubscriberSyncHealthy && readback.Reality {
			readback.FinalEgress, readback.FinalEgressCode = LineEgressExternal, CodeLineEgressExternalDeclared
		} else {
			readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
		}
	case readback.Allowlist == LineEgressHealthy && inbound == common.SubscriberSyncHealthy && readback.Reality:
		readback.FinalEgress = LineEgressHealthy
	case readback.Allowlist == LineEgressHealthy && inbound == common.SubscriberSyncHealthy:
		readback.FinalEgress = LineEgressPartial
		readback.FinalEgressCode = "OUT_EGRESS_REALITY_UNVERIFIED"
	case readback.Allowlist == LineEgressVerifying || inbound == common.SubscriberSyncPending:
		readback.FinalEgress = LineEgressVerifying
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, CodeOutSyncInProgress)
	default:
		readback.FinalEgress = LineEgressPartial
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, "OUT_SYNC_FAILED")
	}
	// The retry pointer is derived from the same evidence as the state above:
	// only a terminal failure is retryable. A transition is still applying its
	// own chain.
	readback.RetryPending = readback.FinalEgress == LineEgressPartial
	return readback, nil
}

// confirmedLineRevisionTx returns the newest Line revision the node confirmed
// together with its compiled digest. It is the rollback pointer of the pair: the
// host keeps this revision's files as its last-known-good state, so any later
// failed chain can be rolled back to it.
func confirmedLineRevisionTx(tx *sql.Tx, lineID string) (int64, string) {
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, lineID)
	if err != nil || !found {
		return 0, ""
	}
	confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return 0, ""
	}
	return revision, digest
}

// lineRealityConfirmedTx reports whether the latest confirmed Line candidate
// still carries the REALITY block its stored transport describes. A Line without
// that block could not serve the client configuration the Hub publishes, so the
// final egress is never claimed healthy on the routing state alone.
func lineRealityConfirmedTx(tx *sql.Tx, lineID string) bool {
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, lineID)
	if err != nil || !found {
		return false
	}
	confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, lineID, revision, digest)
	if err != nil || !confirmed {
		return false
	}
	var candidateJSON string
	if err := tx.QueryRow(`SELECT candidate_json FROM node_candidates WHERE node_id=? AND revision=?`, lineID, revision).
		Scan(&candidateJSON); err != nil {
		return false
	}
	var document coredomain.CandidateDocument
	if json.Unmarshal([]byte(candidateJSON), &document) != nil {
		return false
	}
	return document.Reality != nil && document.Role == coredomain.RoleEdge
}

// firstStableCode returns the first non-empty value so a transition code is never
// replaced by an empty one.
func firstStableCode(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

// drainOutNodeIntentTx reconciles one Out with its own desired candidate.
//
// The rules mirror the subscriber drain and keep the operation bounded:
//   - an unfinished chain is never replaced or cancelled;
//   - an identical, confirmed snapshot needs no publication;
//   - an identical but unconfirmed snapshot is republished only by an explicit
//     retry;
//   - a changed snapshot is new intent and is published;
//   - an offline Out keeps the durable intent but receives no state-changing
//     task.
func (s *Store) DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	return DrainOutNodeIntentTx(tx, outID, now, allowRetry)
}

// DrainOutNodeIntentTx is the handle-free spelling of the Out drain.
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return outDrainNoop, nil
	}
	if err != nil {
		return outDrainNoop, errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(common.NodeRoleHTTP) {
		// An external HTTP proxy has no Agent and no candidate: there is nothing
		// an Out drain could publish, so this is "not applicable" rather than a
		// silent no-op.
		return outDrainNotApplicable, nil
	}
	if role != string(common.NodeRoleOut) {
		return outDrainNoop, nil
	}
	latestRevision, latestDigest, _, hasCandidate, err := candidatepkg.LatestPublishedTx(tx, outID)
	if err != nil {
		return outDrainNoop, err
	}
	if hasCandidate {
		desiredDigest, err := outCandidateAtRevisionTx(tx, outID, latestRevision)
		if err != nil {
			return outDrainNoop, err
		}
		confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, outID, latestRevision, latestDigest)
		if err != nil {
			return outDrainNoop, err
		}
		unfinished, err := candidatepkg.LineUnfinishedTasksTx(tx, outID)
		if err != nil {
			return outDrainNoop, err
		}
		if unfinished != 0 {
			// A chain always finishes first. Publishing a competing chain would
			// leave two apply steps racing on one host.
			return outDrainDeferred, nil
		}
		sameCandidate := latestDigest == desiredDigest
		if sameCandidate && confirmed {
			return outDrainNoop, nil
		}
		if sameCandidate && !allowRetry {
			// The snapshot did not change: an automatic poll never retries it,
			// whether the last chain failed or ended without matching evidence.
			return outDrainNoop, nil
		}
	}
	offline, err := SubscriberLineNodeOfflineTx(tx, outID, now)
	if err != nil {
		return outDrainNoop, err
	}
	if offline {
		return outDrainDeferred, errors.New("OUT_OFFLINE: out is offline; the publication stays pending")
	}
	revision, err := candidatepkg.NextCandidateRevisionTx(tx, outID)
	if err != nil {
		return outDrainNoop, err
	}
	candidate, err := BuildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return outDrainNoop, err
	}
	if _, err := candidatepkg.PublishTx(tx, outID, candidate, now); err != nil {
		return outDrainNoop, err
	}
	return outDrainPublished, nil
}

// publishPairingOutCandidateTx publishes the Out's current desired candidate
// when it differs from the newest stored revision.
//
// A Web-first Out is created before its dial address exists, so revision 1 is
// the transport-free baseline. SetOutTransport cannot publish while the node is
// still pending: the offline guard keeps state-changing tasks off a host that
// has not enrolled. Pairing is therefore the first moment the link-key document
// can be committed, and doing it before SeedInitialTasksTx makes that revision
// the one a fresh install fetches and applies. Without it the node boots the
// baseline guard, which carries no authorization at all.
func publishPairingOutCandidateTx(tx *sql.Tx, nodeID, role string, now time.Time) error {
	if role != string(common.NodeRoleOut) {
		return nil
	}
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, nodeID)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	desired, err := BuildLineCandidateTx(tx, nodeID, revision)
	if err != nil {
		return err
	}
	desiredDigest, err := candidatepkg.CompiledHash(desired)
	if err != nil {
		return err
	}
	if desiredDigest == digest {
		return nil
	}
	next, err := candidatepkg.NextCandidateRevisionTx(tx, nodeID)
	if err != nil {
		return err
	}
	desired, err = BuildLineCandidateTx(tx, nodeID, next)
	if err != nil {
		return err
	}
	_, err = candidatepkg.PublishTx(tx, nodeID, desired, now)
	return err
}

// outCandidateAtRevisionTx is the compiled digest the Hub expects for one Out
// revision. An Out carries no users and no REALITY block, but it may carry the
// link key (v4) for its SS guard; its baseline tag is revision-scoped, so the
// digest is built at the exact revision under test instead of being treated as
// revision independent.
func outCandidateAtRevisionTx(tx *sql.Tx, outID string, revision int64) (string, error) {
	candidate, err := BuildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return "", err
	}
	if candidate.Role != coredomain.RoleOut || candidate.Reality != nil || len(candidate.Users) != 0 {
		return "", errors.New("OUT_CANDIDATE_INVALID: an out candidate must be the baseline or the link-key document")
	}
	return candidatepkg.CompiledHash(candidate)
}

// outSyncStatusTx projects one Out's own chain against the persisted intent.
//
// There is no authorization left to compare: the projection asks only whether
// the newest published revision is the candidate the Hub would build now and
// whether the Agent confirmed that exact revision.
func outSyncStatusTx(tx *sql.Tx, outID string, now time.Time) (string, string, error) {
	revision, digest, _, found, err := candidatepkg.LatestPublishedTx(tx, outID)
	if err != nil {
		return OutSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if !found {
		return OutSyncPending, CodeOutSyncPending, nil
	}
	desiredDigest, err := outCandidateAtRevisionTx(tx, outID, revision)
	if err != nil {
		return OutSyncPartial, common.SanitizeSyncCode(err.Error()), nil
	}
	unfinished, err := candidatepkg.LineUnfinishedTasksTx(tx, outID)
	if err != nil {
		return OutSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if digest != desiredDigest {
		if unfinished != 0 {
			return OutSyncVerifying, CodeOutSyncInProgress, nil
		}
		return OutSyncPending, CodeOutSyncPending, nil
	}
	confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, outID, revision, digest)
	if err != nil {
		return OutSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if confirmed && unfinished == 0 {
		return OutSyncHealthy, "", nil
	}
	if unfinished != 0 {
		return OutSyncVerifying, CodeOutSyncInProgress, nil
	}
	_, code, failed, err := candidatepkg.LineLatestTaskTx(tx, outID)
	if err != nil {
		return OutSyncPartial, common.CodeDatabaseUnavailable, err
	}
	if failed {
		return OutSyncPartial, code, nil
	}
	return OutSyncPending, CodeOutSyncPending, nil
}

// scanIDRows drains one single-column identifier result set, closing it before the
// caller opens another statement or transaction on the single-connection pool.
// Every failure maps to the same stable code so callers never leak driver detail.
func scanIDRows(rows *sql.Rows) ([]string, error) {
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, errors.New(common.CodeDatabaseUnavailable)
		}
		out = append(out, id)
	}
	if err := rows.Err(); err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return out, nil
}

// queryIDsTx runs one bounded identifier query inside the caller's transaction.
func queryIDsTx(tx *sql.Tx, query string, args ...any) ([]string, error) {
	rows, err := tx.Query(query, args...)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// retryOutSync is the explicit retry and rollback pointer of one Out. It
// republishes a chain even when the desired candidate did not change, which is
// exactly what an operator needs after a partial/failed chain. Automatic polls
// never call it.
//
// An external HTTP proxy has no chain to retry (Ruling R11), so the call answers
// CodeOutSyncNotApplicable explicitly: a success here would otherwise read as
// "the chain was published and confirmed", which the Hub never did.
func (s *Store) RetryOutSync(outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !validNodeID(outID) {
		return common.ErrOutIDInvalid()
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	outcome, err := s.DrainOutNodeIntentTx(tx, outID, now, true)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	switch outcome {
	case outDrainNotApplicable:
		return errors.New(CodeOutSyncNotApplicable + ": an external http proxy has no agent chain or readback to retry")
	case outDrainDeferred:
		return errors.New(CodeOutSyncPending + ": the out publication is queued behind an in-flight or offline out")
	}
	return nil
}

// drainOutNode begins its own transaction and reconciles one Out. Failures must
// not fail the request they serve: the next poll, heartbeat or result retries.
func (s *Store) drainOutNode(outID string, now time.Time) {
	tx, err := s.DB.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := s.DrainOutNodeIntentTx(tx, outID, now, false); err != nil {
		return
	}
	_ = tx.Commit()
}

// outIDsForLine reads the Out pool in its own statement so no transaction is held
// open while the per-Out drain begins its own.
func (s *Store) outIDsForLine(lineID string) ([]string, error) {
	return storeIDs(s.DB, `SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
}

// storeIDs runs one bounded identifier query and closes its rows before the
// caller opens another transaction on the single-connection pool.
func storeIDs(db *sql.DB, query string, args ...any) ([]string, error) {
	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, errors.New(common.CodeDatabaseUnavailable)
	}
	return scanIDRows(rows)
}

// DrainOutsForLine is retained as the "Line event" half of the coordination.
//
// A Line event no longer authorizes anything: the Out admits by link key, and a
// Line candidate carries neither an Out endpoint nor a route. The function stays
// because the Agent endpoints call it on every Line event, and each Out drain is
// a bounded no-op unless that Out's own candidate changed.
func (s *Store) DrainOutsForLine(lineID string, now time.Time) {
	outs, err := s.outIDsForLine(lineID)
	if err != nil {
		return
	}
	for _, outID := range outs {
		s.drainOutNode(outID, now)
	}
}

// drainNodeCoordination runs the pre-delivery reconciliation of one node.
//
// An Out event republishes the Out's own chain; a Line event republishes the
// Line. The two directions are independent now, so neither waits for the other.
// Each step owns its own transaction, so nothing nests on the single-connection
// pool. A failure in one direction never fails the request: the next event
// retries it.
func (s *Store) drainNodeCoordination(nodeID string, now time.Time) {
	var role string
	err := s.DB.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if err != nil {
		s.Subscribers.DrainNode(nodeID, now)
		return
	}
	if role == string(common.NodeRoleOut) {
		s.drainOutNode(nodeID, now)
		return
	}
	s.DrainOutsForLine(nodeID, now)
	s.Subscribers.DrainNode(nodeID, now)
}

// RepublishOutAuthorizations reconciles the whole Out pool with its own desired
// candidate.
//
// It is a *node lifecycle* primitive: an Out enrolling, being reconfigured or
// losing its identity republishes its own chain when the content changed. A
// subscription edit deliberately does NOT call it — a subscription selects the
// client's egress, it does not change what any Out publishes.
//
// Each drain is a no-op unless that Out's candidate actually changed, so the
// call is safe to make after any lifecycle event. It runs after the caller's
// transaction committed and never fails it: the durable node state is the
// intent, so a deferred or failed publication is completed by the next Out
// event.
//
// The name is kept: it is the stable lifecycle hook every caller already uses,
// even though the "authorization" it republishes is now just the Out's own
// link-key chain.
func (s *Store) RepublishOutAuthorizations(now time.Time) {
	outIDs, err := storeIDs(s.DB, `SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
	if err != nil {
		return
	}
	for _, outID := range outIDs {
		s.drainOutNode(outID, now)
	}
}

// RepublishLineAuthorizations re-derives and republishes every Line after a node
// lifecycle change (Ruling R9 delete): a deleted Out must not leave a stale
// endpoint in a Line candidate, so each Line is drained through the ordinary
// publication chain, where the policy resolver refuses a reference the Hub
// cannot justify (OUT_BINDING_INVALID). A Line with no such reference publishes
// normally.
//
// Each drain owns its own transaction and never fails the caller: the delete is
// already durable, and the refusal is visible in the Line's own sync state.
func (s *Store) RepublishLineAuthorizations(now time.Time) {
	lineIDs, err := storeIDs(s.DB, `SELECT id FROM nodes WHERE role='edge' ORDER BY id ASC`)
	if err != nil {
		return
	}
	for _, lineID := range lineIDs {
		s.Subscribers.DrainNode(lineID, now)
	}
}

// nodeCoordinationReadback reports the readback state of one node for the audit
// log: a Line reports its egress state, an Out reports its own chain. It is a
// read-only projection and never mutates or publishes; the returned codes are
// stable identifiers only.
//
// An Out reports the same retry semantics as a Line: only a terminal failure is
// retry-pending. A transition is still applying its own chain, and a healthy
// chain has nothing left to retry.
func (s *Store) NodeCoordinationReadback(nodeID string, now time.Time) (OutEgressReadback, error) {
	tx, err := s.DB.Begin()
	if err != nil {
		return OutEgressReadback{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role); err != nil {
		return OutEgressReadback{}, errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(common.NodeRoleOut) {
		state, code, err := outSyncStatusTx(tx, nodeID, now)
		if err != nil {
			return OutEgressReadback{}, errors.New(common.CodeDatabaseUnavailable)
		}
		return OutEgressReadback{
			OutID:         nodeID,
			Allowlist:     state,
			AllowlistCode: code,
			FinalEgress:   state,
			RetryPending:  state == OutSyncPartial,
		}, nil
	}
	if role == string(common.NodeRoleHTTP) {
		// An external HTTP proxy has no Agent and no readback at all (Ruling
		// R11). Reporting it through the Line projection would answer
		// LINE_ROLE_INVALID, which a diagnosis log would misread as a fault; the
		// honest answer is the declaration itself.
		return OutEgressReadback{
			OutID:           nodeID,
			Allowlist:       LineEgressExternal,
			AllowlistCode:   CodeLineEgressExternalDeclared,
			FinalEgress:     LineEgressExternal,
			FinalEgressCode: CodeLineEgressExternalDeclared,
			RetryPending:    false,
		}, nil
	}
	return s.outEgressReadbackTx(tx, nodeID, now)
}
