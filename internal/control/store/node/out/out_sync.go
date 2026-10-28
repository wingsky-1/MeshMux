package out

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
	"errors"
	"strings"
	"time"

	candidatepkg "github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	storeline "github.com/wingsky-1/MeshMux/internal/control/store/node/line"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
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

// outEgressReadbackTx is the Hub-side readback of one Line.
//
// Each fact is derived independently and reported with its own stable code, so a
// partially converged Line can never be summarized as healthy: the egress
// routing state, the Line inbound snapshot, the REALITY block of that snapshot,
// and the resulting final egress.
func outEgressReadbackTx(tx *sql.Tx, subs Subscribers, lineID string, now time.Time) (OutEgressReadback, error) {
	readback := OutEgressReadback{LineID: lineID}
	selected, err := storeline.SelectedEgressIDsForLineTx(tx, lineID)
	if err != nil {
		return OutEgressReadback{}, err
	}
	if len(selected) > 0 {
		readback.OutID = selected[0]
	}
	state, code, err := storeline.LineOutEgressStatusTx(tx, lineID, now)
	if err != nil {
		return OutEgressReadback{}, err
	}
	readback.Allowlist, readback.AllowlistCode = state, code
	// The Line side facts come from the Line's own confirmed snapshot, which is
	// what proves its inbound listener, user set and REALITY transport.
	inbound, inboundCode, inboundErr := subs.LineSyncViewTx(tx, lineID, now)
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
	readback.Reality = storeline.RealityConfirmedTx(tx, lineID)
	readback.ConfirmedRevision, readback.ConfirmedDigest = storeline.ConfirmedRevisionTx(tx, lineID)
	switch {
	case readback.Allowlist == storeline.LineEgressDirect:
		readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
	case readback.Allowlist == storeline.LineEgressExternal:
		// The egress is the operator's external HTTP proxy (Ruling R11): no
		// readback and no controller can prove it. A converged Line proves only
		// its own inbound half, so the pair is reported as the declaration it is
		// instead of a healthy egress the Hub never demonstrated.
		if inbound == common.SubscriberSyncHealthy && readback.Reality {
			readback.FinalEgress, readback.FinalEgressCode = storeline.LineEgressExternal, storeline.CodeLineEgressExternalDeclared
		} else {
			readback.FinalEgress, readback.FinalEgressCode = inbound, inboundCode
		}
	case readback.Allowlist == storeline.LineEgressHealthy && inbound == common.SubscriberSyncHealthy && readback.Reality:
		readback.FinalEgress = storeline.LineEgressHealthy
	case readback.Allowlist == storeline.LineEgressHealthy && inbound == common.SubscriberSyncHealthy:
		readback.FinalEgress = storeline.LineEgressPartial
		readback.FinalEgressCode = "OUT_EGRESS_REALITY_UNVERIFIED"
	case readback.Allowlist == storeline.LineEgressVerifying || inbound == common.SubscriberSyncPending:
		readback.FinalEgress = storeline.LineEgressVerifying
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, CodeOutSyncInProgress)
	default:
		readback.FinalEgress = storeline.LineEgressPartial
		readback.FinalEgressCode = firstStableCode(readback.AllowlistCode, inboundCode, "OUT_SYNC_FAILED")
	}
	// The retry pointer is derived from the same evidence as the state above:
	// only a terminal failure is retryable. A transition is still applying its
	// own chain.
	readback.RetryPending = readback.FinalEgress == storeline.LineEgressPartial
	return readback, nil
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

// DrainOutNodeIntentTx reconciles one Out with its own desired candidate.
//
// The rules mirror the subscriber drain and keep the operation bounded:
//   - an unfinished chain is never replaced or cancelled;
//   - an identical, confirmed snapshot needs no publication;
//   - an identical but unconfirmed snapshot is republished only by an explicit
//     retry;
//   - a changed snapshot is new intent and is published;
//   - an offline Out keeps the durable intent but receives no state-changing
//     task.
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (DrainOutcome, error) {
	var role string
	err := tx.QueryRow(`SELECT role FROM nodes WHERE id=?`, outID).Scan(&role)
	if errors.Is(err, sql.ErrNoRows) {
		return DrainNoop, nil
	}
	if err != nil {
		return DrainNoop, errors.New(common.CodeDatabaseUnavailable)
	}
	if role == string(common.NodeRoleHTTP) {
		// An external HTTP proxy has no Agent and no candidate: there is nothing
		// an Out drain could publish, so this is "not applicable" rather than a
		// silent no-op.
		return DrainNotApplicable, nil
	}
	if role != string(common.NodeRoleOut) {
		return DrainNoop, nil
	}
	latestRevision, latestDigest, _, hasCandidate, err := candidatepkg.LatestPublishedTx(tx, outID)
	if err != nil {
		return DrainNoop, err
	}
	if hasCandidate {
		desiredDigest, err := outCandidateAtRevisionTx(tx, outID, latestRevision)
		if err != nil {
			return DrainNoop, err
		}
		confirmed, err := candidatepkg.LineReadbackConfirmedTx(tx, outID, latestRevision, latestDigest)
		if err != nil {
			return DrainNoop, err
		}
		unfinished, err := candidatepkg.LineUnfinishedTasksTx(tx, outID)
		if err != nil {
			return DrainNoop, err
		}
		if unfinished != 0 {
			// A chain always finishes first. Publishing a competing chain would
			// leave two apply steps racing on one host.
			return DrainDeferred, nil
		}
		sameCandidate := latestDigest == desiredDigest
		if sameCandidate && confirmed {
			return DrainNoop, nil
		}
		if sameCandidate && !allowRetry {
			// The snapshot did not change: an automatic poll never retries it,
			// whether the last chain failed or ended without matching evidence.
			return DrainNoop, nil
		}
	}
	offline, err := storeline.NodeOfflineTx(tx, outID, now)
	if err != nil {
		return DrainNoop, err
	}
	if offline {
		return DrainDeferred, errors.New("OUT_OFFLINE: out is offline; the publication stays pending")
	}
	revision, err := candidatepkg.NextCandidateRevisionTx(tx, outID)
	if err != nil {
		return DrainNoop, err
	}
	candidate, err := storeline.BuildLineCandidateTx(tx, outID, revision)
	if err != nil {
		return DrainNoop, err
	}
	if _, err := candidatepkg.PublishTx(tx, outID, candidate, now); err != nil {
		return DrainNoop, err
	}
	return DrainPublished, nil
}

// PublishPairingOutCandidateTx publishes the Out's current desired candidate
// when it differs from the newest stored revision.
//
// A Web-first Out is created before its dial address exists, so revision 1 is
// the transport-free baseline. SetOutTransport cannot publish while the node is
// still pending: the offline guard keeps state-changing tasks off a host that
// has not enrolled. Pairing is therefore the first moment the link-key document
// can be committed, and doing it before SeedInitialTasksTx makes that revision
// the one a fresh install fetches and applies. Without it the node boots the
// baseline guard, which carries no authorization at all.
func PublishPairingOutCandidateTx(tx *sql.Tx, nodeID, role string, now time.Time) error {
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
	desired, err := storeline.BuildLineCandidateTx(tx, nodeID, revision)
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
	desired, err = storeline.BuildLineCandidateTx(tx, nodeID, next)
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
	candidate, err := storeline.BuildLineCandidateTx(tx, outID, revision)
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
		return OutSyncPending, storeline.CodeOutSyncPending, nil
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
		return OutSyncPending, storeline.CodeOutSyncPending, nil
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
	return OutSyncPending, storeline.CodeOutSyncPending, nil
}

// RetryOutSync is the explicit retry and rollback pointer of one Out. It
// republishes a chain even when the desired candidate did not change, which is
// exactly what an operator needs after a partial/failed chain. Automatic polls
// never call it.
//
// An external HTTP proxy has no chain to retry (Ruling R11), so the call answers
// CodeOutSyncNotApplicable explicitly: a success here would otherwise read as
// "the chain was published and confirmed", which the Hub never did.
func RetryOutSync(db *sql.DB, outID string, now time.Time) error {
	outID = strings.TrimSpace(outID)
	if !storeline.ValidNodeID(outID) {
		return common.ErrOutIDInvalid()
	}
	tx, err := db.Begin()
	if err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	outcome, err := DrainOutNodeIntentTx(tx, outID, now, true)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return errors.New(common.CodeDatabaseUnavailable)
	}
	switch outcome {
	case DrainNotApplicable:
		return errors.New(CodeOutSyncNotApplicable + ": an external http proxy has no agent chain or readback to retry")
	case DrainDeferred:
		return errors.New(storeline.CodeOutSyncPending + ": the out publication is queued behind an in-flight or offline out")
	}
	return nil
}

// drainOutNode begins its own transaction and reconciles one Out. Failures must
// not fail the request they serve: the next poll, heartbeat or result retries.
func drainOutNode(db *sql.DB, outID string, now time.Time) {
	tx, err := db.Begin()
	if err != nil {
		return
	}
	defer tx.Rollback()
	if _, err := DrainOutNodeIntentTx(tx, outID, now, false); err != nil {
		return
	}
	_ = tx.Commit()
}

// outIDs reads the Out pool in its own statement so no transaction is held open
// while the per-Out drain begins its own.
func outIDs(db *sql.DB) ([]string, error) {
	return storeline.QueryIDs(db, `SELECT id FROM nodes WHERE role='out' ORDER BY id ASC`)
}

// DrainOutsForLine is retained as the "Line event" half of the coordination.
//
// A Line event no longer authorizes anything: the Out admits by link key, and a
// Line candidate carries neither an Out endpoint nor a route. The function stays
// because the Agent endpoints call it on every Line event, and each Out drain is
// a bounded no-op unless that Out's own candidate changed.
func DrainOutsForLine(db *sql.DB, lineID string, now time.Time) {
	// The Line id is deliberately unused: a Line event drains the whole pool and
	// each Out decides from its own candidate whether anything has to be
	// published. The parameter is kept because every Agent endpoint passes it
	// and the signature is the stable "Line event" half of the coordination.
	outs, err := outIDs(db)
	if err != nil {
		return
	}
	for _, outID := range outs {
		drainOutNode(db, outID, now)
	}
}

// DrainNodeCoordination runs the pre-delivery reconciliation of one node.
//
// An Out event republishes the Out's own chain; a Line event republishes the
// Line. The two directions are independent now, so neither waits for the other.
// Each step owns its own transaction, so nothing nests on the single-connection
// pool. A failure in one direction never fails the request: the next event
// retries it.
func DrainNodeCoordination(db *sql.DB, subs Subscribers, nodeID string, now time.Time) {
	var role string
	err := db.QueryRow(`SELECT role FROM nodes WHERE id=?`, nodeID).Scan(&role)
	if err != nil {
		subs.DrainNode(nodeID, now)
		return
	}
	if role == string(common.NodeRoleOut) {
		drainOutNode(db, nodeID, now)
		return
	}
	DrainOutsForLine(db, nodeID, now)
	subs.DrainNode(nodeID, now)
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
func RepublishOutAuthorizations(db *sql.DB, now time.Time) {
	outIDs, err := outIDs(db)
	if err != nil {
		return
	}
	for _, outID := range outIDs {
		drainOutNode(db, outID, now)
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
func RepublishLineAuthorizations(db *sql.DB, subs Subscribers, now time.Time) {
	lineIDs, err := storeline.QueryIDs(db, `SELECT id FROM nodes WHERE role='edge' ORDER BY id ASC`)
	if err != nil {
		return
	}
	for _, lineID := range lineIDs {
		subs.DrainNode(lineID, now)
	}
}

// NodeCoordinationReadback reports the readback state of one node for the audit
// log: a Line reports its egress state, an Out reports its own chain. It is a
// read-only projection and never mutates or publishes; the returned codes are
// stable identifiers only.
//
// An Out reports the same retry semantics as a Line: only a terminal failure is
// retry-pending. A transition is still applying its own chain, and a healthy
// chain has nothing left to retry.
func NodeCoordinationReadback(db *sql.DB, subs Subscribers, nodeID string, now time.Time) (OutEgressReadback, error) {
	tx, err := db.Begin()
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
			Allowlist:       storeline.LineEgressExternal,
			AllowlistCode:   storeline.CodeLineEgressExternalDeclared,
			FinalEgress:     storeline.LineEgressExternal,
			FinalEgressCode: storeline.CodeLineEgressExternalDeclared,
			RetryPending:    false,
		}, nil
	}
	return outEgressReadbackTx(tx, subs, nodeID, now)
}
