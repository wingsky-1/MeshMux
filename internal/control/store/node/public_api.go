package node

// The public surface of the node domain, in one place.
//
// The behaviour lives in two layers below this package: node/line holds the Line
// transport, the candidate snapshot and the Line-side egress facts, and node/out
// holds the Out transport, its own chain, the projections and the lifecycle.
// This package keeps the node identity work (nodes.go), the external HTTP proxy
// (node_http.go), the offline window (offline.go), the subscriber port
// (subscribers.go) and the handle (store.go).
//
// Every declaration here is an alias or a one-line forwarder — this file holds no
// behaviour of its own — so node.Store keeps its exact API while the two layers
// own their own transactions and helpers.
//
// A Code* constant is declared here with its literal, not as an alias: the
// stable-error-code golden freezes every Code* const declared in this package,
// and a selector expression would hide the value from that scan. The layer that
// emits the same code declares it in its own vocabulary; TestStableCodesStayInSync
// keeps the two copies equal.

import (
	"database/sql"
	"time"

	storeline "github.com/wingsky-1/MeshMux/internal/control/store/node/line"
	storeout "github.com/wingsky-1/MeshMux/internal/control/store/node/out"

	coredomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// The record and projection types the upper layers name.

type (
	// OutTransport is the stored dial body of one managed Out.
	OutTransport = storeout.OutTransport
	// OutPoolEntry is one Out as the pool projection renders it.
	OutPoolEntry = storeout.OutPoolEntry
	// HTTPProxy is the operator-visible half of one external HTTP proxy.
	HTTPProxy = storeout.HTTPProxy
	// OutEgressFacts is the read-only Out half of one egress decision.
	OutEgressFacts = storeout.OutEgressFacts
	// OutAuthorizationPreview is the read-only authorization projection of one Out.
	OutAuthorizationPreview = storeout.OutAuthorizationPreview
	// OutEgressReadback is the Hub-side readback of one Line that names an egress.
	OutEgressReadback = storeout.OutEgressReadback
)

// The Out and Line synchronization and pool states.

const (
	OutSyncHealthy   = storeout.OutSyncHealthy
	OutSyncVerifying = storeout.OutSyncVerifying
	OutSyncPending   = storeout.OutSyncPending
	OutSyncPartial   = storeout.OutSyncPartial

	LineEgressDirect         = storeline.LineEgressDirect
	LineEgressExternal       = storeline.LineEgressExternal
	LineEgressHealthy        = storeline.LineEgressHealthy
	LineEgressVerifying      = storeline.LineEgressVerifying
	LineEgressPartial        = storeline.LineEgressPartial
	LineEgressPendingPreview = storeout.LineEgressPendingPreview

	OutPoolBound       = storeout.OutPoolBound
	OutPoolLineDirect  = storeout.OutPoolLineDirect
	OutPoolNoOutDirect = storeout.OutPoolNoOutDirect
)

// The stable codes the node domain owns.
//
// The literals are repeated from the emitting layer because the golden scans this
// package; TestStableCodesStayInSync compares them.
const (
	// CodeLineEgressUnverified is retired with the source allowlist: the Hub no
	// longer needs a verifiable source address, because the Out admits by key.
	// It stays declared so a stored diagnosis row and the frozen error-code
	// vocabulary keep resolving.
	CodeLineEgressUnverified = "LINE_EGRESS_UNVERIFIED"
	// CodeLineNotAuthorized is retired with the source allowlist.
	CodeLineNotAuthorized = "LINE_NOT_AUTHORIZED"
	// CodeLineEgressExternalDeclared marks a Line whose egress is an external
	// HTTP proxy the operator declared (LineEgressExternal).
	CodeLineEgressExternalDeclared = "LINE_EGRESS_EXTERNAL_DECLARED"
	// CodeOutSyncInProgress and CodeOutSyncPending are the transition codes of an
	// Out chain, and of a Line that names a managed Out without a dial body.
	CodeOutSyncInProgress = "OUT_SYNC_IN_PROGRESS"
	CodeOutSyncPending    = "OUT_SYNC_PENDING"
	// CodeOutNotAuthorized marks a projected egress that is not established yet.
	CodeOutNotAuthorized = "OUT_NOT_AUTHORIZED"
	// CodeOutSyncNotApplicable marks an Out operation an external HTTP proxy has
	// no Agent, candidate or readback for.
	CodeOutSyncNotApplicable = "OUT_SYNC_NOT_APPLICABLE"
)

// OutAclSourceMismatchCode is the Agent readback code of the retired source
// allowlist; it stays declared because an older Agent may still report it.
const OutAclSourceMismatchCode = storeout.OutAclSourceMismatchCode

// ErrOutCleanupPending is the refusal sentinel of a delete that destroyed
// nothing because the Out still has an unfinished chain.
var ErrOutCleanupPending = storeout.ErrOutCleanupPending

// outDrainOutcome is the drain classification the Out layer returns. The name is
// kept unexported because the public entry point does not invite a caller to
// interpret it beyond the zero/non-zero shape it already had; the root store
// converts it to int for the transaction-scoped re-export.
type outDrainOutcome = storeout.DrainOutcome

// The Line-side transaction-scoped entry points.

// BuildLineCandidateTx assembles the complete desired candidate of one node in
// the caller's transaction.
func BuildLineCandidateTx(tx *sql.Tx, nodeID string, revision int64) (coredomain.Candidate, error) {
	return storeline.BuildLineCandidateTx(tx, nodeID, revision)
}

// LineTrackedTx reports whether a node can carry proxy credentials.
func LineTrackedTx(tx *sql.Tx, nodeID string) (bool, error) {
	return storeline.LineTrackedTx(tx, nodeID)
}

// LineOutEgressStatusTx reports the routing state of one Line's egress slot.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	return storeline.LineOutEgressStatusTx(tx, lineID, now)
}

// The Out-side transaction-scoped entry points.

// OutEgressFactsTx is the transaction-scoped egress projection of one Line.
func OutEgressFactsTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	return storeout.OutEgressFactsTx(tx, lineID, now)
}

// DrainOutNodeIntentTx reconciles one Out with its own desired candidate.
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	return storeout.DrainOutNodeIntentTx(tx, outID, now, allowRetry)
}

// EnsureOutTransportTable creates the Out dial-parameter table on every open.
func EnsureOutTransportTable(tx *sql.Tx) error {
	return storeout.EnsureOutTransportTable(tx)
}

// The Out schema legs of the sequential migration chain.

// MigrateSchema5 creates the historical Out binding table.
func MigrateSchema5(tx *sql.Tx) error { return storeout.MigrateSchema5(tx) }

// MigrateSchema14 drops the Out binding table; admission is the link key.
func MigrateSchema14(tx *sql.Tx) error { return storeout.MigrateSchema14(tx) }

// MigrateSchema15 narrows the candidate immutability trigger so a node can be
// deleted.
func MigrateSchema15(tx *sql.Tx) error { return storeout.MigrateSchema15(tx) }

// The Line entry points.

// SetLine stores the transport of one Line.
func (s *Store) SetLine(line subscription.Line, now time.Time) (subscription.Line, error) {
	return storeline.SetLine(s.DB, line, now)
}

// ListLines returns every stored Line ordered by its sort order.
func (s *Store) ListLines() ([]subscription.Line, error) {
	return storeline.ListLines(s.DB)
}

// The Out entry points.

// SetOutTransport stores the dial address of one Out node.
func (s *Store) SetOutTransport(outID, server string, port int, now time.Time) (OutTransport, error) {
	return storeout.SetOutTransport(s.DB, outID, server, port, now)
}

// OutPool lists every enrolled Out node with its dial address and the Lines a
// subscription selects it for, at one clock.
func (s *Store) OutPool(now time.Time) ([]OutPoolEntry, error) {
	return storeout.OutPool(s.DB, now)
}

// DeleteOutAt deletes an Out or an external HTTP proxy.
func (s *Store) DeleteOutAt(outID string, now time.Time) error {
	return storeout.DeleteOutAt(s.DB, s.Subscribers, outID, now)
}

// PreviewOutAuthorization projects one Out's subscription-driven state.
func (s *Store) PreviewOutAuthorization(outID, lineID string) (OutAuthorizationPreview, error) {
	return storeout.PreviewOutAuthorization(s.DB, outID, lineID)
}

// PreviewOutAuthorizationAt is the request-clock variant of
// PreviewOutAuthorization.
func (s *Store) PreviewOutAuthorizationAt(outID, lineID string, now time.Time) (OutAuthorizationPreview, error) {
	return storeout.PreviewOutAuthorizationAt(s.DB, outID, lineID, now)
}

// OutAuthorizedSubscribers names the subscriptions that select one Out.
func (s *Store) OutAuthorizedSubscribers(outID string) ([]string, error) {
	return storeout.OutAuthorizedSubscribers(s.DB, s.Subscribers, outID)
}

// OutEgressFacts projects one Line's egress preconditions at one clock.
func (s *Store) OutEgressFacts(lineID string, now time.Time) (OutEgressFacts, error) {
	return storeout.ProjectOutEgressFacts(s.DB, lineID, now)
}

// RetryOutSync is the explicit retry and rollback pointer of one Out.
func (s *Store) RetryOutSync(outID string, now time.Time) error {
	return storeout.RetryOutSync(s.DB, outID, now)
}

// DrainOutsForLine is the "Line event" half of the coordination.
func (s *Store) DrainOutsForLine(lineID string, now time.Time) {
	storeout.DrainOutsForLine(s.DB, lineID, now)
}

// RepublishOutAuthorizations reconciles the whole Out pool with its own desired
// candidate.
func (s *Store) RepublishOutAuthorizations(now time.Time) {
	storeout.RepublishOutAuthorizations(s.DB, now)
}

// RepublishLineAuthorizations republishes every Line after a node lifecycle
// change.
func (s *Store) RepublishLineAuthorizations(now time.Time) {
	storeout.RepublishLineAuthorizations(s.DB, s.Subscribers, now)
}

// NodeCoordinationReadback reports the readback state of one node for the audit
// log.
func (s *Store) NodeCoordinationReadback(nodeID string, now time.Time) (OutEgressReadback, error) {
	return storeout.NodeCoordinationReadback(s.DB, s.Subscribers, nodeID, now)
}

// DrainOutNodeIntentTx reconciles one Out with its own desired candidate. It is
// the handle spelling of the transaction-scoped entry point.
func (s *Store) DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (outDrainOutcome, error) {
	return storeout.DrainOutNodeIntentTx(tx, outID, now, allowRetry)
}

// The two unexported hooks nodes.go calls into the Out layer.

// publishPairingOutCandidateTx publishes the Out's current desired candidate
// when it differs from the newest stored revision.
func publishPairingOutCandidateTx(tx *sql.Tx, nodeID, role string, now time.Time) error {
	return storeout.PublishPairingOutCandidateTx(tx, nodeID, role, now)
}

// drainNodeCoordination runs the pre-delivery reconciliation of one node.
func (s *Store) drainNodeCoordination(nodeID string, now time.Time) {
	storeout.DrainNodeCoordination(s.DB, s.Subscribers, nodeID, now)
}
