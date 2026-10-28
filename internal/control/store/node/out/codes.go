package out

// The Out vocabulary: the states of an Out's own chain, the stable codes the Hub
// reports for it, the pool modes of the projection and the drain classification.
//
// The Line egress vocabulary is not repeated here: the Line layer declares it,
// and the projection reads the same constants instead of restating a literal.

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

// OutAclSourceMismatchCode is the Agent readback code of the retired source
// allowlist. It stays declared because an older Agent may still report it; the
// Hub no longer publishes an allowlist and no longer interprets the code.
const OutAclSourceMismatchCode = "OUT_ACL_SOURCE_MISMATCH"

// The stable codes the Hub itself reports for an Out.
const (
	// CodeOutSyncInProgress is the transition code of a chain in flight.
	CodeOutSyncInProgress = "OUT_SYNC_IN_PROGRESS"
	// CodeOutNotAuthorized marks a projected egress that is not established
	// yet. It is a projection-only code: nothing gates a Line publication on it
	// any more.
	CodeOutNotAuthorized = "OUT_NOT_AUTHORIZED"
	// CodeOutSyncNotApplicable marks an operation that has no meaning for an
	// external HTTP proxy: there is no Agent, no candidate and no readback to
	// publish or retry. The action reports it explicitly instead of a silent
	// success, so an operator never believes a chain was sent.
	CodeOutSyncNotApplicable = "OUT_SYNC_NOT_APPLICABLE"
)

// LineEgressPendingPreview is the projection of a proposed egress: the
// subscription records the intent but the Out's own chain is not confirmed yet.
const LineEgressPendingPreview = "pending"

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

// DrainOutcome classifies what one Out drain attempt did. It lets the caller
// tell "nothing to publish" apart from "publish is blocked", which the operator
// has to see.
type DrainOutcome int

const (
	// DrainNoop: the published chain already equals the desired one and is
	// confirmed, or an unchanged unconfirmed snapshot waits for an explicit
	// retry.
	DrainNoop DrainOutcome = iota
	// DrainPublished: a new immutable revision and its fixed chain were
	// enqueued in the caller's transaction.
	DrainPublished
	// DrainDeferred: a publish is required but cannot happen yet (a chain is
	// in flight, or the Out is offline). The change stays pending.
	DrainDeferred
	// DrainNotApplicable: the egress is an external HTTP proxy (Ruling R11).
	// It has no Agent, no candidate and no readback, so there is no out-side
	// chain to publish at all. The caller reports this explicitly instead of a
	// silent no-op.
	DrainNotApplicable
)
