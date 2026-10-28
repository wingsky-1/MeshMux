package line

// The Line egress vocabulary.
//
// The states are the routing state of one Line's egress slot, derived from the
// subscription selection. They live here because LineOutEgressStatusTx is the
// single derivation: the Line layer reports its own slot and the Out layer reads
// the same answer instead of deriving a second one.
//
// The stable codes are the reasons a state is not a plain managed Out. They are
// declared once, at the bottom of the node domain; the Out layer reuses them
// rather than restating a literal that an operator or a log line compares.

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

// The stable codes the Hub itself reports for a Line egress.
const (
	// CodeLineEgressExternalDeclared marks the LineEgressExternal state: the
	// egress is an external HTTP proxy the operator declared, and the Hub
	// deliberately holds no proof of it (no readback, no controller). The code
	// is informational and never blocks a publication; it exists so a readback,
	// a log line and the UI can say "declared" instead of "healthy".
	CodeLineEgressExternalDeclared = "LINE_EGRESS_EXTERNAL_DECLARED"
	// CodeOutSyncPending marks a Line whose selected managed Out has no dial
	// body yet. The Out layer reports the same code for its own chain state, so
	// it is declared here once and reused there.
	CodeOutSyncPending = "OUT_SYNC_PENDING"
)
