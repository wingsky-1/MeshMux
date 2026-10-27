package common

// The store's local limits, in one place.
//
// Ownership, per the repository's single-source rule:
//   - a bound that a lower layer already owns is *referenced*, never copied:
//     the selection Line bound is subscription's (subscription.Selection), and
//     the rule-value bound is the subscription IR's (ir.MaxRuleValues);
//   - a bound this package enforces on its own inputs (how many rules or
//     devices one wizard save may name) lives here and nowhere else;
//   - a bound that protects a *published* contract but is not exported by its
//     owner yet (the node candidate user set, the Agent's allowed-source
//     envelope) is declared here once, named as a mirror of that owner, and
//     deleted the moment the owner exports it. It is never re-typed at a call
//     site.
//
// No call site may repeat one of these numbers or render it into a message
// literal: messages are built with strconv.Itoa from the constant, so changing a
// bound cannot leave a stale number in operator text.

const (
	// MaxSubscriberLines is the number of Lines one subscriber may select. The
	// owner is subscription.Selection.Validate, which refuses the same value;
	// the store checks it earlier so a request is refused before any write.
	MaxSubscriberLines = 32

	// MaxLineCandidateUsers mirrors the node candidate user bound
	// (internal/node, maxCandidateUsers). A Line snapshot refuses an oversized
	// user set before the candidate document is built, independent of the later
	// document validation. Delete this once internal/node exports its bound.
	MaxLineCandidateUsers = 1024

	// MaxOutAllowlistSources mirrors the frozen protocol and Agent bound
	// (internal/node/protocol, maxAllowedSources). One Out may be selected by
	// several subscriptions, so this is a defensive ceiling that keeps the
	// derived list inside the envelope the Agent accepts.
	MaxOutAllowlistSources = 256

	// MaxSelectionRules bounds how many rule revisions one wizard save may
	// pin. It exists so one save cannot produce an unbounded document.
	MaxSelectionRules = 64

	// MaxSelectionDevices bounds how many mesh devices one wizard save may
	// record on a subscription.
	MaxSelectionDevices = 64

	// MaxBatchSubscribers bounds one batch re-approval request. Each member is
	// its own transaction and its own gate run, so the ceiling keeps one HTTP
	// request from turning into an unbounded sequence of kernel invocations.
	MaxBatchSubscribers = 100
)
