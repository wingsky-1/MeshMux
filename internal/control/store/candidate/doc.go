// Package candidate is the store's shared candidate and Agent-task leaf.
//
// An immutable candidate revision and the fixed four-task chain that publishes
// it are one artifact: the row, the idempotent task envelope and the per-node
// monotonic revisions are written together or not at all. Four domains (node,
// policy, subscription, upgrade) need that pair and none of them owns it, so it
// lives here, beside common.
//
// Two things this package deliberately does not do:
//
//   - it does not derive an Out source authorization. The retired allowlist is
//     not published at all any more: an Out admits clients by the link key its
//     own candidate carries;
//   - it does not build a Line snapshot. The node domain composes one and hands
//     it over.
//
// The convergence reads at the bottom (ChainTasksTx, LineReadbackConfirmedTx,
// LatestPublishedTx and friends) answer "did the Agent prove this revision" from
// the candidate and task tables plus the node's observed columns, so the node
// and subscriber domains can ask the same question without either importing the
// other.
package candidate
