package store

// Task and egress status vocabulary the store compares against stored strings.
//
// Owner: internal/node/protocol owns the frozen Agent result state machine (its
// resultStatuses set). It does not export the individual states yet, so this
// package declares the ones it reads exactly once, here — mirroring the owner's
// values — and every query, transition check and projection refers to these
// constants instead of re-typing the string. Delete a mirror the moment the
// protocol exports it.
//
// The egress/synchronization state names below are this package's own: they are
// what a page renders for one Line, one Out or one subscriber, so their single
// source is this package.

const (
	// taskStatusPending: the Agent has not picked the task up yet.
	taskStatusPending = "pending"
	// taskStatusApplying: the Agent is applying the staged configuration.
	taskStatusApplying = "applying"
	// taskStatusVerifying: the Agent is reading the applied state back.
	taskStatusVerifying = "verifying"
	// taskStatusHealthy: the Agent confirmed the applied state.
	taskStatusHealthy = "healthy"
	// taskStatusPartial: the Agent applied part of the chain.
	taskStatusPartial = "partial"
	// taskStatusFailed: the Agent refused or failed the task.
	taskStatusFailed = "failed"
	// taskStatusRolledBack: the Agent restored its last-known-good state.
	taskStatusRolledBack = "rolled_back"

	// nodeStatusPending: a node row that has not completed pairing.
	nodeStatusPending = "pending"
)

// taskStatusTerminal reports whether a status ends a task's life.
func taskStatusTerminal(status string) bool {
	switch status {
	case taskStatusHealthy, taskStatusPartial, taskStatusFailed, taskStatusRolledBack:
		return true
	default:
		return false
	}
}
