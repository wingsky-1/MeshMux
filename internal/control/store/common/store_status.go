package common

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
	// TaskStatusPending: the Agent has not picked the task up yet.
	TaskStatusPending = "pending"
	// TaskStatusApplying: the Agent is applying the staged configuration.
	TaskStatusApplying = "applying"
	// TaskStatusVerifying: the Agent is reading the applied state back.
	TaskStatusVerifying = "verifying"
	// TaskStatusHealthy: the Agent confirmed the applied state.
	TaskStatusHealthy = "healthy"
	// TaskStatusPartial: the Agent applied part of the chain.
	TaskStatusPartial = "partial"
	// TaskStatusFailed: the Agent refused or failed the task.
	TaskStatusFailed = "failed"
	// TaskStatusRolledBack: the Agent restored its last-known-good state.
	TaskStatusRolledBack = "rolled_back"

	// NodeStatusPending: a node row that has not completed pairing.
	NodeStatusPending = "pending"
)

// TaskStatusTerminal reports whether a status ends a task's life.
func TaskStatusTerminal(status string) bool {
	switch status {
	case TaskStatusHealthy, TaskStatusPartial, TaskStatusFailed, TaskStatusRolledBack:
		return true
	default:
		return false
	}
}
