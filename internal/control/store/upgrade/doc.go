// Package upgrade is the persistence boundary of the Hub's upgrade targets and
// the Agent upgrade channel.
//
// An approved release is a stamped row per node plus the four-task chain that
// applies it. The chain is the same publication path every other change uses, so
// this package reads the Line snapshot, the derived route and the candidate
// revision from the node and policy domains; neither of them imports it.
//
// The revision is never caller-supplied: the Agent's own readback names the
// rollback target, so a failed upgrade's rollback is one explicit operator
// action, not a guessed version.
package upgrade
