// Package snapshot reads, writes and restores the installer's durable upgrade
// snapshots.
//
// A successful Node install leaves a self-describing tree under
// UpgradeSourceDir: a snapshot.json manifest plus a payload/ copy. Every entry
// records the absolute target, its payload path, whether it existed, its mode,
// owner and SHA-256, so the revert lane can rebuild the exact file set a
// rollback restores instead of guessing paths from a flat copy.
//
// The package restores only into MeshMux-owned targets, refuses a payload that
// escapes the snapshot directory, and grades the restore (binary-only vs full
// set) from the recorded change set. It imports install/core for the state,
// path and file primitives and never imports a channel; the Node upgrade path
// and internal/cli/update's revert executor are its callers.
package snapshot
