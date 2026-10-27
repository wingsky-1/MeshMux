// Package mesh is the persistence boundary of Mesh devices, enrollment keys and
// subnet routes.
//
// The pure domain (internal/core/mesh) owns the device, key and route rules; this
// package reads and writes the rows, adds the facts the domain cannot check
// without I/O (a subscriber row exists, a node name is unique, a prefix is not
// already declared) and reports the store-level refusals for a missing or corrupt
// row.
//
// Every read validates the stored row against the same rules the write path
// applied, so a hand-edited database is reported as corrupt instead of being
// rendered as a valid device or route.
package mesh
