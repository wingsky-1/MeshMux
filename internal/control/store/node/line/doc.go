// Package line is the Line half of the node domain: the stored transport of one
// edge node and the candidate snapshot the Hub builds from it.
//
// A Line is the only node role that carries client-facing transport. Its stored
// settings are validated on write and on read against the same contract, and the
// snapshot builder turns them into the complete desired user set of the
// subscribers it serves.
//
// # Dependency direction
//
// This package is the bottom of the node domain: the node root and the Out layer
// are built on it, never the other way round. It imports candidate and common.
// It reads the row of an Out only to render that Out's dial body into a
// candidate; the Out lifecycle itself lives in the sibling out package, which
// imports this package.
package line
