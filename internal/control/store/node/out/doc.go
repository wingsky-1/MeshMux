// Package out is the Out half of the node domain: the optional Shadowsocks
// egress, its dial body and link key, its own immutable candidate chain and the
// projections and lifecycle the Web layer drives.
//
// An Out admits any client that presents the Hub-issued link key, so the key is
// the admission: there is no source allowlist to derive, publish, read back or
// gate. What the Hub can still prove about an Out stays narrow — its candidate
// chain was published, and (only with a healthy readback of the same revision
// and digest) the Agent applied it. Nothing here claims an Out is reachable from
// the internet, and nothing claims a client chose the Out.
//
// # Dependency direction
//
// This package is built on the sibling line package and on candidate/common. It
// is above them and is never imported by them: the candidate builder lives in
// line, so the Out lifecycle imports line for the snapshot, the egress status and
// the confirmed-revision facts instead of restating them here.
//
// The subscriber facts it needs are declared as the narrow Subscribers port and
// injected by the node root; subscription reads Line state, so the Out layer
// never reads a subscriber row directly.
package out
