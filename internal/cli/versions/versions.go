// Package versions holds the fixed values that more than one internal role has
// to agree on: third-party release pins, deployment roots, ports, the supported
// architecture matrix and the stable error-code shape. It imports only the
// standard library, so any package — the privileged installer, the Hub-side
// adapters, the release manifest, the Web launcher — can read a value without
// pulling a domain in.
//
// Why this package exists: the Headscale pin used to be re-exported by the
// adapter (internal/headscale, now internal/meshnet) and imported by
// internal/install. After the internal regroup (Task 6) the adapter is part of
// the meshnet domain, and the installer must not depend on a domain it does not
// own — it stages a binary, it does not talk to the control plane. The pin
// therefore lives here, in a leaf both sides may import, so there is still
// exactly one definition of the release MeshMux provisions and speaks to.
//
// The same reasoning applies to every constant in contract.go and codes.go: a
// value copied into two layers is a drift bug waiting for a release. Keep this
// package a zero-internal-import leaf; the DAG guard in cmd/meshmux asserts it.
package versions

// HeadscaleVersion is the single pinned Headscale release of a MeshMux Hub. The
// installer artifact manifest, the adapter's version handshake and the rendered
// Headscale configuration all read this value, so a release bump cannot update
// the downloaded binary while leaving the command contract behind. The drift
// test in internal/install additionally checks it against the recorded upstream
// release digests.
const HeadscaleVersion = "0.29.5"
