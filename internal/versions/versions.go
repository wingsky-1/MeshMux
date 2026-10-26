// Package versions holds the third-party release pins that more than one
// internal role has to agree on. It imports only the standard library (in fact
// nothing), so any package — the privileged installer, the Hub-side adapters,
// the release manifest — can read a pin without pulling a domain in.
//
// Why this package exists: the Headscale pin used to be re-exported by the
// adapter (internal/headscale, now internal/meshnet) and imported by
// internal/install. After the internal regroup (Task 6) the adapter is part of
// the meshnet domain, and the installer must not depend on a domain it does not
// own — it stages a binary, it does not talk to the control plane. The pin
// therefore lives here, in a leaf both sides may import, so there is still
// exactly one definition of the release MeshMux provisions and speaks to.
package versions

// HeadscaleVersion is the single pinned Headscale release of a MeshMux Hub. The
// installer artifact manifest, the adapter's version handshake and the rendered
// Headscale configuration all read this value, so a release bump cannot update
// the downloaded binary while leaving the command contract behind. The drift
// test in internal/install additionally checks it against the recorded upstream
// release digests.
const HeadscaleVersion = "0.29.5"
