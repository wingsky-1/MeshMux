// Package mesh defines the pure domain model for Headscale mesh devices and
// one-time mesh enrollment keys. It is the first implemented slice of ADR-0004
// (device purpose versus platform) and ADR-0007 (the post-v1 boundary).
//
// The package performs no I/O against any subsystem: it does not call
// Headscale (API or CLI), HTTP, SQLite or the file system, and it imports
// neither internal/web nor internal/install. The only external capability it
// uses is crypto/rand for identity and secret generation. Persistence, request
// handling and the Headscale adapter stay outside: they keep the stable
// Headscale node id reference and apply the state machines defined here.
//
// Scope of this slice (PR-9a-1):
//   - MeshDevice identity, mutable display label and unique node name;
//   - purpose (proxy_mesh / mesh_only / subnet_router) and the subscriber
//     binding rule: proxy_mesh requires a Subscriber, mesh_only forbids one,
//     subnet_router may stay unbound;
//   - platform (ios / android / linux / nas / other) as a display-only hint,
//     never a device kind, Headscale identity or behavior switch;
//   - the device lifecycle pending → registered → revoking → revoked, with
//     expired and failed as explicit non-happy states;
//   - the enrollment key lifecycle issued → consumed / expired / revoked, a
//     fixed 15-minute lifetime, hash-only storage and irreversible consumption.
//
// The mesh/node boundary is unchanged: internal/node is the sing-box runtime,
// fixed host layout and Agent data contract on a Line host; mesh is the
// Headscale-side device identity and enrollment state. mesh defines no second
// Node or Agent model and executes no Agent action.
//
// D2: the shared default Headscale user "meshmux" is idempotent. This package
// only records the user-name snapshot (MeshDevice.HeadscaleUser) taken when the
// device was created; it never creates or mutates a Headscale user and runs no
// CLI command.
//
// Subnet routes (PR-9b-2) are modeled as declarations, not as remote state:
//   - ParseRoutePrefix / NormalizeRoutePrefix accept one aligned CIDR prefix and
//     refuse host bits, and ValidateRoutablePrefix refuses exit routes (/0), the
//     tailnet's own ranges (TailnetIPv4Prefix, TailnetIPv6Prefix — the same
//     values the installer renders into Headscale), loopback, link-local,
//     multicast, unspecified, reserved and documentation ranges;
//   - RouteDesired is MeshMux's intent (advertised → approved, both revocable,
//     revoked terminal) while RouteObserved is the last reported Headscale
//     evidence (empty, advertised, approved, served); neither is derived from
//     the other, so no observation approves a prefix and no approval claims a
//     prefix is served;
//   - NormalizeDeclaredPrefixes allows only a subnet_router to pre-declare its
//     LAN prefixes, canonically and once each.
//
// The remote approval call, the Headscale route readback and the Web approval
// surface stay outside this package: they keep the stable prefix declaration
// this package validates and apply the state machine defined here.
//
// Revision (2026-10-22, PR-9b-2): route modeling landed in route.go. Before
// this revision the package explicitly did not model subnet route advertisement;
// it now owns the pure prefix rules and the declared/observed vocabulary, while
// persistence (schema 7), the approval argv and the Web surface remain outside.
// The device and enrollment conclusions above are unchanged.
//
// Revocation intent records why a device is being removed. See ADR-0004 and
// ADR-0007 for the decisions and their revision records.
package mesh
