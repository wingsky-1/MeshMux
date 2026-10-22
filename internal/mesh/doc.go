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
// Subnet route advertisement, approval and online evidence are not modeled in
// this slice: PurposeSubnetRouter only records the device intent, and the
// revocation intent records why a device is being removed. See ADR-0004 and
// ADR-0007 for the decisions and their revision records.
package mesh
