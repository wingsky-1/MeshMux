// Package subscription defines the pure domain model for subscribers,
// per-Line proxy credentials, subscription bearer tokens and Line transport
// settings, plus the pure subscription composer and its selection snapshot.
//
// The package performs no I/O, persistence, HTTP handling or kernel execution.
// A Line references an existing node record by its stable NodeID; this package
// deliberately does not define a second Node entity.
//
// The composer (compose.go) is the single renderer of one subscription:
// ComposeSubscription(lines, outs, rules, network) returns the two client
// documents, one selection id and one content id. It is deterministic by
// construction — the same selection always produces byte-identical output — so a
// download can be re-derived and compared with the approved digest instead of
// trusting a cached copy.
//
// Inside, the composer is a few pure stages over one kernel-neutral IR
// (compose_plan.go): mesh material, the Line selector block, the client egress
// (the selected Out) and the client route. Three direct makers (standard
// sing-box, mesh sing-box, Mihomo) in render.go consume that plan; none is
// chosen by a flag, so mesh material can never be silently rendered as a
// standard subscription. A blocking diagnostic yields no document, and ContentID
// is the approval credential the download compares against.
//
// The Line publishes no route for a subscription (client-chain egress,
// docs/superpowers/plans/2026-10-27-client-chain-egress.md): the Out is one more
// egress in the client document, so the client hops Line -> Out itself and every
// proxy rule names the Out tag. ComposeDocuments.LineRoutes is therefore always
// empty and only kept for source compatibility.
//
// The subscription IR vocabulary (matcher kinds, actions, pins, tailnet
// prefixes) lives in the child package ir, the one place policy may import
// downward; policy's generators read it instead of keeping a second copy.
//
// The snapshot (snapshot.go) records what one subscription chose: the
// referenced entities, their immutable versions and their order. It never
// carries rendered bytes; it exists for the reference graph (used-by) and for
// restoring the wizard.
//
// The identities have independent lifetimes:
//   - a Subscriber ID survives a display-name rename;
//   - each Line gets a Credential with its own VLESS UUID;
//   - a SubscriptionToken is a high-entropy bearer secret, never a UUID, and
//     only its SHA-256 hash is stored.
//
// Callers must never log or persist the plaintext token returned by NewToken
// or NewSubscriptionToken.
package subscription
