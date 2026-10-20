// Package subscription defines the pure domain model for subscribers,
// per-Line proxy credentials, subscription bearer tokens and Line transport
// settings.
//
// The package performs no I/O, persistence, HTTP handling or subscription
// rendering. A Line references an existing node record by its stable NodeID;
// this package deliberately does not define a second Node entity.
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
