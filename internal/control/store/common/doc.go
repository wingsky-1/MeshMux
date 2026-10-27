// Package common is the shared vocabulary of the store's domains.
//
// It is the leaf of the split: nothing here imports a domain, so every domain
// can read these values without a cycle.
//
// What lives here is what more than one domain must agree on:
//
//   - the stable codes and sentinel refusals a page compares by value;
//   - the role, task-status and limit vocabulary the domains share;
//   - the session/offline lifetimes and the SQLite DSN pragmas;
//   - the Argon2id/token helpers and the fixed kernel gate;
//   - the row scanner surface and the two small SQL helpers.
//
// A value a domain owns stays in that domain and is exported from there; a value
// several domains emit or compare is declared once here. Nothing in this package
// reads a table of its own domain: it holds vocabulary and pure helpers only.
package common
