// Package handler is the HTTP layer of the Hub control plane: routing, the
// management boundary (operation ID, security headers, host and Origin
// checks), session authentication (login/setup/logout/password, CSRF, login
// budget, KDF guard) and every management/agent handler.
//
// The subscription wizard (server_subscribers_wizard.go) is the only writer of
// a subscription selection: four groups (Lines, Out, rules, mesh devices), a
// preview that writes nothing, and a save that persists only an artifact which
// passed the kernel gate. Preview findings render "!" for a reminder and "✖"
// for a blocking refusal.
//
// The route-policy write API (server_policies_write.go) keeps the server layer
// writable and the client layer read-only: since Task 6 every client-layer
// create/revise/activate/revoke is refused with POLICY_LAYER_RETIRED, and the
// retired exceptions/ssids payload keys are refused with
// POLICY_PAYLOAD_RETIRED. The client layer remains a gated preview of its
// legacy revision, never a subscription input.
//
// Dependency direction (compiler-enforced): handler → internal/control/store
// and handler → view. Handlers use Store.DB only for the session/auth
// transactions that moved here untouched; domain writes go through store
// methods or the policy rule-library store constructed on the same handle
// (migration stays in store). Rendering goes through view components and view
// page-models built from store records. handler never imports web; nothing
// below handler imports handler.
//
// codes.go is the single source of the error-code literals this package spells
// in more than one file and of the grammar predicates (operation id, digest,
// release version) aliased from internal/cli/backup. A literal a second handler
// needs belongs there, never in a per-file copy. Display wording (page rows,
// labels, hit chains, verdicts) lives in the view package: the handler states
// facts and codes, the view states the words.
package handler
