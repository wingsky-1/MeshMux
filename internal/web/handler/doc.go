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
// Dependency direction (compiler-enforced): handler → store and handler →
// view. Handlers use Store.DB only for the session/auth transactions that
// moved here untouched; domain writes go through store methods or the policy
// rule-library store constructed on the same handle (migration stays in
// store). Rendering goes through view components and view page-models built
// from store records. handler never imports web; nothing below handler
// imports handler.
package handler
