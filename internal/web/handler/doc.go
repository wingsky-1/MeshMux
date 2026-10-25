// Package handler is the HTTP layer of the Hub control plane: routing, the
// management boundary (operation ID, security headers, host and Origin
// checks), session authentication (login/setup/logout/password, CSRF, login
// budget, KDF guard) and every management/agent handler.
//
// Dependency direction (compiler-enforced): handler → store and handler →
// view. Handlers use Store.DB only for the session/auth transactions that
// moved here untouched; domain writes go through store methods. Rendering
// goes through view components and view page-models built from store records.
// handler never imports web; nothing below handler imports handler.
package handler
