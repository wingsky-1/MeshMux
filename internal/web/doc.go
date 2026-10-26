// Package web is the thin assembly of the Hub control plane: operator Config
// with validation, New (validate, convert, delegate), and Server as a holder
// of the handler runtime with Close/Handler.
//
// Dependency direction (compiler-enforced): web → handler → store,
// handler → view, view → store. web imports handler, store and view for
// wiring only. No package below web imports web; store never imports handler
// or view; view never imports handler or web.
//
// All HTTP behavior (routing, the management boundary, session authentication,
// CSRF/Origin guards, handlers) lives in handler. All persistence lives in
// store. All rendering (templ pages plus page view-models) lives in view.
package web
