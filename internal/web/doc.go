// Package web is the thin assembly of the Hub control plane: operator Config
// with validation, New (validate, convert, delegate), and Server as a holder
// of the handler runtime with Close/Handler.
//
// Dependency direction (compiler-enforced): web → handler → control/store,
// handler → view, view → control/store. web imports handler, control/store and
// view for wiring only. No package below web imports web; control/store never
// imports handler or view; view never imports handler or web.
//
// All HTTP behavior (routing, the management boundary, session authentication,
// CSRF/Origin guards, handlers) lives in handler. All persistence lives in
// internal/control/store. All rendering (templ pages plus page view-models)
// lives in view.
package web
