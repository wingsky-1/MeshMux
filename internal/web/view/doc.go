// Package view is the rendering layer of the Hub control plane: the templ
// pages (Document, AuthPage, Dashboard, NodesPage, SubscribersPage, MeshPage,
// PoliciesPage and fragments), the page view-models handlers fill from store
// records, and small display helpers (ShellQuote, policy labels).
//
// Dependency direction (compiler-enforced): view → store for shared record
// types only (Node, MeshDeviceRecord and subscriber snapshots). view never
// imports handler or web; handler builds the view-models, view only renders
// them. Regenerate the templ output with: go generate ./internal/web/view
// (runs the //go:generate directive in views.go in place).
package view
