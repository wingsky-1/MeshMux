// Package view is the rendering layer of the Hub control plane: the templ
// pages (Document, AuthPage, Dashboard, NodesPage, SubscribersPage,
// SubscriptionWizardPage, MeshPage, PoliciesPage, RulesLibraryPage and
// fragments), the page view-models handlers fill from store
// records, and small display helpers (ShellQuote, policy labels, the upgrade
// verdicts and approval-exclusion notes of /tasks).
//
// The view owns the operator-facing wording of the page models: row builders,
// action/matcher labels, hit-explanation chains and verdict strings live here
// (views_policies.go, upgrades.go), so a handler can state a fact or a code but
// never re-spell the words. Extension points for richer components (an
// impact-preview panel, a batch re-approval status widget) hang off the same
// view models: PolicyPageView.Conflicts/Hits already render as independent
// blocks, and UpgradeSnapshot.StagedVerdict/ApprovalNotes already separate the
// per-node conclusion from the table markup.
//
// Dependency direction (compiler-enforced): view → store for shared record
// types only (Node, MeshDeviceRecord and subscriber snapshots). view never
// imports handler or web; handler builds the view-models, view only renders
// them. Regenerate the templ output with: go generate ./internal/web/view
// (runs the //go:generate directive in views.go in place).
package view
