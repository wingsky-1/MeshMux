// Package handler is the HTTP assembly of the Hub control plane. It owns the
// router, the navigation fallbacks and the process lifecycle; every route body
// lives in a domain package next to the facts it reads.
//
// Layout:
//
//   - infra: the deployment configuration, session/CSRF/form-token boundary,
//     request operation id, failure and success writers, security headers, login
//     budget, KDF guard and the error-code vocabulary shared by more than one
//     domain.
//   - subscription: the public bearer download boundary, which runs before the
//     management boundary so a download never carries a session.
//   - node: nodes, the Agent channel, pairing, and Out management.
//   - mesh: Mesh devices, enrollment keys and subnet routes.
//   - subscriber: the subscriber page/API, per-Line selection and the
//     subscription wizard.
//   - policy: the route-policy snapshot, write API, server preview, gated
//     publication, rule library and the database-migration confirmation.
//   - upgrade: /tasks, the release check and per-node approval, the Agent upgrade
//     channels, Hub backup/handoff/restore, and the read-only Hub identity
//     readback with its journal state machine.
//
// The subscription wizard is the only writer of a subscription selection: four
// groups (Lines, Out, rules, mesh devices), a preview that writes nothing, and a
// save that persists only an artifact which passed the kernel gate. Preview
// findings render "!" for a reminder and "✖" for a blocking refusal.
//
// The route-policy write API keeps the server layer writable and the client
// layer read-only: every client-layer create/revise/activate/revoke is refused
// with POLICY_LAYER_RETIRED, and the retired exceptions/ssids payload keys are
// refused with POLICY_PAYLOAD_RETIRED. The client layer remains a gated preview
// of its legacy revision, never a subscription input.
//
// Dependency direction (compiler-enforced): every domain imports infra; domains
// do not import each other, and a domain that needs another one's fact receives
// it through a narrow interface the root package satisfies (subscriber.Backends,
// policy.Backends, upgrade.AgentAuth) or through a small bridge in backends.go.
// subscriber reads the public download boundary, which has no edge back. infra
// imports internal/control/store and internal/web/view only. Nothing below this
// package imports it, and it never imports internal/web.
//
// infra owns the shared error-code vocabulary and the grammar predicates
// (operation id, digest, release version) aliased from internal/cli/backup. A
// literal two domains need belongs there, never in a per-domain copy. Display
// wording (page rows, labels, hit chains, verdicts) lives in the view package:
// the handler states facts and codes, the view states the words.
//
// boundary_test.go pins both halves of that contract: the compiled import graph
// of every domain, and the fact that this package holds no route body.
package handler
