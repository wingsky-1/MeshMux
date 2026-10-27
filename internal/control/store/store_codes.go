package store

// Stable code strings shared by more than one file of this package.
//
// Ownership and direction, per the repository's single-source rule:
//   - a code a lower layer exports is referenced from that layer (node, policy,
//     subscription, backup, mesh, versions); it is never re-typed here;
//   - a code this package owns lives in the file that owns the behaviour, or
//     here when several files of this package must agree — declared once, with
//     every call site referring to the constant;
//   - a code a lower layer still spells as a literal, but that this package must
//     also emit or compare, is declared here once as an explicit mirror with the
//     owner named, and deleted the moment the owner exports it.
//
// The error-code golden (internal/upgrade/codes_golden_test.go) freezes these
// VALUES and requires each Code* constant to carry a string literal, so code
// literals stay visible in exactly one place per value.

// Mirrors of internal/policy's stable codes that the policy generator does not
// export yet. Each one is emitted by the policy-write and policy-publish paths
// of this package and compared by the publication receipt mapping, so a single
// definition here is what keeps those two views identical.
const (
	codePolicyOperationRequired = "POLICY_OPERATION_REQUIRED"
	codePolicyPayloadInvalid    = "POLICY_PAYLOAD_INVALID"
	codePolicyPinsInvalid       = "POLICY_PINS_INVALID"
	codePolicyLayerInvalid      = "POLICY_LAYER_INVALID"
	codePolicyNameInvalid       = "POLICY_NAME_INVALID"
	codePolicySecretRefused     = "POLICY_SECRET_REFUSED"
	codePolicyCorrupt           = "POLICY_CORRUPT"
	codePolicyStateInvalid      = "POLICY_STATE_INVALID"
	codePolicyWriteFailed       = "POLICY_WRITE_FAILED"
)
