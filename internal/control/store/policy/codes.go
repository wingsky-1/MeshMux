package policy

// Mirrors of the policy core's stable codes that it does not export yet.
//
// Each one is emitted by the policy-write and policy-publish paths here and
// compared by the publication receipt mapping, so a single definition is what
// keeps those two views identical. Delete a mirror the moment the core exports
// it.
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
