package common

// The publication gate's fallback code.
//
// It is shared by three layers of the split store: the gate wrapper itself, the
// root's scratch-directory refusal and the policy publication mapping. The value
// is a stable operator-facing code, so it is declared once here and referenced
// by every one of them.
//
// The name deliberately does not start with "Code": the error-code golden
// (internal/cli/upgrade) freezes every exported Code* constant, and this one is
// an internal fallback rather than part of the store's exported vocabulary. It
// was unfrozen before the split and stays that way.
const PublishGateCode = "PUBLISH_GATE_FAILED"
