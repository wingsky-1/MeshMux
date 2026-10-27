package common

// The publication gate's fallback code.
//
// It is shared by three layers of the split store: the gate wrapper itself, the
// root's scratch-directory refusal and the policy publication mapping. The value
// is a stable operator-facing code, so it is declared once here and referenced
// by every one of them.
const CodePublishGate = "PUBLISH_GATE_FAILED"
