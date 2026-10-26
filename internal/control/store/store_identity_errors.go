package store

// Identity refusals shared by the whole package.
//
// The same shape rule ("32 lowercase hex") is enforced on a subscriber, a Line,
// an Out and a mesh device. Spelling the refusal at each call site is how the
// wording and the code drift apart between pages, so each refusal is built here
// once and every call site returns it. The stable code stays in front of the
// colon, which is what the pages compare.

import "errors"

// hex32Shape is the one detail text of a canonical identity refusal.
const hex32Shape = "need 32 lowercase hex characters"

// errSubscriberIDInvalid reports a malformed subscriber id.
func errSubscriberIDInvalid() error { return errors.New("SUBSCRIBER_ID_INVALID: " + hex32Shape) }

// errLineIDInvalid reports a malformed Line id.
func errLineIDInvalid() error { return errors.New("LINE_ID_INVALID: " + hex32Shape) }

// errLineNodeIDInvalid reports a malformed Line node id.
func errLineNodeIDInvalid() error { return errors.New("LINE_NODE_ID_INVALID: " + hex32Shape) }

// errOutIDInvalid reports a malformed egress (Out or HTTP proxy) id.
func errOutIDInvalid() error {
	return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
}

// errMeshDeviceIDInvalid reports a malformed mesh-device id.
func errMeshDeviceIDInvalid() error { return errors.New("MESH_DEVICE_ID_INVALID: " + hex32Shape) }
