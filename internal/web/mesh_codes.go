package web

import (
	"github.com/wingsky-1/MeshMux/internal/headscale"
	"github.com/wingsky-1/MeshMux/internal/mesh"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// The Mesh error codes are a closed set.
//
// meshErrorCode is the single place that turns an error into an operator-facing
// code, and it only ever returns a value registered here. Everything else a
// message happens to say - a Headscale socket path, a store label, a formatted
// Go error - stays out of the contract: an unregistered value becomes
// codeMeshInternalError, never a code assembled from message text.
//
// The sets are built by name from the constants of the packages that produce the
// refusals, so a renamed or removed constant is a build failure instead of a
// silent change to the HTTP contract.

const (
	// codeDisplayNameInvalid is the subscription package's display-label
	// refusal, which the Mesh create form surfaces directly.
	codeDisplayNameInvalid = "DISPLAY_NAME_INVALID"
	// codeMeshInternalError is the fail-closed replacement for any value that
	// is not a registered code. The page says "internal", never the message.
	codeMeshInternalError = "MESH_INTERNAL_ERROR"
	// codeMeshDeviceNotReenrollable refuses a one-time key for a device whose
	// state no longer allows a new enrollment attempt.
	codeMeshDeviceNotReenrollable = "MESH_DEVICE_NOT_REENROLLABLE"

	// Handler fallbacks. A failure that has no code of its own still reports
	// the stage it belongs to, so the page names the operation that failed
	// instead of a generic internal error.
	codeMeshDeviceCreateFailed = "MESH_DEVICE_CREATE_FAILED"
	codeMeshDeviceKeyIssue     = "MESH_DEVICE_KEY_ISSUE_FAILED"
	codeMeshDeviceRekeyFailed  = "MESH_DEVICE_REKEY_FAILED"
	codeMeshDeviceRevokeFailed = "MESH_DEVICE_REVOKE_FAILED"
	codeMeshReconcileFailed    = "MESH_RECONCILE_FAILED"
	codeMeshRouteApproval      = "MESH_ROUTE_APPROVAL_FAILED"
	codeMeshRouteWithdraw      = "MESH_ROUTE_WITHDRAW_FAILED"
)

var (
	// meshOwnCodes are the codes this package owns: store-level row facts and
	// web-level lifecycle/claim refusals.
	meshOwnCodes = codeSet(
		codeDatabaseUnavailable,
		codeDisplayNameInvalid,
		codeMeshInternalError,

		codeMeshDeviceNotFound,
		codeMeshDeviceCorrupt,
		codeMeshEnrollmentKeyNotFound,
		codeMeshRouteConflict,
		codeMeshRouteNotFound,
		codeMeshRouteCorrupt,

		codeMeshHeadscaleUserUnknown,
		codeMeshRouteApprovalUnconfirmed,
		codeMeshRouteNodeUnobserved,
		codeMeshEndpointControlURLUnavailable,
		codeMeshEndpointPurposeUnsupported,
		codeMeshEndpointSubscriberUnavailable,
		codeMeshEndpointKeyIssueFailed,
		codeMeshEndpointRenderFailed,
		codeMeshClaimNodeNotFound,
		codeMeshClaimNodeMismatch,
		codeMeshClaimNodeOccupied,
		codeMeshClaimFailed,

		codeMeshDeviceCreateFailed,
		codeMeshDeviceNotReenrollable,
		codeMeshDeviceKeyIssue,
		codeMeshDeviceRekeyFailed,
		codeMeshDeviceRevokeFailed,
		codeMeshReconcileFailed,
		codeMeshRouteApproval,
		codeMeshRouteWithdraw,
	)

	// meshDomainCodes are the refusals of the pure domain package.
	meshDomainCodes = codeSet(
		mesh.CodeIDGenerationFailed,
		mesh.CodeDeviceIDInvalid,
		mesh.CodeDisplayNameInvalid,
		mesh.CodePurposeInvalid,
		mesh.CodePlatformInvalid,
		mesh.CodeSubscriberBindingInvalid,
		mesh.CodeNodeNameInvalid,
		mesh.CodeNodeNameDuplicate,
		mesh.CodeHeadscaleUserInvalid,
		mesh.CodeHeadscaleNodeIDInvalid,
		mesh.CodeStatusInvalid,
		mesh.CodeStatusTransitionInvalid,
		mesh.CodeRevokeDeviceMismatch,
		mesh.CodeRevokeReasonInvalid,
		mesh.CodeKeyIDInvalid,
		mesh.CodeKeyDeviceIDInvalid,
		mesh.CodeKeyStateInvalid,
		mesh.CodeKeyTransitionInvalid,
		mesh.CodeKeyExpired,
		mesh.CodeKeyNotExpired,
		mesh.CodeKeyDeviceMismatch,
		mesh.CodeKeyTTLInvalid,
		mesh.CodeKeyHashInvalid,
		mesh.CodeKeySecretInvalid,
		mesh.CodeKeyGenerationFailed,
		mesh.CodeKeyAlreadyActive,
		mesh.CodeRoutePrefixInvalid,
		mesh.CodeRoutePrefixNotRoutable,
		mesh.CodeRouteDeclarationInvalid,
		mesh.CodeRouteDesiredInvalid,
		mesh.CodeRouteObservedInvalid,
		mesh.CodeRouteSourceInvalid,
		mesh.CodeRouteTransitionInvalid,
	)

	// headscaleCodes are the control-plane adapter refusals. They are the only
	// values a Mesh page reports as 503 instead of a conflict.
	headscaleCodes = codeSet(
		headscale.CodeVersionMismatch,
		headscale.CodeSocketUnavailable,
		headscale.CodeUnavailable,
		headscale.CodeTimeout,
		headscale.CodeCommandFailed,
		headscale.CodeOutputInvalid,
		headscale.CodeArgumentInvalid,
		headscale.CodeCanceled,
		headscale.CodeNotFound,
		headscale.CodeAlreadyExists,
		headscale.CodeRouteInvalid,
	)

	// meshExportCodes are the client-configuration exporter refusals. They
	// describe a device input the Hub could not render, never a server fault.
	meshExportCodes = codeSet(
		subscription.CodeMeshControlURLUnavailable,
		subscription.CodeMeshControlURLInvalid,
		subscription.CodeMeshAuthKeyInvalid,
		subscription.CodeMeshHostnameInvalid,
		subscription.CodeMeshLineInTailnet,
		subscription.CodeMeshPolicyInvalid,
		subscription.CodeMeshPurposeUnsupported,
	)
)

// codeSet builds a membership set from stable code constants.
func codeSet(codes ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		set[code] = struct{}{}
	}
	return set
}

// isMeshCode reports whether code is one of the registered Mesh codes.
func isMeshCode(code string) bool {
	for _, set := range []map[string]struct{}{meshOwnCodes, meshDomainCodes, headscaleCodes, meshExportCodes} {
		if _, ok := set[code]; ok {
			return true
		}
	}
	return false
}
