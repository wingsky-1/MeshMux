package mesh

// The Mesh code vocabulary the Mesh pages render, re-exported by name for the
// root package's HTTP tests. They pin the exact bodies a page or a JSON receipt
// produces after a stop-the-world refactor, so the names have to cross the
// package boundary; the values and their single definition stay in codes.go,
// devices.go and config.go.
const (
	CodeMeshInternalError                 = codeMeshInternalError
	CodeMeshHeadscaleUserUnknown          = codeMeshHeadscaleUserUnknown
	CodeMeshDeviceNotReenrollable         = codeMeshDeviceNotReenrollable
	CodeMeshDeviceCreateFailed            = codeMeshDeviceCreateFailed
	CodeMeshDeviceKeyIssue                = codeMeshDeviceKeyIssue
	CodeMeshDeviceRekeyFailed             = codeMeshDeviceRekeyFailed
	CodeMeshDeviceRevokeFailed            = codeMeshDeviceRevokeFailed
	CodeMeshReconcileFailed               = codeMeshReconcileFailed
	CodeMeshRouteApproval                 = codeMeshRouteApproval
	CodeMeshRouteWithdraw                 = codeMeshRouteWithdraw
	CodeMeshRouteApprovalPartial          = codeMeshRouteApprovalPartial
	CodeMeshRouteWithdrawPartial          = codeMeshRouteWithdrawPartial
	CodeMeshRouteApprovalUnconfirmed      = codeMeshRouteApprovalUnconfirmed
	CodeMeshRouteNodeUnobserved           = codeMeshRouteNodeUnobserved
	CodeMeshRouteUntrackedDropped         = codeMeshRouteUntrackedDropped
	CodeMeshRouteCompensated              = codeMeshRouteCompensated
	CodeMeshEndpointControlURLUnavailable = codeMeshEndpointControlURLUnavailable
	CodeMeshEndpointPurposeUnsupported    = codeMeshEndpointPurposeUnsupported
	CodeMeshEndpointSubscriberUnavailable = codeMeshEndpointSubscriberUnavailable
	CodeMeshEndpointKeyIssueFailed        = codeMeshEndpointKeyIssueFailed
	CodeMeshEndpointRenderFailed          = codeMeshEndpointRenderFailed
	CodeMeshClaimNodeNotFound             = codeMeshClaimNodeNotFound
	CodeMeshClaimNodeMismatch             = codeMeshClaimNodeMismatch
	CodeMeshClaimNodeOccupied             = codeMeshClaimNodeOccupied
	CodeMeshClaimFailed                   = codeMeshClaimFailed
)
