package infra

import (
	"strings"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// codes.go is the single source of the error-code literals this package spells
// in more than one file. The store and the domain packages own the codes they
// produce (store.CodePolicyLayerRetired, policy.CodeOutOfflineFailClosed, …);
// every constant here is one the handler itself emits or compares against, so
// the literal exists exactly once and every use names it. The golden test in
// internal/cli/upgrade freezes the values, not the identifiers, so a rename is a
// build fix and a value change is a visible diff.
//
// The regexp aliases follow the same rule: the lexical grammar of an operation
// id, a digest and a release version is frozen in internal/cli/backup/grammar.go
// (and re-exported by internal/core/node/protocol for the wire), so this package
// imports the predicates instead of compiling a private copy that could drift
// from the producers.
const (
	// CodeNodeNotFound is the store's unknown-node refusal, re-spelled by the
	// approval and Out handlers when they map a store error onto its status.
	CodeNodeNotFound = "NODE_NOT_FOUND"
	// CodeOutNotFound, CodeOutRoleInvalid, CodeLineNotFound and
	// CodeLineRoleInvalid are the Out-management refusals of the authorization
	// projection. The store emits them; the handler maps them.
	CodeOutNotFound     = "OUT_NOT_FOUND"
	CodeOutRoleInvalid  = "OUT_ROLE_INVALID"
	CodeLineNotFound    = "LINE_NOT_FOUND"
	CodeLineRoleInvalid = "LINE_ROLE_INVALID"
	// CodeOutBindingInvalid marks an Out/Line reference that does not name a
	// usable pair. The store, the publish gate and the approval gate all emit
	// it, so the handlers compare one constant.
	CodeOutBindingInvalid = "OUT_BINDING_INVALID"
	// CodePolicyPayloadInvalid is the malformed policy JSON refusal of the
	// write API, the validate dry run and the server preview.
	CodePolicyPayloadInvalid = "POLICY_PAYLOAD_INVALID"
	// CodePolicyOperationRequired is the missing-operation_id refusal.
	CodePolicyOperationRequired = "POLICY_OPERATION_REQUIRED"
	// CodePolicyNotFound, CodePolicyConflict and CodePolicyStateInvalid are
	// the store's row-level policy refusals mapped onto the HTTP contract.
	CodePolicyNotFound     = "POLICY_NOT_FOUND"
	CodePolicyConflict     = "POLICY_CONFLICT"
	CodePolicyStateInvalid = "POLICY_STATE_INVALID"
	CodePolicyLayerInvalid = "POLICY_LAYER_INVALID"
	// CodePolicyCorrupt marks an unreadable stored policy. The approval gate
	// folds it into the chain refusal.
	CodePolicyCorrupt = "POLICY_CORRUPT"
	// CodePolicyPinsInvalid is the malformed pins JSON refusal.
	CodePolicyPinsInvalid = "POLICY_PINS_INVALID"
	// CodeTasksInProgress marks a node whose task chain is still running.
	CodeTasksInProgress = "TASKS_IN_PROGRESS"
	// CodeUpgradeAlreadyCurrent and CodeUpgradeAgentUnobserved are the
	// approval-state refusals of #11c-1.
	CodeUpgradeAlreadyCurrent  = "UPGRADE_ALREADY_CURRENT"
	CodeUpgradeAgentUnobserved = "UPGRADE_AGENT_UNOBSERVED"
	CodeUpgradeChainInvalid    = "UPGRADE_CHAIN_INVALID"
	CodeCandidateInvalid       = "CANDIDATE_INVALID"
	CodeCandidateMismatch      = "CANDIDATE_MISMATCH"
	// CodeRoleMismatch is the pairing role refusal; it is the one pairing
	// failure the response may distinguish, because it describes the caller's
	// own configuration.
	CodeRoleMismatch = "ROLE_MISMATCH"
	// CodePairingExpired and CodePairingConsumed are log-only pairing
	// reasons: the response stays a neutral PAIRING_INVALID.
	CodePairingExpired  = "PAIRING_EXPIRED"
	CodePairingConsumed = "PAIRING_CONSUMED"
	// CodeVersionInvalid and CodeIdentityIssueFailed are the remaining
	// pairing refusals with distinct statuses.
	CodeVersionInvalid      = "VERSION_INVALID"
	CodeIdentityIssueFailed = "IDENTITY_ISSUE_FAILED"
	// CodeTaskNotFound, CodeTaskAlreadyFinal, CodeTaskStateInvalid and
	// CodeTaskParamsInvalid are the agent result-state refusals.
	CodeTaskNotFound      = "TASK_NOT_FOUND"
	CodeTaskAlreadyFinal  = "TASK_ALREADY_FINAL"
	CodeTaskStateInvalid  = "TASK_STATE_INVALID"
	CodeTaskParamsInvalid = "TASK_PARAMS_INVALID"
	// CodeManifestUnavailable is shared by the release check (no pinned
	// manifest describes the release) and the Hub handoff (root manifest
	// unreadable). Same value, two producers, one constant.
	CodeManifestUnavailable = "MANIFEST_UNAVAILABLE"
)

// The handler's four body limits are the shared request grammar of the
// mutation wrapper and the agent channel. They are not configuration: raising
// one is a boundary decision, spelled once.
const (
	// MutationFormMaxBytes bounds every admin form POST (the mutation
	// wrapper) and the pairing/result agent bodies that carry JSON.
	MutationFormMaxBytes = 4096
	// HeartbeatBodyMaxBytes bounds the agent heartbeat, whose body is two
	// version strings.
	HeartbeatBodyMaxBytes = 2048
)

// NodeRoleEdge, NodeRoleOut and NodeRoleHTTP alias the node domain's frozen
// role spellings. store.Node carries Role as a string, so handlers compare
// these constants instead of raw literals.
const (
	NodeRoleEdge = string(node.RoleEdge)
	NodeRoleOut  = string(node.RoleOut)
	NodeRoleHTTP = string(node.RoleHTTP)
)

// AgentAPI reports whether the path is an outbound-Agent endpoint. These
// endpoints use Bearer identity instead of admin session + Origin, because
// the Agent connects from a remote host over HTTPS without a browser.
func AgentAPI(path string) bool { return strings.HasPrefix(path, "/api/agent/") }

// IsValidNodeID reports whether value is the fixed 32-hex node id shape. The
// grammar is the node wire contract; the handler re-names it because every
// form field and path segment passes through here before a query.
func IsValidNodeID(value string) bool { return protocol.ValidID(value) }

// IsValidOperationID reports whether value is the fixed 32-hex operation id
// shape. The journal, the request directory and the store backup gate all use
// the same frozen grammar; the handler's alias keeps that single source.
func IsValidOperationID(value string) bool { return backup.ValidOperationID(value) }

// IsValidReleaseVersion reports whether value is a pinned SemVer release. The
// shape is frozen in internal/cli/backup/grammar.go; the manifest producers and
// the approval route must accept exactly the same bytes.
func IsValidReleaseVersion(version string) bool { return backup.ValidReleaseVersion(version) }
