package handler

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
	// codeNodeNotFound is the store's unknown-node refusal, re-spelled by the
	// approval and Out handlers when they map a store error onto its status.
	codeNodeNotFound = "NODE_NOT_FOUND"
	// codeOutNotFound, codeOutRoleInvalid, codeLineNotFound and
	// codeLineRoleInvalid are the Out-management refusals of the authorization
	// projection. The store emits them; the handler maps them.
	codeOutNotFound     = "OUT_NOT_FOUND"
	codeOutRoleInvalid  = "OUT_ROLE_INVALID"
	codeLineNotFound    = "LINE_NOT_FOUND"
	codeLineRoleInvalid = "LINE_ROLE_INVALID"
	// codeOutBindingInvalid marks an Out/Line reference that does not name a
	// usable pair. The store, the publish gate and the approval gate all emit
	// it, so the handlers compare one constant.
	codeOutBindingInvalid = "OUT_BINDING_INVALID"
	// codePolicyPayloadInvalid is the malformed policy JSON refusal of the
	// write API, the validate dry run and the server preview.
	codePolicyPayloadInvalid = "POLICY_PAYLOAD_INVALID"
	// codePolicyOperationRequired is the missing-operation_id refusal.
	codePolicyOperationRequired = "POLICY_OPERATION_REQUIRED"
	// codePolicyNotFound, codePolicyConflict and codePolicyStateInvalid are
	// the store's row-level policy refusals mapped onto the HTTP contract.
	codePolicyNotFound     = "POLICY_NOT_FOUND"
	codePolicyConflict     = "POLICY_CONFLICT"
	codePolicyStateInvalid = "POLICY_STATE_INVALID"
	codePolicyLayerInvalid = "POLICY_LAYER_INVALID"
	// codePolicyCorrupt marks an unreadable stored policy. The approval gate
	// folds it into the chain refusal.
	codePolicyCorrupt = "POLICY_CORRUPT"
	// codePolicyPinsInvalid is the malformed pins JSON refusal.
	codePolicyPinsInvalid = "POLICY_PINS_INVALID"
	// codeTasksInProgress marks a node whose task chain is still running.
	codeTasksInProgress = "TASKS_IN_PROGRESS"
	// codeUpgradeAlreadyCurrent and codeUpgradeAgentUnobserved are the
	// approval-state refusals of #11c-1.
	codeUpgradeAlreadyCurrent  = "UPGRADE_ALREADY_CURRENT"
	codeUpgradeAgentUnobserved = "UPGRADE_AGENT_UNOBSERVED"
	codeUpgradeChainInvalid    = "UPGRADE_CHAIN_INVALID"
	codeCandidateInvalid       = "CANDIDATE_INVALID"
	codeCandidateMismatch      = "CANDIDATE_MISMATCH"
	// codeRoleMismatch is the pairing role refusal; it is the one pairing
	// failure the response may distinguish, because it describes the caller's
	// own configuration.
	codeRoleMismatch = "ROLE_MISMATCH"
	// codePairingExpired and codePairingConsumed are log-only pairing
	// reasons: the response stays a neutral PAIRING_INVALID.
	codePairingExpired  = "PAIRING_EXPIRED"
	codePairingConsumed = "PAIRING_CONSUMED"
	// codeVersionInvalid and codeIdentityIssueFailed are the remaining
	// pairing refusals with distinct statuses.
	codeVersionInvalid      = "VERSION_INVALID"
	codeIdentityIssueFailed = "IDENTITY_ISSUE_FAILED"
	// codeTaskNotFound, codeTaskAlreadyFinal, codeTaskStateInvalid and
	// codeTaskParamsInvalid are the agent result-state refusals.
	codeTaskNotFound      = "TASK_NOT_FOUND"
	codeTaskAlreadyFinal  = "TASK_ALREADY_FINAL"
	codeTaskStateInvalid  = "TASK_STATE_INVALID"
	codeTaskParamsInvalid = "TASK_PARAMS_INVALID"
	// codeManifestUnavailable is shared by the release check (no pinned
	// manifest describes the release) and the Hub handoff (root manifest
	// unreadable). Same value, two producers, one constant.
	codeManifestUnavailable = "MANIFEST_UNAVAILABLE"
)

// The handler's four body limits are the shared request grammar of the
// mutation wrapper and the agent channel. They are not configuration: raising
// one is a boundary decision, spelled once.
const (
	// mutationFormMaxBytes bounds every admin form POST (the mutation
	// wrapper) and the pairing/result agent bodies that carry JSON.
	mutationFormMaxBytes = 4096
	// heartbeatBodyMaxBytes bounds the agent heartbeat, whose body is two
	// version strings.
	heartbeatBodyMaxBytes = 2048
)

// nodeRoleEdge, nodeRoleOut and nodeRoleHTTP alias the node domain's frozen
// role spellings. store.Node carries Role as a string, so handlers compare
// these constants instead of raw literals.
const (
	nodeRoleEdge = string(node.RoleEdge)
	nodeRoleOut  = string(node.RoleOut)
	nodeRoleHTTP = string(node.RoleHTTP)
)

// agentAPI reports whether the path is an outbound-Agent endpoint. These
// endpoints use Bearer identity instead of admin session + Origin, because
// the Agent connects from a remote host over HTTPS without a browser.
func agentAPI(path string) bool { return strings.HasPrefix(path, "/api/agent/") }

// isValidNodeID reports whether value is the fixed 32-hex node id shape. The
// grammar is the node wire contract; the handler re-names it because every
// form field and path segment passes through here before a query.
func isValidNodeID(value string) bool { return protocol.ValidID(value) }

// isValidOperationID reports whether value is the fixed 32-hex operation id
// shape. The journal, the request directory and the store backup gate all use
// the same frozen grammar; the handler's alias keeps that single source.
func isValidOperationID(value string) bool { return backup.ValidOperationID(value) }

// isValidReleaseVersion reports whether value is a pinned SemVer release. The
// shape is frozen in internal/cli/backup/grammar.go; the manifest producers and
// the approval route must accept exactly the same bytes.
func isValidReleaseVersion(version string) bool { return backup.ValidReleaseVersion(version) }
