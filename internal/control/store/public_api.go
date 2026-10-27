package store

// The public surface of the split store, in one place.
//
// The domains live in internal/control/store/<domain>; this file is the whole of
// what the HTTP, view and CLI layers still import. Every declaration is an alias
// or a one-line forwarder, so the split is invisible above this package and the
// root holds no behaviour of its own.
//
// A Code* constant whose literal moved into a domain is re-exported as a
// variable: the error-code golden freezes each literal where it is declared, and
// a const alias would hide the value from that scan. Nothing compares these
// values by identity, only by string.

import (
	"database/sql"
	"encoding/json"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/upgrade"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	storecandidate "github.com/wingsky-1/MeshMux/internal/control/store/candidate"
	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	storemesh "github.com/wingsky-1/MeshMux/internal/control/store/mesh"
	storenode "github.com/wingsky-1/MeshMux/internal/control/store/node"
	storepolicy "github.com/wingsky-1/MeshMux/internal/control/store/policy"
	storesubscription "github.com/wingsky-1/MeshMux/internal/control/store/subscription"
	storeupgrade "github.com/wingsky-1/MeshMux/internal/control/store/upgrade"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	nodedomain "github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	policycore "github.com/wingsky-1/MeshMux/internal/core/policy"
)

// Node is the Hub-visible record for a Line/Out host.
type Node = storenode.Node

// OutPoolEntry is one Out as the pool projection renders it.
type OutPoolEntry = storenode.OutPoolEntry

// StagedReadback is the newest staged evidence of one node.
type StagedReadback = storeupgrade.StagedReadback

// ApprovedTarget is the newest release record one node carries.
type ApprovedTarget = storeupgrade.ApprovedTarget

// SubscriberSyncSnapshot is the subscriber-level convergence summary.
// SubscriberLineSyncSnapshot is the per-Line convergence evidence.
type SubscriberLineSyncSnapshot = storesubscription.SubscriberLineSyncSnapshot

// BatchApproveOutcome is one subscriber's batch result.
type BatchApproveOutcome = storesubscription.BatchApproveOutcome

// BatchApproveResult is the whole batch result.
type BatchApproveResult = storesubscription.BatchApproveResult

// BatchOutcomeStatus is one member's outcome in a batch re-approval.
type BatchOutcomeStatus = storesubscription.BatchOutcomeStatus

// SelectionSpec is the normalized input of one selection.
type SelectionSpec = storesubscription.SelectionSpec

// SubscriptionDraft is one draft selection.
// RuleRevision pins one rule revision in a selection.
type RuleRevision = storesubscription.RuleRevision

// SelectionImpact is the read-only impact preview of one selection.
// SelectionPreview is the gated preview of one selection.
// SubscriptionDocuments is one subscriber's download artifact.
// BatchOutcomeStatus is one member's outcome in a batch re-approval.
// BatchApproveOutcome is one subscriber's batch result.
// BatchApproveResult is the whole batch result.
// PolicyLayer is a stored policy layer.
type PolicyLayer = storepolicy.PolicyLayer

// PolicyStatus is a stored policy revision status.
// RoutePolicy is one immutable policy revision.
type RoutePolicy = storepolicy.RoutePolicy

// RoutePolicyPayload is the stored intent of one revision.
type RoutePolicyPayload = storepolicy.RoutePolicyPayload

// PolicyPublication is the stored outcome of one publication.
type PolicyPublication = storepolicy.PolicyPublication

// PolicyPublishRequest is the strict body of POST /policies/publish.
type PolicyPublishRequest = storepolicy.PolicyPublishRequest

// PolicyAssembly is the gated result of one publication attempt.
type PolicyAssembly = storepolicy.PolicyAssembly

// PolicyPublishRequest is the strict body of POST /policies/publish.
// PolicyPublishReceipt is the stable publication receipt.
type PolicyPublishReceipt = storepolicy.PolicyPublishReceipt

// PolicyCheckEvidence is one kernel gate result.
type PolicyCheckEvidence = storepolicy.PolicyCheckEvidence

// PolicyCandidateEvidence references the immutable candidate a publication
// produced.
// PolicyLineEvidence is one Line's outcome in a publication.
// PolicyPublication is the stored outcome of one publication.
// PublishTarget is one Line the assembled server route is published to.
type PublishTarget = storepolicy.PublishTarget

// OutTransport is the stored dial body of one managed Out.
type OutTransport = storenode.OutTransport

// OutEgressFacts is the read-only Out half of one AI egress decision.
// OutAuthorizationPreview is the read-only authorization projection of one Out.
type OutAuthorizationPreview = storenode.OutAuthorizationPreview

// OutEgressReadback is the Hub-side dual readback of one Line.
// The subscriber state names.
const (

	// The subscriber convergence states every projection reports.
	SubscriberSyncHealthy = common.SubscriberSyncHealthy
	SubscriberSyncPending = common.SubscriberSyncPending
	SubscriberSyncPartial = common.SubscriberSyncPartial
)

// The policy layer, status and schema values.
const (
	PolicyLayerClient = storepolicy.PolicyLayerClient
	PolicyLayerServer = storepolicy.PolicyLayerServer

	PolicyDraft      = storepolicy.PolicyDraft
	PolicyActive     = storepolicy.PolicyActive
	PolicySuperseded = storepolicy.PolicySuperseded
	PolicyRevoked    = storepolicy.PolicyRevoked

	PolicySchemaVersion = storepolicy.PolicySchemaVersion

	PolicyEgressFailClosed = storepolicy.PolicyEgressFailClosed
	PolicyEgressMixed      = storepolicy.PolicyEgressMixed
)

// The batch outcome states.
const (
	BatchSaved   = storesubscription.BatchSaved
	BatchBlocked = storesubscription.BatchBlocked
	BatchFailed  = storesubscription.BatchFailed
)

const ()

// The Out and Line synchronization states the node domain owns.
const (
	OutSyncHealthy   = storenode.OutSyncHealthy
	OutSyncVerifying = storenode.OutSyncVerifying
	OutSyncPartial   = storenode.OutSyncPartial

	LineEgressDirect         = storenode.LineEgressDirect
	LineEgressExternal       = storenode.LineEgressExternal
	LineEgressHealthy        = storenode.LineEgressHealthy
	LineEgressVerifying      = storenode.LineEgressVerifying
	LineEgressPartial        = storenode.LineEgressPartial
	LineEgressPendingPreview = storenode.LineEgressPendingPreview

	OutPoolBound       = storenode.OutPoolBound
	OutPoolNoOutDirect = storenode.OutPoolNoOutDirect
	OutPoolLineDirect  = storenode.OutPoolLineDirect
)

// SubscriberChainKinds is the fixed publication chain of one candidate
// revision.
var SubscriberChainKinds = storecandidate.ChainKinds

// SyncErrorCodePattern bounds a sanitized status code.
var SyncErrorCodePattern = versions.StableCodePattern

// The mesh record types.
type (
	MeshDeviceRecord        = storemesh.MeshDeviceRecord
	MeshEnrollmentKeyRecord = storemesh.MeshEnrollmentKeyRecord
	MeshRouteRecord         = storemesh.MeshRouteRecord
	MeshRouteObservation    = storemesh.MeshRouteObservation
)

// The subscription download sentinels.
var (
	ErrSubscriptionRejected         = storesubscription.ErrSubscriptionRejected
	ErrSubscriptionStoreUnavailable = storesubscription.ErrSubscriptionStoreUnavailable
	ErrOutCleanupPending            = storenode.ErrOutCleanupPending
)

// The stable codes the domains own, re-exported by value.
var (
	CodeMeshDeviceNotFound        = storemesh.CodeMeshDeviceNotFound
	CodeMeshDeviceCorrupt         = storemesh.CodeMeshDeviceCorrupt
	CodeMeshEnrollmentKeyNotFound = storemesh.CodeMeshEnrollmentKeyNotFound
	CodeMeshRouteConflict         = storemesh.CodeMeshRouteConflict
	CodeMeshRouteNotFound         = storemesh.CodeMeshRouteNotFound
	CodeMeshRouteCorrupt          = storemesh.CodeMeshRouteCorrupt
	CodeMeshRouteUntracked        = storemesh.CodeMeshRouteUntracked

	CodeLineEgressUnverified = storenode.CodeLineEgressUnverified
	CodeLineNotAuthorized    = storenode.CodeLineNotAuthorized
	CodeOutSyncPending       = storenode.CodeOutSyncPending
	CodeOutNotAuthorized     = storenode.CodeOutNotAuthorized
	OutAclSourceMismatchCode = storenode.OutAclSourceMismatchCode

	CodePolicyLayerRetired     = storepolicy.CodePolicyLayerRetired
	CodePolicyPayloadRetired   = storepolicy.CodePolicyPayloadRetired
	CodePublishNoLines         = storepolicy.CodePublishNoLines
	CodePublishNoPolicy        = storepolicy.CodePublishNoPolicy
	CodePublishRevisionChanged = storepolicy.CodePublishRevisionChanged
	CodePublishTasksInProgress = storepolicy.CodePublishTasksInProgress

	CodeComposeGateUnavailable = storesubscription.CodeComposeGateUnavailable
	CodeComposeMihomoSkipped   = storesubscription.CodeComposeMihomoSkipped
	CodeOutSelectionConflict   = storesubscription.CodeOutSelectionConflict
	CodeOutReferenced          = storesubscription.CodeOutReferenced
	CodeSelectionInvalid       = storesubscription.CodeSelectionInvalid
	CodeArtifactDrift          = storesubscription.CodeArtifactDrift
	CodeArtifactNotApproved    = storesubscription.CodeArtifactNotApproved
	CodeComposeGateFailed      = storesubscription.CodeComposeGateFailed

	CodeUpgradeNotAdjacent       = storeupgrade.CodeUpgradeNotAdjacent
	CodeUpgradeAgentIncompatible = storeupgrade.CodeUpgradeAgentIncompatible
)

// The route event kinds the audit trail records.
const (
	RouteEventDeclared  = storemesh.RouteEventDeclared
	RouteEventApproved  = storemesh.RouteEventApproved
	RouteEventWithdrawn = storemesh.RouteEventWithdrawn
	RouteEventRevoked   = storemesh.RouteEventRevoked
)

// MeshError builds a mesh refusal with its stable code.
func MeshError(code, detail string) error { return storemesh.MeshError(code, detail) }

// ParseSelectionSpec decodes one JSON selection body into a canonical spec.
func ParseSelectionSpec(raw []byte) (SelectionSpec, error) {
	return storesubscription.ParseSelectionSpec(raw)
}

// HistoricalLineIDsTx returns every Line one subscriber references now plus
// every Line that ever carried a credential of it.
func HistoricalLineIDsTx(tx *sql.Tx, subscriberID string) ([]string, error) {
	return storesubscription.HistoricalLineIDsTx(tx, subscriberID)
}

// SubscriptionStoreError maps a store error onto the two public download
// outcomes.
func SubscriptionStoreError(err error) error { return storesubscription.SubscriptionStoreError(err) }

// SanitizeSubscriberSyncCode keeps only the stable code part of a sync error.
func SanitizeSubscriberSyncCode(raw string) string { return common.SanitizeSyncCode(raw) }

// OutAllowlistSource validates one stored allowlist source.
func OutAllowlistSource(raw string) (string, error) { return storenode.OutAllowlistSource(raw) }

// ParsePolicyPublishRequest decodes and validates the publish body.
func ParsePolicyPublishRequest(raw []byte) (PolicyPublishRequest, error) {
	return storepolicy.ParsePolicyPublishRequest(raw)
}

// PolicyPublishFailure maps one refusal onto the HTTP contract.
func PolicyPublishFailure(err error) (int, string, string) {
	return storepolicy.PolicyPublishFailure(err)
}

// PublishRetryHint is the operator next-action of one publication refusal.
func PublishRetryHint(err error) string { return storepolicy.PublishRetryHint(err) }

// PublicationReceipt renders the stable receipt of one publication.
func PublicationReceipt(assembly PolicyAssembly, publication PolicyPublication) PolicyPublishReceipt {
	return storepolicy.PublicationReceipt(assembly, publication)
}

// AggregatePolicyEgress reduces the per-Line states of one publication.
func AggregatePolicyEgress(states, codes []string) (string, string) {
	return storepolicy.AggregatePolicyEgress(states, codes)
}

// RuleUsageSource returns the control-layer implementation of policy's used-by
// port.
func RuleUsageSource() policycore.RuleUsageReader { return storepolicy.RuleUsageSource() }

// The leaf helpers and lifetimes the layers above the store use.
const (
	// CodeDatabaseUnavailable is the one "database unusable" code. The literal
	// lives in the versions leaf because the CLI, the core rule library and the
	// store all emit it.
	CodeDatabaseUnavailable = versions.CodeDatabaseUnavailable

	// SessionLifetime is the absolute lifetime of one authenticated session.
	SessionLifetime = common.SessionLifetime
	// OfflineAfter is the window after which a node that stopped contacting the
	// Hub is reported offline.
	OfflineAfter = common.OfflineAfter
	// PasswordPrefix is the stored Argon2id parameter prefix.
)

// PublishVerifier checks assembled documents with the pinned kernels.
type PublishVerifier = common.PublishVerifier

// PublishGateConfig is the deployment configuration of the gate.
type PublishGateConfig = common.PublishGateConfig

// ErrorCodeOf returns the stable code segment of err.
func ErrorCodeOf(err error) string { return common.ErrorCodeOf(err) }

// NewPublishVerifier builds the fixed kernel gate.
func NewPublishVerifier(cfg PublishGateConfig, dir string) (PublishVerifier, error) {
	return common.NewPublishVerifier(cfg, dir)
}

// HashPassword derives one Argon2id hash.
func HashPassword(password string) (string, error) { return common.HashPassword(password) }

// VerifyPassword compares a password against one stored hash.
func VerifyPassword(hash, password string) bool { return common.VerifyPassword(hash, password) }

// PasswordValid reports whether a password satisfies the policy.
func PasswordValid(password string) bool { return common.PasswordValid(password) }

// RandomToken returns one URL-safe random token.
func RandomToken() string { return common.RandomToken() }

// TokenHash returns the stored digest of a bearer token.
func TokenHash(token string) []byte { return common.TokenHash(token) }

// Equal compares two secrets without leaking their length by timing.
func Equal(a, b string) bool { return common.Equal(a, b) }

// Itoa renders an integer for an operator message.
func Itoa(n int) string { return common.Itoa(n) }

// CandidateSHA256 is the compiled digest of one candidate document.
func CandidateSHA256(document []byte) (string, error) { return storecandidate.SHA256(document) }

// InsertCandidateTx stores one immutable candidate revision.
func InsertCandidateTx(tx *sql.Tx, document node.Candidate, now int64) error {
	return storecandidate.InsertTx(tx, document, now)
}

// NextCandidateRevisionTx returns the next immutable revision of one node.
func NextCandidateRevisionTx(tx *sql.Tx, nodeID string) (int64, error) {
	return storecandidate.NextCandidateRevisionTx(tx, nodeID)
}

// NewFixedTask builds one task envelope of the fixed publication chain.
func NewFixedTask(nodeID, kind string, params json.RawMessage, revision int64) (protocol.Task, error) {
	return storecandidate.NewFixedTask(nodeID, kind, params, revision)
}

// SeedInitialTasksTx enqueues the fixed reconcile chain of a freshly paired node.
func SeedInitialTasksTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return storecandidate.SeedInitialTasksTx(tx, nodeID, now, storenode.OutAuthorizationTx)
}

// StampUpgradeTargetTx records one approved release for a node.
func StampUpgradeTargetTx(tx *sql.Tx, operationID string, target upgrade.Target, now time.Time) error {
	return storeupgrade.StampUpgradeTargetTx(tx, operationID, target, now)
}

// ApprovedReleaseChainTx returns the release versions one node's chains named.
func ApprovedReleaseChainTx(tx *sql.Tx, nodeID string) ([]string, error) {
	return storeupgrade.ApprovedReleaseChainTx(tx, nodeID)
}

// MixedVersionGate refuses to publish a candidate the node's read-back Agent
// version does not match.
func MixedVersionGate(candidate node.Candidate, observed string) error {
	return storeupgrade.MixedVersionGate(candidate, observed)
}

// BuildLineCandidateTx assembles the complete desired candidate of one node in
// the caller's transaction.
func BuildLineCandidateTx(tx *sql.Tx, nodeID string, revision int64) (node.Candidate, error) {
	return storenode.BuildLineCandidateTxTx(tx, nodeID, revision)
}

// OutEgressFactsTx is the transaction-scoped Out projection of one Line.

// CandidateUsersMatch compares a stored candidate's user set with the desired
// one.
func CandidateUsersMatch(document nodedomain.CandidateDocument, desired map[string]string) error {
	return storesubscription.CandidateUsersMatch(document, desired)
}

// LineServerRouteTx returns the route fragment a Line must publish now.

// LineServerRouteTx returns the route fragment a Line must publish now, on a
// transaction the caller owns.
func LineServerRouteTx(tx *sql.Tx, nodeID string, now time.Time) (json.RawMessage, error) {
	return storepolicy.LineServerRouteTx(tx, nodeID, now)
}

// SubscriberLineNodeOfflineTx reports whether a node is outside the delivery
// window used by the task endpoints.
func SubscriberLineNodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
	return storenode.SubscriberLineNodeOfflineTx(tx, nodeID, now)
}

// LineOutEgressStatusTx reports whether a Line may use its selected Out path.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	return storenode.LineOutEgressStatusTxTx(tx, lineID, now)
}

// OutReadbackAllowlistTx reads the allowlist the newest chain of one Out
// carried.
func OutReadbackAllowlistTx(tx *sql.Tx, outID string, revision int64) ([]string, bool, error) {
	return storenode.OutReadbackAllowlistTx(tx, outID, revision)
}

// DrainSubscriberNodeIntentTx publishes one Line's persisted intent.
func DrainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	return storesubscription.DrainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry)
}

// SubscriberLineSyncViewTx evaluates one Line against the persisted desired
// snapshot and the exact readback evidence.
func SubscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	return storesubscription.SubscriberLineSyncViewTx(tx, nodeID, now)
}

// DesiredLineDigestTx builds the desired snapshot of one Line and returns its
// compiled digest.
func DesiredLineDigestTx(tx *sql.Tx, nodeID string, now time.Time) (string, error) {
	return storesubscription.DesiredLineDigestTx(tx, nodeID, now)
}

// LatestPublishedCandidateTx reads the latest immutable candidate of one node.
func LatestPublishedCandidateTx(tx *sql.Tx, nodeID string) (int64, string, []node.VLESSUser, bool, error) {
	return storecandidate.LatestPublishedTx(tx, nodeID)
}

// SubscriberLineLatestTaskTx reports the decisive status of the newest fixed
// chain.
func SubscriberLineLatestTaskTx(tx *sql.Tx, nodeID string) (string, string, bool, error) {
	return storecandidate.LineLatestTaskTx(tx, nodeID)
}

// SubscriberLineChainHealthyTx reports whether the complete latest chain of
// exactly one candidate revision is healthy.
func SubscriberLineChainHealthyTx(tx *sql.Tx, nodeID string, revision int64) (bool, error) {
	return storecandidate.LineChainHealthyTx(tx, nodeID, revision)
}

// FinalizeDeletingSubscribersTx moves a deleting subscriber to deleted.
func FinalizeDeletingSubscribersTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return storesubscription.FinalizeDeletingSubscribersTx(tx, nodeID, now)
}

// DrainOutNodeIntentTx publishes one Out's persisted authorization intent. The
// returned outcome is the node domain's drain classification.
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (int, error) {
	outcome, err := storenode.DrainOutNodeIntentTx(tx, outID, now, allowRetry)
	return int(outcome), err
}
