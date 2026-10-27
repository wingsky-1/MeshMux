package store

// The public surface of the split store, in one place.
//
// The domains live in internal/control/store/<domain>; this file is the whole of
// what the HTTP, view and CLI layers still import. Every declaration is an alias
// or a one-line forwarder — the root holds no behaviour of its own.
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
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	policycore "github.com/wingsky-1/MeshMux/internal/core/policy"
)

// The record and projection types the upper layers name.

type (
	// Node is the Hub-visible record for a Line/Out host.
	Node = storenode.Node
	// OutPoolEntry is one Out as the pool projection renders it.
	OutPoolEntry = storenode.OutPoolEntry
	// OutTransport is the stored dial body of one managed Out.
	OutTransport = storenode.OutTransport
	// HTTPProxy is the operator-visible half of one external HTTP proxy.
	HTTPProxy = storenode.HTTPProxy
	// OutEgressFacts is the read-only Out half of one AI egress decision.
	OutEgressFacts = storenode.OutEgressFacts
	// OutAuthorizationPreview is the read-only authorization projection of one Out.
	OutAuthorizationPreview = storenode.OutAuthorizationPreview
	// OutEgressReadback is the Hub-side dual readback of one Line.
	OutEgressReadback = storenode.OutEgressReadback

	// MeshDeviceRecord is one stored mesh device plus its audit fields.
	MeshDeviceRecord = storemesh.MeshDeviceRecord
	// MeshEnrollmentKeyRecord is the persisted view of one one-time key.
	MeshEnrollmentKeyRecord = storemesh.MeshEnrollmentKeyRecord
	// MeshRouteRecord is one stored subnet route.
	MeshRouteRecord = storemesh.MeshRouteRecord
	// MeshRouteObservation is one observed route state.
	MeshRouteObservation = storemesh.MeshRouteObservation

	// RoutePolicy is one immutable policy revision.
	RoutePolicy = storepolicy.RoutePolicy
	// RoutePolicyPayload is the stored intent of one revision.
	RoutePolicyPayload = storepolicy.RoutePolicyPayload
	// PolicyLayer is a stored policy layer.
	PolicyLayer = storepolicy.PolicyLayer
	// PolicyStatus is a stored policy revision status.
	PolicyStatus = storepolicy.PolicyStatus
	// PolicyAssembly is the gated result of one publication attempt.
	PolicyAssembly = storepolicy.PolicyAssembly
	// PolicyPublishRequest is the strict body of POST /policies/publish.
	PolicyPublishRequest = storepolicy.PolicyPublishRequest
	// PolicyPublishReceipt is the stable publication receipt.
	PolicyPublishReceipt = storepolicy.PolicyPublishReceipt
	// PolicyCheckEvidence is one kernel gate result.
	PolicyCheckEvidence = storepolicy.PolicyCheckEvidence
	// PolicyCandidateEvidence references the immutable candidate a publication
	// produced.
	PolicyCandidateEvidence = storepolicy.PolicyCandidateEvidence
	// PolicyLineEvidence is one Line's outcome in a publication.
	PolicyLineEvidence = storepolicy.PolicyLineEvidence
	// PolicyPublication is the stored outcome of one publication.
	PolicyPublication = storepolicy.PolicyPublication
	// PublishTarget is one Line the assembled server route is published to.
	PublishTarget = storepolicy.PublishTarget

	// SelectionSpec is the normalized input of one selection.
	SelectionSpec = storesubscription.SelectionSpec
	// SubscriptionDraft is one draft selection.
	SubscriptionDraft = storesubscription.SubscriptionDraft
	// SelectionPreview is the gated preview of one selection.
	SelectionPreview = storesubscription.SelectionPreview
	// SelectionImpact is the read-only impact preview of one selection.
	SelectionImpact = storesubscription.SelectionImpact
	// SubscriptionDocuments is one subscriber's download artifact.
	SubscriptionDocuments = storesubscription.SubscriptionDocuments
	// RuleRevision pins one rule revision in a selection.
	RuleRevision = storesubscription.RuleRevision
	// SubscriberSyncSnapshot is the subscriber-level convergence summary.
	SubscriberSyncSnapshot = storesubscription.SubscriberSyncSnapshot
	// SubscriberLineSyncSnapshot is the per-Line convergence evidence.
	SubscriberLineSyncSnapshot = storesubscription.SubscriberLineSyncSnapshot
	// BatchOutcomeStatus is one member's outcome in a batch re-approval.
	BatchOutcomeStatus = storesubscription.BatchOutcomeStatus
	// BatchApproveOutcome is one subscriber's batch result.
	BatchApproveOutcome = storesubscription.BatchApproveOutcome
	// BatchApproveResult is the whole batch result.
	BatchApproveResult = storesubscription.BatchApproveResult

	// StagedReadback is the newest staged evidence of one node.
	StagedReadback = storeupgrade.StagedReadback
	// ApprovedTarget is the newest release record one node carries.
	ApprovedTarget = storeupgrade.ApprovedTarget
	// ApprovedUpgrade is the result of one approval.
	ApprovedUpgrade = storeupgrade.ApprovedUpgrade

	// PublishVerifier checks assembled documents with the pinned kernels.
	PublishVerifier = common.PublishVerifier
	// PublishGateConfig is the deployment configuration of the gate.
	PublishGateConfig = common.PublishGateConfig
)

// The leaf helpers and lifetimes.

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
	PasswordPrefix = common.PasswordPrefix
)

func ErrorCodeOf(err error) string          { return common.ErrorCodeOf(err) }
func HashPassword(p string) (string, error) { return common.HashPassword(p) }
func VerifyPassword(h, p string) bool       { return common.VerifyPassword(h, p) }
func PasswordValid(p string) bool           { return common.PasswordValid(p) }
func RandomToken() string                   { return common.RandomToken() }
func TokenHash(t string) []byte             { return common.TokenHash(t) }
func Equal(a, b string) bool                { return common.Equal(a, b) }
func Itoa(n int) string                     { return common.Itoa(n) }

func NewPublishVerifier(cfg PublishGateConfig, dir string) (PublishVerifier, error) {
	return common.NewPublishVerifier(cfg, dir)
}

// The Out and Line synchronization states.

const (
	OutSyncHealthy   = storenode.OutSyncHealthy
	OutSyncVerifying = storenode.OutSyncVerifying
	OutSyncPending   = storenode.OutSyncPending
	OutSyncPartial   = storenode.OutSyncPartial

	LineEgressDirect         = storenode.LineEgressDirect
	LineEgressExternal       = storenode.LineEgressExternal
	LineEgressHealthy        = storenode.LineEgressHealthy
	LineEgressVerifying      = storenode.LineEgressVerifying
	LineEgressPartial        = storenode.LineEgressPartial
	LineEgressPendingPreview = storenode.LineEgressPendingPreview

	OutPoolBound       = storenode.OutPoolBound
	OutPoolLineDirect  = storenode.OutPoolLineDirect
	OutPoolNoOutDirect = storenode.OutPoolNoOutDirect
)

// The subscriber convergence states and batch outcomes.

const (
	SubscriberSyncHealthy = common.SubscriberSyncHealthy
	SubscriberSyncPending = common.SubscriberSyncPending
	SubscriberSyncPartial = common.SubscriberSyncPartial

	BatchSaved   = storesubscription.BatchSaved
	BatchBlocked = storesubscription.BatchBlocked
	BatchFailed  = storesubscription.BatchFailed
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

// The route event kinds the mesh audit trail records.

const (
	RouteEventDeclared  = storemesh.RouteEventDeclared
	RouteEventApproved  = storemesh.RouteEventApproved
	RouteEventWithdrawn = storemesh.RouteEventWithdrawn
	RouteEventRevoked   = storemesh.RouteEventRevoked
)

// SubscriberChainKinds is the fixed publication chain of one candidate
// revision.
var SubscriberChainKinds = storecandidate.ChainKinds

// SyncErrorCodePattern bounds a sanitized status code.
var SyncErrorCodePattern = versions.StableCodePattern

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

	CodeLineEgressUnverified       = storenode.CodeLineEgressUnverified
	CodeLineEgressExternalDeclared = storenode.CodeLineEgressExternalDeclared
	CodeLineNotAuthorized          = storenode.CodeLineNotAuthorized
	CodeOutSyncInProgress          = storenode.CodeOutSyncInProgress
	CodeOutSyncPending             = storenode.CodeOutSyncPending
	CodeOutSyncNotApplicable       = storenode.CodeOutSyncNotApplicable
	CodeOutNotAuthorized           = storenode.CodeOutNotAuthorized
	OutAclSourceMismatchCode       = storenode.OutAclSourceMismatchCode

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

// MeshError builds a mesh refusal with its stable code.
func MeshError(code, detail string) error { return storemesh.MeshError(code, detail) }

// SubscriptionStoreError maps a store error onto the two public download
// outcomes.
func SubscriptionStoreError(err error) error { return storesubscription.SubscriptionStoreError(err) }

// SanitizeSubscriberSyncCode keeps only the stable code part of a sync error.
func SanitizeSubscriberSyncCode(raw string) string { return common.SanitizeSyncCode(raw) }

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

// The candidate/task helpers.

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
	return storecandidate.SeedInitialTasksTx(tx, nodeID, now)
}

// LatestPublishedCandidateTx reads the latest immutable candidate of one node.
func LatestPublishedCandidateTx(tx *sql.Tx, nodeID string) (int64, string, []node.VLESSUser, bool, error) {
	return storecandidate.LatestPublishedTx(tx, nodeID)
}

// SubscriberLineLatestTaskTx reports the decisive status of the newest fixed
// chain of one Line.
func SubscriberLineLatestTaskTx(tx *sql.Tx, nodeID string) (string, string, bool, error) {
	return storecandidate.LineLatestTaskTx(tx, nodeID)
}

// SubscriberLineChainHealthyTx reports whether the complete latest chain of
// exactly one candidate revision is healthy.
func SubscriberLineChainHealthyTx(tx *sql.Tx, nodeID string, revision int64) (bool, error) {
	return storecandidate.LineChainHealthyTx(tx, nodeID, revision)
}

// The node-side transaction-scoped entry points.

// BuildLineCandidateTx assembles the complete desired candidate of one node.
func BuildLineCandidateTx(tx *sql.Tx, nodeID string, revision int64) (node.Candidate, error) {
	return storenode.BuildLineCandidateTx(tx, nodeID, revision)
}

// LineOutEgressStatusTx reports whether a Line may use its selected Out path.
func LineOutEgressStatusTx(tx *sql.Tx, lineID string, now time.Time) (string, string, error) {
	return storenode.LineOutEgressStatusTx(tx, lineID, now)
}

// OutEgressFactsTx is the transaction-scoped Out projection of one Line.
func OutEgressFactsTx(tx *sql.Tx, lineID string, now time.Time) (OutEgressFacts, error) {
	return storenode.OutEgressFactsTx(tx, lineID, now)
}

// DrainOutNodeIntentTx publishes one Out's persisted authorization intent. The
// returned outcome is the node domain's drain classification.
func DrainOutNodeIntentTx(tx *sql.Tx, outID string, now time.Time, allowRetry bool) (int, error) {
	outcome, err := storenode.DrainOutNodeIntentTx(tx, outID, now, allowRetry)
	return int(outcome), err
}

// SubscriberLineNodeOfflineTx reports whether a node is outside the delivery
// window used by the task endpoints.
func SubscriberLineNodeOfflineTx(tx *sql.Tx, nodeID string, now time.Time) (bool, error) {
	return storenode.SubscriberLineNodeOfflineTx(tx, nodeID, now)
}

// The subscription-side transaction-scoped entry points.

// DesiredLineDigestTx builds the desired snapshot of one Line and returns its
// compiled digest.
func DesiredLineDigestTx(tx *sql.Tx, nodeID string, now time.Time) (string, error) {
	return storesubscription.DesiredLineDigestTx(tx, nodeID, now)
}

// SubscriberLineSyncViewTx evaluates one Line against the persisted desired
// snapshot and the exact readback evidence.
func SubscriberLineSyncViewTx(tx *sql.Tx, nodeID string, now time.Time) (string, string, error) {
	return storesubscription.SubscriberLineSyncViewTx(tx, nodeID, now)
}

// DrainSubscriberNodeIntentTx publishes one Line's persisted intent.
func DrainSubscriberNodeIntentTx(tx *sql.Tx, nodeID string, now time.Time, allowRetry bool) error {
	return storesubscription.DrainSubscriberNodeIntentTx(tx, nodeID, now, allowRetry)
}

// FinalizeDeletingSubscribersTx moves a deleting subscriber to deleted.
func FinalizeDeletingSubscribersTx(tx *sql.Tx, nodeID string, now time.Time) error {
	return storesubscription.FinalizeDeletingSubscribersTx(tx, nodeID, now)
}

// HistoricalLineIDsTx returns every Line one subscriber references now plus
// every Line that ever carried a credential of it.
func HistoricalLineIDsTx(tx *sql.Tx, subscriberID string) ([]string, error) {
	return storesubscription.HistoricalLineIDsTx(tx, subscriberID)
}

// ParseSelectionSpec decodes one JSON selection body into a canonical spec.
func ParseSelectionSpec(raw []byte) (SelectionSpec, error) {
	return storesubscription.ParseSelectionSpec(raw)
}

// CandidateUsersMatch compares a stored candidate's user set with the desired
// one.
func CandidateUsersMatch(document node.CandidateDocument, desired map[string]string) error {
	return storesubscription.CandidateUsersMatch(document, desired)
}

// The upgrade entry points.

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
