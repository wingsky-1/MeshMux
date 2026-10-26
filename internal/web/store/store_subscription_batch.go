package store

// Extension point 2: one-key re-approval (batch approve).
//
// The model is deliberately one transaction per subscription: a fleet-wide
// re-approval must be able to succeed partially, and a failure on one subscriber
// must not roll back another subscriber's already-durable approval. The caller
// receives one outcome per requested subscriber, in request order, so a page can
// report "3 saved, 1 blocked, 1 failed" honestly.
//
// Flow of one batch:
//
//	request ids -> shape validation (fail closed, before any work) ->
//	for each id: draft -> gate -> save (own transaction) -> outcome
//
// Each step reuses the single-subscriber path, so a batch can never approve
// something the single save would refuse. No new gating, ordering or writing
// rule exists here.
//
// Audit: BatchApproveResult carries the count and the per-id stable code; the
// handler logs one event per outcome, so a partial batch is auditable per
// subscriber rather than as one opaque operation.

import (
	"context"
	"errors"
	"strconv"
	"time"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// BatchOutcomeStatus is the terminal state of one batch member.
type BatchOutcomeStatus string

const (
	// BatchSaved: the draft was approved and persisted.
	BatchSaved BatchOutcomeStatus = "saved"
	// BatchBlocked: a blocking diagnostic refused the artifact; nothing was
	// written for this subscriber.
	BatchBlocked BatchOutcomeStatus = "blocked"
	// BatchFailed: the save itself failed (database, or a record that no longer
	// resolves). The subscriber's previous state is untouched.
	BatchFailed BatchOutcomeStatus = "failed"
)

// BatchApproveOutcome is one member's result. It carries the stable code, never
// a diagnostic detail, so a batch report cannot leak a credential or a Line.
type BatchApproveOutcome struct {
	SubscriberID string
	Status       BatchOutcomeStatus
	// Code is the first blocking code for a blocked member, or the stable
	// failure code for a failed one. Empty on success.
	Code string
	// ArtifactID is the approved digest of a saved member.
	ArtifactID string
}

// BatchApproveResult is the whole batch: one outcome per requested subscriber,
// in request order, plus the counts a page renders.
type BatchApproveResult struct {
	Outcomes []BatchApproveOutcome
	Saved    int
	Blocked  int
	Failed   int
}

// Complete reports whether every requested subscriber was saved.
func (r BatchApproveResult) Complete() bool {
	return len(r.Outcomes) > 0 && r.Saved == len(r.Outcomes)
}

// BatchApproveSubscriptions re-approves the saved selection of every requested
// subscriber.
//
// It reads each subscriber's CURRENT stored selection, so the operator approves
// what is stored rather than an old form body; a subscriber without a saved
// selection is reported as failed with SUBSCRIPTION_ARTIFACT_NOT_APPROVED-style
// vocabulary instead of silently doing nothing.
func (s *Store) BatchApproveSubscriptions(ctx context.Context, subscriberIDs []string, verifier PublishVerifier, now time.Time) (BatchApproveResult, error) {
	ids, err := normalizeBatchIDs(subscriberIDs)
	if err != nil {
		return BatchApproveResult{}, err
	}
	result := BatchApproveResult{Outcomes: make([]BatchApproveOutcome, 0, len(ids))}
	for _, subscriberID := range ids {
		outcome := s.approveStoredSelection(ctx, subscriberID, verifier, now)
		switch outcome.Status {
		case BatchSaved:
			result.Saved++
		case BatchBlocked:
			result.Blocked++
		default:
			result.Failed++
		}
		result.Outcomes = append(result.Outcomes, outcome)
	}
	return result, nil
}

// approveStoredSelection re-approves one subscriber's stored selection. It is
// one member of a batch and one transaction of its own.
func (s *Store) approveStoredSelection(ctx context.Context, subscriberID string, verifier PublishVerifier, now time.Time) BatchApproveOutcome {
	outcome := BatchApproveOutcome{SubscriberID: subscriberID}
	stored, saved, err := s.SubscriptionSelection(subscriberID)
	if err != nil {
		outcome.Status, outcome.Code = refusalStatus(err), ErrorCodeOf(err)
		return outcome
	}
	if !saved {
		outcome.Status, outcome.Code = BatchBlocked, CodeArtifactNotApproved
		return outcome
	}
	draft, err := s.draftStoredSelection(subscriberID, stored)
	if err != nil {
		outcome.Status, outcome.Code = refusalStatus(err), ErrorCodeOf(err)
		return outcome
	}
	preview := runComposeGate(ctx, draft.inputs, verifier, draft.diagnostics)
	if preview.Blocking() {
		outcome.Status, outcome.Code = BatchBlocked, preview.Code()
		return outcome
	}
	if _, err := s.SaveSubscriptionDraft(draft, preview.ContentID, now); err != nil {
		outcome.Status, outcome.Code = refusalStatus(err), ErrorCodeOf(err)
		return outcome
	}
	outcome.Status, outcome.ArtifactID = BatchSaved, preview.ContentID
	return outcome
}

// draftStoredSelection rebuilds a draft from one already-stored selection
// without re-reading the reference tables' business meaning: the stored edges
// are canonical, so the draft only has to carry them, their credentials and the
// composer inputs.
func (s *Store) draftStoredSelection(subscriberID string, stored subscription.Selection) (SubscriptionDraft, error) {
	spec := SelectionSpec{OutID: outIDOf(stored)}
	for _, line := range stored.Ordered().Lines {
		spec.LineIDs = append(spec.LineIDs, line.NodeID)
	}
	for _, rule := range stored.Ordered().Rules {
		spec.Rules = append(spec.Rules, RuleRevision{StableKey: rule.StableKey, Version: rule.Version})
	}
	for _, device := range stored.Ordered().Networks {
		spec.NetworkIDs = append(spec.NetworkIDs, device.DeviceID)
	}
	// The draft rebuilds the same references and derives the next snapshot
	// version, so a re-approval is a new snapshot identity over the same choice
	// — exactly like pressing save in the wizard. Nothing from the request body
	// reaches this path: the only input is the stored row.
	draft, err := s.DraftSubscriptionSelection(subscriberID, "", spec)
	if err != nil {
		return SubscriptionDraft{}, err
	}
	// The references must still be the ones that were saved; a concurrent edit
	// between the read and the draft is a refusal rather than a silent
	// re-approval of a different choice.
	if !sameReferences(draft.Selection, stored) {
		return SubscriptionDraft{}, errors.New(CodeSelectionInvalid + ": the stored selection changed during re-approval")
	}
	return draft, nil
}

// sameReferences reports whether two selections name exactly the same ordered
// references. Neither the snapshot version nor the informational candidate
// revision is compared: a re-approval advances the first on purpose, and the
// second is a read-time observation, not part of the choice.
func sameReferences(left, right subscription.Selection) bool {
	left, right = left.Ordered(), right.Ordered()
	if len(left.Lines) != len(right.Lines) || len(left.Rules) != len(right.Rules) || len(left.Networks) != len(right.Networks) {
		return false
	}
	for index := range left.Lines {
		if left.Lines[index].NodeID != right.Lines[index].NodeID || left.Lines[index].Position != right.Lines[index].Position {
			return false
		}
	}
	for index := range left.Rules {
		if left.Rules[index] != right.Rules[index] {
			return false
		}
	}
	for index := range left.Networks {
		if left.Networks[index] != right.Networks[index] {
			return false
		}
	}
	switch {
	case left.Out == nil && right.Out == nil:
		return true
	case left.Out == nil || right.Out == nil:
		return false
	default:
		return left.Out.OutID == right.Out.OutID && left.Out.Position == right.Out.Position
	}
}

// refusalStatus classifies one member's error. A database failure is the only
// "failed" outcome: the member's state is unknown, so the operator must look.
// Every other refusal is a stable answer ("this subscriber cannot be approved in
// its current state"), which is a blocked member and leaves the previous state
// untouched — the same distinction the single-subscriber path draws between a
// diagnostic and an error.
func refusalStatus(err error) BatchOutcomeStatus {
	if ErrorCodeOf(err) == CodeDatabaseUnavailable {
		return BatchFailed
	}
	return BatchBlocked
}

// normalizeBatchIDs accepts at most one bounded page of subscribers and
// refuses a non-canonical identity before any work starts.
func normalizeBatchIDs(subscriberIDs []string) ([]string, error) {
	if len(subscriberIDs) == 0 {
		return nil, errors.New(CodeSelectionInvalid + ": name at least one subscriber")
	}
	if len(subscriberIDs) > maxBatchSubscribers {
		return nil, errors.New(CodeSelectionInvalid + ": at most " + strconv.Itoa(maxBatchSubscribers) + " subscribers per batch")
	}
	seen := make(map[string]struct{}, len(subscriberIDs))
	ids := make([]string, 0, len(subscriberIDs))
	for _, raw := range subscriberIDs {
		id := raw
		if err := subscription.ValidateID(id); err != nil {
			return nil, errSubscriberIDInvalid()
		}
		if _, duplicate := seen[id]; duplicate {
			continue
		}
		seen[id] = struct{}{}
		ids = append(ids, id)
	}
	return ids, nil
}
