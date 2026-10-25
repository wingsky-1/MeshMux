package web

// The AI egress preconditions of one Line.
//
// The Out-missing and Out-failure cases are deliberately different, and this
// projection is where the Hub states which one it is:
//
//   - no enabled binding: the Line egresses directly, which is a configured
//     state (the Out-free deployment), not a degradation;
//   - an enabled binding whose Out is offline, still converging or partially
//     failed: the AI traffic must not fall back to the Line on its own. The
//     facts report the Out as unavailable together with the stable reason, so
//     the decision layer refuses the publication instead of publishing a path
//     that would leak from the Line address.
//
// This file only reads. It reuses the T3 derivation (lineOutEgressStatusTx) and
// the T3 offline window, so the AI decision can never disagree with the Out
// synchronization or the publish gate. It does not add a ruleset marketplace,
// multi-Out load balancing or latency probing.

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/route"
	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// OutEgressFacts is the read-only Out half of one AI egress decision. It
// carries no address, allowlist entry or credential.
type OutEgressFacts struct {
	LineID string `json:"line_id"`
	// OutID is the bound Out, empty when no Out serves the Line.
	OutID string `json:"out_id,omitempty"`
	// Configured is true when at least one enabled binding exists. A false
	// value means "direct by configuration", never "the Out broke".
	Configured bool `json:"configured"`
	// Available is true only when the Out path is confirmed healthy and the
	// Out is currently reporting.
	Available bool `json:"available"`
	// Code is the stable reason when Configured is true and Available is
	// false: OUT_OFFLINE, OUT_SYNC_IN_PROGRESS, OUT_SYNC_PENDING,
	// LINE_NOT_AUTHORIZED, LINE_EGRESS_UNVERIFIED or the Agent's own code.
	Code string `json:"code,omitempty"`
}

// OutEgressFacts projects one Line's AI egress preconditions at one clock.
//
// The Line must exist with the immutable edge role; a wrong role or an unknown
// id is rejected instead of being reported as "no Out", because silently
// treating an Out node as a Line would hide an operator mistake behind a
// healthy-looking direct egress.
func (s *store) OutEgressFacts(lineID string, now time.Time) (OutEgressFacts, error) {
	lineID = strings.TrimSpace(lineID)
	if err := subscription.ValidateID(lineID); err != nil {
		return OutEgressFacts{}, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.db.Begin()
	if err != nil {
		return OutEgressFacts{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	return outEgressFactsTx(tx, lineID, now)
}

// aiEgressPlan pairs one resolved decision with the facts it was derived from,
// so a caller can render the reason without re-reading the store.
type aiEgressPlan struct {
	Decision route.AIEgressDecision
	Facts    OutEgressFacts
}

// planAIEgress resolves one Line's AI egress: it reads the Out facts and asks
// the route package for the decision, so the Out-missing case stays a
// configured Line egress and every Out fault stays fail-closed.
//
// The request operation id is passed through so an explicit Line fallback is
// recorded with the deviation instead of being silently taken. A refusal is
// returned as a *route.BlockedError; the caller reports its code and detail.
// A nil fetcher selects the production HTTPS fetcher; the seam exists so a
// caller can resolve the pin from an already verified artifact.
//
// The publication path that renders the client document from this decision is
// deliberately out of #8's scope: this is the selection rule, not the renderer.
func (s *store) planAIEgress(ctx context.Context, fetch route.RulesetFetcher, lineID string, pin route.RulesetPin, fallbackToLine bool, operationID string, now time.Time) (aiEgressPlan, error) {
	facts, err := s.OutEgressFacts(lineID, now)
	if err != nil {
		return aiEgressPlan{}, err
	}
	decision, err := route.DecideAIEgressWithFetcher(ctx, fetch, route.AIEgressRequest{
		LineID:         facts.LineID,
		OutID:          facts.OutID,
		OutConfigured:  facts.Configured,
		OutAvailable:   facts.Available,
		OutCode:        facts.Code,
		Pin:            pin,
		FallbackToLine: fallbackToLine,
		OperationID:    operationID,
	})
	if err != nil {
		return aiEgressPlan{Facts: facts}, err
	}
	return aiEgressPlan{Decision: decision, Facts: facts}, nil
}
