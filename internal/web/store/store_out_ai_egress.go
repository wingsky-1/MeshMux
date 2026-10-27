package store

// The AI egress preconditions of one Line.
//
// The Out-missing and Out-failure cases are deliberately different, and this
// projection is where the Hub states which one it is:
//
//   - no enabled binding: the Line egresses directly, which is a configured
//     state (the Out-free deployment), not a degradation;
//   - an enabled binding whose Out is offline, still converging or partially
//     failed: the facts report the Out as unavailable together with the stable
//     reason. The composer/policy resolver refuses a route that would leak from the
//     Line address rather than treating the fault as a direct egress.
//
// This file only reads. It reuses the T3 derivation (LineOutEgressStatusTx) and
// the T3 offline window, so the projection can never disagree with the Out
// synchronization or the publish gate. The former PlanAIEgress decision wrapper
// was removed in Task 6: the rule library and the subscription composer own the
// decision, and this projection is their single Out fact source.

import (
	"errors"
	"strings"
	"time"

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
	// Available is true when the Out path may carry traffic: a managed Out the
	// Agent confirmed, or an external HTTP proxy the operator declared. The
	// external case is a declaration, not a proof; ExternalDeclared and Code
	// distinguish the two, so a caller can never present a declaration as a
	// confirmed egress.
	Available bool `json:"available"`
	// ExternalDeclared is true only for the external HTTP proxy egress: the Hub
	// has no ACL, no Agent and no readback for it, so "available" is the
	// operator's own endpoint. Code carries CodeLineEgressExternalDeclared in
	// that state.
	ExternalDeclared bool `json:"external_declared,omitempty"`
	// Code is the stable reason when Configured is true and Available is
	// false: OUT_OFFLINE, OUT_SYNC_IN_PROGRESS, OUT_SYNC_PENDING,
	// LINE_NOT_AUTHORIZED, LINE_EGRESS_UNVERIFIED or the Agent's own code. It
	// also carries LINE_EGRESS_EXTERNAL_DECLARED when Available is the
	// external declaration rather than a confirmed Out.
	Code string `json:"code,omitempty"`
}

// OutEgressFacts projects one Line's AI egress preconditions at one clock.
//
// The Line must exist with the immutable edge role; a wrong role or an unknown
// id is rejected instead of being reported as "no Out", because silently
// treating an Out node as a Line would hide an operator mistake behind a
// healthy-looking direct egress.
func (s *Store) OutEgressFacts(lineID string, now time.Time) (OutEgressFacts, error) {
	lineID = strings.TrimSpace(lineID)
	if err := subscription.ValidateID(lineID); err != nil {
		return OutEgressFacts{}, errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return OutEgressFacts{}, errors.New("DATABASE_UNAVAILABLE")
	}
	defer tx.Rollback()
	return outEgressFactsTx(tx, lineID, now)
}
