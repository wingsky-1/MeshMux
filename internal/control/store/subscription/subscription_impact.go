package subscription

// Extension point 1: impact preview.
//
// Before anything is written, the operator asks "who else does this change
// touch?". The answer is derived from the same edge tables the save writes, in
// one read transaction, and it never composes a document or runs a gate.
//
// Flow:
//
//	SelectionSpec -> Normalize (shape) -> one read transaction:
//	  other active subscriptions on the selected Lines (their Line publication
//	    changes, because a Line publishes one listener for every subscriber)
//	  selected Out reachability (configured? managed Out or HTTP proxy?)
//	  rule revisions and devices that no longer exist
//	-> SelectionImpact (plain data, no write, no task, no audit row)
//
// A blocking finding here is exactly the finding SaveSubscriptionSelection
// would return; a warning is informational. Splitting "would this save be
// refused" from "what else changes" is what lets the page show both before the
// operator presses save.
//
// There is no same-Line Out conflict to report: the egress is part of the
// client document the subscriber downloads, so two subscriptions on one Line
// may name different Outs without contradicting each other.

import (
	"database/sql"
	"errors"
	"sort"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
	coredomain "github.com/wingsky-1/MeshMux/internal/core/subscription"
)

// ImpactFinding is one read-only statement about a proposed selection.
//
// Level reuses the composer's two levels so a page renders one vocabulary:
// blocking means "save would be refused", reminder means "save may proceed but
// the operator should know".
type ImpactFinding struct {
	Level  coredomain.DiagnosticLevel
	Code   string
	Detail string
}

// SelectionImpact is the read-only answer of one impact preview.
type SelectionImpact struct {
	// Lines are the Lines the selection adds or keeps, in submitted order.
	Lines []string
	// OutID is the canonical egress id, or "" for a direct subscription.
	OutID string
	// AffectedSubscribers names the other active subscriptions on these Lines
	// whose Line publication would change. It is sorted and de-duplicated.
	AffectedSubscribers []string
	// Existing is true when the subscriber already saved a selection, so the
	// preview is also a comparison, not only an addition.
	Existing bool
	// Findings are the blocking and reminder statements, blocking first.
	Findings []ImpactFinding
}

// Blocking reports whether the same save would be refused.
func (i SelectionImpact) Blocking() bool {
	for _, finding := range i.Findings {
		if finding.Level == coredomain.DiagnosticBlocking {
			return true
		}
	}
	return false
}

// Code returns the first blocking code, or "" when the save would proceed.
func (i SelectionImpact) Code() string {
	for _, finding := range i.Findings {
		if finding.Level == coredomain.DiagnosticBlocking {
			return finding.Code
		}
	}
	return ""
}

// PreviewSelectionImpact reports what one proposed selection would change,
// without writing, composing or gating anything.
//
// subscriberID may be empty (the create form): a new subscriber conflicts with
// no Line, so only the other subscriptions are reported.
//
// The clock is accepted so the signature matches the save path and a later
// freshness check (for example "a Line heartbeat lapsed since the wizard opened")
// needs no new API; today the derivation is a pure function of the stored rows
// and does not read it.
func (s *Store) PreviewSelectionImpact(subscriberID string, spec SelectionSpec, _ time.Time) (SelectionImpact, error) {
	spec, err := spec.Normalize()
	if err != nil {
		return SelectionImpact{}, err
	}
	if subscriberID != "" {
		if err := coredomain.ValidateID(subscriberID); err != nil {
			return SelectionImpact{}, common.ErrSubscriberIDInvalid()
		}
	}
	tx, err := s.DB.Begin()
	if err != nil {
		return SelectionImpact{}, errors.New(common.CodeDatabaseUnavailable)
	}
	defer tx.Rollback()
	impact, err := buildImpactTx(tx, subscriberID, spec)
	if err != nil {
		return SelectionImpact{}, err
	}
	return impact, nil
}

// buildImpactTx is the read-only impact derivation. Every check is the same
// predicate the save uses; a missing subscriber is reported as a finding rather
// than an error, because the create form has none.
func buildImpactTx(tx *sql.Tx, subscriberID string, spec SelectionSpec) (SelectionImpact, error) {
	impact := SelectionImpact{Lines: append([]string(nil), spec.LineIDs...), OutID: spec.OutID, Findings: []ImpactFinding{}}

	if subscriberID != "" {
		if _, err := getSubscriberTx(tx, subscriberID); err != nil {
			return SelectionImpact{}, err
		}
		stored, err := readSelectionTx(tx, subscriberID)
		if err != nil {
			return SelectionImpact{}, err
		}
		impact.Existing = len(stored.Lines) > 0 || stored.Out != nil || len(stored.Rules) > 0 || len(stored.Networks) > 0
	}

	// Who else publishes these Lines. This is a change, not a defect: a Line
	// serves one listener for every subscriber attached to it.
	affected, err := lineSubscribersTx(tx, subscriberID, spec.LineIDs)
	if err != nil {
		return SelectionImpact{}, err
	}
	impact.AffectedSubscribers = mergeNames(impact.AffectedSubscribers, affected)
	if len(impact.AffectedSubscribers) > 0 {
		impact.Findings = append(impact.Findings, ImpactFinding{
			Level: coredomain.DiagnosticReminder, Code: "SUBSCRIPTION_IMPACT_LINES",
			Detail: "保存后将重新发布这些订阅所使用的 Line：" + joinNames(impact.AffectedSubscribers),
		})
	}

	// References that no longer resolve: the save would refuse them, so they
	// are blocking findings with the save's own code.
	for _, lineID := range spec.LineIDs {
		if err := validateLineTx(tx, lineID); err != nil {
			impact.Findings = append(impact.Findings, ImpactFinding{Level: coredomain.DiagnosticBlocking, Code: common.ErrorCodeOf(err), Detail: err.Error()})
		}
	}
	if err := validateSelectionOutTx(tx, spec.OutID); err != nil {
		impact.Findings = append(impact.Findings, ImpactFinding{Level: coredomain.DiagnosticBlocking, Code: common.ErrorCodeOf(err), Detail: err.Error()})
	}
	for _, revision := range spec.Rules {
		if err := validateRuleRevisionTx(tx, revision); err != nil {
			impact.Findings = append(impact.Findings, ImpactFinding{Level: coredomain.DiagnosticBlocking, Code: common.ErrorCodeOf(err), Detail: err.Error()})
		}
	}
	for _, deviceID := range spec.NetworkIDs {
		if err := validateSelectionDeviceTx(tx, deviceID); err != nil {
			impact.Findings = append(impact.Findings, ImpactFinding{Level: coredomain.DiagnosticBlocking, Code: common.ErrorCodeOf(err), Detail: err.Error()})
		}
	}
	return impact, nil
}

// mergeNames unions two name lists without duplicates, keeping sort order.
func mergeNames(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, name := range append(append([]string{}, left...), right...) {
		if _, duplicate := seen[name]; duplicate {
			continue
		}
		seen[name] = struct{}{}
		merged = append(merged, name)
	}
	sort.Strings(merged)
	return merged
}

// joinNames renders one name list for operator text.
func joinNames(names []string) string {
	out := ""
	for index, name := range names {
		if index > 0 {
			out += "、"
		}
		out += name
	}
	return out
}
