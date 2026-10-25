package subscription

// The selection snapshot is the durable record of what one subscription chose:
// the referenced entities, their immutable versions and their order. It never
// carries rendered bytes. Two consumers read it:
//
//   - the reference graph: deleting a rule, a Line or a device asks the
//     snapshot which subscriptions would break;
//   - the wizard: reopening a subscription restores the last confirmed choice.
//
// The download is not read from the snapshot. It is always re-derived by
// ComposeSubscription from the snapshot plus the current entity versions, and
// then compared with the approved artifact digest.

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sort"
	"strconv"
	"strings"
)

// SelectionLine is one referenced Line and the candidate revision the snapshot
// saw. The revision is informational: a Line's transport is not versioned by
// the subscription, so a newer Line revision never invalidates the choice.
type SelectionLine struct {
	NodeID       string `json:"node_id"`
	Position     int    `json:"position"`
	LineRevision int64  `json:"line_revision,omitempty"`
}

// SelectionOut is the single optional Out of a 1.0 subscription.
type SelectionOut struct {
	OutID       string `json:"out_id"`
	Position    int    `json:"position"`
	OutRevision int64  `json:"out_revision,omitempty"`
}

// SelectionRule is one pinned rule revision: rule_revision_id is exactly
// (StableKey, Version), the identity Task 3 froze.
type SelectionRule struct {
	StableKey string `json:"stable_key"`
	Version   int    `json:"version"`
	Position  int    `json:"position"`
}

// SelectionNetwork is one recorded mesh device. It participates in the
// reference graph and in the page, not in the standard client document.
type SelectionNetwork struct {
	DeviceID string `json:"device_id"`
	Position int    `json:"position"`
}

// Selection is the whole snapshot of one subscription.
type Selection struct {
	SubscriberID string             `json:"subscriber_id"`
	Version      int64              `json:"version"`
	Lines        []SelectionLine    `json:"lines"`
	Out          *SelectionOut      `json:"out,omitempty"`
	Rules        []SelectionRule    `json:"rules"`
	Networks     []SelectionNetwork `json:"networks"`
}

// Validate enforces the snapshot contract: canonical identities, unique
// positions per group, at most one Out, and no duplicate reference.
func (s Selection) Validate() error {
	if err := ValidateID(s.SubscriberID); err != nil {
		return errors.New("SUBSCRIBER_ID_INVALID: need 32 lowercase hex characters")
	}
	if s.Version < 1 {
		return errors.New("SELECTION_VERSION_INVALID: the snapshot needs a positive version")
	}
	if len(s.Lines) == 0 {
		return errors.New(CodeComposeNoLines + ": select at least one Line")
	}
	if len(s.Lines) > 32 {
		return errors.New("LINES_TOO_MANY: select at most 32 lines")
	}
	linePositions := make(map[int]struct{}, len(s.Lines))
	lineIDs := make(map[string]struct{}, len(s.Lines))
	for _, line := range s.Lines {
		if err := ValidateID(line.NodeID); err != nil {
			return errors.New("LINE_ID_INVALID: need 32 lowercase hex characters")
		}
		if line.Position < 0 {
			return errors.New("SELECTION_POSITION_INVALID: positions are non-negative")
		}
		if _, duplicate := linePositions[line.Position]; duplicate {
			return errors.New("SELECTION_POSITION_DUPLICATE: two Lines share one position")
		}
		if _, duplicate := lineIDs[line.NodeID]; duplicate {
			return errors.New("LINE_ID_DUPLICATE: the same Line was selected twice")
		}
		linePositions[line.Position] = struct{}{}
		lineIDs[line.NodeID] = struct{}{}
	}
	if s.Out != nil {
		if err := ValidateID(s.Out.OutID); err != nil {
			return errors.New("OUT_BINDING_INVALID: out_id must be 32 lowercase hex characters")
		}
		if s.Out.Position < 0 {
			return errors.New("SELECTION_POSITION_INVALID: positions are non-negative")
		}
	}
	rulePositions := make(map[int]struct{}, len(s.Rules))
	ruleIDs := make(map[string]struct{}, len(s.Rules))
	for _, rule := range s.Rules {
		if strings.TrimSpace(rule.StableKey) == "" || rule.Version < 1 {
			return errors.New("RULE_REVISION_INVALID: a rule needs a stable key and a positive version")
		}
		if rule.Position < 0 {
			return errors.New("SELECTION_POSITION_INVALID: positions are non-negative")
		}
		if _, duplicate := rulePositions[rule.Position]; duplicate {
			return errors.New("SELECTION_POSITION_DUPLICATE: two rules share one position")
		}
		identity := rule.StableKey + "@" + strconv.Itoa(rule.Version)
		if _, duplicate := ruleIDs[identity]; duplicate {
			return errors.New(CodeComposeRuleDuplicate + ": the same rule revision was selected twice")
		}
		rulePositions[rule.Position] = struct{}{}
		ruleIDs[identity] = struct{}{}
	}
	networkPositions := make(map[int]struct{}, len(s.Networks))
	deviceIDs := make(map[string]struct{}, len(s.Networks))
	for _, device := range s.Networks {
		if err := ValidateID(device.DeviceID); err != nil {
			return errors.New("MESH_DEVICE_ID_INVALID: need 32 lowercase hex characters")
		}
		if device.Position < 0 {
			return errors.New("SELECTION_POSITION_INVALID: positions are non-negative")
		}
		if _, duplicate := networkPositions[device.Position]; duplicate {
			return errors.New("SELECTION_POSITION_DUPLICATE: two devices share one position")
		}
		if _, duplicate := deviceIDs[device.DeviceID]; duplicate {
			return errors.New("MESH_DEVICE_DUPLICATE: the same device was selected twice")
		}
		networkPositions[device.Position] = struct{}{}
		deviceIDs[device.DeviceID] = struct{}{}
	}
	return nil
}

// Ordered returns copies of every group sorted by position. The store writes
// positions but the composer must not depend on row order.
func (s Selection) Ordered() Selection {
	out := s
	out.Lines = append([]SelectionLine(nil), s.Lines...)
	out.Rules = append([]SelectionRule(nil), s.Rules...)
	out.Networks = append([]SelectionNetwork(nil), s.Networks...)
	sort.SliceStable(out.Lines, func(i, j int) bool { return out.Lines[i].Position < out.Lines[j].Position })
	sort.SliceStable(out.Rules, func(i, j int) bool { return out.Rules[i].Position < out.Rules[j].Position })
	sort.SliceStable(out.Networks, func(i, j int) bool { return out.Networks[i].Position < out.Networks[j].Position })
	return out
}

// SnapshotID hashes the selection identity: ordered references and their
// immutable versions, never a rendered byte. The version of the snapshot row
// is included so an explicit re-approval of the same choice is a new identity.
func (s Selection) SnapshotID() string {
	ordered := s.Ordered()
	var builder strings.Builder
	builder.WriteString("meshmux-subscription-snapshot/1\n")
	builder.WriteString(s.SubscriberID + "\n")
	builder.WriteString(strconv.FormatInt(s.Version, 10) + "\n")
	for _, line := range ordered.Lines {
		builder.WriteString("line\t" + line.NodeID + "\t" + strconv.FormatInt(line.LineRevision, 10) + "\n")
	}
	if ordered.Out != nil {
		builder.WriteString("out\t" + ordered.Out.OutID + "\t" + strconv.FormatInt(ordered.Out.OutRevision, 10) + "\n")
	}
	for _, rule := range ordered.Rules {
		builder.WriteString("rule\t" + rule.StableKey + "\t" + strconv.Itoa(rule.Version) + "\n")
	}
	for _, device := range ordered.Networks {
		builder.WriteString("network\t" + device.DeviceID + "\n")
	}
	sum := sha256.Sum256([]byte(builder.String()))
	return hex.EncodeToString(sum[:])
}

// RuleRevisions returns the referenced rule identities in snapshot order.
func (s Selection) RuleRevisions() []SelectionRule {
	return append([]SelectionRule(nil), s.Ordered().Rules...)
}
