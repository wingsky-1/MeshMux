package view

import (
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
)

// rules_library.go holds the display model for the /rules library page (Task
// 3, ADR-0008 §5): preset rows (read-only), custom rows (latest revision with
// its used-by names), the create modal, per-row view modals with the revise
// form, and the two-step delete confirm. The page never edits a row in place:
// a match/action change is a new revision and a referenced delete is refused
// with the subscriber names.

// RuleLibraryRow is one rendered library row: the latest revision of a key
// with the names of the subscriptions pinning exactly that revision.
type RuleLibraryRow struct {
	StableKey string
	Version   int
	Name      string
	Action    string
	Matcher   string
	Values    []string
	// ValuesText pre-fills the revise textarea, one value per line.
	ValuesText string
	// ActionValue and KindValue are the raw stored values behind the
	// display labels, so the revise form can pre-select them.
	ActionValue string
	KindValue   string
	Origin      string
	Preset      bool
	UsedBy      []string
	History     []int
}

// PendingRuleDelete is the explicit delete confirm: the first POST names the
// revision and re-renders the page with the impacted subscriptions; only a
// second POST with confirm=1 deletes. A referenced revision never reaches the
// second step: the store refuses it with the same names.
type PendingRuleDelete struct {
	StableKey string
	Version   int
	Name      string
	UsedBy    []string
}

// RulesLibraryView is the whole /rules page snapshot.
type RulesLibraryView struct {
	Presets []RuleLibraryRow
	Customs []RuleLibraryRow
	// Notice is one-shot feedback of the last mutation. Empty renders nothing.
	Notice string
	// Pending names the revision awaiting an explicit delete confirm.
	Pending PendingRuleDelete
	// HasPending renders the delete-protection block.
	HasPending bool
}

// RuleLibraryActionLabel renders the three library actions.
func RuleLibraryActionLabel(action policy.Action) string {
	switch action {
	case policy.ActionDirect:
		return "直连"
	case policy.ActionProxy:
		return "代理"
	case policy.ActionReject:
		return "拒绝"
	default:
		return string(action)
	}
}

// RuleLibraryMatcherLabel renders one matcher kind with its values.
func RuleLibraryMatcherLabel(kind policy.MatcherKind, values []string) string {
	joined := strings.Join(values, "、")
	switch kind {
	case policy.MatcherDomain:
		return "域名（" + joined + "）"
	case policy.MatcherDomainSuffix:
		return "域名后缀（" + joined + "）"
	case policy.MatcherIPCIDR:
		return "IP 网段（" + joined + "）"
	case policy.MatcherGeoSite:
		return "GeoSite（" + joined + "）"
	case policy.MatcherGeoIP:
		return "GeoIP（" + joined + "）"
	case policy.MatcherRuleSet:
		return "规则集（" + joined + "）"
	default:
		return joined
	}
}

// RuleLibraryOriginLabel renders the row provenance.
func RuleLibraryOriginLabel(preset bool) string {
	if preset {
		return "预置"
	}
	return "自定义"
}

// RuleVersionsLabel renders the revision trail of one key.
func RuleVersionsLabel(history []int, current int) string {
	parts := make([]string, 0, len(history))
	for _, v := range history {
		part := "v" + strconv.Itoa(v)
		if v == current {
			part += "（当前）"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "、")
}
