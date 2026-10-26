package compiler

// Server route fragment: RenderServerRoute assembles only route.rules,
// route.rule_set and route.final; the "out" outbound body belongs to the Out
// access path.
//
// The fragment names a tag, it does not create it. node.CompileCandidateWithRoute
// declares every tag the fragment references, so the published candidate is
// schema-complete; until the Out access path owns the real body that tag is a
// fail-closed block stub, never a silent Line fallback.

import (
	"encoding/json"
	"errors"
)

const (
	singBoxServerOutTag = "out"
	singBoxServerFormat = "binary" // pinned artifacts are .srs rule sets
)

var serverSingBoxTags = map[Action]string{
	ActionDirect: singBoxDirectTag,
	ActionOut:    singBoxServerOutTag,
}

type serverRoute struct {
	Rules   []map[string]any `json:"rules"`
	RuleSet []serverRuleSet  `json:"rule_set,omitempty"`
	Final   string           `json:"final"`
}

type serverRuleSet struct {
	Type   string `json:"type"`
	Tag    string `json:"tag"`
	Format string `json:"format"`
	URL    string `json:"url"`
}

// RenderServerRoute renders a resolved ServerPolicy in priority order, mapping
// ActionOut to "out" and ActionDirect to "direct". The caller must run
// ResolveServerPolicy first; a still-unresolved Out reference is refused here
// (OUT_BINDING_INVALID / OUT_OFFLINE_FAIL_CLOSED), never rendered as direct.
func RenderServerRoute(policy ServerPolicy, pins RuleSetPins) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := pins.Validate(policy.Rules); err != nil {
		return nil, err
	}
	needsOut := policy.Default == ActionOut
	for _, rule := range policy.Rules {
		needsOut = needsOut || rule.Action == ActionOut
	}
	if needsOut && !policy.OutConfigured {
		return nil, errors.New("OUT_BINDING_INVALID: the server policy references an Out that is not configured")
	}
	if needsOut && !policy.OutAvailable {
		return nil, &BlockedError{Code: CodeOutOfflineFailClosed, Detail: "OUT_OFFLINE"}
	}
	final := serverSingBoxTags[policy.Default]
	rules := make([]map[string]any, 0, len(policy.Rules))
	sets := make([]serverRuleSet, 0, len(policy.Rules))
	declared := make(map[string]struct{}, len(policy.Rules))
	for _, rule := range policy.Rules {
		entry := map[string]any{"outbound": serverSingBoxTags[rule.Action]}
		switch {
		case len(rule.Match.SSIDs) > 0:
			// A Line cannot observe the client's Wi-Fi.
			return nil, errors.New(CodeRenderUnsupported + ": a server rule cannot match a client Wi-Fi SSID")
		case len(rule.Match.Domains) > 0:
			entry["domain"] = rule.Match.Domains
		case len(rule.Match.DomainSuffixes) > 0:
			entry["domain_suffix"] = rule.Match.DomainSuffixes
		case len(rule.Match.IPCIDRs) > 0:
			entry["ip_cidr"] = rule.Match.IPCIDRs
		default:
			tags, definitions := serverRuleSets(rule.Match, pins, declared)
			entry["rule_set"] = tags
			sets = append(sets, definitions...)
		}
		rules = append(rules, entry)
	}
	body, err := json.MarshalIndent(serverRoute{Rules: rules, RuleSet: sets, Final: final}, "", "  ")
	if err != nil {
		return nil, errors.New("RENDER_SERVER_FAILED")
	}
	return append(body, '\n'), nil
}

func serverRuleSets(match Match, pins RuleSetPins, declared map[string]struct{}) ([]string, []serverRuleSet) {
	tags := make([]string, 0, len(match.GeoSite)+len(match.GeoIP)+len(match.RuleSets))
	sets := make([]serverRuleSet, 0, cap(tags))
	add := func(base string, pin RulesetPin) {
		tag := base + "@" + pin.Version
		tags = append(tags, tag)
		if _, ok := declared[tag]; ok {
			return
		}
		declared[tag] = struct{}{}
		sets = append(sets, serverRuleSet{Type: "remote", Tag: tag, Format: singBoxServerFormat, URL: pin.Source})
	}
	for _, code := range match.GeoSite {
		add("geosite-"+code, pins.GeoSite[code])
	}
	for _, code := range match.GeoIP {
		add("geoip-"+code, pins.GeoIP[code])
	}
	for _, tag := range match.RuleSets {
		add(tag, pins.Remote[tag])
	}
	return tags, sets
}
