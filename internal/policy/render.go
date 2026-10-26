package policy

// Format generators. They consume only policy intent and pinned rulesets; no
// domain, CIDR or AI list is embedded here. Each function emits a routing
// fragment (rules plus final egress); the publish path embeds it and assembles
// rule-provider definitions from the same pins. Transport, staging, apply and
// readback stay outside this package.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/netip"
)

// CodeRenderUnsupported marks a policy the target format cannot express.
const CodeRenderUnsupported = "RENDER_UNSUPPORTED"

const (
	singBoxDirectTag    = "direct"
	singBoxProxyTag     = "meshmux-selector"
	singBoxTailscaleTag = "meshmux-ts"
)

var singBoxTags = map[CompilerAction]string{
	CompilerActionDirect:    singBoxDirectTag,
	CompilerActionProxy:     singBoxProxyTag,
	CompilerActionTailscale: singBoxTailscaleTag,
}

var mihomoTags = map[CompilerAction]string{
	CompilerActionDirect: "DIRECT",
	CompilerActionProxy:  "PROXY",
	CompilerActionOut:    "OUT",
}

// RenderSingBox renders the client policy as a sing-box 1.14.3 route fragment.
func RenderSingBox(policy ClientPolicy, pins RuleSetPins) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	return renderSingBox(policy.Default, policy.Rules, pins)
}

func renderSingBox(defaultAction CompilerAction, rules []CompilerRule, pins RuleSetPins) ([]byte, error) {
	if err := pins.Validate(rules); err != nil {
		return nil, err
	}
	rendered := make([]map[string]any, 0, len(rules))
	for _, rule := range rules {
		outbound, ok := singBoxTags[rule.Action]
		if !ok {
			return nil, errors.New(CodeRenderUnsupported + ": unknown action")
		}
		entry := map[string]any{"outbound": outbound}
		switch {
		case len(rule.Match.SSIDs) > 0:
			// Verified against sing-box 1.14.3: route/rule/rule_item_wifi_ssid.go
			// and `sing-box check` accept wifi_ssid.
			entry["wifi_ssid"] = rule.Match.SSIDs
		case len(rule.Match.Domains) > 0:
			entry["domain"] = rule.Match.Domains
		case len(rule.Match.DomainSuffixes) > 0:
			entry["domain_suffix"] = rule.Match.DomainSuffixes
		case len(rule.Match.IPCIDRs) > 0:
			entry["ip_cidr"] = rule.Match.IPCIDRs
		default:
			entry["rule_set"] = ruleSetTags(rule.Match)
		}
		rendered = append(rendered, entry)
	}
	final, ok := singBoxTags[defaultAction]
	if !ok {
		return nil, errors.New(CodeRenderUnsupported + ": unknown default action")
	}
	body, err := json.MarshalIndent(map[string]any{
		"route": map[string]any{"rules": rendered, "final": final},
	}, "", "  ")
	if err != nil {
		return nil, errors.New("RENDER_SINGBOX_FAILED")
	}
	return append(body, '\n'), nil
}

// RenderMihomo renders the client policy as a Mihomo rules fragment. A
// Tailscale action is refused: the supported mesh client document is sing-box
// 1.14.3, and emitting a different action would change the policy silently.
func RenderMihomo(policy ClientPolicy, pins RuleSetPins) ([]byte, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if err := pins.Validate(policy.Rules); err != nil {
		return nil, err
	}
	final, ok := mihomoTags[policy.Default]
	if !ok {
		return nil, errors.New(CodeRenderUnsupported + ": Mihomo cannot express the Tailscale endpoint action")
	}
	lines := make([]string, 0, len(policy.Rules)+1)
	for _, rule := range policy.Rules {
		action, ok := mihomoTags[rule.Action]
		if !ok {
			return nil, errors.New(CodeRenderUnsupported + ": Mihomo cannot express the Tailscale endpoint action")
		}
		if len(rule.Match.SSIDs) > 0 {
			// Mihomo 1.19.32 rules/parser.go has no SSID rule type; emitting a
			// guess would silently change the policy.
			return nil, errors.New(CodeRenderUnsupported + ": Mihomo cannot express an SSID matcher")
		}
		lines = append(lines, mihomoRuleLines(rule.Match, action)...)
	}
	lines = append(lines, "MATCH,"+final)
	body := []byte("rules:\n")
	for _, line := range lines {
		body = append(body, []byte("  - \""+line+"\"\n")...)
	}
	return body, nil
}

// Hash is the stable configuration hash exposed to the publish chain.
func Hash(document []byte) string {
	sum := sha256.Sum256(document)
	return hex.EncodeToString(sum[:])
}

func mihomoRuleLines(match Match, action string) []string {
	lines := make([]string, 0, len(match.Domains)+len(match.DomainSuffixes)+len(match.IPCIDRs)+len(match.GeoSite)+len(match.GeoIP)+len(match.RuleSets))
	for _, domain := range match.Domains {
		lines = append(lines, "DOMAIN,"+domain+","+action)
	}
	for _, suffix := range match.DomainSuffixes {
		lines = append(lines, "DOMAIN-SUFFIX,"+suffix+","+action)
	}
	for _, raw := range match.IPCIDRs {
		kind := "IP-CIDR"
		if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Addr().Is6() {
			kind = "IP-CIDR6"
		}
		lines = append(lines, kind+","+raw+","+action+",no-resolve")
	}
	for _, tag := range ruleSetTags(match) {
		lines = append(lines, "RULE-SET,"+tag+","+action)
	}
	return lines
}

// ruleSetTags maps one match to the target-neutral tags both formats share.
func ruleSetTags(match Match) []string {
	tags := make([]string, 0, len(match.GeoSite)+len(match.GeoIP)+len(match.RuleSets))
	for _, code := range match.GeoSite {
		tags = append(tags, "geosite-"+code)
	}
	for _, code := range match.GeoIP {
		tags = append(tags, "geoip-"+code)
	}
	return append(tags, match.RuleSets...)
}
