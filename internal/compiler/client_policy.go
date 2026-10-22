package compiler

// 10b-1 client policy: default CN/international/Tailnet/SSID intent, conflict
// refusal and the hit explanation. Storage is 10b-2.

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/subscription"
)

// ClientDefaults configures the default client policy.
type ClientDefaults struct {
	Exceptions        []string
	RemoteLANPrefixes []string
}

// DefaultClientPolicy is the issue #10 default: tailnet and remote home LAN via
// the Tailscale endpoint, CN direct, exceptions direct, else the selected Line.
// The Line is final, so disabling a rule can only widen it.
func DefaultClientPolicy(model subscription.MeshConfigModel, proxyLine string, defaults ClientDefaults) (ClientPolicy, error) {
	policy, err := MeshClientPolicy(model, proxyLine)
	if err != nil {
		return ClientPolicy{}, err
	}
	var rules []Rule
	if prefixes := append(append([]string{}, model.TailnetPrefixes...), defaults.RemoteLANPrefixes...); len(prefixes) > 0 {
		rules = append(rules, Rule{100, Match{IPCIDRs: prefixes, DNS: DNSEncrypted}, ActionTailscale})
	}
	if len(model.TailnetPrefixes) > 0 {
		rules = append(rules, Rule{200, Match{GeoSite: []string{"cn"}, DNS: DNSDomestic}, ActionDirect})
	}
	if len(defaults.Exceptions) > 0 {
		rules = append(rules, Rule{300, Match{Domains: defaults.Exceptions, DNS: DNSDomestic}, ActionDirect})
	}
	policy.Rules = rules
	return policy, policy.Validate()
}

// checkClientConflicts refuses an order that would silently shadow a rule.
func checkClientConflicts(rules []Rule) error {
	tailnet := 0
	for _, rule := range rules {
		if rule.Action == ActionTailscale && tailnet == 0 {
			tailnet = rule.Priority
		}
	}
	for index, rule := range rules {
		if tailnet != 0 && rule.Action != ActionTailscale && rule.Priority < tailnet {
			return conflict(rule.Priority, "precedes the tailnet rule at priority %d", tailnet)
		}
		if len(rule.Match.SSIDs) > 0 && (index > 0 || rule.Action != ActionDirect || tailnet != 0) {
			return conflict(rule.Priority, "an SSID rule must be first, direct, and never combined with the tailnet rule")
		}
	}
	for index, later := range rules {
		for _, earlier := range rules[:index] {
			if earlier.Action == later.Action {
				continue
			}
			for _, sample := range later.Match.samples() {
				if matched, value := matchTarget(earlier.Match, sample); matched {
					return conflict(earlier.Priority, "shadows %s at priority %d", value, later.Priority)
				}
			}
		}
	}
	return nil
}

func conflict(priority int, format string, args ...any) error {
	return fmt.Errorf("%s: priority %d: %s", CodePolicyConflict, priority, fmt.Sprintf(format, args...))
}

// samples are concrete targets the matcher matches.
func (m Match) samples() []string {
	samples := slices.Clone(append(m.Domains, m.SSIDs...))
	for _, suffix := range m.DomainSuffixes {
		samples = append(samples, "x."+suffix)
	}
	for _, raw := range m.IPCIDRs {
		if prefix, err := netip.ParsePrefix(raw); err == nil {
			samples = append(samples, prefix.Addr().String())
		}
	}
	return append(samples, slices.Concat(m.GeoSite, m.GeoIP)...)
}

// HitExplanation is rule, action, egress and DNS; priority zero is fallback.
type HitExplanation struct {
	Priority int
	Matcher  string
	Action   Action
	Egress   string
	DNS      DNSResolver
}

var clientEgress = map[Action]string{
	ActionDirect:    "direct",
	ActionProxy:     "meshmux-selector (selected Line)",
	ActionTailscale: "meshmux-ts (Tailscale endpoint)",
}

// ExplainHit reports the first expressible match, else the fallback; geo and
// remote rulesets need pinned data and are not evaluated.
func ExplainHit(target string, policy ClientPolicy) (HitExplanation, error) {
	if err := policy.Validate(); err != nil {
		return HitExplanation{}, err
	}
	for _, rule := range policy.Rules {
		if matched, value := matchTarget(rule.Match, target); matched {
			return HitExplanation{rule.Priority, value, rule.Action, clientEgress[rule.Action], resolverFor(rule.Action)}, nil
		}
	}
	return HitExplanation{0, "fallback", policy.Default, clientEgress[policy.Default], resolverFor(policy.Default)}, nil
}

func matchTarget(match Match, target string) (bool, string) {
	if slices.Contains(match.Domains, target) {
		return true, "domain " + target
	}
	for _, suffix := range match.DomainSuffixes {
		if target == suffix || strings.HasSuffix(target, "."+suffix) {
			return true, "domain_suffix " + suffix
		}
	}
	if slices.Contains(match.GeoSite, target) || slices.Contains(match.GeoIP, target) {
		return true, "geo " + target
	}
	if addr, err := netip.ParseAddr(target); err == nil {
		for _, raw := range match.IPCIDRs {
			if prefix, err := netip.ParsePrefix(raw); err == nil && prefix.Contains(addr) {
				return true, "ip_cidr " + raw
			}
		}
	}
	return false, ""
}
