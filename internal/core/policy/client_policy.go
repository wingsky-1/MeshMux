package policy

// 10b-1 client policy: default CN/international/Tailnet/SSID intent, conflict
// refusal and the hit explanation. Storage is 10b-2.

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
	"github.com/wingsky-1/MeshMux/internal/core/subscription/ir"
)

// ClientDefaults configures the default client policy.
type ClientDefaults struct {
	Exceptions        []string
	RemoteLANPrefixes []string
}

// DefaultClientPolicy is the issue #10 default; the selected Line is final.
func DefaultClientPolicy(model ir.MeshView, proxyLine string, defaults ClientDefaults) (ClientPolicy, error) {
	policy, err := MeshClientPolicy(model, proxyLine)
	if err != nil {
		return ClientPolicy{}, err
	}
	var rules []CompilerRule
	if prefixes := append(append([]string{}, model.TailnetPrefixes...), defaults.RemoteLANPrefixes...); len(prefixes) > 0 {
		rules = append(rules, CompilerRule{100, Match{IPCIDRs: prefixes, DNS: DNSEncrypted}, CompilerActionTailscale})
	}
	rules = append(rules, CompilerRule{200, Match{GeoSite: []string{"cn"}, DNS: DNSDomestic}, CompilerActionDirect})
	if len(defaults.Exceptions) > 0 {
		rules = append(rules, CompilerRule{300, Match{Domains: defaults.Exceptions, DNS: DNSDomestic}, CompilerActionDirect})
	}
	policy.Rules = rules
	return policy, policy.Validate()
}

// checkClientConflicts refuses an order that would silently shadow a rule.
func checkClientConflicts(rules []CompilerRule) error {
	tailnet := 0
	for _, rule := range rules {
		if rule.Action == CompilerActionTailscale && tailnet == 0 {
			tailnet = rule.Priority
		}
	}
	for index, rule := range rules {
		if tailnet != 0 && rule.Action != CompilerActionTailscale && rule.Priority < tailnet && len(rule.Match.SSIDs) == 0 {
			return fmt.Errorf("%s: priority %d precedes the tailnet rule at priority %d", CodePolicyConflict, rule.Priority, tailnet)
		}
		if len(rule.Match.SSIDs) > 0 && (index > 0 || rule.Action != CompilerActionDirect) {
			return fmt.Errorf("%s: priority %d: an SSID rule must be first and direct", CodePolicyConflict, rule.Priority)
		}
	}
	for index, later := range rules {
		for _, earlier := range rules[:index] {
			if earlier.Action == later.Action {
				continue
			}
			for _, sample := range later.Match.samples() {
				if matched, value := matchTarget(earlier.Match, sample); matched {
					return fmt.Errorf("%s: priority %d shadows %s at priority %d", CodePolicyConflict, earlier.Priority, value, later.Priority)
				}
			}
		}
	}
	return nil
}

// samples are concrete targets the matcher matches.
func (m Match) samples() []string {
	samples := slices.Clone(m.Domains)
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
	Action   CompilerAction
	Egress   string
	DNS      DNSResolver
}

var clientEgress = map[CompilerAction]string{
	CompilerActionDirect:    protocol.OutboundDirectTag,
	CompilerActionProxy:     protocol.SelectorTag + " (selected Line)",
	CompilerActionTailscale: protocol.TailscaleEndpointTag + " (Tailscale endpoint)",
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
