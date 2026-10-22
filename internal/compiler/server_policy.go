package compiler

// Default server intent: AI ruleset, operator domains and CIDRs use the single
// optional Out; everything else stays on the Line. Fixed priority order:
// AI 100, domains 200, CIDRs 300.

// ServerPriority* are the default priorities, exported for the Web rows.
const (
	ServerPriorityAI      = 100
	ServerPriorityDomains = 200
	ServerPriorityCIDRs   = 300
)

// DefaultServerPolicy assembles the default server intent; empty input is the
// all-direct deployment. Validate refuses malformed tags, domains and CIDRs.
func DefaultServerPolicy(aiRulesetTag string, extraDomains, extraCIDRs []string) (ServerPolicy, error) {
	policy := ServerPolicy{Default: ActionDirect}
	if aiRulesetTag != "" {
		policy.Rules = append(policy.Rules, Rule{ServerPriorityAI, Match{RuleSets: []string{aiRulesetTag}}, ActionOut})
	}
	if len(extraDomains) > 0 {
		policy.Rules = append(policy.Rules, Rule{ServerPriorityDomains, Match{Domains: append([]string(nil), extraDomains...)}, ActionOut})
	}
	if len(extraCIDRs) > 0 {
		policy.Rules = append(policy.Rules, Rule{ServerPriorityCIDRs, Match{IPCIDRs: append([]string(nil), extraCIDRs...)}, ActionOut})
	}
	return policy, policy.Validate()
}
