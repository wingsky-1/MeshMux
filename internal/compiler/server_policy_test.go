package compiler

import (
	"strings"
	"testing"
)

func TestDefaultServerPolicy(t *testing.T) {
	if policy, err := DefaultServerPolicy("", nil, nil); err != nil || policy.Default != ActionDirect || len(policy.Rules) != 0 {
		t.Fatalf("empty default = %+v err=%v", policy, err)
	}
	policy, err := DefaultServerPolicy("ai", []string{"chat.example.invalid"}, []string{"203.0.113.0/24"})
	if err != nil || policy.Default != ActionDirect || len(policy.Rules) != 3 {
		t.Fatalf("default = %+v err=%v", policy, err)
	}
	if policy.Rules[0].Priority != 100 || len(policy.Rules[0].Match.RuleSets) != 1 || policy.Rules[0].Action != ActionOut ||
		policy.Rules[1].Priority != 200 || len(policy.Rules[1].Match.Domains) != 1 || policy.Rules[1].Action != ActionOut ||
		policy.Rules[2].Priority != 300 || len(policy.Rules[2].Match.IPCIDRs) != 1 || policy.Rules[2].Action != ActionOut {
		t.Fatalf("rules = %+v, want out ruleset/domain/CIDR at 100/200/300", policy.Rules)
	}
	if _, err := DefaultServerPolicy("", []string{"Chat.Example.invalid"}, nil); err == nil || !strings.HasPrefix(err.Error(), CodePolicyInvalid) {
		t.Fatalf("invalid domain error = %v, want %s", err, CodePolicyInvalid)
	}
	if _, err := DefaultServerPolicy("AI", nil, nil); err == nil || !strings.HasPrefix(err.Error(), CodePolicyInvalid) {
		t.Fatalf("invalid tag error = %v, want %s", err, CodePolicyInvalid)
	}
}
