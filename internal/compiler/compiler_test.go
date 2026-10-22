package compiler

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/route"
)

func digest(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// TestRulesetVersionLockAndChecksum covers the Geo/remote pin contract: a
// mutable channel is a configuration defect, an unpinned identifier never
// reaches a generator, and downloaded bytes are usable only when non-empty,
// bounded and matching the pinned SHA-256.
func TestRulesetVersionLockAndChecksum(t *testing.T) {
	payload := []byte(`{"version":1,"rules":[]}`)
	pin := RulesetPin{
		Source:  "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs",
		Version: "2026.10.21",
		SHA256:  digest(payload),
	}
	pins := RuleSetPins{GeoSite: map[string]RulesetPin{"cn": pin}}
	policy := ClientPolicy{
		Default: ActionProxy,
		Rules: []Rule{{
			Priority: 10,
			Match:    Match{GeoSite: []string{"cn"}},
			Action:   ActionDirect,
		}},
	}
	if err := pins.Validate(policy.Rules); err != nil {
		t.Fatalf("pinned geosite rejected: %v", err)
	}

	mutable := pin
	for _, version := range []string{"latest", "head", "main", "master", "stable", "dev", "nightly"} {
		mutable.Version = version
		if err := (RuleSetPins{GeoSite: map[string]RulesetPin{"cn": mutable}}).Validate(policy.Rules); err == nil ||
			!strings.HasPrefix(err.Error(), route.CodeRulesetPinInvalid) {
			t.Fatalf("mutable version %q error = %v, want %s", version, err, route.CodeRulesetPinInvalid)
		}
	}
	for name, source := range map[string]string{
		"http":     "http://rulesets.example.invalid/geosite/cn/2026.10.21.srs",
		"query":    "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs?x=1",
		"fragment": "https://rulesets.example.invalid/geosite/cn/2026.10.21.srs#x",
	} {
		unsafe := pin
		unsafe.Source = source
		if err := (RuleSetPins{GeoSite: map[string]RulesetPin{"cn": unsafe}}).Validate(policy.Rules); err == nil ||
			!strings.HasPrefix(err.Error(), route.CodeRulesetPinInvalid) {
			t.Fatalf("%s source error = %v, want %s", name, err, route.CodeRulesetPinInvalid)
		}
	}

	policy.Rules[0].Match.GeoSite = []string{"us"}
	if err := pins.Validate(policy.Rules); err == nil || !strings.HasPrefix(err.Error(), CodeRulesetUnpinned) {
		t.Fatalf("unpinned geosite error = %v, want %s", err, CodeRulesetUnpinned)
	}

	if _, err := VerifyRuleset(pin, payload); err != nil {
		t.Fatalf("matching ruleset rejected: %v", err)
	}
	for name, body := range map[string][]byte{
		"empty":     nil,
		"tampered":  []byte(`{"version":1,"rules":[{"domain_suffix":["evil.invalid"]}]}`),
		"oversized": make([]byte, MaxRulesetBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyRuleset(pin, body); err == nil ||
				!strings.HasPrefix(err.Error(), route.CodeRulesetFetchFailed) {
				t.Fatalf("VerifyRuleset(%s) error = %v, want %s", name, err, route.CodeRulesetFetchFailed)
			}
		})
	}
}

// TestServerPolicyFailsClosedOnOutOffline pins the #8 handover: a configured but
// unavailable Out never becomes a direct Line silently. Only an explicit,
// audited fallback resolves to direct; a missing Out or an unaudited fallback
// is refused.
func TestServerPolicyFailsClosedOnOutOffline(t *testing.T) {
	policy := ServerPolicy{
		Default:       ActionDirect,
		OutConfigured: true,
		Rules: []Rule{{
			Priority: 10,
			Match:    Match{Domains: []string{"ai.example.invalid"}},
			Action:   ActionOut,
		}},
	}
	if _, err := ResolveServerPolicy(policy); err == nil {
		t.Fatal("offline Out resolved without a decision")
	} else {
		var blocked *route.BlockedError
		if !errors.As(err, &blocked) || blocked.Code != route.CodeOutOfflineFailClosed || blocked.Detail != "OUT_OFFLINE" {
			t.Fatalf("offline error = %v, want OUT_OFFLINE_FAIL_CLOSED/OUT_OFFLINE", err)
		}
	}

	policy.FallbackToLine = true
	if _, err := ResolveServerPolicy(policy); err == nil ||
		!strings.HasPrefix(err.Error(), route.CodeOutFallbackUnaudited) {
		t.Fatalf("unaudited fallback error = %v, want %s", err, route.CodeOutFallbackUnaudited)
	}

	policy.OperationID = "abcdefghijklmnopqrstuv"
	resolved, err := ResolveServerPolicy(policy)
	if err != nil {
		t.Fatal(err)
	}
	if resolved.Rules[0].Action != ActionDirect || resolved.Default != ActionDirect {
		t.Fatalf("audited fallback did not rewrite the Out action: %#v", resolved)
	}

	policy.OutAvailable = true
	resolved, err = ResolveServerPolicy(policy)
	if err != nil || resolved.Rules[0].Action != ActionOut {
		t.Fatalf("healthy Out resolved = %#v err=%v", resolved, err)
	}

	missing := policy
	missing.OutConfigured = false
	missing.OutAvailable = false
	if _, err := ResolveServerPolicy(missing); err == nil ||
		!strings.HasPrefix(err.Error(), "OUT_BINDING_INVALID") {
		t.Fatalf("missing Out error = %v, want OUT_BINDING_INVALID", err)
	}
	direct := ServerPolicy{Default: ActionDirect}
	if resolved, err := ResolveServerPolicy(direct); err != nil || resolved.Default != ActionDirect {
		t.Fatalf("out-free direct policy = %#v err=%v", resolved, err)
	}
}

// TestPolicyRejectsConflictsAndCrossRoleActions covers the validation the Web
// layer needs before a candidate can be compiled.
func TestPolicyRejectsConflictsAndCrossRoleActions(t *testing.T) {
	cases := []struct {
		name   string
		policy ClientPolicy
		want   string
	}{
		{"duplicate priority", ClientPolicy{Default: ActionProxy, Rules: []Rule{
			{Priority: 1, Match: Match{Domains: []string{"a.example.invalid"}}, Action: ActionDirect},
			{Priority: 1, Match: Match{Domains: []string{"b.example.invalid"}}, Action: ActionDirect},
		}}, CodePolicyConflict},
		{"two matchers", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1,
			Match:    Match{Domains: []string{"a.example.invalid"}, IPCIDRs: []string{"203.0.113.0/24"}},
			Action:   ActionDirect,
		}}}, CodePolicyInvalid},
		{"host bits", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Match: Match{IPCIDRs: []string{"203.0.113.7/24"}}, Action: ActionDirect,
		}}}, CodePolicyInvalid},
		{"client out", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Match: Match{Domains: []string{"a.example.invalid"}}, Action: ActionOut,
		}}}, CodePolicyInvalid},
		{"empty matcher", ClientPolicy{Default: ActionProxy, Rules: []Rule{{
			Priority: 1, Action: ActionDirect,
		}}}, CodePolicyInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.policy.Validate(); err == nil || !strings.HasPrefix(err.Error(), tc.want) {
				t.Fatalf("Validate() = %v, want %s", err, tc.want)
			}
		})
	}
	if err := (ServerPolicy{Default: ActionProxy}).Validate(); err == nil ||
		!strings.HasPrefix(err.Error(), CodePolicyInvalid) {
		t.Fatalf("server proxy error = %v, want %s", err, CodePolicyInvalid)
	}
}
