package handler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/route"
)

// blockedCode returns the stable code of a refused decision, or "" when err is
// nil or not a refusal.
func blockedCode(err error) string {
	var blocked *route.BlockedError
	if errors.As(err, &blocked) {
		return blocked.Code
	}
	return ""
}

// blockedDetail returns the stable underlying reason of a refusal.
func blockedDetail(err error) string {
	var blocked *route.BlockedError
	if errors.As(err, &blocked) {
		return blocked.Detail
	}
	return ""
}

// aiRulesetFixture returns one pinned artifact and a fetcher that serves it, so
// the AI decision can be exercised without a network.
func aiRulesetFixture(t *testing.T) (route.RulesetPin, route.RulesetFetcher) {
	t.Helper()
	payload := []byte(`{"version":1,"rules":[{"domain_suffix":["example.invalid"]}]}`)
	sum := sha256.Sum256(payload)
	pin := route.RulesetPin{
		Source:  "https://rulesets.example.invalid/ai/2026.10.21.srs",
		Version: "2026.10.21",
		SHA256:  hex.EncodeToString(sum[:]),
	}
	return pin, func(context.Context, string) ([]byte, error) { return payload, nil }
}

// TestAIRuleset_FailClosedOnOutOffline is the Task 4 case at the Hub boundary:
// an Out that is configured but unavailable never sends AI traffic down the
// Line on its own, and only the explicit opt-in with an operation id does.
func TestAIRuleset_FailClosedOnOutOffline(t *testing.T) {
	f := newOutSyncFixture(t)
	s, line, out := f.store, f.line, f.out
	now := f.now
	pin, fetch := aiRulesetFixture(t)

	// No Out at all: the direct Line egress is the configured state.
	plan, err := s.PlanAIEgress(context.Background(), fetch, line, pin, false, "", now)
	if err != nil {
		t.Fatalf("out-free ai egress error = %v", err)
	}
	if plan.Facts.Configured || plan.Decision.Mode != route.AIEgressLine {
		t.Fatalf("out-free plan = %+v, want a configured line egress", plan)
	}

	// Bind and confirm the Out: the AI path is available.
	enableOutForLine(t, s, out, line, now)
	confirmChain(t, s, out, now)
	markLineOnline(t, s, line, now)
	if err := prepareSubscriberSyncForLine(s, line, now); err != nil {
		t.Fatalf("line publish after out confirmation failed: %v", err)
	}
	confirmChain(t, s, line, now)
	plan, err = s.PlanAIEgress(context.Background(), fetch, line, pin, false, "", now)
	if err != nil {
		t.Fatalf("healthy ai egress error = %v", err)
	}
	if !plan.Facts.Configured || !plan.Facts.Available || plan.Decision.Mode != route.AIEgressOut ||
		plan.Decision.Payload == nil {
		t.Fatalf("healthy plan = %+v, want the out path with the pinned ruleset", plan)
	}

	// The Out stops reporting: the AI path is unavailable and the default is a
	// refusal, never a silent Line fallback.
	if _, err := s.DB.Exec(`UPDATE nodes SET last_heartbeat=0 WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	plan, err = s.PlanAIEgress(context.Background(), fetch, line, pin, false, "", now)
	if plan.Decision.Mode != "" || blockedCode(err) != route.CodeOutOfflineFailClosed || blockedDetail(err) != "OUT_OFFLINE" {
		t.Fatalf("offline plan = %+v err=%v, want OUT_OFFLINE_FAIL_CLOSED/OUT_OFFLINE", plan, err)
	}
	if !plan.Facts.Configured || plan.Facts.Available {
		t.Fatalf("offline facts = %+v, want configured but unavailable", plan.Facts)
	}

	// The explicit fallback without an operation id is refused.
	if _, err = s.PlanAIEgress(context.Background(), fetch, line, pin, true, "", now); err == nil ||
		!strings.HasPrefix(err.Error(), route.CodeOutFallbackUnaudited) {
		t.Fatalf("unaudited fallback error = %v, want %s", err, route.CodeOutFallbackUnaudited)
	}

	// With the operation id the fallback is recorded and carries no ruleset:
	// the Line does not render one.
	plan, err = s.PlanAIEgress(context.Background(), fetch, line, pin, true, "abcdefghijklmnopqrstuv", now)
	if err != nil {
		t.Fatalf("audited fallback error = %v", err)
	}
	if plan.Decision.Mode != route.AIEgressLineFallback || plan.Decision.Code != route.CodeOutOfflineFailClosed ||
		plan.Decision.Detail != "OUT_OFFLINE" || plan.Decision.OperationID != "abcdefghijklmnopqrstuv" ||
		plan.Decision.Payload != nil {
		t.Fatalf("audited fallback decision = %+v", plan.Decision)
	}

	// A ruleset that cannot be resolved refuses the publication even though the
	// Out is back: a client document naming an unverified artifact is not
	// publishable.
	markLineOnline(t, s, out, now)
	failing := func(context.Context, string) ([]byte, error) {
		return nil, errors.New(route.CodeRulesetFetchFailed + ": download failed")
	}
	plan, err = s.PlanAIEgress(context.Background(), failing, line, pin, false, "", now)
	if plan.Decision.Mode != "" || blockedCode(err) != route.CodeOutOfflineFailClosed ||
		blockedDetail(err) != route.CodeRulesetFetchFailed {
		t.Fatalf("ruleset failure plan = %+v err=%v, want a fail-closed refusal", plan, err)
	}
	// A tampered artifact is the same refusal.
	tampered := pin
	tampered.SHA256 = strings.Repeat("a", 64)
	plan, err = s.PlanAIEgress(context.Background(), fetch, line, tampered, false, "", now)
	if plan.Decision.Mode != "" || blockedCode(err) != route.CodeOutOfflineFailClosed ||
		blockedDetail(err) != route.CodeRulesetFetchFailed {
		t.Fatalf("tampered ruleset plan = %+v err=%v, want a fail-closed refusal", plan, err)
	}
}

// TestAIRuleset_FactsRejectNonLineIDs keeps an Out node from being treated as a
// Line, which would otherwise read as a healthy direct egress.
func TestAIRuleset_FactsRejectNonLineIDs(t *testing.T) {
	f := newOutSyncFixture(t)
	s, line, out := f.store, f.line, f.out
	now := f.now

	if _, err := s.OutEgressFacts(out, now); err == nil || !hasErrorCode(err, "LINE_ROLE_INVALID") {
		t.Fatalf("facts of an out = %v, want LINE_ROLE_INVALID", err)
	}
	if _, err := s.OutEgressFacts(strings.Repeat("d", 32), now); err == nil || !hasErrorCode(err, "LINE_NOT_FOUND") {
		t.Fatalf("facts of an unknown node = %v, want LINE_NOT_FOUND", err)
	}
	if _, err := s.OutEgressFacts("nope", now); err == nil || !hasErrorCode(err, "LINE_ID_INVALID") {
		t.Fatalf("facts of a malformed id = %v, want LINE_ID_INVALID", err)
	}
	// An Out-bound Line whose guard has not been confirmed is reported as unavailable
	// with the transition code, never as available.
	enableOutForLine(t, s, out, line, now)
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0, observed_revision=0, observed_config_sha256='' WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	facts, err := s.OutEgressFacts(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Configured || facts.Available || facts.Code == "" || facts.OutID != out {
		t.Fatalf("converging facts = %+v, want configured and not available with a code", facts)
	}
}
