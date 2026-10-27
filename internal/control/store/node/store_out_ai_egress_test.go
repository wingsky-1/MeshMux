package node_test

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/control/store/storetest"
)

// TestAIRuleset_FactsRejectNonLineIDs keeps an Out node from being treated as a
// Line, which would otherwise read as a healthy direct egress.
func TestAIRuleset_FactsRejectNonLineIDs(t *testing.T) {
	f := storetest.NewOutSyncFixture(t)
	s, line, out := f.Store, f.Line, f.Out
	now := f.Now

	if _, err := s.OutEgressFacts(out, now); err == nil || !storetest.HasErrorCode(err, "LINE_ROLE_INVALID") {
		t.Fatalf("facts of an out = %v, want LINE_ROLE_INVALID", err)
	}
	if _, err := s.OutEgressFacts(strings.Repeat("d", 32), now); err == nil || !storetest.HasErrorCode(err, "LINE_NOT_FOUND") {
		t.Fatalf("facts of an unknown node = %v, want LINE_NOT_FOUND", err)
	}
	if _, err := s.OutEgressFacts("nope", now); err == nil || !storetest.HasErrorCode(err, "LINE_ID_INVALID") {
		t.Fatalf("facts of a malformed id = %v, want LINE_ID_INVALID", err)
	}
	// An Out-bound Line whose guard has not been confirmed is reported as unavailable
	// with the transition code, never as available.
	storetest.EnableOutForLine(t, s, out, line, now)
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
