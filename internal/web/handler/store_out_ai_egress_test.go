package handler

import (
	"strings"
	"testing"
)

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
	// An Out-bound Line whose own chain is not confirmed is still available to
	// the client document: it names the Out's dial body, and admission is the
	// link key, not the Out's publication state.
	enableOutForLine(t, s, out, line, now)
	if _, err := s.DB.Exec(`UPDATE nodes SET observed_at=0, observed_revision=0, observed_config_sha256='' WHERE id=?`, out); err != nil {
		t.Fatal(err)
	}
	facts, err := s.OutEgressFacts(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if !facts.Configured || !facts.Available || facts.Code != "" || facts.OutID != out {
		t.Fatalf("converging facts = %+v, want configured and available by link key", facts)
	}
	// An Out without a transport has no dial body, so the client document cannot
	// name it yet; that is the pending case.
	if _, err := s.DB.Exec(`DELETE FROM out_settings WHERE node_id=?`, out); err != nil {
		t.Fatal(err)
	}
	pending, err := s.OutEgressFacts(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if !pending.Configured || pending.Available || pending.Code != "OUT_SYNC_PENDING" {
		t.Fatalf("transport-less facts = %+v, want configured and pending", pending)
	}
}
