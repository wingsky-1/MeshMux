package store

// The aggregation invariants that this package owns, proven at the
// orchestration layer rather than in the composer:
//
//   - a rule whose artifact is not pinned by the active server policy is a
//     blocking finding, so approval (not just rendering) requires the pin;
//   - the download's convergence gate still runs before the approved artifact is
//     served;
//   - the pinned artifact digest is never stored as bytes.

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestRuleWithoutAnActivePinBlocksApproval(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)

	// A geo matcher needs an artifact pin. No active server policy revision
	// exists yet, so the pin source is empty and the composer refuses it: the
	// approval must therefore block and write nothing.
	verifier := &selectionVerifier{}
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{
		LineIDs: []string{lineID},
		Rules:   []RuleRevision{{StableKey: "preset-direct-cn", Version: 1}},
	}, verifier, now)
	if err != nil {
		t.Fatalf("a missing pin must be a diagnostic, not an error: %v", err)
	}
	if result.Saved || !result.Preview.Blocking() {
		t.Fatalf("result = %+v, want a blocked unsaved preview", result)
	}
	if code := result.Preview.Code(); code != "COMPOSE_RULESET_UNPINNED" {
		t.Fatalf("blocking code = %q, want COMPOSE_RULESET_UNPINNED", code)
	}
	if verifier.singBoxCalls != 0 || verifier.mihomoCalls != 0 {
		t.Fatalf("a blocked composer ran the kernel gate: %d/%d", verifier.singBoxCalls, verifier.mihomoCalls)
	}
	if countRows(t, s, "subscription_snapshots") != 0 {
		t.Fatal("a pin-blocked approval wrote a snapshot")
	}
}

func TestSnapshotStoresNoRenderedByte(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{}, now)
	if err != nil || !result.Saved {
		t.Fatalf("approve: %+v err=%v", result, err)
	}
	var selectionJSON, artifactID string
	var approved int
	if err := s.DB.QueryRow(`SELECT selection_json, artifact_id, artifact_approved FROM subscription_snapshots WHERE subscriber_id=?`, subID).
		Scan(&selectionJSON, &artifactID, &approved); err != nil {
		t.Fatal(err)
	}
	for _, rendered := range []string{"outbounds", "mixed-port", "proxy-groups", "uuid", "private_key"} {
		if strings.Contains(selectionJSON, rendered) {
			t.Fatalf("the snapshot stores rendered material (%q): %s", rendered, selectionJSON)
		}
	}
	if approved != 1 || artifactID != result.Preview.ContentID {
		t.Fatalf("snapshot digest = %q approved=%d, want the gated %q", artifactID, approved, result.Preview.ContentID)
	}
}

// TestArtifactDownloadKeepsTheConvergenceGate proves the approved artifact is
// never served from an unconverged Line: the gate runs before the digest is
// even consulted.
func TestArtifactDownloadKeepsTheConvergenceGate(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{}, now)
	if err != nil || !result.Saved {
		t.Fatalf("approve: %+v err=%v", result, err)
	}
	// No Line has ever confirmed a candidate in this fixture, so the convergence
	// gate refuses the download even though a digest is approved.
	token, err := s.RotateToken(subID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SubscriptionArtifactDownload(token, now); err == nil ||
		!strings.HasPrefix(err.Error(), "SUBSCRIPTION_DOWNLOAD_REJECTED") {
		t.Fatalf("download = %v, want SUBSCRIPTION_DOWNLOAD_REJECTED", err)
	}
}
