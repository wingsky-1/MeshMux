package store_test

// The aggregation invariants that this package owns, proven at the
// orchestration layer rather than in the composer:
//
//   - a rule is assembled exactly as configured: the Hub performs no artifact
//     pin or content check, so approval never depends on a server-side pin;
//   - the download's convergence gate still runs before the approved artifact is
//     served;
//   - the approved artifact digest is never stored as bytes.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

func TestRuleAssemblesWithoutAServerSidePin(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)

	// The store no longer reads an artifact lock from the active server policy:
	// the selected revision is assembled exactly as configured. The rule here is
	// a plain domain matcher, so the assertion holds for the composer as it is
	// now; the artifact-pin retirement itself is proven in the composer's own
	// tests.
	if _, err := s.DB.Exec(`INSERT INTO policy_rules(stable_key, version, name, action, matcher_kind, matcher_value, origin, created_at, updated_at)
	  VALUES('custom-domain','1','AI','proxy','domain','["ai.example.invalid"]','custom',?,?)`, now.Unix(), now.Unix()); err != nil {
		t.Fatal(err)
	}
	// No active policy revision exists at all, and the approval still proceeds:
	// nothing in the store gates a subscription on a server-side artifact lock.
	verifier := &selectionVerifier{}
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", store.SelectionSpec{
		LineIDs: []string{lineID},
		Rules:   []store.RuleRevision{{StableKey: "custom-domain", Version: 1}},
	}, verifier, now)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if result.Preview.Blocking() {
		t.Fatalf("preview blocked on a retired pin: %+v", result.Preview.Diagnostics)
	}
	if !result.Saved {
		t.Fatal("an approval with no server-side policy revision was not saved")
	}
	if countRows(t, s, "subscription_snapshots") != 1 {
		t.Fatal("the approval did not write exactly one snapshot")
	}
}

func TestSnapshotStoresNoRenderedByte(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", store.SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{}, now)
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
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", store.SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{}, now)
	if err != nil || !result.Saved {
		t.Fatalf("approve: %+v err=%v", result, err)
	}
	// No Line has ever confirmed a candidate in this fixture, so the convergence
	// gate refuses the download even though a digest is approved.
	token, err := s.RotateToken(subID, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SubscriptionArtifactDownload(token, now); err == nil ||
		!strings.HasPrefix(err.Error(), "SUBSCRIPTION_DOWNLOAD_REJECTED") {
		t.Fatalf("download = %v, want SUBSCRIPTION_DOWNLOAD_REJECTED", err)
	}
}
