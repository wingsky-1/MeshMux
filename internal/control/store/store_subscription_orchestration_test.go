package store_test

// The orchestration split's public contract:
//
//	Draft / Preview write nothing.
//	Approve writes only an approved artifact.
//	Artifact re-derives and compares the approved digest.
//	Impact preview reports the same refusal the save would return.
//	Batch approval succeeds or fails per subscriber, never as one blob.

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"

	"github.com/wingsky-1/MeshMux/internal/control/store/common"
)

func TestPreviewSelectionImpactWritesNothingAndNamesTheConflict(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, outID, subID := selectionFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(subID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: outID}, now); err != nil {
		t.Fatal(err)
	}
	second, _, err := s.CreateSubscriber("bob", []string{lineID}, now)
	if err != nil {
		t.Fatal(err)
	}
	edgesBefore := countRows(t, s, "subscription_lines")
	snapshotsBefore := countRows(t, s, "subscription_snapshots")

	// A conflicting Out choice is exactly the save's refusal, reported before
	// anything is written.
	impact, err := s.PreviewSelectionImpact(second.ID, store.SelectionSpec{LineIDs: []string{lineID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !impact.Blocking() || impact.Code() != store.CodeOutSelectionConflict {
		t.Fatalf("impact = %+v, want a blocking %s", impact, store.CodeOutSelectionConflict)
	}
	if len(impact.AffectedSubscribers) != 1 || impact.AffectedSubscribers[0] != "alice" {
		t.Fatalf("affected = %v, want [alice]", impact.AffectedSubscribers)
	}

	// The agreeing choice is a reminder about the shared Line, not a refusal.
	agreeing, err := s.PreviewSelectionImpact(second.ID, store.SelectionSpec{LineIDs: []string{lineID}, OutID: outID}, now)
	if err != nil {
		t.Fatal(err)
	}
	if agreeing.Blocking() {
		t.Fatalf("agreeing impact = %+v, want no blocking finding", agreeing)
	}
	if len(agreeing.AffectedSubscribers) != 1 || agreeing.AffectedSubscribers[0] != "alice" {
		t.Fatalf("agreeing affected = %v, want [alice]", agreeing.AffectedSubscribers)
	}

	if countRows(t, s, "subscription_lines") != edgesBefore || countRows(t, s, "subscription_snapshots") != snapshotsBefore {
		t.Fatal("the impact preview wrote rows")
	}
}

func TestPreviewSelectionImpactOnTheCreateForm(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, _ := selectionFixture(t, s, now)
	// No subscriber yet: the create form must still answer, and it must not
	// conflict with itself.
	impact, err := s.PreviewSelectionImpact("", store.SelectionSpec{LineIDs: []string{lineID}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if impact.Blocking() {
		t.Fatalf("create-form impact = %+v, want no blocking finding", impact)
	}
	// A reference that does not exist is a blocking finding with the save code.
	unknown, err := s.PreviewSelectionImpact("", store.SelectionSpec{LineIDs: []string{"ffffffffffffffffffffffffffffffff"}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !unknown.Blocking() || unknown.Code() != "LINE_NOT_FOUND" {
		t.Fatalf("unknown-line impact = %+v, want a blocking LINE_NOT_FOUND", unknown)
	}
}

func TestBatchApproveSucceedsPerSubscriber(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, first := selectionFixture(t, s, now)
	if _, err := s.SaveSubscriptionSelection(first, store.SelectionSpec{LineIDs: []string{lineID}}, now); err != nil {
		t.Fatal(err)
	}
	// A second subscriber with a saved-but-unapproved selection: it can be
	// approved by the batch.
	secondSub, _, err := s.CreateSubscriber("bob", []string{lineID}, now)
	if err != nil {
		t.Fatal(err)
	}
	second := secondSub.ID
	// A third subscriber on its own Line, whose transport is removed after the
	// save: the gate refuses that member alone, so the batch must not roll back
	// the two durable approvals.
	thirdLine, _, err := s.CreateNode("edge", "line-3", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SetLine(testSelectionLine(t, thirdLine.ID), now); err != nil {
		t.Fatal(err)
	}
	thirdSub, _, err := s.CreateSubscriber("carol", []string{thirdLine.ID}, now)
	if err != nil {
		t.Fatal(err)
	}
	third := thirdSub.ID
	if _, err := s.DB.Exec(`DELETE FROM line_settings WHERE node_id=?`, thirdLine.ID); err != nil {
		t.Fatal(err)
	}

	result, err := s.BatchApproveSubscriptions(context.Background(), []string{first, second, third}, &selectionVerifier{}, now)
	if err != nil {
		t.Fatalf("BatchApproveSubscriptions: %v", err)
	}
	if len(result.Outcomes) != 3 {
		t.Fatalf("outcomes = %d, want 3", len(result.Outcomes))
	}
	status := map[string]store.BatchApproveOutcome{}
	for _, outcome := range result.Outcomes {
		status[outcome.SubscriberID] = outcome
	}
	if status[first].Status != store.BatchSaved || status[first].ArtifactID == "" {
		t.Fatalf("first outcome = %+v, want saved with a digest", status[first])
	}
	if status[second].Status != store.BatchSaved || status[second].ArtifactID == "" {
		t.Fatalf("second outcome = %+v, want saved with a digest", status[second])
	}
	if status[third].Status != store.BatchBlocked || status[third].Code != "LINE_NOT_CONFIGURED" {
		t.Fatalf("third outcome = %+v, want blocked LINE_NOT_CONFIGURED (its Line transport is gone)", status[third])
	}
	// The two successful members really are approved and downloadable.
	for _, id := range []string{first, second} {
		if _, artifactID, err := s.SubscriptionArtifact(id); err != nil || artifactID == "" {
			t.Fatalf("artifact of %s: id=%q err=%v", id, artifactID, err)
		}
	}
	if _, _, err := s.SubscriptionArtifact(third); err == nil {
		t.Fatal("the blocked member became downloadable")
	}
	if result.Saved != 2 || result.Blocked != 1 || result.Failed != 0 {
		t.Fatalf("counts = %d/%d/%d, want 2/1/0", result.Saved, result.Blocked, result.Failed)
	}
	if result.Complete() {
		t.Fatal("a partially blocked batch reported complete")
	}
}

func TestBatchApproveRefusesBadInputBeforeAnyWork(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	if _, err := s.BatchApproveSubscriptions(context.Background(), nil, &selectionVerifier{}, now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodeSelectionInvalid) {
		t.Fatalf("empty batch = %v, want %s", err, store.CodeSelectionInvalid)
	}
	tooMany := make([]string, 0, common.MaxBatchSubscribers+1)
	for index := range common.MaxBatchSubscribers + 1 {
		tooMany = append(tooMany, strings.Repeat("a", 31)+string(rune('0'+index%10)))
	}
	if _, err := s.BatchApproveSubscriptions(context.Background(), tooMany, &selectionVerifier{}, now); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodeSelectionInvalid) {
		t.Fatalf("oversized batch = %v, want %s", err, store.CodeSelectionInvalid)
	}
	if _, err := s.BatchApproveSubscriptions(context.Background(), []string{"nope"}, &selectionVerifier{}, now); err == nil ||
		!strings.HasPrefix(err.Error(), "SUBSCRIBER_ID_INVALID") {
		t.Fatalf("bad id = %v, want SUBSCRIBER_ID_INVALID", err)
	}
}

// TestArtifactDownloadRejectsAChangedSelection proves the download compares the
// recomposition with the approved digest instead of trusting a stored byte.
func TestArtifactDownloadRejectsAChangedSelection(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", store.SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{}, now)
	if err != nil || !result.Saved {
		t.Fatalf("approve: %+v err=%v", result, err)
	}
	// The approved digest no longer matches the stored selection's derivation.
	if _, err := s.DB.Exec(`UPDATE subscription_snapshots SET artifact_id='deadbeef' WHERE subscriber_id=?`, subID); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SubscriptionArtifact(subID); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodeArtifactDrift) {
		t.Fatalf("artifact after a stale digest = %v, want %s", err, store.CodeArtifactDrift)
	}
}

// TestBlockingSaveLeavesEveryTableUntouched is the "blocking does not write"
// invariant across all five storage legs of one save.
func TestBlockingSaveLeavesEveryTableUntouched(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	lineID, _, subID := selectionFixture(t, s, now)
	tables := []string{"subscribers", "subscription_lines", "subscription_outs", "subscription_rules", "subscription_networks", "subscription_snapshots", "proxy_credentials", "subscription_tokens"}
	before := make(map[string]int, len(tables))
	for _, table := range tables {
		before[table] = countRows(t, s, table)
	}
	// A refusing kernel gate is a blocking diagnostic, not an error.
	result, err := s.ApproveSubscriptionSelection(context.Background(), subID, "", store.SelectionSpec{LineIDs: []string{lineID}}, &selectionVerifier{failSingBox: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Saved || !result.Preview.Blocking() {
		t.Fatalf("result = %+v, want a blocked unsaved preview", result)
	}
	for _, table := range tables {
		if after := countRows(t, s, table); after != before[table] {
			t.Fatalf("%s changed %d -> %d after a blocked save", table, before[table], after)
		}
	}
}

// TestSelectionSpecNormalizeIsTheAntiCorruptionBoundary proves the submitted
// value cannot smuggle a duplicate, a non-canonical id or an unbounded list past
// the public entry points.
func TestSelectionSpecNormalizeIsTheAntiCorruptionBoundary(t *testing.T) {
	spec := store.SelectionSpec{
		LineIDs: []string{"  " + strings.Repeat("a", 32) + " ", strings.Repeat("a", 32)},
		OutID:   " ",
	}
	normalized, err := spec.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	if len(normalized.LineIDs) != 1 || normalized.LineIDs[0] != strings.Repeat("a", 32) {
		t.Fatalf("normalized lines = %q, want one canonical id", normalized.LineIDs)
	}
	if normalized.OutID != "" {
		t.Fatalf("normalized out = %q, want the empty slot", normalized.OutID)
	}
	// The caller's slice is not aliased by the result.
	normalized.LineIDs[0] = "mutated"
	if spec.LineIDs[0] == "mutated" {
		t.Fatal("Normalize returned a slice aliasing the caller's input")
	}
	if _, err := (store.SelectionSpec{LineIDs: []string{"A" + strings.Repeat("a", 31)}}).Normalize(); err == nil {
		t.Fatal("a non-canonical id was accepted")
	}
	if _, err := (store.SelectionSpec{LineIDs: []string{strings.Repeat("a", 32)}, OutID: "nope"}).Normalize(); err == nil ||
		!strings.HasPrefix(err.Error(), store.CodeSelectionInvalid) {
		t.Fatalf("bad out id = %v, want %s", err, store.CodeSelectionInvalid)
	}
}

// countRows is the shared row counter of this file.
func countRows(t *testing.T, s *store.Store, table string) int {
	t.Helper()
	var count int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}

// TestParseSelectionSpecIsAnAntiCorruptionBoundary proves a JSON body cannot
// smuggle an unknown field, a second document or a non-canonical id past the
// store's input boundary.
func TestParseSelectionSpecIsAnAntiCorruptionBoundary(t *testing.T) {
	line := strings.Repeat("a", 32)
	spec, err := store.ParseSelectionSpec([]byte(`{"line_ids":["` + line + `"],"rules":[{"stable_key":"preset-direct-cn","version":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	if len(spec.LineIDs) != 1 || spec.LineIDs[0] != line || len(spec.Rules) != 1 || spec.Rules[0].Version != 1 {
		t.Fatalf("spec = %+v", spec)
	}
	cases := map[string]string{
		"unknown field":   `{"line_ids":["` + line + `"],"extra":true}`,
		"second document": `{"line_ids":["` + line + `"]}{"line_ids":[]}`,
		"empty":           `   `,
		"not json":        `line_ids=`,
		"bad id":          `{"line_ids":["nope"]}`,
		"bad out":         `{"line_ids":["` + line + `"],"out_id":"nope"}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := store.ParseSelectionSpec([]byte(body)); err == nil {
				t.Fatalf("store.ParseSelectionSpec(%q) accepted the body", body)
			}
		})
	}
}
