package policy

import (
	"database/sql"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	_ "modernc.org/sqlite"
)

func openPolicyTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(SchemaDDL()); err != nil {
		t.Fatalf("SchemaDDL: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := SeedPresetsTx(tx, time.Now().Unix()); err != nil {
		t.Fatalf("SeedPresetsTx: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	return db
}

// fakeUsage is the injected used-by port: the policy core must delegate the
// control-layer edge tables rather than query them itself. It is keyed by
// "stable_key@version" so a sibling revision stays unreferenced.
type fakeUsage struct {
	used  map[string][]RuleUsage
	err   error
	calls int
}

func (f *fakeUsage) RuleUsedBy(_ Querier, stableKey string, version int) ([]RuleUsage, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.used[stableKey+"@"+itoa(version)], nil
}

func TestPresetWritesAreImmutable(t *testing.T) {
	s := New(openPolicyTestDB(t), &fakeUsage{})
	now := time.Now()
	if _, err := s.CreateCustomRule("preset-evil", " squat", ActionDirect, MatcherGeoSite, []string{"cn"}, now); err == nil ||
		!strings.HasPrefix(err.Error(), "RULE_PRESET_IMMUTABLE") {
		t.Fatalf("preset-namespace create = %v, want RULE_PRESET_IMMUTABLE", err)
	}
	seeded, err := s.GetRule("preset-direct-cn", 1)
	if err != nil {
		t.Fatalf("seeded preset missing: %v", err)
	}
	if seeded.Origin != "preset" || seeded.Version != 1 {
		t.Fatalf("seeded preset = %+v, want origin preset version 1", seeded)
	}
	if _, err := s.ReviseCustomRule(seeded.StableKey, "改名", ActionProxy, MatcherGeoSite, []string{"cn"}, now); err == nil ||
		!strings.HasPrefix(err.Error(), "RULE_PRESET_IMMUTABLE") {
		t.Fatalf("preset revise = %v, want RULE_PRESET_IMMUTABLE", err)
	}
	if err := s.DeleteRule(seeded.StableKey, seeded.Version); err == nil ||
		!strings.HasPrefix(err.Error(), "RULE_PRESET_IMMUTABLE") {
		t.Fatalf("preset delete = %v, want RULE_PRESET_IMMUTABLE", err)
	}
}

func TestCustomRuleCRUDAndRevisionChain(t *testing.T) {
	s := New(openPolicyTestDB(t), &fakeUsage{})
	now := time.Now()
	created, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if created.Version != 1 || created.Origin != "custom" {
		t.Fatalf("created = %+v", created)
	}
	if _, err := s.CreateCustomRule("proxy-ai", "重名键", ActionDirect, MatcherGeoSite, []string{"cn"}, now); err == nil ||
		!strings.HasPrefix(err.Error(), "RULE_CONFLICT") {
		t.Fatalf("duplicate stable_key create = %v, want RULE_CONFLICT", err)
	}
	revised, err := s.ReviseCustomRule("proxy-ai", "AI 走代理 v2", ActionProxy, MatcherRuleSet, []string{"ai", "ai-video"}, now)
	if err != nil {
		t.Fatalf("revise: %v", err)
	}
	if revised.Version != 2 {
		t.Fatalf("revised version = %d, want 2", revised.Version)
	}
	old, err := s.GetRule("proxy-ai", 1)
	if err != nil || old.Name != "AI 走代理" {
		t.Fatalf("old revision changed: %+v %v", old, err)
	}
	latest, err := s.LatestRule("proxy-ai")
	if err != nil || latest.Version != 2 {
		t.Fatalf("latest = %+v %v", latest, err)
	}
	all, err := s.LatestRules()
	if err != nil {
		t.Fatalf("LatestRules: %v", err)
	}
	foundCustom, foundPreset := false, false
	for _, r := range all {
		if r.StableKey == "proxy-ai" && r.Version == 2 {
			foundCustom = true
		}
		if r.Origin == "preset" {
			foundPreset = true
		}
	}
	if !foundCustom || !foundPreset {
		t.Fatalf("LatestRules misses rows: %+v", all)
	}
	if _, err := s.GetRule("proxy-ai", 9); err == nil || !strings.HasPrefix(err.Error(), "RULE_NOT_FOUND") {
		t.Fatalf("missing revision = %v, want RULE_NOT_FOUND", err)
	}
	if err := s.DeleteRule("proxy-ai", 1); err != nil {
		t.Fatalf("unreferenced delete: %v", err)
	}
	if _, err := s.GetRule("proxy-ai", 1); err == nil {
		t.Fatal("deleted row still readable")
	}
}

func TestUsedByAndDeleteGuardShareOneSource(t *testing.T) {
	db := openPolicyTestDB(t)
	usage := &fakeUsage{used: map[string][]RuleUsage{
		"proxy-ai@1":         {{SubscriberID: "sub-alice", SubscriberName: "爱丽丝"}, {SubscriberID: "sub-bob", SubscriberName: "鲍勃"}},
		"preset-direct-cn@1": {{SubscriberID: "sub-alice", SubscriberName: "爱丽丝"}},
	}}
	s := New(db, usage)
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	used, err := s.RuleUsedBy("proxy-ai", 1)
	if err != nil {
		t.Fatalf("RuleUsedBy: %v", err)
	}
	var names []string
	for _, u := range used {
		names = append(names, u.SubscriberName)
	}
	if len(names) != 2 || names[0] != "爱丽丝" || names[1] != "鲍勃" {
		t.Fatalf("used-by names = %q, want [爱丽丝 鲍勃]", names)
	}
	err = s.DeleteRule("proxy-ai", 1)
	if err == nil || !strings.HasPrefix(err.Error(), "RULE_REFERENCED_BY_SUBSCRIPTIONS") {
		t.Fatalf("referenced delete = %v, want RULE_REFERENCED_BY_SUBSCRIPTIONS", err)
	}
	for _, want := range []string{"爱丽丝", "鲍勃"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal hides the subscriber list: %v", err)
		}
	}
	// The guard and the page read the same injected port, so a referenced
	// revision can never be deleted by the page path either.
	if usage.calls < 2 {
		t.Fatalf("used-by port calls = %d, want the page and the guard to share it", usage.calls)
	}
	// A sibling revision nobody references is still deletable.
	if _, err := s.ReviseCustomRule("proxy-ai", "AI 走代理 v2", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRule("proxy-ai", 2); err != nil {
		t.Fatalf("unreferenced sibling delete refused: %v", err)
	}
	// Referencing the preset proves the guard is not custom-only.
	if used, err := s.RuleUsedBy("preset-direct-cn", 1); err != nil || len(used) != 1 || used[0].SubscriberName != "爱丽丝" {
		t.Fatalf("preset used-by = %+v %v", used, err)
	}
}

func TestUsedByFailClosedOnUnknownEdgeShape(t *testing.T) {
	db := openPolicyTestDB(t)
	s := New(db, &fakeUsage{err: errors.New(versions.CodeDatabaseUnavailable)})
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// C1: an unreadable edge table (a partial migration, a broken reader) is
	// doubt, never "nobody references this".
	if _, err := s.RuleUsedBy("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), versions.CodeDatabaseUnavailable) {
		t.Fatalf("unreadable used-by = %v, want %s", err, versions.CodeDatabaseUnavailable)
	}
	if err := s.DeleteRule("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), versions.CodeDatabaseUnavailable) {
		t.Fatalf("unreadable delete = %v, want %s", err, versions.CodeDatabaseUnavailable)
	}
	if _, err := s.GetRule("proxy-ai", 1); err != nil {
		t.Fatalf("failed delete removed the row: %v", err)
	}
}

func TestUsedByWithoutReaderFailsClosed(t *testing.T) {
	s := New(openPolicyTestDB(t), nil)
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// A missing used-by port cannot prove the revision is unused, so both the
	// answer and the delete guard fail closed instead of guessing.
	if _, err := s.RuleUsedBy("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), versions.CodeDatabaseUnavailable) {
		t.Fatalf("missing reader used-by = %v, want %s", err, versions.CodeDatabaseUnavailable)
	}
	if err := s.DeleteRule("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), versions.CodeDatabaseUnavailable) {
		t.Fatalf("missing reader delete = %v, want %s", err, versions.CodeDatabaseUnavailable)
	}
	if _, err := s.GetRule("proxy-ai", 1); err != nil {
		t.Fatalf("failed delete removed the row: %v", err)
	}
}

func TestUsedByCountsOrphanEdgeRows(t *testing.T) {
	db := openPolicyTestDB(t)
	s := New(db, &fakeUsage{used: map[string][]RuleUsage{
		"proxy-ai@1": {{SubscriberID: "ghost-sub"}},
	}})
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// I4: an edge row with no subscriber (a missing cascade on the subscriber
	// delete) must still block deletion, surfaced by id. The port reports the
	// orphan; the guard must not drop it for the missing name.
	used, err := s.RuleUsedBy("proxy-ai", 1)
	if err != nil {
		t.Fatalf("RuleUsedBy: %v", err)
	}
	if len(used) != 1 || used[0].SubscriberID != "ghost-sub" {
		t.Fatalf("orphan used-by = %+v, want the ghost row", used)
	}
	if err := s.DeleteRule("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), "RULE_REFERENCED_BY_SUBSCRIPTIONS") {
		t.Fatalf("orphan delete = %v, want RULE_REFERENCED_BY_SUBSCRIPTIONS", err)
	} else if !strings.Contains(err.Error(), "ghost-sub") {
		t.Fatalf("orphan refusal hides the id: %v", err)
	}
}
