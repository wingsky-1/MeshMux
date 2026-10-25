package policy

import (
	"database/sql"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// seedSubscriptionEdge builds the minimal Task-4-shaped reference edge the
// used-by lookup and the delete guard share: a subscribers row plus the
// subscription_rules side table (subscriber_id, rule_stable_key, rule_version,
// position). Task 4 owns this table; the DDL here is the contract it must
// honor (same table and column names).
func seedSubscriptionEdge(t *testing.T, db *sql.DB, subscriberID, subscriberName, stableKey string, version int) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS subscribers(
	  id TEXT PRIMARY KEY, display_name TEXT NOT NULL, state TEXT NOT NULL DEFAULT 'active',
	  revision INTEGER NOT NULL DEFAULT 1, created_at INTEGER NOT NULL DEFAULT 0, updated_at INTEGER NOT NULL DEFAULT 0)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS subscription_rules(
	  subscriber_id TEXT NOT NULL, rule_stable_key TEXT NOT NULL, rule_version INTEGER NOT NULL,
	  position INTEGER NOT NULL, UNIQUE(subscriber_id, position))`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	if _, err := db.Exec(`INSERT INTO subscribers(id, display_name, state, revision, created_at, updated_at)
	  VALUES(?,?,?,?,?,?) ON CONFLICT(id) DO NOTHING`, subscriberID, subscriberName, "active", 1, now, now); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO subscription_rules(subscriber_id, rule_stable_key, rule_version, position)
	  VALUES(?,?,?,COALESCE((SELECT MAX(position)+1 FROM subscription_rules WHERE subscriber_id=?),0))`, subscriberID, stableKey, version, subscriberID); err != nil {
		t.Fatal(err)
	}
}

func TestPresetWritesAreImmutable(t *testing.T) {
	s := New(openPolicyTestDB(t))
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
	s := New(openPolicyTestDB(t))
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
	s := New(openPolicyTestDB(t))
	db := s.DB()
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// No edge table yet: nothing references the rule and deletion succeeds.
	if used, err := s.RuleUsedBy("proxy-ai", 1); err != nil || len(used) != 0 {
		t.Fatalf("used-by without edge table = %+v %v", used, err)
	}
	seedSubscriptionEdge(t, db, "sub-alice", "爱丽丝", "proxy-ai", 1)
	seedSubscriptionEdge(t, db, "sub-bob", "鲍勃", "proxy-ai", 1)
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
	// A sibling revision nobody references is still deletable.
	if _, err := s.ReviseCustomRule("proxy-ai", "AI 走代理 v2", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteRule("proxy-ai", 2); err != nil {
		t.Fatalf("unreferenced sibling delete refused: %v", err)
	}
	// Referencing the preset proves the guard is not custom-only.
	seedSubscriptionEdge(t, db, "sub-alice", "爱丽丝", "preset-direct-cn", 1)
	if used, err := s.RuleUsedBy("preset-direct-cn", 1); err != nil || len(used) != 1 || used[0].SubscriberName != "爱丽丝" {
		t.Fatalf("preset used-by = %+v %v", used, err)
	}
}

func TestUsedByFailClosedOnUnknownEdgeShape(t *testing.T) {
	s := New(openPolicyTestDB(t))
	db := s.DB()
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// C1: the edge table exists but not in the Task-4 shape (a partial
	// migration). The answer must be doubt, never "nobody references this".
	if _, err := db.Exec(`CREATE TABLE subscription_rules(broken TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RuleUsedBy("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE") {
		t.Fatalf("wrong-shape used-by = %v, want DATABASE_UNAVAILABLE", err)
	}
	if err := s.DeleteRule("proxy-ai", 1); err == nil || !strings.HasPrefix(err.Error(), "DATABASE_UNAVAILABLE") {
		t.Fatalf("wrong-shape delete = %v, want DATABASE_UNAVAILABLE", err)
	}
	if _, err := s.GetRule("proxy-ai", 1); err != nil {
		t.Fatalf("failed delete removed the row: %v", err)
	}
}

func TestUsedByCountsOrphanEdgeRows(t *testing.T) {
	s := New(openPolicyTestDB(t))
	db := s.DB()
	now := time.Now()
	if _, err := s.CreateCustomRule("proxy-ai", "AI 走代理", ActionProxy, MatcherRuleSet, []string{"ai"}, now); err != nil {
		t.Fatal(err)
	}
	// I4: an edge row with no subscriber (a missing cascade on the subscriber
	// delete) must still block deletion, surfaced by id.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS subscribers(
	  id TEXT PRIMARY KEY, display_name TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS subscription_rules(
	  subscriber_id TEXT NOT NULL, rule_stable_key TEXT NOT NULL, rule_version INTEGER NOT NULL,
	  position INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO subscription_rules(subscriber_id, rule_stable_key, rule_version, position)
	  VALUES('ghost-sub','proxy-ai',1,0)`); err != nil {
		t.Fatal(err)
	}
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
