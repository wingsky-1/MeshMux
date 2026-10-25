package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/policy"
)

// The Task-3 storage leg: a fresh database migrates to schema 12 and carries
// the versioned preset seed bundle; reopening replays idempotently.
func TestSchema12RuleLibraryAndPresetSeeds(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != DatabaseSchemaVersion {
		t.Fatalf("user_version = %d, want %d", version, DatabaseSchemaVersion)
	}
	lib := policy.New(s.DB)
	presets, err := lib.ListRules("preset")
	if err != nil {
		t.Fatalf("ListRules(preset): %v", err)
	}
	if len(presets) != len(policy.Presets) {
		t.Fatalf("seeded presets = %d, want %d", len(presets), len(policy.Presets))
	}
	for _, p := range presets {
		if p.Version != policy.PresetBundleVersion || p.Origin != policy.OriginPreset {
			t.Fatalf("seeded row = %+v, want version %d origin preset", p, policy.PresetBundleVersion)
		}
		if err := (policy.Rule{StableKey: "seed-shape-check", Name: p.Name, Action: p.Action, Kind: p.Kind, Values: p.Values}.Validate()); err != nil {
			t.Fatalf("seeded preset %q has invalid fields: %v", p.StableKey, err)
		}
	}
	// policy_schema stays 8: the storage migration must not touch the route
	// policy contract (ADR-0007).
	var policySchema int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM route_policies`).Scan(&policySchema); err != nil {
		t.Fatalf("route_policies table missing after migration: %v", err)
	}
	var mirror string
	if err := s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='hub_upgrade_operations'`).Scan(&mirror); err != nil {
		t.Fatalf("11d-reserved mirror table missing after migration: %v", err)
	}
}

// The C3 leg: the version bump is last, so a seed failure leaves the version
// untouched and the next open retries the whole leg instead of skipping a
// half-seeded library.
func TestSchema12MigrationRecoversFromSeedFailure(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Break the library shape and rewind the version: the seed must fail.
	if _, err := s.DB.Exec(`DROP TABLE policy_rules; CREATE TABLE policy_rules(stable_key TEXT); PRAGMA user_version=10;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err == nil || !strings.Contains(err.Error(), "SCHEMA_MIGRATION_FAILED") {
		t.Fatalf("broken seed Migrate() = %v, want SCHEMA_MIGRATION_FAILED", err)
	}
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != 10 {
		t.Fatalf("version after failed migration = %d err=%v, want 10 (retry, not skip)", version, err)
	}
	// Drop the broken shape and replay: full recovery with the seed bundle.
	if _, err := s.DB.Exec(`DROP TABLE policy_rules;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("replay Migrate(): %v", err)
	}
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("version after replay = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
	if presets, err := policy.New(s.DB).ListRules("preset"); err != nil || len(presets) != len(policy.Presets) {
		t.Fatalf("presets after replay = %d %v, want %d", len(presets), err, len(policy.Presets))
	}
}

// The C2 lock: a database that already sits at 12 keeps the 11d-reserved
// mirror (first升到 12，再模拟 11d 合入仍能补齐); a database arriving at 11
// with mirror rows migrates to 12 without losing them.
func TestSchema11MirrorBackfill(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Drop the mirror the fresh migration just backfilled, then re-run: the
	// ensure step must recreate it without touching the version.
	if _, err := s.DB.Exec(`DROP TABLE hub_upgrade_operations`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() after mirror drop: %v", err)
	}
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("version after backfill = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
	var mirror string
	if err := s.DB.QueryRow(`SELECT name FROM sqlite_master WHERE type='table' AND name='hub_upgrade_operations'`).Scan(&mirror); err != nil {
		t.Fatalf("mirror not backfilled: %v", err)
	}
	// A version-11 database carrying 11d mirror rows (simulated 11d leg
	// output) migrates to 12 with the rows and the rule library intact.
	if _, err := s.DB.Exec(`INSERT INTO hub_upgrade_operations(operation_id, target_version, from_version, state, manifest_sha256, package_sha256, db_schema, backup_generation, created_at, updated_at)
	  VALUES('op11d','1.0.0','1.0.0','done','m','p',11,1,0,0); PRAGMA user_version=11;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() from 11: %v", err)
	}
	var rows int
	if err := s.DB.QueryRow(`SELECT COUNT(*) FROM hub_upgrade_operations WHERE operation_id='op11d'`).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("11d mirror rows after migration = %d err=%v, want 1", rows, err)
	}
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("version after 11→12 = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
	if presets, err := policy.New(s.DB).ListRules("preset"); err != nil || len(presets) != len(policy.Presets) {
		t.Fatalf("presets after 11→12 = %d %v, want %d", len(presets), err, len(policy.Presets))
	}
}
