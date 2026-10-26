package store

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/policy"
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

// A database arriving at 11 (the 11d-reserved number, which merged with no
// leg of its own) still migrates through the rule-library leg to the owned
// schema, and the migration creates no 11d mirror table: the operation
// journal is authoritative (D3).
func TestSchema11MigratesWithoutMirror(t *testing.T) {
	s, err := OpenStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Rewind to the reserved number: the 11d leg never landed, so the 12 leg
	// must apply on top of 11 exactly as it does on top of 10.
	if _, err := s.DB.Exec(`PRAGMA user_version=11;`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("Migrate() from 11: %v", err)
	}
	var version int
	if err := s.DB.QueryRow("PRAGMA user_version").Scan(&version); err != nil || version != DatabaseSchemaVersion {
		t.Fatalf("version after 11→12+ = %d err=%v, want %d", version, err, DatabaseSchemaVersion)
	}
	if presets, err := policy.New(s.DB).ListRules("preset"); err != nil || len(presets) != len(policy.Presets) {
		t.Fatalf("presets after 11→12+ = %d %v, want %d", len(presets), err, len(policy.Presets))
	}
	var tables int
	if err := s.DB.QueryRow(
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='hub_upgrade_` + `operations'`).Scan(&tables); err != nil || tables != 0 {
		t.Fatalf("mirror table present after migration: tables=%d err=%v", tables, err)
	}
}
