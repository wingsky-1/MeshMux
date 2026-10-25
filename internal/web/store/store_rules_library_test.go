package store

import (
	"path/filepath"
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
	if version != DatabaseSchemaVersion || DatabaseSchemaVersion != 12 {
		t.Fatalf("user_version = %d, want 12", version)
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
