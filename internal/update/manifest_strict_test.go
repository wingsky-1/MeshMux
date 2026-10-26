package update

// The anti-corruption tests of the handoff's inbound documents. The manifest
// set and the Agent config file both arrive from another layer, so they are
// decoded strictly: a shape this build does not understand is refused instead
// of being partially trusted.

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

// TestDecodeManifestSetRejectsUnknownEnvelopeField keeps the set decode exact.
// An extra top-level key is how a newer Hub would signal a contract this binary
// does not implement; silently dropping it would apply a release under rules
// the manifest was written against.
func TestDecodeManifestSetRejectsUnknownEnvelopeField(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	body, err := json.Marshal(fixtureSet(m))
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	document["releases"] = []string{"1.0.0"}
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeManifestSet(tampered); err == nil || codeOf(err) != "MANIFEST_INVALID" {
		t.Fatalf("unknown envelope field err = %v, want MANIFEST_INVALID", err)
	}
}

// TestDecodeManifestSetRejectsTrailingDocument refuses a second JSON document
// travelling after the set: one authenticated byte string describes one set.
func TestDecodeManifestSetRejectsTrailingDocument(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	body, err := json.Marshal(fixtureSet(m))
	if err != nil {
		t.Fatal(err)
	}
	trailing := append(append([]byte{}, body...), []byte("\n{}")...)
	if _, err := decodeManifestSet(trailing); err == nil || codeOf(err) != "MANIFEST_INVALID" {
		t.Fatalf("trailing document err = %v, want MANIFEST_INVALID", err)
	}
}

// TestDecodeManifestSetKeepsSchemaCode keeps the operator-visible classification
// of a pre-set (bare manifest) or foreign envelope.
func TestDecodeManifestSetKeepsSchemaCode(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	bare, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeManifestSet(bare); err == nil || codeOf(err) != "MANIFEST_SCHEMA_INVALID" {
		t.Fatalf("bare manifest err = %v, want MANIFEST_SCHEMA_INVALID", err)
	}
	set := fixtureSet(m)
	set.Schema = upgrade.SetSchema + "-v2"
	foreign, err := json.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeManifestSet(foreign); err == nil || codeOf(err) != "MANIFEST_SCHEMA_INVALID" {
		t.Fatalf("foreign schema err = %v, want MANIFEST_SCHEMA_INVALID", err)
	}
}

// TestRunRefusesUnknownManifestFieldBeforeAnyEffect proves the strict decode is
// wired into the entry point, not only into its helper: a manifest the build
// cannot fully understand must not reach the space check, the record or the
// package fetch.
func TestRunRefusesUnknownManifestFieldBeforeAnyEffect(t *testing.T) {
	m := fixtureManifest(t, []byte("fixture package\n"), strings.Repeat("a", 64))
	body := setBody(t, m)
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatal(err)
	}
	document["database_migration"] = "irreversible"
	tampered, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	cfg := fixtureConfig(t, m)
	cfg.FetchManifest = func(context.Context) ([]byte, error) { return tampered, nil }
	runner := &fixtureRunner{}
	if _, err := Run(context.Background(), cfg, runner); err == nil || codeOf(err) != "MANIFEST_INVALID" {
		t.Fatalf("code = %v, want MANIFEST_INVALID", err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("an unreadable manifest executed %v", runner.calls)
	}
}
