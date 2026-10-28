package dispatch

// The restored marker is written by the Web account (meshmux) and read by both
// the Web and the root executor. The reader therefore takes the expected owner
// explicitly (the root executor must not assume its own euid) and still refuses
// a loose, symlinked, foreign-owned or malformed document.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func writeMarkerFixture(t *testing.T, dataDir string, marker RestoredMarker) string {
	t.Helper()
	dir := filepath.Join(dataDir, HubUpgradeDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	body, err := json.MarshalIndent(marker, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, restoredMarkerName)
	if err := os.WriteFile(path, body, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestReadRestoredMarkerOwnerParameter(t *testing.T) {
	dataDir := t.TempDir()
	marker := RestoredMarker{
		Schema: RestoredSchema, OperationID: strings.Repeat("a", 32),
		SnapshotAt: time.Date(2026, 10, 26, 9, 30, 0, 0, time.UTC), Lossy: true,
	}
	writeMarkerFixture(t, dataDir, marker)

	got, ok, err := ReadRestoredMarkerFor(dataDir, os.Geteuid())
	if err != nil || !ok || got.OperationID != marker.OperationID || !got.Lossy {
		t.Fatalf("owner-parameterized read = %+v ok=%v err=%v", got, ok, err)
	}
	// The root executor runs as uid 0 while the marker is meshmux's. A wrong
	// expected owner must be a stable refusal, not a silent "no marker": the
	// reverse is the production bug where root's euid never matches the Web's.
	if os.Geteuid() != 0 {
		if _, _, err := ReadRestoredMarkerFor(dataDir, os.Geteuid()+1); err == nil ||
			!strings.HasPrefix(err.Error(), "HUB_RESTORE_MARKER_INVALID") {
			t.Fatalf("foreign-owner read err = %v, want HUB_RESTORE_MARKER_INVALID", err)
		}
	}
	// The default reader still means "this account", so the Web path is unchanged.
	if _, ok, err := ReadRestoredMarker(dataDir); err != nil || !ok {
		t.Fatalf("default read ok=%v err=%v", ok, err)
	}
}
