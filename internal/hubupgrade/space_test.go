package hubupgrade

// Space-derivation tests of #11d Task 3 (spec §5.9, C14). The Hub backup is
// larger than the Node constant, so the floor is re-derived here and pinned:
// target package + two database copies + the staged old binary + restore
// headroom, raised to the installer's 1 GiB preflight.

import (
	"strings"
	"testing"
)

func TestBackupSpaceFloor(t *testing.T) {
	const mib = uint64(1 << 20)
	if got, want := RequiredSpace(0), uint64(512)*mib; got != want {
		t.Fatalf("RequiredSpace(0) = %d, want %d", got, want)
	}
	db := uint64(37) * mib
	want := uint64(128)*mib + 2*db + uint64(128)*mib + db + uint64(256)*mib
	if got := RequiredSpace(db); got != want {
		t.Fatalf("RequiredSpace(%d) = %d, want %d", db, got, want)
	}
	if got, want := Floor(0), uint64(1<<30); got != want {
		t.Fatalf("Floor(0) = %d, want %d", got, want)
	}
	if Floor(db) != 1<<30 {
		t.Fatalf("Floor(%d) = %d, want the 1 GiB floor", db, Floor(db))
	}
	large := uint64(512) * mib
	if got, want := Floor(large), RequiredSpace(large); got != want {
		t.Fatalf("Floor(%d) = %d, want %d", large, got, want)
	}
	if RequiredSpace(1) <= RequiredSpace(0) {
		t.Fatal("the database term is missing")
	}
}

func TestCheckFreeSpaceRefusesImpossibleNeed(t *testing.T) {
	dir := t.TempDir()
	if err := CheckFreeSpace(dir, 1); err != nil {
		t.Fatalf("small need refused: %v", err)
	}
	if err := CheckFreeSpace(dir, ^uint64(0)/2); err == nil || !strings.HasPrefix(err.Error(), "HUB_SPACE_INSUFFICIENT") {
		t.Fatalf("impossible need = %v", err)
	}
	if _, err := freeBytes(dir); err != nil {
		t.Fatalf("freeBytes: %v", err)
	}
}
