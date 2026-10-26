package node

// Staged revision retention (#113 4-3).
//
// staged/<revision>-{candidate,config}.json was written once per revision and
// never removed, so the directory grew by one pair per applied change set for
// the lifetime of the node. The LKG candidate is read back from that directory
// (loadLKGCandidate), so the collection can only run after an apply+readback
// proved the change set: the current revision must survive, and the previous
// one must survive too because it is the release a revert can return to. That
// is the same N-1 rule the 11c-3 rollback store applies to its confirmed
// generations (update.backupKeepConfirmed = 1).

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// TestStagedGCKeepsTheCurrentAndPreviousRevision is the end-to-end rule: after
// two healthy applies the revision two steps back is collected, while the LKG
// revision and the one before it stay readable for readback and revert.
func TestStagedGCKeepsTheCurrentAndPreviousRevision(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)

	// The bootstrap revision (7) is staged by the first start.
	for _, revision := range []int64{7} {
		if _, err := os.Lstat(stagedCandidatePath(root, revision)); err != nil {
			t.Fatalf("bootstrap staged candidate %d is missing: %v", revision, err)
		}
	}

	// Revision 9: current=9, previous=7. Nothing is older than the window, so
	// both pairs survive.
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("a", 32), 11, 9)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply 9 = %+v", result)
	}
	for _, revision := range []int64{7, 9} {
		assertStagedRevision(t, root, revision, true)
	}

	// Revision 10: current=10, previous=9. The window is [9, 10], so revision 7
	// is collected and the revert anchor (9) survives.
	controller.candidate = testCandidate(10)
	apply = task(protocol.KindConfigApply, strings.Repeat("2", 32), strings.Repeat("b", 32), 12, 10)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply 10 = %+v", result)
	}
	assertStagedRevision(t, root, 7, false)
	for _, revision := range []int64{9, 10} {
		assertStagedRevision(t, root, revision, true)
	}

	// The current revision's candidate is what every readback reads, so a
	// config.readback for 10 must still find it after the collection.
	readback := task(protocol.KindConfigReadback, strings.Repeat("3", 32), strings.Repeat("c", 32), 13, 10)
	if result := runtime.Execute(context.Background(), readback); result.Status != "healthy" {
		t.Fatalf("readback after GC = %+v", result)
	}
}

// TestStagedGCKeepsThePreviousRevisionAcrossARevisionJump pins the carve-out
// that the window arithmetic alone would miss: a Hub that skips revisions
// (10 -> 12) leaves the recorded previous revision (10) outside the numeric
// window, and it is still the release a revert restores.
func TestStagedGCKeepsThePreviousRevisionAcrossARevisionJump(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(10)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("a", 32), 11, 10)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply 10 = %+v", result)
	}
	// A stage-only revision 11: pending work, never collected by the next apply
	// because it sits above the window.
	stage := task(protocol.KindConfigStage, strings.Repeat("2", 32), strings.Repeat("b", 32), 12, 11)
	controller.candidate = testCandidate(11)
	if result := runtime.Execute(context.Background(), stage); result.Status != "healthy" {
		t.Fatalf("stage 11 = %+v", result)
	}

	// Apply 12: current=12, previous=10, oldest kept = 11. Revision 10 is below
	// the window but is the revert anchor, so it survives; 11 is inside it.
	controller.candidate = testCandidate(12)
	apply = task(protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("c", 32), 13, 12)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply 12 = %+v", result)
	}
	for _, revision := range []int64{10, 11, 12} {
		assertStagedRevision(t, root, revision, true)
	}
	// The bootstrap revision (7) is outside both the window and the anchors.
	assertStagedRevision(t, root, 7, false)
}

// TestStagedGCLeavesAFailedApplyAlone pins the trigger: only a proven change
// set collects. A rolled-back apply still needs every staged file it may have
// to restore from, so nothing is removed.
func TestStagedGCLeavesAFailedApplyAlone(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("a", 32), 11, 9)
	if result := runtime.Execute(context.Background(), apply); result.Status != "healthy" {
		t.Fatalf("apply 9 = %+v", result)
	}

	// Revision 12 writes its staged pair and then fails at the kernel restart.
	runner.restartFail = true
	controller.candidate = testCandidate(12)
	failed := task(protocol.KindConfigApply, strings.Repeat("2", 32), strings.Repeat("b", 32), 12, 12)
	if result := runtime.Execute(context.Background(), failed); result.Status != "rolled_back" {
		t.Fatalf("failed apply = %+v", result)
	}
	// The failed revision's staged pair stays, and so does the LKG pair: the
	// rollback restored 9, which must remain readable.
	for _, revision := range []int64{7, 9, 12} {
		assertStagedRevision(t, root, revision, true)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	if state.Revision != 9 {
		t.Fatalf("state revision after rollback = %d, want 9", state.Revision)
	}
}

// TestStagedGCCollectsOnlyItsOwnRegularFiles pins the collection boundary: only
// staged revision pairs below the window are removed. Foreign names, a
// directory that merely looks like a revision, and a symlink are all left
// untouched — the directory is never walked recursively and no link is
// followed.
func TestStagedGCCollectsOnlyItsOwnRegularFiles(t *testing.T) {
	root := t.TempDir()
	dir := rooted(root, stagedDir)
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	write := func(name string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("{}"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	for _, revision := range []int64{2, 3, 4} {
		write(fmt.Sprintf("%020d-candidate.json", revision))
		write(fmt.Sprintf("%020d-config.json", revision))
	}
	// Not collectable: a foreign name, a malformed number, a directory with the
	// staged shape, and a symlink to a file that must survive. Revision 1 is
	// below the window, so only its file type keeps it.
	write("notes.txt")
	write("0000000000000000000x-candidate.json")
	if err := os.Mkdir(filepath.Join(dir, fmt.Sprintf("%020d-candidate.json", 1)), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "outside.json")
	if err := os.WriteFile(target, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, fmt.Sprintf("%020d-config.json", 1))); err != nil {
		t.Fatal(err)
	}

	removed, err := gcStagedRevisions(root, 4, 3, stagedKeepRevisions)
	if err != nil {
		t.Fatal(err)
	}
	// current=4, previous=3, keep=2 => window [3, 4]: revision 2 is collected.
	if len(removed) != 2 {
		t.Fatalf("collected %v, want the two files of revision 2", removed)
	}
	for _, name := range []string{
		fmt.Sprintf("%020d-candidate.json", 3),
		fmt.Sprintf("%020d-config.json", 3),
		fmt.Sprintf("%020d-candidate.json", 4),
		fmt.Sprintf("%020d-config.json", 4),
		"notes.txt",
		"0000000000000000000x-candidate.json",
	} {
		if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s was collected: %v", name, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("%020d-candidate.json", 2))); !os.IsNotExist(err) {
		t.Fatalf("the staged pair of revision 2 survived: %v", err)
	}
	if info, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("%020d-candidate.json", 1))); err != nil || !info.IsDir() {
		t.Fatalf("the look-alike directory was removed or replaced: %v", err)
	}
	// The symlink is untouched and its target still exists: a link is never
	// followed, so the collection cannot reach outside the staged directory.
	if info, err := os.Lstat(filepath.Join(dir, fmt.Sprintf("%020d-config.json", 1))); err != nil ||
		info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("the symlink was collected or replaced: %v", err)
	}
	if _, err := os.Lstat(target); err != nil {
		t.Fatalf("the symlink target was removed: %v", err)
	}
}

// TestStagedGCRetentionMatchesTheRollbackStore pins the constant: the staged
// window is the same N-1 shape as update.backupKeepConfirmed, expressed as
// "current + previous" rather than "newest confirmed only".
func TestStagedGCRetentionMatchesTheRollbackStore(t *testing.T) {
	if stagedKeepRevisions != 2 {
		t.Fatalf("stagedKeepRevisions = %d, want the current revision and the N-1 revert anchor", stagedKeepRevisions)
	}
	// A missing staged directory is a fresh host, not an error.
	root := t.TempDir()
	removed, err := gcStagedRevisions(root, 5, 0, stagedKeepRevisions)
	if err != nil || len(removed) != 0 {
		t.Fatalf("missing staged directory = %v, %v", removed, err)
	}
	// A revision below 1 is not a revision the Agent can ever have written.
	if _, err := gcStagedRevisions(root, 0, 0, stagedKeepRevisions); err == nil {
		t.Fatal("a zero current revision was accepted")
	}
}

// assertStagedRevision checks both files of one staged revision.
func assertStagedRevision(t *testing.T, root string, revision int64, want bool) {
	t.Helper()
	for _, path := range []string{stagedCandidatePath(root, revision), stagedConfigPath(root, revision)} {
		_, err := os.Lstat(path)
		if want && err != nil {
			t.Fatalf("staged revision %d is missing %s: %v", revision, path, err)
		}
		if !want && !os.IsNotExist(err) {
			t.Fatalf("staged revision %d still has %s: %v", revision, path, err)
		}
	}
}
