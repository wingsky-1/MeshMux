package ledger

// Tests for the #11d Task 6 crash claim (spec §5.6 step 6, oracle R1). The
// claim is root-written evidence: it must round-trip the complete old pin set,
// live at exactly <dir>/upgrade-claim.json, reject unknown/trailing bytes, and
// be removable idempotently.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func claimFixture() Claim {
	return Claim{
		Schema: ClaimSchema, Phase: ClaimPhaseSwapping,
		OperationID:   strings.Repeat("a", 32),
		TargetVersion: "1.0.1", FromVersion: "1.0.0-dev",
		NewSHA256: strings.Repeat("b", 64),
		OldPins: Pins{
			HubSharedSHA: strings.Repeat("c", 64), HubManagedSHA: strings.Repeat("c", 64),
			LineSharedSHA: strings.Repeat("c", 64), LineAgentVersion: "1.0.0-dev",
			LineAgentSHA: strings.Repeat("c", 64), LineAgentManagedSHA: strings.Repeat("d", 64),
			AgentJSONVersion: "1.0.0-dev", AgentJSONSHA: strings.Repeat("c", 64),
		},
		CreatedAt: time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC),
	}
}

func TestClaimRoundTrip(t *testing.T) {
	dir := t.TempDir()
	claim := claimFixture()
	if err := WriteClaim(dir, claim); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(filepath.Join(dir, "upgrade-claim.json"))
	if err != nil || info.Mode().Perm() != 0640 {
		t.Fatalf("claim file = %v, %v; want 0640", info, err)
	}
	got, ok, err := ReadClaim(dir)
	if err != nil || !ok {
		t.Fatalf("ReadClaim ok=%v err=%v", ok, err)
	}
	if got.OperationID != claim.OperationID || got.Phase != ClaimPhaseSwapping ||
		got.NewSHA256 != claim.NewSHA256 || got.OldPins != claim.OldPins {
		t.Fatalf("claim round-trip = %+v", got)
	}
	if err := RemoveClaim(dir); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := ReadClaim(dir); ok || err != nil {
		t.Fatalf("after remove ok=%v err=%v", ok, err)
	}
	if err := RemoveClaim(dir); err != nil {
		t.Fatalf("remove is not idempotent: %v", err)
	}
}

func TestClaimRejectsMalformedDocument(t *testing.T) {
	for name, body := range map[string]string{
		"unknown field": `{"schema":1,"phase":"swapping","operation_id":"` + strings.Repeat("a", 32) + `","target_version":"1.0.1","from_version":"1.0.0-dev","new_sha256":"` + strings.Repeat("b", 64) + `","old_pins":{"hub_shared_sha256":"` + strings.Repeat("c", 64) + `","hub_managed_sha256":"` + strings.Repeat("c", 64) + `"},"created_at":"2026-10-26T12:00:00Z","extra":true}`,
		"trailing":      `{"schema":1} {}`,
		"bad phase":     `{"schema":1,"phase":"other"}`,
		"partial line":  `{"schema":1,"phase":"swapping","operation_id":"` + strings.Repeat("a", 32) + `","target_version":"1.0.1","from_version":"1.0.0-dev","new_sha256":"` + strings.Repeat("b", 64) + `","old_pins":{"hub_shared_sha256":"` + strings.Repeat("c", 64) + `","hub_managed_sha256":"` + strings.Repeat("c", 64) + `","line_shared_sha256":"` + strings.Repeat("c", 64) + `"},"created_at":"2026-10-26T12:00:00Z"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "upgrade-claim.json")
			if err := os.WriteFile(path, []byte(body), 0640); err != nil {
				t.Fatal(err)
			}
			if _, _, err := ReadClaim(dir); err == nil {
				t.Fatal("malformed claim was accepted")
			}
		})
	}
}

func TestClaimRejectsLooseMode(t *testing.T) {
	dir := t.TempDir()
	if err := WriteClaim(dir, claimFixture()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "upgrade-claim.json"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadClaim(dir); err == nil {
		t.Fatal("0644 claim was accepted")
	}
}

// TestClaimGroupMissingFailsClosed: a production root publisher cannot make the
// claim Web-readable without the meshmux group. It must publish nothing rather
// than leave a root:root claim the boot reconcile can never read.
func TestClaimGroupMissingFailsClosed(t *testing.T) {
	oldEUID, oldGroup := claimEUID, claimGroupID
	claimEUID = func() int { return 0 }
	claimGroupID = func() (int, bool) { return 0, false }
	defer func() { claimEUID, claimGroupID = oldEUID, oldGroup }()

	dir := t.TempDir()
	err := WriteClaim(dir, claimFixture())
	if err == nil || codeOf(err) != codeClaimWrite {
		t.Fatalf("error = %v, want %s", err, codeClaimWrite)
	}
	if _, ok, readErr := ReadClaim(dir); ok || readErr != nil {
		t.Fatalf("a claim was published: ok=%v err=%v", ok, readErr)
	}
	entries, readErr := os.ReadDir(dir)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if len(entries) != 0 {
		t.Fatalf("scratch debris was published: %v", entries)
	}
}
