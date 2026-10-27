package hubupgrade

// The shared stable codes are one definition for both halves of the Hub
// self-upgrade: the Web-side producer (this package) and the root-side executor
// (rootexec). This test freezes the values and proves the executor half really
// reads them instead of keeping a private copy.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSharedCodesAreTheFrozenValues pins every exported code to its literal.
// A value change is an operator-visible contract change (spec §5.9), so it must
// be an explicit edit of this test as well.
func TestSharedCodesAreTheFrozenValues(t *testing.T) {
	want := map[string]string{
		"CodeHandoffBusy":             "HUB_HANDOFF_BUSY",
		"CodeHandoffInvalidState":     "HUB_HANDOFF_INVALID_STATE",
		"CodeHandoffRequestInvalid":   "HUB_HANDOFF_REQUEST_INVALID",
		"CodeBackupIdentityMissing":   "HUB_BACKUP_IDENTITY_MISSING",
		"CodeRestoreBinaryMissing":    "HUB_RESTORE_BINARY_MISSING",
		"CodeRestoreDigestMismatch":   "HUB_RESTORE_DIGEST_MISMATCH",
		"CodeRestoreUnitShapeInvalid": "HUB_RESTORE_UNIT_SHAPE_INVALID",
		"CodeManifestPackageMismatch": "HUB_MANIFEST_PACKAGE_MISMATCH",
		"CodeSharedBinaryRepinFailed": "HUB_SHARED_BINARY_REPIN_FAILED",
	}
	got := map[string]string{
		"CodeHandoffBusy":             CodeHandoffBusy,
		"CodeHandoffInvalidState":     CodeHandoffInvalidState,
		"CodeHandoffRequestInvalid":   CodeHandoffRequestInvalid,
		"CodeBackupIdentityMissing":   CodeBackupIdentityMissing,
		"CodeRestoreBinaryMissing":    CodeRestoreBinaryMissing,
		"CodeRestoreDigestMismatch":   CodeRestoreDigestMismatch,
		"CodeRestoreUnitShapeInvalid": CodeRestoreUnitShapeInvalid,
		"CodeManifestPackageMismatch": CodeManifestPackageMismatch,
		"CodeSharedBinaryRepinFailed": CodeSharedBinaryRepinFailed,
	}
	for name, expected := range want {
		if got[name] != expected {
			t.Fatalf("%s = %q, want %q", name, got[name], expected)
		}
	}
}

// TestRootexecReusesTheSharedCodes refuses a private copy in the privileged
// half. The scan is source-level on purpose: importing rootexec here would put a
// root-only executor into the test binary, and the drift it guards against is
// exactly a reintroduced string literal.
func TestRootexecReusesTheSharedCodes(t *testing.T) {
	shared := []string{
		CodeHandoffBusy, CodeHandoffInvalidState, CodeHandoffRequestInvalid,
		CodeBackupIdentityMissing, CodeRestoreBinaryMissing, CodeRestoreDigestMismatch,
		CodeRestoreUnitShapeInvalid, CodeManifestPackageMismatch, CodeSharedBinaryRepinFailed,
	}
	for _, code := range shared {
		literal := `"` + code + `"`
		entries, err := os.ReadDir("rootexec")
		if err != nil {
			t.Fatalf("read rootexec: %v", err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			body, err := os.ReadFile(filepath.Join("rootexec", name))
			if err != nil {
				t.Fatalf("read rootexec/%s: %v", name, err)
			}
			if strings.Contains(string(body), literal) {
				t.Fatalf("rootexec/%s re-declares the shared code %s; import hubupgrade.%s instead",
					name, code, strings.Trim(literal, `"`))
			}
		}
	}
}
