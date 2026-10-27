package node

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// TestStableCodeOnlyAcceptsRegisteredCodes pins the closed set: a value that is
// not a registered constant never becomes an error code, however code-shaped it
// looks.
func TestStableCodeOnlyAcceptsRegisteredCodes(t *testing.T) {
	accepted := []string{
		"SINGBOX_NOT_RUNNING",
		codeSingboxRunningBinaryMismatch,
		"UPDATE_HANDOFF_INCOMPLETE",
		"TASK_FAILED",
	}
	for _, code := range accepted {
		if got := stableCode(code); got != code {
			t.Errorf("stableCode(%q) = %q, want %q", code, got, code)
		}
	}
	// Unknown but well-formed values, runtime values that merely look like
	// codes, and free-form text all collapse to the fixed fallback.
	rejected := []string{
		"",
		"NOT_A_REGISTERED_CODE",
		"SOMETHING_ELSE",
		"/var/lib/meshmux-agent/runtime.json",
		"0123456789abcdef",
		"lowercase_code",
		"SINGBOX_NOT_RUNNING_A_BIT",
		"TASK_FAILED ",
		"TASK_FAILED: some detail",
	}
	for _, value := range rejected {
		if got := stableCode(value); got != taskFailedCode {
			t.Errorf("stableCode(%q) = %q, want %q", value, got, taskFailedCode)
		}
	}
}

// TestErrorCodeDropsDetailAndRefusesUnknown pins that only the code half of an
// error survives, and only when it is registered.
func TestErrorCodeDropsDetailAndRefusesUnknown(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{errors.New("SINGBOX_NOT_RUNNING"), "SINGBOX_NOT_RUNNING"},
		{errors.New("ACTIVE_CONFIG_HASH_MISMATCH: sha256 differs"), "ACTIVE_CONFIG_HASH_MISMATCH"},
		{errors.New("STAGE_TARGET_UNAVAILABLE: /var/lib/meshmux-agent/x.json"), "STAGE_TARGET_UNAVAILABLE"},
		// A path before the colon is not a code.
		{errors.New("/etc/meshmux/agent.json: unreadable"), taskFailedCode},
		// An unknown code with a detail is not registered either.
		{errors.New("SOMETHING_BROKE: a message"), taskFailedCode},
		// A digest-only message has no code.
		{errors.New("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"), taskFailedCode},
	}
	for _, tc := range cases {
		if got := errorCode(tc.err); got != tc.want {
			t.Errorf("errorCode(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}

// TestErrorCodeOrFallsBackToARegisteredCode proves the fallback is itself
// washed through the registry, so an unregistered fallback cannot leak.
func TestErrorCodeOrFallsBackToARegisteredCode(t *testing.T) {
	if got := errorCodeOr(errors.New("/var/lib/x: unreadable"), "CANDIDATE_CHECK_FAILED"); got != "CANDIDATE_CHECK_FAILED" {
		t.Errorf("registered fallback = %q", got)
	}
	// An unregistered fallback must not become a code.
	if got := errorCodeOr(errors.New("/var/lib/x: unreadable"), "SOMETHING_NOT_REGISTERED"); got != taskFailedCode {
		t.Errorf("unregistered fallback = %q, want %q", got, taskFailedCode)
	}
	if got := errorCodeOr(nil, "CANDIDATE_CHECK_FAILED"); got != "CANDIDATE_CHECK_FAILED" {
		t.Errorf("nil error fallback = %q", got)
	}
	if got := errorCodeOr(nil, ""); got != taskFailedCode {
		t.Errorf("empty fallback = %q, want %q", got, taskFailedCode)
	}
}

// TestRunningBinaryMismatchReportsOnlyACode proves the readback refusal no
// longer carries the executable path or a digest: those are log fields.
func TestRunningBinaryMismatchReportsOnlyACode(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	// A kernel digest that cannot match the running test binary.
	cfg.KernelSHA256 = strings.Repeat("a", 64)
	var logged strings.Builder
	runtime := &Runtime{
		cfg: cfg, root: root, runner: runner,
		procRoot: filepath.Join(root, "proc"),
		logger:   slog.New(slog.NewJSONHandler(&logged, nil)),
	}
	candidate := testCandidate(7).Candidate()
	_, err := runtime.readbackFor(context.Background(), cfg.Role, candidate, "")
	if err == nil {
		t.Fatal("wrong running binary accepted")
	}
	if got := errorCode(err); got != codeSingboxRunningBinaryMismatch {
		t.Fatalf("error code = %q, want %q (message %q)", got, codeSingboxRunningBinaryMismatch, err)
	}
	if err.Error() != codeSingboxRunningBinaryMismatch {
		t.Fatalf("error text carries more than the code: %q", err)
	}
	// The diagnostics are still available, but only as log fields.
	line := logged.String()
	for _, want := range []string{`"msg":"sing-box running binary mismatch"`, `"exe":`, `"running_sha256":`, `"want_sha256":`} {
		if !strings.Contains(line, want) {
			t.Fatalf("log line lost %q: %s", want, line)
		}
	}
	if !strings.Contains(line, `"error_code":"`+codeSingboxRunningBinaryMismatch+`"`) {
		t.Fatalf("log line lost the code: %s", line)
	}
	if strings.Contains(err.Error(), filepath.Join(root, "proc")) {
		t.Fatalf("error text leaked the proc path: %q", err)
	}
}

// TestRunningBinaryMismatchSurvivesWithoutALogger proves the refusal does not
// depend on a configured logger, so the code is reported either way.
func TestRunningBinaryMismatchSurvivesWithoutALogger(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	cfg.KernelSHA256 = strings.Repeat("b", 64)
	runtime := &Runtime{cfg: cfg, root: root, runner: runner, procRoot: filepath.Join(root, "proc"),
		logger: slog.New(slog.NewTextHandler(io.Discard, nil))}
	_, err := runtime.readbackFor(context.Background(), cfg.Role, testCandidate(7).Candidate(), "")
	if errorCode(err) != codeSingboxRunningBinaryMismatch {
		t.Fatalf("error code = %q, want %q", errorCode(err), codeSingboxRunningBinaryMismatch)
	}
}

// TestRuntimeCodesAreCodeShaped keeps the registry itself honest: every entry
// has the documented shape and matches what the protocol validates.
func TestRuntimeCodesAreCodeShaped(t *testing.T) {
	for code := range runtimeCodes {
		if !protocol.ValidErrorCode(code) {
			t.Errorf("registered code %q does not match the protocol shape", code)
		}
		if got := stableCode(code); got != code {
			t.Errorf("registry entry %q is not accepted by stableCode: %q", code, got)
		}
	}
	if len(runtimeCodes) < 100 {
		t.Fatalf("registry shrank to %d entries; a missing code silently becomes TASK_FAILED", len(runtimeCodes))
	}
}

// TestUpgradeBoundaryCodesAreRegistered pins the codes this package names as
// constants for the 11c-3 revert/confirm boundary. They reach a receipt through
// failedResult, errorCodeOr and the log paths, so an unregistered one would be
// washed to TASK_FAILED and the operator would lose the reason an upgrade or
// its revert ended. The updater's own vocabulary is wider still (backup,
// confirm and ROLLBACK_* codes travel in the revert verdict); this guard keeps
// the constants that live here from drifting out of the set.
func TestUpgradeBoundaryCodesAreRegistered(t *testing.T) {
	for _, code := range []string{
		upgradeConfirmUnavailableCode,
		upgradeConfirmFailedCode,
		upgradeRevertUnavailableCode,
		handoffIncompleteCode,
		handoffOrphanedErrorCode,
	} {
		if !isRuntimeCode(code) {
			t.Errorf("%q is reported at the upgrade boundary but not registered", code)
		}
	}
}
