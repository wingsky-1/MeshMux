package node

// Tests for the publish gate's kernel wrappers. The fixture runner proves the
// fixed argv, the version pin and the refusal codes; the real binaries are
// used only when the CI environment provides them, exactly like the existing
// native check tests.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gateRunner records every call and returns a scripted result.
type gateRunner struct {
	calls  [][]string
	output []byte
	err    error
}

func (r *gateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.output, r.err
}

func TestCheckSingBoxDocumentUsesFixedArgv(t *testing.T) {
	runner := &gateRunner{}
	if err := CheckSingBoxDocument(context.Background(), runner, "/usr/local/libexec/meshmux-sing-box", "/tmp/x.json"); err != nil {
		t.Fatal(err)
	}
	if len(runner.calls) != 1 {
		t.Fatalf("calls = %d, want 1", len(runner.calls))
	}
	want := []string{"/usr/local/libexec/meshmux-sing-box", "check", "-c", "/tmp/x.json"}
	if strings.Join(runner.calls[0], " ") != strings.Join(want, " ") {
		t.Fatalf("argv = %v, want %v", runner.calls[0], want)
	}
	// A missing binary path is a refusal, not a skipped check.
	if err := CheckSingBoxDocument(context.Background(), runner, "  ", "/tmp/x.json"); err == nil ||
		!strings.HasPrefix(err.Error(), CodePublishCheckSingBox) {
		t.Fatalf("empty binary = %v", err)
	}
	// A kernel refusal maps onto the stable code and never echoes the output.
	runner = &gateRunner{output: []byte("FATAL decode config: unknown field"), err: errors.New("exit 1")}
	err := CheckSingBoxDocument(context.Background(), runner, "/usr/bin/sing-box", "/tmp/x.json")
	if err == nil || !strings.HasPrefix(err.Error(), CodePublishCheckSingBox) {
		t.Fatalf("kernel refusal = %v", err)
	}
	if strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("kernel output leaked into the refusal: %v", err)
	}
}

func TestCheckMihomoDocumentPinsTheVersion(t *testing.T) {
	// The version probe runs first and must name the pinned release.
	wrong := &gateRunner{output: []byte("Mihomo Meta v1.18.0 linux amd64")}
	if _, err := CheckMihomoDocument(context.Background(), wrong, "/usr/bin/mihomo", "/tmp/x.yaml", "/tmp"); err == nil ||
		!strings.HasPrefix(err.Error(), CodePublishMihomoVersion) {
		t.Fatalf("wrong version = %v", err)
	}
	if len(wrong.calls) != 1 || strings.Join(wrong.calls[0], " ") != "/usr/bin/mihomo -v" {
		t.Fatalf("version probe argv = %v", wrong.calls)
	}

	// A missing binary is its own refusal: the gate cannot be skipped.
	if _, err := CheckMihomoDocument(context.Background(), &gateRunner{}, "", "/tmp/x.yaml", "/tmp"); err == nil ||
		!strings.HasPrefix(err.Error(), CodePublishMihomoMissing) {
		t.Fatalf("missing binary = %v", err)
	}

	// The check itself uses the fixed argv and keeps a short summary.
	mihomo := &scriptedRunner{version: "Mihomo Meta v" + MihomoVersion, checkOutput: "rules[1] error: rule set not found", checkErr: errors.New("exit 1")}
	detail, err := CheckMihomoDocument(context.Background(), mihomo, "/usr/bin/mihomo", "/tmp/x.yaml", "/tmp")
	if err == nil || !strings.HasPrefix(err.Error(), CodePublishCheckMihomo) {
		t.Fatalf("kernel refusal = %v", err)
	}
	if !strings.Contains(detail, "rule set not found") {
		t.Fatalf("summary = %q", detail)
	}
	if len(mihomo.calls) != 2 || strings.Join(mihomo.calls[1], " ") != "/usr/bin/mihomo -t -f /tmp/x.yaml -d /tmp" {
		t.Fatalf("check argv = %v", mihomo.calls)
	}
}

// scriptedRunner answers the version probe and the config check differently.
type scriptedRunner struct {
	calls       [][]string
	version     string
	checkOutput string
	checkErr    error
}

func (r *scriptedRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	if len(args) == 1 && args[0] == "-v" {
		return []byte(r.version), nil
	}
	return []byte(r.checkOutput), r.checkErr
}

func TestSummarizeCheckOutputIsBounded(t *testing.T) {
	var lines []string
	for i := 0; i < 20; i++ {
		lines = append(lines, "error line "+strings.Repeat("x", 300))
	}
	summary := summarizeCheckOutput([]byte(strings.Join(lines, "\n")))
	if parts := strings.Split(summary, " | "); len(parts) != publishCheckOutputLines {
		t.Fatalf("summary lines = %d, want %d", len(parts), publishCheckOutputLines)
	}
	for _, part := range strings.Split(summary, " | ") {
		if len(part) > 200 {
			t.Fatalf("summary line length = %d, want <= 200", len(part))
		}
	}
	if summarizeCheckOutput([]byte("\n\n  \n")) != "" {
		t.Fatal("blank output produced a summary")
	}
}

// TestPublishGateAgainstRealKernels runs both kernels on a real assembled
// document when the environment provides them. The sing-box environment
// variable is the same one the native candidate check uses.
func TestPublishGateAgainstRealKernels(t *testing.T) {
	singBox := strings.TrimSpace(os.Getenv("MESHMUX_SINGBOX_TEST_BINARY"))
	if singBox == "" {
		t.Skip("MESHMUX_SINGBOX_TEST_BINARY is not set: skipping the native publish-gate check")
	}
	if !filepath.IsAbs(singBox) {
		t.Fatal("MESHMUX_SINGBOX_TEST_BINARY must be an absolute path")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "candidate.json")
	document := []byte(`{"log":{"disabled":true},"inbounds":[{"type":"vless","tag":"in","listen":"0.0.0.0","listen_port":8443,"users":[]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"rules":[{"domain":["ai.example.invalid"],"outbound":"direct"}],"final":"direct"}}`)
	if err := os.WriteFile(path, document, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := CheckSingBoxDocument(context.Background(), ExecRunner{}, singBox, path); err != nil {
		t.Fatalf("sing-box refused the assembled candidate: %v", err)
	}

	mihomo := strings.TrimSpace(os.Getenv("MESHMUX_MIHOMO_TEST_BINARY"))
	if mihomo == "" {
		t.Skip("MESHMUX_MIHOMO_TEST_BINARY is not set: skipping the native Mihomo publish-gate check")
	}
	yamlPath := filepath.Join(dir, "client.yaml")
	yaml := "mixed-port: 7890\nmode: rule\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - DIRECT\nrules:\n  - \"DOMAIN,ai.example.invalid,DIRECT\"\n  - \"MATCH,PROXY\"\n"
	if err := os.WriteFile(yamlPath, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CheckMihomoDocument(context.Background(), ExecRunner{}, mihomo, yamlPath, dir); err != nil {
		t.Fatalf("mihomo refused the assembled client document: %v", err)
	}
}

// TestCheckMihomoDocumentRefusesNearMissVersions pins the exact comparison: a
// build whose release merely starts with the pin, or a prerelease of it, would
// validate a schema this gate was never written against.
func TestCheckMihomoDocumentRefusesNearMissVersions(t *testing.T) {
	for _, output := range []string{
		"Mihomo Meta v" + MihomoVersion + "0 linux amd64",
		"Mihomo Meta v" + MihomoVersion + "-beta linux amd64",
		"Mihomo Meta v1.19.3 linux amd64",
		"Mihomo Meta linux amd64",
	} {
		runner := &gateRunner{output: []byte(output)}
		if _, err := CheckMihomoDocument(context.Background(), runner, "/usr/bin/mihomo", "/tmp/x.yaml", "/tmp"); err == nil ||
			!strings.HasPrefix(err.Error(), CodePublishMihomoVersion) {
			t.Fatalf("version output %q = %v", output, err)
		}
		// The refusal is decided by the probe alone: no config check runs.
		if len(runner.calls) != 1 {
			t.Fatalf("version output %q ran %d commands, want only the probe", output, len(runner.calls))
		}
	}
}
