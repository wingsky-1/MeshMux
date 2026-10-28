package node

// Tests of the one journald configuration MeshMux writes. The drop-in is a
// host-level file, so the Hub, a standalone Line and a co-located Line must
// agree on exactly one owner and on exactly one set of quota keys.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/install/hub"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// journaldValues parses a drop-in the way systemd does: comments and blank
// lines are ignored, "[Journal]" opens the only section, and every other line is
// one "Key=Value" pair. A duplicate key or a line outside [Journal] is a
// configuration systemd would silently misread, so it fails the test.
func journaldValues(t *testing.T, body string) map[string]string {
	t.Helper()
	values := map[string]string{}
	section := ""
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = line
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if !found {
			t.Fatalf("journald line is not Key=Value: %q", line)
		}
		if section != "[Journal]" {
			t.Fatalf("key %q is outside the [Journal] section", name)
		}
		if _, duplicate := values[name]; duplicate {
			t.Fatalf("duplicate journald key %q", name)
		}
		values[name] = value
	}
	return values
}

// TestJournaldDropInIsQuotaOnly pins the rendered file: three quota keys, no
// storage/forwarding/rate-limit takeover, and byte-identical Hub and standalone
// Line renderers.
func TestJournaldDropInIsQuotaOnly(t *testing.T) {
	want := map[string]string{"SystemMaxUse": "1G", "RuntimeMaxUse": "512M", "MaxFileSec": "30day"}

	hubFiles, err := hub.CandidateFiles(core.Config{ManagementDomain: "admin.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org"}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	hub, ok := hubFiles[core.JournaldDropInPath]
	if !ok {
		t.Fatalf("the Hub does not render %s", core.JournaldDropInPath)
	}
	values := journaldValues(t, hub)
	if len(values) != len(want) {
		t.Fatalf("journald drop-in keys = %v, want exactly %v", values, want)
	}
	for key, value := range want {
		if values[key] != value {
			t.Fatalf("journald %s = %q, want %q", key, values[key], value)
		}
	}
	if mode, owner := core.FilePolicy(core.JournaldDropInPath); mode != 0644 || owner != "root:root" {
		t.Fatalf("journald drop-in policy = %o %s, want 0644 root:root", mode, owner)
	}

	cfg := corenode.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: corenode.RoleEdge, VLESSPort: 443, SSHPort: 2222,
		AgentVersion: corenode.CurrentAgentVersion(), AgentSHA256: strings.Repeat("b", 64),
	}
	identity := corenode.Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	lineFiles, err := nodeManagedFiles(cfg, []int{2222}, identity)
	if err != nil {
		t.Fatal(err)
	}
	line, ok := lineFiles[core.JournaldDropInPath]
	if !ok {
		t.Fatalf("a standalone Line does not render %s", core.JournaldDropInPath)
	}
	if line.Body != hub {
		t.Fatalf("Hub and Line render different journald drop-ins:\nHub:\n%s\nLine:\n%s", hub, line.Body)
	}
	if line.Mode != 0644 || line.Owner != "root:root" || !line.Static {
		t.Fatalf("Line journald drop-in = %o %s static=%v, want 0644 root:root static", line.Mode, line.Owner, line.Static)
	}
}

// TestHubInstallWritesJournaldQuota proves the drop-in is a real managed file:
// applied with the pinned bytes, recorded in the ledger, and rewritten in place
// by a repair without leaving a second copy or an ownership conflict.
func TestHubInstallWritesJournaldQuota(t *testing.T) {
	f := makeHubInstallerFixture(t)
	if _, err := invokeHubInstaller(t, f, strings.Repeat("a", 32), false); err != nil {
		t.Fatalf("install: %v", err)
	}
	target := core.Rooted(f.root, core.JournaldDropInPath)
	data, err := os.ReadFile(target)
	if err != nil || string(data) != hub.JournaldDropIn {
		t.Fatalf("journald drop-in = %q, %v", data, err)
	}
	state, _, err := core.ReadState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if state.ManagedFiles[core.JournaldDropInPath] != fileSHA256ForTest(t, target) {
		t.Fatalf("journald drop-in is not recorded in the Hub ledger: %+v", state.ManagedFiles)
	}

	if _, err := invokeHubInstaller(t, f, strings.Repeat("b", 32), true); err != nil {
		t.Fatalf("repair: %v", err)
	}
	repaired, err := os.ReadFile(target)
	if err != nil || string(repaired) != hub.JournaldDropIn {
		t.Fatalf("repair changed the journald drop-in: %q, %v", repaired, err)
	}
	entries, err := os.ReadDir(filepath.Dir(target))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "99-meshmux.conf" {
		t.Fatalf("journald.conf.d entries after repair = %v, want only 99-meshmux.conf", entries)
	}
}

// TestStandaloneLineWritesJournaldQuota pins that a Line that owns its host
// writes the same drop-in and records it as a static managed file.
func TestStandaloneLineWritesJournaldQuota(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("install: %v", err)
	}
	target := core.Rooted(f.root, core.JournaldDropInPath)
	data, err := os.ReadFile(target)
	if err != nil || string(data) != hub.JournaldDropIn {
		t.Fatalf("journald drop-in = %q, %v", data, err)
	}
	state, _, err := core.ReadState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	if state.ManagedFiles[core.JournaldDropInPath] != fileSHA256ForTest(t, target) {
		t.Fatalf("journald drop-in is not recorded in the Line ledger: %+v", state.ManagedFiles)
	}
}

// TestCoLocatedLineReusesHubJournaldQuota pins the host-level ownership rule:
// the Hub already owns the drop-in, so the Line neither rewrites it nor records
// it in its own ledger (a second owner would make the Hub's own file a
// MANAGED_PATH_CONFLICT on repair).
func TestCoLocatedLineReusesHubJournaldQuota(t *testing.T) {
	f := makeLocalLineFixture(t)
	target := core.Rooted(f.root, core.JournaldDropInPath)
	before, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("fixture Hub drop-in missing: %v", err)
	}
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	lineState, exists, err := core.ReadStateAt(f.root, core.LocalLineStatePath)
	if err != nil || !exists {
		t.Fatalf("local Line ledger missing: %+v %v", lineState, err)
	}
	if _, claimed := lineState.ManagedFiles[core.JournaldDropInPath]; claimed {
		t.Fatalf("the co-located Line claimed the Hub-owned journald drop-in: %+v", lineState.ManagedFiles)
	}
	after, err := os.ReadFile(target)
	if err != nil || string(after) != string(before) {
		t.Fatalf("the co-located Line rewrote the Hub-owned journald drop-in: %q, %v", after, err)
	}
}
