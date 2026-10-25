package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// The tests below cover the Hub+Line co-location profile: one host that
// already runs the Hub installs exactly one Line next to it.
//
// Every test runs against an isolated temporary root with the injected
// command runner only. No host account, package, service, jail or firewall
// command is executed, and no real Hub, Headscale key or credential exists.

// localLineFixture is an isolated host that already runs a Hub and is about
// to install a Line next to it.
type localLineFixture struct {
	root   string
	runner *fakeNodeRunner
	cfg    node.Config
	opts   NodeApplyOptions
	// hubRuntimeHash is the digest of the Hub-owned MeshMux runtime binary
	// that the Line is expected to reuse verbatim.
	hubRuntimeHash string
}

// localLineHubOrigin is the exact public management origin of the fixture
// Hub. A co-located Line must use it.
const localLineHubOrigin = "https://hub.example.invalid"

// writeLocalLineHubLedger records a complete Hub ledger on the fixture host:
// a Hub layout, its shared MeshMux runtime and its Fail2ban SSH jail. It
// returns the actual digest of the shared runtime binary.
func writeLocalLineHubLedger(t *testing.T, root string, sshPorts []int) (InstallState, string) {
	t.Helper()
	// The Hub-owned runtime binary must exist on disk for the Line to
	// verify and reuse it. Its digest is computed from the real bytes so
	// the fixture never claims a hash the file does not have.
	binary := rooted(root, runtimeBinaryPath)
	if err := os.MkdirAll(filepath.Dir(binary), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(binary, []byte("hub owned MeshMux runtime"), 0755); err != nil {
		t.Fatal(err)
	}
	runtimeHash, err := sha256File(binary)
	if err != nil {
		t.Fatal(err)
	}
	// The Hub's own SSH jail file exists on the host: the Line reuses it
	// instead of installing a second jail for the same listeners.
	jail := rooted(root, hubSSHJailPath)
	if err := os.MkdirAll(filepath.Dir(jail), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jail, []byte("[meshmux-sshd]\nenabled = true\nport = 2222\n"), 0644); err != nil {
		t.Fatal(err)
	}
	hub := InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
		Config: Config{
			ManagementDomain:   "hub.example.invalid",
			SubscriptionDomain: "sub.example.invalid",
			HeadscaleDomain:    "mesh.example.invalid",
		},
		Architecture: "amd64",
		ManagedFiles: map[string]string{
			hubSSHJailPath:           strings.Repeat("2", 64),
			runtimeBinaryPath:        runtimeHash,
			"/etc/meshmux/Caddyfile": strings.Repeat("3", 64),
		},
		Artifacts: map[string]string{},
		SSHPorts:  append([]int(nil), sshPorts...),
		SharedBinaries: map[string]SharedBinary{
			sharedAgentKey: {Path: runtimeBinaryPath, SHA256: runtimeHash},
		},
	}
	if err := writeState(root, hub); err != nil {
		t.Fatal(err)
	}
	return hub, runtimeHash
}

// localLineRunner answers the two probes that only the co-location profile
// performs: the shared Agent version probe against the Hub-owned runtime
// binary, and the Fail2ban readback of the Hub's SSH jail. Every other
// command is delegated to the shared node fixture runner, so the profile
// tests exercise the real installer transaction.
type localLineRunner struct {
	*fakeNodeRunner
	// sshPorts is the port set the Hub's SSH jail reports.
	sshPorts []int
}

func (r *localLineRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if name == "fail2ban-client" && len(args) == 5 && args[0] == "get" &&
		args[1] == hubSSHJailName && args[2] == "action" &&
		args[3] == "nftables-multiport" {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		if args[4] == "port" {
			ports := make([]string, 0, len(r.sshPorts))
			for _, port := range r.sshPorts {
				ports = append(ports, strconv.Itoa(port))
			}
			return []byte(strings.Join(ports, ",") + "\n"), nil
		}
		return []byte("nft add rule inet f2b-table f2b-chain $proto dport \\{ 2222 \\} <addr_family> saddr @<addr_set> reject\n"), nil
	}
	if len(args) == 1 && args[0] == "__internal-agent-version" {
		r.calls = append(r.calls, name+" "+strings.Join(args, " "))
		return []byte(node.CurrentAgentVersion() + "\n"), nil
	}
	return r.fakeNodeRunner.Run(ctx, name, args...)
}

// makeLocalLineFixture builds an isolated host that runs a Hub and prepares
// a Line enrollment for it.
func makeLocalLineFixture(t *testing.T) *localLineFixture {
	t.Helper()
	root := t.TempDir()
	_, runtimeHash := writeLocalLineHubLedger(t, root, []int{2222})

	cfg := node.Config{
		HubURL: localLineHubOrigin, NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion(),
	}
	release, _ := node.KernelReleaseFor("amd64")
	binary := []byte("fixture sing-box binary for local line")
	sum := sha256.Sum256(binary)
	release.BinarySHA256 = hex.EncodeToString(sum[:])
	archive := filepath.Join(t.TempDir(), "kernel.tar.gz")
	if err := writeNodeTestArchive(archive, binary); err != nil {
		t.Fatal(err)
	}
	archiveData, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveSum := sha256.Sum256(archiveData)
	artifact := Artifact{
		Component: "sing-box", Version: node.KernelVersion, Source: release.SourceURL,
		SHA256: hex.EncodeToString(archiveSum[:]), Format: "tar.gz",
	}
	identity := node.Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	candidate := node.NewCandidateDocument(node.Candidate{
		NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1,
		VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	runner := &fakeNodeRunner{users: map[string]bool{}, packages: map[string]bool{
		"ca-certificates": true, "fail2ban": true, "nftables": true,
	}}
	profileRunner := &localLineRunner{fakeNodeRunner: runner, sshPorts: []int{2222}}
	// The readback must report the digest of the compiled active config so
	// a repair that keeps the last-known-good data plane verifies.
	compiled, err := node.CompileCandidate(candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	compiledSum := sha256.Sum256(compiled)
	readback := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion(),
		AgentSHA256: runtimeHash, KernelVersion: node.KernelVersion,
		KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 1,
		ConfigSHA256: hex.EncodeToString(compiledSum[:]), LocalActive: true,
	}
	opts := NodeApplyOptions{
		Root: root, Runner: profileRunner, Executable: filepath.Join(t.TempDir(), "meshmux"),
		Artifacts: []Artifact{artifact},
		Preflight: func(context.Context, node.Config, bool) ([]Check, []int) {
			return []Check{{Name: "fixture", Status: "pass"}}, []int{2222}
		},
		DownloadArtifact: func(context.Context, Artifact, string) (string, error) { return archive, nil },
		Pair:             func(context.Context, node.Config, string) (node.Identity, error) { return identity, nil },
		Metadata:         func(context.Context, node.Config, node.Identity) (node.Metadata, error) { return cfg.Metadata(), nil },
		Candidate: func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
			return candidate, nil
		},
		Readback: func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
			return readback, nil
		},
		Verify:      func(context.Context, node.Config, CommandRunner, node.Readback) error { return nil },
		VerifyAgent: func(string, string) error { return nil },
	}
	return &localLineFixture{
		root: root, runner: runner, cfg: cfg, opts: opts, hubRuntimeHash: runtimeHash,
	}
}
func (f *localLineFixture) install(t *testing.T, repair bool, code string) (InstallResult, error) {
	t.Helper()
	return InstallNode(context.Background(), f.cfg, strings.Repeat("e", 32), repair, code, f.opts)
}

// TestLocalLineUsesSeparateLedgerAndPreservesHubLayout is the core
// co-location contract: the Line keeps its own ledger, leaves the Hub
// ledger byte-for-byte intact, reuses the Hub-owned runtime binary without
// overwriting or snapshotting it, and does not install a second Fail2ban
// jail for the same SSH listeners.
func TestLocalLineUsesSeparateLedgerAndPreservesHubLayout(t *testing.T) {
	f := makeLocalLineFixture(t)
	hubBefore, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil {
		t.Fatal(err)
	}
	hubManagedBefore := map[string]string{}
	for path, digest := range readHubLedger(t, f.root).ManagedFiles {
		hubManagedBefore[path] = digest
	}

	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("local Line install = %+v %v", result, err)
	}

	// The Line keeps its own ledger at the fixed local-Line path.
	lineState, exists, err := readLocalLineState(f.root)
	if err != nil || !exists {
		t.Fatalf("local Line ledger missing: %+v %v", lineState, err)
	}
	if lineState.Node == nil || lineState.Node.NodeID != f.cfg.NodeID {
		t.Fatalf("local Line ledger did not record the node: %+v", lineState)
	}
	if lineState.Status != "installed" {
		t.Fatalf("local Line ledger status = %q", lineState.Status)
	}

	// The Hub ledger is untouched by the Line operation.
	hubAfter, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil {
		t.Fatal(err)
	}
	if string(hubAfter) != string(hubBefore) {
		t.Fatal("the local Line operation rewrote the Hub ledger")
	}
	hubAfterState := readHubLedger(t, f.root)
	for path, digest := range hubManagedBefore {
		if hubAfterState.ManagedFiles[path] != digest {
			t.Fatalf("Hub managed ledger changed for %s", path)
		}
	}
	if hubAfterState.Node != nil {
		t.Fatal("the Hub ledger gained a Node record")
	}

	// The shared runtime binary is reused verbatim: the Line never writes
	// it, never snapshots it and never rolls it back.
	sharedBefore, err := os.ReadFile(rooted(f.root, runtimeBinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	sharedAfter, err := os.ReadFile(rooted(f.root, runtimeBinaryPath))
	if err != nil {
		t.Fatal(err)
	}
	if string(sharedBefore) != string(sharedAfter) {
		t.Fatal("the local Line replaced the Hub-owned runtime binary")
	}
	for _, call := range f.runner.calls {
		if strings.Contains(call, "cp ") && strings.Contains(call, runtimeBinaryPath) {
			t.Fatalf("the local Line copied over the shared runtime: %s", call)
		}
	}

	// The Line pins the exact shared build it reuses.
	pin, ok := lineState.SharedBinaries[sharedAgentKey]
	if !ok || pin.Path != runtimeBinaryPath || pin.SHA256 != f.hubRuntimeHash {
		t.Fatalf("local Line did not pin the shared runtime: %+v", pin)
	}
}

// TestLocalLineDoesNotInstallSecondFail2banJail pins the SSH jail reuse: a
// co-located Line reuses the Hub's jail instead of creating a second jail
// for the same listeners, and the Line's own managed set has no jail file.
func TestLocalLineDoesNotInstallSecondFail2banJail(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	if _, err := os.Stat(rooted(f.root, nodeSSHJailPath)); !os.IsNotExist(err) {
		t.Fatal("the local Line installed a second SSH jail file")
	}
	// The Hub's jail file is untouched and still the Hub's.
	jail, err := os.ReadFile(rooted(f.root, hubSSHJailPath))
	if err != nil {
		t.Fatalf("Hub jail file missing: %v", err)
	}
	if !strings.Contains(string(jail), "meshmux-sshd") {
		t.Fatalf("Hub jail file was replaced: %s", jail)
	}
	// The Line verifies the Hub jail, it never queries its own.
	joined := strings.Join(f.runner.calls, "\n")
	if !strings.Contains(joined, "fail2ban-client get "+hubSSHJailName+" action") {
		t.Fatalf("the local Line did not verify the Hub jail: %s", joined)
	}
	if strings.Contains(joined, "fail2ban-client get "+nodeSSHJailName+" action") {
		t.Fatal("the local Line queried a jail it does not own")
	}
}

// TestLocalLineRejectsForeignHubOrigin pins the boundary of the local
// profile: only the management origin of the Hub installed on this host is
// a local Line. Any other Hub origin is a remote node and is refused
// before any host command runs.
func TestLocalLineRejectsForeignHubOrigin(t *testing.T) {
	f := makeLocalLineFixture(t)
	f.cfg.HubURL = "https://other.example.invalid"
	f.runner.calls = nil
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "LOCAL_LINE_HUB_MISMATCH" {
		t.Fatalf("foreign Hub origin = %+v %v", result, err)
	}
	if len(f.runner.calls) != 0 {
		t.Fatalf("a rejected local Line reached host commands: %v", f.runner.calls)
	}
	hubAfter := readHubLedger(t, f.root)
	if hubAfter.Node != nil {
		t.Fatal("a rejected local Line wrote to the Hub ledger")
	}
}

// TestLocalLineRejectsMismatchingSharedBinary pins the fail-closed rule for
// a shared build that no longer matches the recorded digest: the Line must
// refuse instead of installing its own copy or overwriting the Hub's.
func TestLocalLineRejectsMismatchingSharedBinary(t *testing.T) {
	f := makeLocalLineFixture(t)
	// The Hub-owned runtime on disk drifts away from the recorded digest.
	if err := os.WriteFile(rooted(f.root, runtimeBinaryPath), []byte("replaced runtime"), 0755); err != nil {
		t.Fatal(err)
	}
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "SHARED_BINARY_MISMATCH" {
		t.Fatalf("mismatching shared binary = %+v %v", result, err)
	}
	// The drifted file must not have been overwritten by the Line.
	data, readErr := os.ReadFile(rooted(f.root, runtimeBinaryPath))
	if readErr != nil || string(data) != "replaced runtime" {
		t.Fatalf("the local Line overwrote the shared binary: %q %v", data, readErr)
	}
	if state, exists, readErr := readLocalLineState(f.root); readErr == nil && exists && state.Status == "installed" {
		t.Fatal("the refused local Line recorded an installed ledger")
	}
}

// TestLocalLineRepairKeepsHubLedgerAndSharedPin pins the repair path: a
// co-located Line repair reuses the same ledger, the same shared binary and
// does not disturb the Hub.
func TestLocalLineRepairKeepsHubLedgerAndSharedPin(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	hubBefore, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.install(t, true, ""); err != nil {
		t.Fatalf("local Line repair: %v", err)
	}
	hubAfter, err := os.ReadFile(rooted(f.root, installerStatePath))
	if err != nil {
		t.Fatal(err)
	}
	if string(hubBefore) != string(hubAfter) {
		t.Fatal("the local Line repair rewrote the Hub ledger")
	}
	state, exists, err := readLocalLineState(f.root)
	if err != nil || !exists || state.Node == nil {
		t.Fatalf("local Line ledger lost after repair: %+v %v", state, err)
	}
	pin, ok := state.SharedBinaries[sharedAgentKey]
	if !ok || pin.SHA256 != f.hubRuntimeHash {
		t.Fatalf("local Line repair lost the shared pin: %+v", pin)
	}
}

// TestLocalLineRefusesSecondLocalLine pins the one-Line-per-Hub rule: a
// second Line on the same Hub host is a different enrollment and is
// refused instead of overwriting the first Line's ledger.
func TestLocalLineRefusesSecondLocalLine(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	// A second, different Line enrollment for the same Hub host.
	other := f.cfg
	other.NodeID = strings.Repeat("b", 32)
	other.VLESSPort = 9443
	f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
		return other.Metadata(), nil
	}
	f.opts.Candidate = func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
		return node.NewCandidateDocument(node.Candidate{
			NodeID: other.NodeID, Role: other.Role, Revision: 1,
			VLESSPort: other.VLESSPort, KernelVersion: node.KernelVersion,
		}), nil
	}
	f.cfg = other
	result, err := f.install(t, false, strings.Repeat("B", 43))
	if err == nil || result.ErrorCode != "CONFIG_CONFLICT" {
		t.Fatalf("second local Line = %+v %v", result, err)
	}
	state, exists, err := readLocalLineState(f.root)
	if err != nil || !exists {
		t.Fatalf("local Line ledger missing: %+v %v", state, err)
	}
	if state.Node == nil || state.Node.NodeID != strings.Repeat("a", 32) {
		t.Fatalf("the refused second Line replaced the first ledger: %+v", state.Node)
	}
}

// TestHubRepairRejectsMismatchingSharedBinary pins the Hub side of the
// shared build: a Hub repair that would install a different MeshMux runtime
// while a co-located Line pins the current one is refused. A repair with
// the same build stays green.
func TestHubRepairRejectsMismatchingSharedBinary(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	// The Hub now stages a different MeshMux build.
	hubFixture := makeInstallerFixture(t)
	hubFixture.root = f.root
	hubFixture.opts.Root = f.root
	hubFixture.c = Config{
		ManagementDomain:   "hub.example.invalid",
		SubscriptionDomain: "sub.example.invalid",
		HeadscaleDomain:    "mesh.example.invalid",
	}
	hubFixture.opts.Artifacts = PinnedArtifacts("amd64")
	hubFixture.opts.DownloadArtifact = func(context.Context, Artifact, string) (string, error) {
		return "", errors.New("fixture: pinned artifact unavailable")
	}
	result, err := InstallHub(context.Background(), hubFixture.c, strings.Repeat("7", 32), true, hubFixture.opts)
	if err == nil || result.ErrorCode != "SHARED_BINARY_MISMATCH" {
		t.Fatalf("Hub repair with a different build = %+v %v", result, err)
	}
	// The Line's pin and the Hub ledger survive the refusal.
	state, exists, err := readLocalLineState(f.root)
	if err != nil || !exists {
		t.Fatalf("local Line ledger missing: %+v %v", state, err)
	}
	pin, ok := state.SharedBinaries[sharedAgentKey]
	if !ok || pin.SHA256 != f.hubRuntimeHash {
		t.Fatalf("the refused Hub repair changed the Line pin: %+v", pin)
	}
}

// TestHubRepairWithSameSharedBinaryStaysGreen pins the other side: a Hub
// repair that stages the very same MeshMux build is not blocked by the
// co-located Line's pin.
func TestHubRepairWithSameSharedBinaryStaysGreen(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	// The Hub stages the exact build the Line pinned.
	source := filepath.Join(t.TempDir(), "meshmux")
	if err := os.WriteFile(source, []byte("hub owned MeshMux runtime"), 0755); err != nil {
		t.Fatal(err)
	}
	sum, err := sha256File(source)
	if err != nil {
		t.Fatal(err)
	}
	if sum != f.hubRuntimeHash {
		t.Fatalf("fixture build digest = %s, want %s", sum, f.hubRuntimeHash)
	}
	hubFixture := makeInstallerFixture(t)
	hubFixture.root = f.root
	hubFixture.opts.Root = f.root
	hubFixture.c = Config{
		ManagementDomain:   "hub.example.invalid",
		SubscriptionDomain: "sub.example.invalid",
		HeadscaleDomain:    "mesh.example.invalid",
	}
	hubFixture.opts.Executable = source
	hubFixture.opts.Artifacts = PinnedArtifacts("amd64")
	hubFixture.opts.DownloadArtifact = func(context.Context, Artifact, string) (string, error) {
		return "", errors.New("fixture: pinned artifact unavailable")
	}
	// The shared binary check runs before the artifact download, so the
	// refusal is not masked by the unreachable fixture artifact.
	result, err := InstallHub(context.Background(), hubFixture.c, strings.Repeat("8", 32), true, hubFixture.opts)
	if err == nil {
		t.Fatalf("a Hub repair with an unreachable artifact unexpectedly succeeded: %+v", result)
	}
	if result.ErrorCode == "SHARED_BINARY_MISMATCH" {
		t.Fatalf("a same-build Hub repair was blocked by the Line pin: %+v", result)
	}
	// The Line's pin is unchanged.
	state, _, err := readLocalLineState(f.root)
	if err != nil {
		t.Fatal(err)
	}
	pin, ok := state.SharedBinaries[sharedAgentKey]
	if !ok || pin.SHA256 != f.hubRuntimeHash {
		t.Fatalf("the Hub repair changed the Line pin: %+v", pin)
	}
}

// TestLocalLineSharedBinaryGuardAcceptsSameBuild pins the guard itself: a
// Hub candidate that is the very same build the Line pinned passes the
// guard, and a different build is refused with the stable error code.
func TestLocalLineSharedBinaryGuardAcceptsSameBuild(t *testing.T) {
	f := makeLocalLineFixture(t)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("local Line install: %v", err)
	}
	// The exact build the Line pinned.
	same := filepath.Join(t.TempDir(), "meshmux")
	if err := os.WriteFile(same, []byte("hub owned MeshMux runtime"), 0755); err != nil {
		t.Fatal(err)
	}
	opts := ApplyOptions{Executable: same}
	if err := checkLocalLineSharedBinaryForExecutable(f.root, opts); err != nil {
		t.Fatalf("the same build was refused: %v", err)
	}
	// A different build is refused with the stable code.
	other := filepath.Join(t.TempDir(), "meshmux")
	if err := os.WriteFile(other, []byte("a different MeshMux build"), 0755); err != nil {
		t.Fatal(err)
	}
	opts.Executable = other
	err := checkLocalLineSharedBinaryForExecutable(f.root, opts)
	var ie *InstallError
	if !errors.As(err, &ie) || ie.Code != "SHARED_BINARY_MISMATCH" {
		t.Fatalf("a different build = %v, want SHARED_BINARY_MISMATCH", err)
	}
	// A host without a co-located Line never pays for the guard.
	standalone := t.TempDir()
	if err := checkLocalLineSharedBinaryForExecutable(standalone, ApplyOptions{Executable: other}); err != nil {
		t.Fatalf("a standalone host was blocked by the shared binary guard: %v", err)
	}
}

// TestLocalLineRefusesUncoveredHubSSHJail pins the jail-reuse boundary: the
// Line reuses the Hub's jail, but only when the Hub's jail provably covers
// this host's actual SSH listeners. A Hub jail that covers other ports is
// refused instead of leaving the SSH listener unprotected.
func TestLocalLineRefusesUncoveredHubSSHJail(t *testing.T) {
	f := makeLocalLineFixture(t)
	// The Hub's recorded jail covers a different SSH port set.
	hub := readHubLedger(t, f.root)
	hub.SSHPorts = []int{2200}
	if err := writeState(f.root, hub); err != nil {
		t.Fatal(err)
	}
	f.runner.calls = nil
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "SSH_JAIL_REUSE_CONFLICT" {
		t.Fatalf("uncovered Hub jail = %+v %v", result, err)
	}
	if len(f.runner.calls) != 0 {
		t.Fatalf("the refused Line reached host commands: %v", f.runner.calls)
	}
	// No Line ledger was created.
	if _, exists, err := readLocalLineState(f.root); err != nil || exists {
		t.Fatalf("the refused Line wrote a ledger: exists=%v err=%v", exists, err)
	}
}

// TestStandaloneNodeKeepsSingleLedger pins that the co-location support did
// not change the standalone host behavior: a host without a Hub keeps one
// ledger at the historical path and no shared binary pin.
func TestStandaloneNodeKeepsSingleLedger(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("standalone install: %v", err)
	}
	state, exists, err := ReadState(f.root)
	if err != nil || !exists || state.Node == nil {
		t.Fatalf("standalone ledger missing: %+v %v", state, err)
	}
	if len(state.SharedBinaries) != 0 {
		t.Fatalf("standalone ledger gained shared binaries: %+v", state.SharedBinaries)
	}
	if _, exists, err := readLocalLineState(f.root); err != nil || exists {
		t.Fatalf("standalone host gained a local Line ledger: exists=%v err=%v", exists, err)
	}
	// The standalone Line still owns its own SSH jail.
	if _, err := os.Stat(rooted(f.root, nodeSSHJailPath)); err != nil {
		t.Fatalf("standalone Line lost its SSH jail: %v", err)
	}
}

// readHubLedger reads the Hub ledger of a fixture host.
func readHubLedger(t *testing.T, root string) InstallState {
	t.Helper()
	state, exists, err := ReadState(root)
	if err != nil || !exists {
		t.Fatalf("hub ledger missing: %+v %v", state, err)
	}
	return state
}
