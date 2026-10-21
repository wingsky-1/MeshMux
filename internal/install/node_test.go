package install

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

type fakeNodeRunner struct {
	calls    []string
	failCall string
	failUsed bool
	users    map[string]bool
	packages map[string]bool
	readback node.Readback
	// aclRequiresFile, when set, makes the Out ACL unit fail to start while
	// the file is absent. It emulates a clean host where nft -f cannot
	// apply a table file that installNodeDynamic has not written yet.
	aclRequiresFile string
	// jailPorts is the SSH port set the fixture's Fail2ban jail reports.
	// The installer now requires the jail to cover every actual SSH
	// listener, so the fixture answers with the same set its preflight
	// detects instead of a single hard-coded port.
	jailPorts []int
}

// fixtureSSHPorts is the SSH listener set the node fixture detects. The
// fixture preflight and its Fail2ban jail readback both use it, so a real
// host with more than one SSH listener is represented consistently.
var fixtureSSHPorts = []int{2222, 2200}

func (f *fakeNodeRunner) fail2banJailPorts() string {
	ports := f.jailPorts
	if len(ports) == 0 {
		ports = fixtureSSHPorts
	}
	sorted := append([]int(nil), ports...)
	sort.Ints(sorted)
	values := make([]string, 0, len(sorted))
	for _, port := range sorted {
		values = append(values, strconv.Itoa(port))
	}
	return strings.Join(values, ",")
}

func (f *fakeNodeRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if f.failCall != "" && !f.failUsed && strings.Contains(call, f.failCall) {
		f.failUsed = true
		return nil, errors.New("fixture fault")
	}
	if f.aclRequiresFile != "" && name == "systemctl" && strings.Contains(call, node.ACLUnit) {
		if _, err := os.Stat(f.aclRequiresFile); err != nil {
			return nil, errors.New("fixture: ACL unit started before the dynamic file existed")
		}
	}
	switch name {
	case "dpkg":
		return []byte("amd64\n"), nil
	case "apt-get":
		return nil, nil
	case "getent":
		if len(args) == 2 && f.users[args[1]] {
			return []byte("fixture user"), nil
		}
		return nil, errors.New("missing user")
	case "useradd":
		if f.users == nil {
			f.users = map[string]bool{}
		}
		f.users[args[len(args)-1]] = true
	case "dpkg-query":
		if f.packages != nil && f.packages[args[len(args)-1]] {
			return []byte("install ok installed"), nil
		}
		return nil, errors.New("missing package")
	case "fail2ban-client":
		// fail2ban 1.1.0 has no `get <JAIL> port`; the installer reads the
		// jail port back through the nftables-multiport action instance.
		if len(args) == 5 && args[0] == "get" && args[1] == "meshmux-node-sshd" &&
			args[2] == "action" && args[3] == "nftables-multiport" && args[4] == "port" {
			return []byte(f.fail2banJailPorts() + "\n"), nil
		}
		if len(args) == 5 && args[0] == "get" && args[1] == "meshmux-node-sshd" &&
			args[2] == "action" && args[3] == "nftables-multiport" && args[4] == "actionstart" {
			// Real fail2ban 1.1.0 shell-escapes the set braces; the L1 fake
			// uses the exact daemon format so the readback is validated.
			return []byte("nft add rule inet f2b-table f2b-chain $proto dport \\{ $(echo '" + f.fail2banJailPorts() + "' | sed s/:/-/g) \\} <addr_family> saddr @<addr_set> reject\n"), nil
		}
	case "systemctl":
		if len(args) > 1 && args[0] == "show" && strings.Contains(call, node.SingBoxUnit) {
			return []byte("ActiveState=active\nSubState=running\nMainPID=4242\n"), nil
		}
	case "timedatectl":
		// Hermetic unit tests simulate a synchronized clock; the real
		// waitForClockSync poll is covered by its own flap/ctx tests.
		// Without this the new bounded poll would idle 90s per test that
		// exercises the real preflight (e.g. TestNodeFirstInstallAndLedger).
		return []byte("yes\n"), nil
	case "nft":
		if len(args) >= 2 && args[0] == "list" {
			return []byte("table inet meshmux_out {\n chain input { policy accept; tcp dport 8443 drop; udp dport 8443 drop; }\n}"), nil
		}
	default:
		if len(args) == 1 && args[0] == "version" {
			return []byte(node.CurrentAgentVersion + " " + node.KernelVersion), nil
		}
	}
	return nil, nil
}

type nodeFixture struct {
	root        string
	runner      *fakeNodeRunner
	cfg         node.Config
	opts        NodeApplyOptions
	identity    node.Identity
	candidate   node.CandidateDocument
	archivePath string
	binaryHash  string
}

func makeNodeFixture(t *testing.T, role node.Role) *nodeFixture {
	t.Helper()
	root := t.TempDir()
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: role, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion,
	}
	release, _ := node.KernelReleaseFor("amd64")
	binary := []byte("fixture sing-box binary " + string(role))
	binaryHash := sha256.Sum256(binary)
	release.BinarySHA256 = hex.EncodeToString(binaryHash[:])
	archive := filepath.Join(t.TempDir(), "kernel.tar.gz")
	if err := writeNodeTestArchive(archive, binary); err != nil {
		t.Fatal(err)
	}
	archiveData, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	archiveHash := sha256.Sum256(archiveData)
	artifact := Artifact{
		Component: "sing-box", Version: node.KernelVersion, Source: release.SourceURL,
		SHA256: hex.EncodeToString(archiveHash[:]), Format: "tar.gz",
	}
	executable := filepath.Join(t.TempDir(), "meshmux")
	if err := os.WriteFile(executable, []byte("fixture MeshMux Agent executable"), 0755); err != nil {
		t.Fatal(err)
	}
	identity := node.Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	candidate := node.NewCandidateDocument(node.Candidate{
		NodeID: cfg.NodeID, Role: role, Revision: 7, VLESSPort: cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	runner := &fakeNodeRunner{users: map[string]bool{}, packages: map[string]bool{"ca-certificates": true, "fail2ban": true, "nftables": true}}
	readback := node.Readback{
		Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
		AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
		KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 7,
		ConfigSHA256: strings.Repeat("d", 64), LocalActive: true,
		OutDefaultDeny: role == node.RoleOut,
	}
	opts := NodeApplyOptions{
		Root: root, Runner: runner, Executable: executable, Artifacts: []Artifact{artifact},
		Preflight: func(context.Context, node.Config, bool) ([]Check, []int) {
			return []Check{{Name: "os", Status: "pass"}, {Name: "public", Status: "pending"}}, []int{2222, 2200}
		},
		DownloadArtifact: func(context.Context, Artifact, string) (string, error) { return archive, nil },
		Pair:             func(context.Context, node.Config, string) (node.Identity, error) { return identity, nil },
		Metadata: func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
			return cfg.Metadata(), nil
		},
		Candidate: func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
			return candidate, nil
		},
		Readback: func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
			return readback, nil
		},
		Verify:      func(context.Context, node.Config, CommandRunner, node.Readback) error { return nil },
		VerifyAgent: func(string, string) error { return nil },
	}
	return &nodeFixture{root: root, runner: runner, cfg: cfg, opts: opts, identity: identity,
		candidate: candidate, archivePath: archive, binaryHash: release.BinarySHA256}
}

func writeNodeTestArchive(path string, binary []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{Name: "sing-box-1.14.3-linux-amd64/sing-box", Mode: 0755, Size: int64(len(binary)), Typeflag: tar.TypeReg}); err != nil {
		return err
	}
	if _, err := tw.Write(binary); err != nil {
		return err
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := gz.Close(); err != nil {
		return err
	}
	return f.Close()
}

func fileSHA256ForTest(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// The fake binary must report the pinned strings without pretending to be a
// real executable. The runner seam returns these outputs from the install
// transaction's command boundary.
func (f *nodeFixture) install(t *testing.T, repair bool, code string) (InstallResult, error) {
	t.Helper()
	return InstallNode(context.Background(), f.cfg, strings.Repeat("e", 32), repair, code, f.opts)
}

func TestSameNodeConfigIgnoresInstalledDigests(t *testing.T) {
	a := node.Config{HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32), Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222}
	b := a
	b.AgentVersion, b.AgentSHA256, b.KernelSHA256 = "other", strings.Repeat("b", 64), strings.Repeat("c", 64)
	if !SameNodeConfig(a, b) || a.Validate() != nil {
		t.Fatal("installed digest fields changed user configuration comparison")
	}
	b.HubURL = "https://other.example.invalid"
	if SameNodeConfig(a, b) {
		t.Fatal("Hub URL change was ignored")
	}
	b = a
	b.VLESSPort++
	if SameNodeConfig(a, b) {
		t.Fatal("port change was ignored")
	}
}

func TestNodePlanRoleUnitsAndHubArtifactsRemainSeparate(t *testing.T) {
	cfg := node.Config{HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32), Role: node.RoleOut, VLESSPort: 8443, SSHPort: 2222}
	plan := BuildNodePlanForRoot(t.TempDir(), strings.Repeat("f", 32), cfg, "amd64", []Check{{Name: "external", Status: "pending"}}, []int{2222})
	if plan.Config.HubURL != cfg.HubURL || plan.Config.VLESSPort != cfg.VLESSPort || !plan.ApplyAvailable {
		t.Fatalf("Node plan config/status = %+v", plan)
	}
	if len(plan.Artifacts) != 1 || plan.Artifacts[0].Component != "sing-box" || len(PinnedArtifacts("amd64")) != 2 {
		t.Fatal("Node manifest leaked into Hub allowlist or vice versa")
	}
	if plan.ACLTable != node.ACLTable || !containsUnit(plan.Units, node.ACLUnit) {
		t.Fatalf("Out plan omitted ACL ownership: %+v", plan)
	}
	if len(plan.ExternalPending) != 1 || plan.ExternalPending[0] != "external" {
		t.Fatalf("pending external evidence lost: %+v", plan.ExternalPending)
	}
}

func TestNodeUnitsKeepRoleDependenciesAndSandboxPathsPrecise(t *testing.T) {
	edge := nodeManagedFilesForTest(t, node.RoleEdge)
	out := nodeManagedFilesForTest(t, node.RoleOut)
	agent := edge["/etc/systemd/system/"+node.AgentUnit].Body
	if !strings.Contains(agent, "ReadWritePaths=/var/lib/meshmux-agent /var/lib/meshmux-singbox\n") ||
		strings.Contains(agent, "ReadWritePaths=/var/lib/meshmux-agent /var/lib/meshmux-singbox /etc/") ||
		strings.Contains(agent, "/run/nftables") {
		t.Fatalf("Agent sandbox has overbroad or missing paths:\n%s", agent)
	}
	if !strings.Contains(agent, "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE\n") ||
		!strings.Contains(agent, "AmbientCapabilities=CAP_DAC_READ_SEARCH CAP_NET_ADMIN CAP_CHOWN CAP_SYS_PTRACE\n") {
		t.Fatalf("Agent lacks the minimum process-read capability required for live exe/cmdline/ss verification:\n%s", agent)
	}
	edgeKernel := edge["/etc/systemd/system/"+node.SingBoxUnit].Body
	if strings.Contains(edgeKernel, "Requires=meshmux-out-acl.service") || strings.Contains(edgeKernel, "After=meshmux-out-acl.service") {
		t.Fatalf("Edge kernel unexpectedly depends on Out ACL:\n%s", edgeKernel)
	}
	outKernel := out["/etc/systemd/system/"+node.SingBoxUnit].Body
	if !strings.Contains(outKernel, "Requires=meshmux-out-acl.service\n") ||
		!strings.Contains(outKernel, "After=meshmux-out-acl.service\n") {
		t.Fatalf("Out kernel does not hard-require ACL:\n%s", outKernel)
	}
	aclUnit := out["/etc/systemd/system/"+node.ACLUnit].Body
	if !strings.Contains(aclUnit, "Before=meshmux-sing-box.service\n") {
		t.Fatalf("ACL ordering missing:\n%s", aclUnit)
	}
	for name, body := range map[string]string{"agent": agent, "edge kernel": edgeKernel, "out kernel": outKernel} {
		for _, line := range strings.Split(body, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "//") {
				t.Fatalf("%s unit uses // comments, which systemd ignores with warnings; use #:\n%s", name, body)
			}
		}
	}
	if !strings.Contains(edgeKernel, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n") ||
		!strings.Contains(outKernel, "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n") {
		t.Fatalf("kernel unit must keep AF_NETLINK: sing-box enumerates interfaces at startup:\n%s\n%s", edgeKernel, outKernel)
	}
	aclFile, exists := out[node.ACLPath]
	if !exists || aclFile.Static || aclFile.Body != "" {
		t.Fatalf("ACL path is not a dynamic-only managed entry: %+v", aclFile)
	}
}

func nodeManagedFilesForTest(t *testing.T, role node.Role) map[string]nodeManagedFile {
	t.Helper()
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: role, VLESSPort: 8443, SSHPort: 2222,
		AgentVersion: node.CurrentAgentVersion,
	}
	identity := node.Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	files, err := nodeManagedFiles(cfg, []int{2222}, identity)
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestNodeLayoutConflictNeverOverwritesHubState(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	hub := InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
		Config: Config{ManagementDomain: "hub.example.invalid"}, ManagedFiles: map[string]string{},
	}
	if err := writeState(f.root, hub); err != nil {
		t.Fatal(err)
	}
	// A Hub ledger that publishes no SharedBinaries cannot host a
	// co-located Line: resolveNodeLayout reports HubHost without CoLocated,
	// so InstallNode fails closed at preflight with NODE_OWNERSHIP_UNVERIFIED
	// before readNodeState, rather than reporting a HOST_LAYOUT_CONFLICT from
	// the Hub ledger's nil Node record. The Hub ledger is never treated as
	// Node ownership evidence.
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "NODE_OWNERSHIP_UNVERIFIED" {
		t.Fatalf("Hub without shared runtime = %+v %v", result, err)
	}
	state, _, _ := ReadState(f.root)
	if state.Config.ManagementDomain != "hub.example.invalid" || state.Node != nil {
		t.Fatal("Node operation changed Hub ownership state")
	}
	if len(f.runner.calls) != 0 {
		t.Fatalf("ownership failure reached host commands: %v", f.runner.calls)
	}
}

// TestNodeLayoutRepairUsesEffectiveLineLedgerNotHubLedger pins the repair
// ownership source on a co-located host: the Hub ledger at the historical
// path has Node=nil, so only the Line's own ledger may supply the kernel
// digest and bind it to this exact Node, role and port set.
func TestNodeLayoutRepairUsesEffectiveLineLedgerNotHubLedger(t *testing.T) {
	root := t.TempDir()
	hub, _ := writeLocalLineHubLedger(t, root, []int{2222})
	if hub.Node != nil {
		t.Fatal("fixture Hub ledger unexpectedly records a Node")
	}
	cfg := node.Config{
		HubURL: localLineHubOrigin, NodeID: strings.Repeat("a", 32),
		Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
	}
	recorded := cfg
	recorded.AgentVersion = node.CurrentAgentVersion
	recorded.AgentSHA256 = strings.Repeat("b", 64)
	recorded.KernelSHA256 = strings.Repeat("c", 64)
	if err := writeLocalLineState(root, InstallState{
		Schema: 1, OperationID: strings.Repeat("2", 32), Status: "installed",
		Node: &recorded, ManagedFiles: map[string]string{}, Artifacts: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}

	oldCgroup := cgroupOf
	oldExecutable := processExecutableOf
	oldExecutableHash := processExecutableHashOf
	defer func() { cgroupOf = oldCgroup }()
	defer func() { processExecutableOf = oldExecutable }()
	defer func() { processExecutableHashOf = oldExecutableHash }()
	cgroupOf = func(pid string) ([]byte, error) {
		return []byte("0::/system.slice/" + node.SingBoxUnit + "\n"), nil
	}
	processExecutableOf = func(string) (string, error) { return node.SingBoxBinaryPath, nil }
	processExecutableHashOf = func(string) (string, error) { return recorded.KernelSHA256, nil }

	runner := &fixedNodeRunner{name: "ss", output: []byte(
		"tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:((\"meshmux-sing-bo\",pid=4242,fd=6))\n" +
			"udp UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:((\"meshmux-sing-bo\",pid=4242,fd=7))\n",
	)}
	checks := nodePortPreflight(context.Background(), cfg, true, root, runner)
	for _, check := range checks {
		if check.Status != "pass" {
			t.Fatalf("effective Line ledger did not authorize its kernel listener: %+v", check)
		}
	}
}

// TestNodeLayoutRepairRejectsUnboundLineLedger pins that a ledger which does
// not bind this exact Node, or records no verified kernel digest, yields the
// stable ownership code instead of blaming a third-party PORT_CONFLICT.
func TestNodeLayoutRepairRejectsUnboundLineLedger(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*node.Config)
	}{
		{"node id", func(cfg *node.Config) { cfg.NodeID = strings.Repeat("f", 32) }},
		{"role", func(cfg *node.Config) { cfg.Role = node.RoleOut }},
		{"vless port", func(cfg *node.Config) { cfg.VLESSPort = 9443 }},
		{"ssh port", func(cfg *node.Config) { cfg.SSHPort = 2200 }},
		{"missing kernel digest", func(cfg *node.Config) { cfg.KernelSHA256 = "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeLocalLineHubLedger(t, root, []int{2222})
			cfg := node.Config{
				HubURL: localLineHubOrigin, NodeID: strings.Repeat("a", 32),
				Role: node.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
			}
			recorded := cfg
			recorded.AgentVersion = node.CurrentAgentVersion
			recorded.AgentSHA256 = strings.Repeat("b", 64)
			recorded.KernelSHA256 = strings.Repeat("c", 64)
			tc.mutate(&recorded)
			if err := writeLocalLineState(root, InstallState{
				Schema: 1, OperationID: strings.Repeat("2", 32), Status: "installed",
				Node: &recorded, ManagedFiles: map[string]string{}, Artifacts: map[string]string{},
			}); err != nil {
				t.Fatal(err)
			}
			listeners := "tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:((\"meshmux-sing-bo\",pid=4242,fd=6))\n"
			checks := nodePortPreflight(context.Background(), cfg, true, root,
				&fixedNodeRunner{name: "ss", output: []byte(listeners)})
			for _, check := range checks {
				if check.Status != "fail" || check.Code != nodeOwnershipUnverified {
					t.Fatalf("unbound ledger = %+v, want %s", check, nodeOwnershipUnverified)
				}
			}
		})
	}
}

func TestNodeBadArchiveHashDoesNotWriteHostFiles(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	f.opts.Artifacts[0].SHA256 = strings.Repeat("0", 64)
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "ARTIFACT_CHECKSUM_MISMATCH" {
		t.Fatalf("bad archive = %+v %v", result, err)
	}
	for _, path := range []string{node.AgentBinaryPath, node.SingBoxBinaryPath, node.IdentityPath} {
		if _, statErr := os.Stat(rooted(f.root, path)); !os.IsNotExist(statErr) {
			t.Fatalf("bad archive wrote %s", path)
		}
	}
}

func TestNodeIdentityPersistedBeforeMetadataFailure(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	f.cfg.AgentVersion = node.CurrentAgentVersion
	f.cfg.AgentSHA256 = strings.Repeat("b", 64)
	f.cfg.KernelSHA256 = f.binaryHash
	f.candidate = node.NewCandidateDocument(node.Candidate{
		NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 1,
		VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	f.opts.Candidate = func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
		return node.NewCandidateDocument(node.Candidate{
			NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 1,
			VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
		}), nil
	}
	f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
		return node.Metadata{}, errors.New("metadata fault")
	}
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != "PAIRING_METADATA_FAILED" {
		t.Fatalf("metadata fault = %+v %v", result, err)
	}
	if _, statErr := os.Stat(rooted(f.root, node.IdentityPath)); statErr != nil {
		t.Fatal("pairing identity was not persisted before Metadata/Candidate validation")
	}
	// A repair must reuse that private credential and must not accept the old
	// pairing code again.
	f.opts.Pair = func(context.Context, node.Config, string) (node.Identity, error) {
		return node.Identity{}, errors.New("code consumed")
	}
	f.opts.Metadata = func(context.Context, node.Config, node.Identity) (node.Metadata, error) {
		return f.cfg.Metadata(), nil
	}
	f.opts.Candidate = func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
		return f.candidate, nil
	}
	f.opts.DownloadArtifact = func(context.Context, Artifact, string) (string, error) {
		return f.archivePath, nil
	}
	f.opts.Artifacts[0].SHA256 = fileSHA256ForTest(t, f.archivePath)
	release, ok := node.KernelReleaseFor("amd64")
	if !ok {
		t.Fatal("missing amd64 release")
	}
	f.opts.Artifacts[0].Source = release.SourceURL
	info, err := os.Stat(f.archivePath)
	if err != nil || info.Size() == 0 {
		t.Fatalf("archive unavailable: %v", err)
	}
	if _, err := f.install(t, true, ""); err != nil {
		t.Fatalf("repair did not reuse persisted identity: %v", err)
	}
}

func TestNodePortConsistencyAndACLReadback(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	_, err := InstallNode(context.Background(), f.cfg, strings.Repeat("e", 32), false, strings.Repeat("A", 43), f.opts)
	if err != nil {
		t.Fatalf("fixture install: %v", err)
	}
	if !strings.Contains(strings.Join(f.runner.calls, "\n"), "dpkg --print-architecture") {
		t.Fatal("actual dpkg architecture was not queried")
	}
	for _, call := range f.runner.calls {
		if strings.Contains(call, "apt-get install") && strings.Contains(call, "upgrade") {
			t.Fatalf("apt upgrade was requested: %s", call)
		}
	}

	files, err := nodeManagedFiles(f.cfg, []int{2222, 2200}, f.identity)
	if err != nil {
		t.Fatal(err)
	}
	jail := files["/etc/fail2ban/jail.d/meshmux-node-ssh.local"].Body
	if !strings.Contains(jail, "port = 2200,2222") || strings.Contains(jail, "8443") {
		t.Fatalf("SSH jail ports are not the actual listener set without VLESS: %s", jail)
	}
	aclFile, exists := files[node.ACLPath]
	if !exists || aclFile.Static || aclFile.Body != "" {
		t.Fatal("ACL rules must be initialized only from the validated candidate")
	}
}

func TestParseFail2banSSHPortSets(t *testing.T) {
	for _, tc := range []struct {
		name, ports, action string
		want                []int
	}{
		{"debian-13-multiport", "2200,2222\n", "nft add rule inet f2b-table f2b-chain tcp dport { 2200, 2222 } ip saddr @addr-set-meshmux-node-sshd reject\n", []int{2200, 2222}},
		{"single-action-port", "2222", "tcp dport 2222 ip saddr @addr-set-meshmux-node-sshd reject", []int{2222}},
		{"real-1.1.0-actionstart", "22", "nft add rule inet f2b-table f2b-chain $proto dport \\{ $(echo '22' | sed s/:/-/g) \\} <addr_family> saddr @<addr_set> reject", []int{22}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gotPorts, err := parseFail2banPorts(tc.ports)
			if err != nil {
				t.Fatal(err)
			}
			gotAction, err := parseFail2banActionPorts(tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if !equalIntSets(gotPorts, tc.want) || !equalIntSets(gotAction, tc.want) {
				t.Fatalf("jail=%v action=%v, want %v", gotPorts, gotAction, tc.want)
			}
		})
	}
	for _, tc := range []struct {
		ports, action string
	}{
		{"2222", "tcp dport { 12222 } ip saddr @addr-set-meshmux-node-sshd reject"},
		{"2222,2222", "tcp dport { 2222 } ip saddr @addr-set-meshmux-node-sshd reject"},
		{"2222,2200", "tcp dport { 2222 } ip saddr @addr-set-meshmux-node-sshd reject"},
		{"ssh", "tcp dport { 22 } ip saddr @addr-set-meshmux-node-sshd reject"},
	} {
		jailPorts, jailErr := parseFail2banPorts(tc.ports)
		actionPorts, actionErr := parseFail2banActionPorts(tc.action)
		if jailErr == nil && actionErr == nil && equalIntSets(jailPorts, actionPorts) {
			t.Fatalf("inconsistent port evidence accepted: %q / %q", tc.ports, tc.action)
		}
	}
}

func TestNodeManagedPortUsesPIDCgroupAndTruncatedComm(t *testing.T) {
	oldCgroup := cgroupOf
	oldExecutable := processExecutableOf
	oldExecutableHash := processExecutableHashOf
	defer func() { cgroupOf = oldCgroup }()
	defer func() { processExecutableOf = oldExecutable }()
	defer func() { processExecutableHashOf = oldExecutableHash }()
	cgroupByPID := map[string]string{
		"4242": "0::/system.slice/meshmux-sing-box.service\n",
		"5555": "0::/system.slice/other.service\n",
	}
	cgroupOf = func(pid string) ([]byte, error) {
		value, ok := cgroupByPID[pid]
		if !ok {
			return nil, errors.New("gone")
		}
		return []byte(value), nil
	}
	processExecutableOf = func(string) (string, error) {
		return node.SingBoxBinaryPath, nil
	}
	processExecutableHashOf = func(string) (string, error) {
		return strings.Repeat("a", 64), nil
	}
	ctx := context.Background()
	for _, tc := range []struct {
		name, line, protocol string
		port                 int
		want                 string
	}{
		{
			name:     "debian13 truncated comm",
			line:     `tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("meshmux-sing-bo",pid=4242,fd=6))`,
			protocol: "tcp", port: 8443, want: "pass",
		},
		{
			name:     "udp without netid",
			line:     `UNCONN 0 0 0.0.0.0:8443 0.0.0.0:* users:(("meshmux-sing-bo",pid=4242,fd=7))`,
			protocol: "udp", port: 8443, want: "pass",
		},
		{
			name:     "lookalike comm in wrong unit",
			line:     `tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("meshmux-sing-box",pid=5555,fd=6))`,
			protocol: "tcp", port: 8443, want: "fail",
		},
		{
			name:     "multiple owners",
			line:     "tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:((\"meshmux-sing-bo\",pid=4242,fd=6),(\"other\",pid=5555,fd=8))",
			protocol: "tcp", port: 8443, want: "fail",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := nodeManagedPort(ctx, tc.line, tc.name, tc.protocol, tc.port, strings.Repeat("a", 64))
			if got.Status != tc.want {
				t.Fatalf("managed port = %+v, want %s", got, tc.want)
			}
		})
	}
}

func TestNodeManagedPortUsesUniquePIDAndRejectsAmbiguousOwnership(t *testing.T) {
	oldCgroup := cgroupOf
	oldExecutable := processExecutableOf
	oldExecutableHash := processExecutableHashOf
	defer func() { cgroupOf = oldCgroup }()
	defer func() { processExecutableOf = oldExecutable }()
	defer func() { processExecutableHashOf = oldExecutableHash }()
	cgroupOf = func(pid string) ([]byte, error) {
		if pid == "4242" {
			return []byte("0::/system.slice/meshmux-sing-box.service\n"), nil
		}
		return []byte("0::/system.slice/" + pid + ".service\n"), nil
	}
	processExecutableOf = func(string) (string, error) {
		return node.SingBoxBinaryPath, nil
	}
	processExecutableHashOf = func(string) (string, error) {
		return strings.Repeat("a", 64), nil
	}
	twoOwners := `tcp LISTEN 0 4096 0.0.0.0:8443 0.0.0.0:* users:(("meshmux-sing-bo",pid=4242,fd=6),("meshmux-sing-bo",pid=5555,fd=7))`
	check := nodeManagedPort(context.Background(), twoOwners, "vless_tcp", "tcp", 8443, strings.Repeat("a", 64))
	if check.Status != "fail" || check.Code != "PORT_OWNER_UNVERIFIED" {
		t.Fatalf("ambiguous listener = %+v", check)
	}
}

func TestNodeTableOwnershipDistinguishesAbsentAndProbeFailure(t *testing.T) {
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleOut, VLESSPort: 8443, SSHPort: 2222,
	}
	// A recorded table is only adopted when this host's own Node ledger
	// binds the exact config, so the ledger lives under a temporary root
	// instead of the real /var/lib/meshmux-installer.
	root := t.TempDir()
	recorded := cfg
	recorded.AgentVersion, recorded.AgentSHA256, recorded.KernelSHA256 =
		node.CurrentAgentVersion, strings.Repeat("b", 64), strings.Repeat("c", 64)
	if err := writeState(root, InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed", Node: &recorded,
	}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name       string
		output     string
		err        error
		allow      bool
		wantKind   tableOwnershipKind
		wantStatus string
	}{
		{"absent", "Error: No such file or directory\n", errors.New("exit"), false, tableAbsent, "pass"},
		{"absent kmsg style", "table inet meshmux_out: object not found\n", errors.New("exit"), false, tableAbsent, "pass"},
		{"permission", "Operation not permitted\n", errors.New("exit"), false, tableProbeFailed, "fail"},
		{"kernel unsupported", "Error: Could not process rule: Operation not supported\n", errors.New("exit"), false, tableProbeFailed, "fail"},
		{"third party without ledger", "table inet meshmux_out {\n}\n", nil, false, tableConflict, "fail"},
		{"recorded managed", "table inet meshmux_out {\n}\n", nil, true, tableManaged, "pass"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			runner := &fixedNodeRunner{name: "nft", output: []byte(tc.output), err: tc.err}
			got := nodeTableOwnership(context.Background(), root, runner, cfg, tc.allow)
			if got.Kind != tc.wantKind {
				t.Fatalf("kind = %v, want %v", got.Kind, tc.wantKind)
			}
			if check := got.checkName("out_acl_table"); check.Status != tc.wantStatus {
				t.Fatalf("check = %+v, want status %s", check, tc.wantStatus)
			}
		})
	}
}

func TestNodeTableOwnershipIsRecheckedAfterNftablesInstall(t *testing.T) {
	cfg := node.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: node.RoleOut, VLESSPort: 8443, SSHPort: 2222,
	}
	runner := &fixedNodeRunner{
		name: "nft", output: []byte("Operation not permitted\n"), err: errors.New("exit"),
	}
	// The recheck only classifies the table; the ledger root is empty here.
	root := t.TempDir()
	if err := verifyNodeTableOwnershipAfterInstall(context.Background(), root, runner, cfg, false); err == nil {
		t.Fatal("permission failure was accepted after nftables install")
	}
	runner.output, runner.err = []byte("Error: No such file or directory\n"), errors.New("exit")
	if err := verifyNodeTableOwnershipAfterInstall(context.Background(), root, runner, cfg, false); err != nil {
		t.Fatalf("explicit absent table after nftables install: %v", err)
	}
}

func TestNodeHTTPSPreflightRejectsRedirect(t *testing.T) {
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirect.Close()
	got := nodeHTTPSPreflightWithClient(context.Background(), redirect.URL, redirect.Client())
	if got.Status != "fail" || got.Code != "NETWORK_UNAVAILABLE" {
		t.Fatalf("redirecting Hub accepted: %+v", got)
	}
}

type fixedNodeRunner struct {
	name   string
	output []byte
	err    error
}

func (r *fixedNodeRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	if name != r.name {
		return nil, errors.New("unexpected command")
	}
	return r.output, r.err
}

func TestNodeRepairReusesIdentityAndPreservesLKG(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	f.candidate = node.NewCandidateDocument(node.Candidate{
		NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 1,
		VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	f.opts.Candidate = func(context.Context, node.Config, node.Identity, int64) (node.CandidateDocument, error) {
		return f.candidate, nil
	}
	if err := writeState(f.root, InstallState{
		Schema: 1, OperationID: strings.Repeat("1", 32), Status: "partial",
		Node: &f.cfg, ManagedFiles: map[string]string{}, Artifacts: map[string]string{},
	}); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateNodeDirectory(rooted(f.root, nodeAgentStateDir)); err != nil {
		t.Fatal(err)
	}
	if err := persistNodeIdentity(f.root, f.identity); err != nil {
		t.Fatal(err)
	}
	dir := rooted(f.root, nodeKernelDataDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	lkg := filepath.Join(dir, "config.json")
	candidateBody, err := json.Marshal(node.NewCandidateDocument(node.Candidate{
		NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 9,
		VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(f.root, node.ActiveCandidatePath), candidateBody, 0600); err != nil {
		t.Fatal(err)
	}
	compiled, err := node.CompileCandidate(node.Candidate{
		NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 9,
		VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lkg, compiled, 0640); err != nil {
		t.Fatal(err)
	}
	compiledHash := sha256.Sum256(compiled)
	f.opts.Readback = func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
		return node.Readback{
			Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 9,
			ConfigSHA256: hex.EncodeToString(compiledHash[:]), LocalActive: true,
		}, nil
	}
	pairCalls := 0
	f.opts.Pair = func(context.Context, node.Config, string) (node.Identity, error) {
		pairCalls++
		return node.Identity{}, errors.New("repair must not consume a code")
	}
	result, err := f.install(t, true, "")
	if err != nil || result.Status != "installed" {
		t.Fatalf("repair preserved LKG but failed: %+v %v", result, err)
	}
	if pairCalls != 0 {
		t.Fatal("repair requested a replacement pairing code")
	}
	data, err := os.ReadFile(lkg)
	if err != nil || !bytes.Equal(data, compiled) {
		t.Fatalf("repair lost the existing valid LKG: %q %v", data, err)
	}
}

func TestNodeLKGRequiresCanonicalBytes(t *testing.T) {
	f := makeNodeFixture(t, node.RoleEdge)
	dir := rooted(f.root, nodeKernelDataDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateNodeDirectory(rooted(f.root, nodeAgentStateDir)); err != nil {
		t.Fatal(err)
	}
	candidate := node.Candidate{
		NodeID: f.cfg.NodeID, Role: f.cfg.Role, Revision: 1,
		VLESSPort: f.cfg.VLESSPort, KernelVersion: node.KernelVersion,
	}
	document := node.NewCandidateDocument(candidate)
	documentBody, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(f.root, node.ActiveCandidatePath), documentBody, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rooted(f.root, node.ActiveConfigPath), []byte(`{"listen_port":8443}`), 0640); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("corrupt JSON containing the port was retained as LKG")
	}
}

func containsUnit(units []string, unit string) bool {
	for _, got := range units {
		if got == unit {
			return true
		}
	}
	return false
}

func TestStateNodeJSONCompatibility(t *testing.T) {
	state := InstallState{Schema: 1, OperationID: strings.Repeat("a", 32), Status: "installed", ManagedFiles: map[string]string{}}
	body, err := json.Marshal(state)
	if err != nil || bytes.Contains(body, []byte(`"node"`)) {
		t.Fatalf("Hub state gained an empty Node object: %s %v", body, err)
	}
}

// TestNodeFirstInstallAndLedger runs the complete mutation path against a
// temporary root. It uses only the injected command runner and a loopback Hub
// fixture; no host account, apt, service or firewall command is executed.
func TestNodeFirstInstallAndLedger(t *testing.T) {
	f := makeNodeFixture(t, node.RoleOut)
	hub := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/agent/pair":
			if r.Method != http.MethodPost || strings.Contains(r.URL.RawQuery, "A") {
				http.Error(w, "invalid", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]string{
				"node_id": f.cfg.NodeID, "identity_token": f.identity.IdentityToken,
				"operation_id": strings.Repeat("1", 32),
			})
		case "/api/agent/node":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(f.cfg.Metadata())
		case "/api/agent/config/1":
			documentCandidate := f.candidate
			documentCandidate.Revision = 1
			document, err := json.Marshal(documentCandidate)
			if err != nil {
				t.Error(err)
				http.Error(w, "invalid", http.StatusInternalServerError)
				return
			}
			sum := sha256.Sum256(document)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-MeshMux-Config-SHA256", hex.EncodeToString(sum[:]))
			_, _ = w.Write(document)
		default:
			http.NotFound(w, r)
		}
	}))
	defer hub.Close()
	f.cfg.HubURL = hub.URL
	f.opts.Preflight = nil
	f.opts.Pair, f.opts.Metadata, f.opts.Candidate = nil, nil, nil
	f.opts.HTTPClient = hub.Client()
	f.opts.Readback = func(context.Context, node.Config, string, node.CommandRunner) (node.Readback, error) {
		return node.Readback{
			Architecture: "amd64", AgentVersion: node.CurrentAgentVersion,
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: node.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 1,
			ConfigSHA256: strings.Repeat("d", 64), LocalActive: true, OutDefaultDeny: true,
		}, nil
	}
	runner := f.runner
	runner.packages = map[string]bool{"fail2ban": true, "nftables": true}
	runner.packages["ca-certificates"] = false
	// The real preflight proves it queries the host through the injected
	// runner, while its read-only network probes remain isolated.
	if _, err := InstallNode(context.Background(), f.cfg, strings.Repeat("e", 32), false, strings.Repeat("A", 43), f.opts); err == nil {
		t.Fatal("fixture unexpectedly passed a real host preflight")
	}
	if !strings.Contains(strings.Join(runner.calls, "\n"), "dpkg --print-architecture") {
		t.Fatal("preflight did not use the injected runner")
	}

	// Exercise the mutation path with the focused read-only checks used by the
	// VM harness, while retaining the real Client + pair + candidate flow.
	f.opts.Preflight = func(context.Context, node.Config, bool) ([]Check, []int) {
		return []Check{{Name: "fixture", Status: "pass"}}, append([]int(nil), fixtureSSHPorts...)
	}
	runner.failCall = ""
	runner.calls = nil
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("first install = %+v %v", result, err)
	}
	state, exists, err := ReadState(f.root)
	if err != nil || !exists || state.Status != "installed" || state.Node == nil || state.Node.NodeID != f.cfg.NodeID {
		t.Fatalf("Node state = %+v %v", state, err)
	}
	// The standalone Line owns one jail for every actual SSH listener, not
	// just the configured rescue port, and records that full set.
	if !equalIntSets(state.SSHPorts, fixtureSSHPorts) {
		t.Fatalf("recorded SSH ports = %v, want %v", state.SSHPorts, fixtureSSHPorts)
	}
	for _, path := range []string{node.AgentConfigPath, node.IdentityPath, "/etc/systemd/system/" + node.AgentUnit, "/etc/systemd/system/" + node.SingBoxUnit, "/etc/fail2ban/jail.d/meshmux-node-ssh.local"} {
		if _, statErr := os.Stat(rooted(f.root, path)); statErr != nil {
			t.Fatalf("managed path missing %s: %v", path, statErr)
		}
	}
	if _, recorded := state.ManagedFiles[node.IdentityPath]; recorded {
		t.Fatal("private identity must not enter the static managed-file ledger")
	}
	for _, target := range []string{node.RuntimeStatePath, node.ActiveCandidatePath, node.ActiveConfigPath, node.ACLPath} {
		if _, recorded := state.ManagedFiles[target]; recorded {
			t.Fatalf("dynamic path %s entered the static ledger", target)
		}
	}
	joined := strings.Join(runner.calls, "\n")
	if !strings.Contains(joined, "apt-get install") || strings.Contains(joined, "apt-get upgrade") || strings.Contains(joined, "apt-get dist-upgrade") {
		t.Fatalf("apt behavior is not a fixed missing-package install: %s", joined)
	}
}

type probeRunner struct {
	out  []byte
	err  error
	args []string
}

func (r *probeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.args = append([]string(nil), args...)
	return r.out, r.err
}

func TestVerifyAgentBinaryRequiresExactVersionProbe(t *testing.T) {
	selfHash, err := sha256File("/proc/self/exe")
	if err != nil {
		t.Skipf("probe requires /proc/self/exe, unavailable on this platform: %v", err)
	}
	newOpts := func(runner CommandRunner) NodeApplyOptions {
		return NodeApplyOptions{Root: "/", Runner: runner}
	}
	r := &probeRunner{out: []byte(node.CurrentAgentVersion + "\n")}
	if err := verifyAgentBinary(context.Background(), newOpts(r), "/tmp/staged-meshmuxd", selfHash); err != nil {
		t.Fatalf("exact probe = %v, want nil", err)
	}
	if len(r.args) != 1 || r.args[0] != "__internal-agent-version" {
		t.Fatalf("probe argv = %q, want exactly [__internal-agent-version]", r.args)
	}
	r = &probeRunner{out: []byte(node.CurrentAgentVersion + " extra")}
	if err := verifyAgentBinary(context.Background(), newOpts(r), "/tmp/staged-meshmuxd", selfHash); err == nil {
		t.Fatal("substring probe accepted, want AGENT_VERSION_MISMATCH")
	}
	r = &probeRunner{err: errors.New("exec failed")}
	if err := verifyAgentBinary(context.Background(), newOpts(r), "/tmp/staged-meshmuxd", selfHash); err == nil {
		t.Fatal("failed probe accepted, want AGENT_VERSION_PROBE_FAILED")
	}
	r = &probeRunner{out: []byte(node.CurrentAgentVersion + "\n")}
	if err := verifyAgentBinary(context.Background(), newOpts(r), "/tmp/staged-meshmuxd", strings.Repeat("0", 64)); err == nil {
		t.Fatal("hash mismatch accepted, want AGENT_NOT_SELF_COPY")
	}
}

// clockFlapRunner emulates a time service that is still starting: the first
// calls fail or report "no" before settling on "yes". Industry practice is
// to retry such eventually-consistent signals with a bounded deadline
// instead of failing a single-shot check (SRE retry-with-deadline).
type clockFlapRunner struct {
	calls int
	ready int
	fail  int
}

func (r *clockFlapRunner) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	if name != "timedatectl" {
		return nil, errors.New("unexpected command " + name)
	}
	r.calls++
	if r.calls <= r.fail {
		return nil, errors.New("time service starting")
	}
	if r.calls <= r.ready {
		return []byte("no\n"), nil
	}
	return []byte("yes\n"), nil
}

func TestWaitForClockSyncRetriesTransientNoAndErrors(t *testing.T) {
	r := &clockFlapRunner{fail: 1, ready: 3}
	if err := waitForClockSync(context.Background(), r); err != nil {
		t.Fatalf("flapping clock = %v, want nil (calls=%d)", err, r.calls)
	}
	if r.calls < 4 {
		t.Fatalf("clock calls = %d, want >=4 (errors+no retried)", r.calls)
	}
}

func TestWaitForClockSyncRespectsContext(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	r := &clockFlapRunner{fail: 1000, ready: 1000}
	if err := waitForClockSync(ctx, r); err == nil {
		t.Fatal("cancelled clock wait accepted, want ctx error")
	}
}
