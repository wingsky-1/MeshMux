package install

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// dumpGuestServiceState logs the kernel unit state, its journal tail and
// the guest listeners when an install step fails. The VM is ephemeral, so
// without this the failure reason never leaves the guest. Output is ports
// and service state only; pairing material is never printed.
func dumpGuestServiceState(t *testing.T) {
	t.Helper()
	for _, args := range [][]string{
		{"systemctl", "show", "meshmux-sing-box", "--property=ActiveState,SubState,MainPID,ExecMainPID,Result", "--value", "--no-pager"},
		{"journalctl", "-u", "meshmux-sing-box", "--no-pager", "-n", "60"},
		{"ss", "-H", "-lntup"},
		// Time-sync evidence distinguishes a QEMU TCG clock flake
		// (TSC unstable, NTP still converging) from a real install bug.
		{"timedatectl", "status"},
		{"journalctl", "-u", "systemd-timesyncd", "--no-pager", "-n", "30"},
	} {
		out, err := exec.Command(args[0], args[1:]...).CombinedOutput()
		t.Logf("$ %s (err=%v):\n%s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
}

// TestNodeSystemVM runs only in an ephemeral Debian 13 VM with real systemd.
// It performs the first install against the runner-side Hub fixture, then
// repair with the persisted identity, failure injection and reboot
// persistence. It never runs on a production node. Pairing codes and
// identity tokens are never logged.
func TestNodeSystemVM(t *testing.T) {
	if os.Getenv("MESHMUX_NODE_SYSTEM_VM") != "1" {
		t.Skip("MESHMUX_NODE_SYSTEM_VM is not set to 1: requires an explicit disposable Debian 13 QEMU VM")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated VM integration test requires root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("VM did not boot with systemd")
	}
	role := node.Role(os.Getenv("MESHMUX_NODE_ROLE"))
	if role != node.RoleEdge && role != node.RoleOut {
		t.Fatal("fixture role must be edge or out")
	}
	phase := os.Getenv("MESHMUX_NODE_PHASE")
	if phase != "install" && phase != "post-reboot" {
		t.Fatal("fixture phase must be install or post-reboot")
	}
	statusPath := os.Getenv("MESHMUX_NODE_FIXTURE_STATUS")
	caPath := os.Getenv("MESHMUX_NODE_FIXTURE_CA")
	if statusPath == "" || caPath == "" {
		t.Fatal("fixture status and CA paths are required")
	}
	status := readNodeFixtureStatus(t, statusPath)
	if node.Role(status.Role) != role || status.NodeID == "" || status.HubURL == "" || status.PairingCode == "" {
		t.Fatal("fixture status does not match the requested role")
	}
	installNodeFixtureCA(t, caPath)
	cfg := node.Config{
		HubURL: status.HubURL, NodeID: status.NodeID, Role: role,
		VLESSPort: status.VLESSPort, SSHPort: status.SSHPort,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("fixture status produced an invalid Node config: %v", err)
	}
	// The meshmux binary path defaults to the QEMU guest layout and can be
	// relocated for harnesses (e.g. a systemd container where /tmp is a
	// tmpfs that docker cp cannot populate from outside the mount ns).
	meshmuxBin := os.Getenv("MESHMUX_NODE_MESHMUX_BIN")
	if meshmuxBin == "" {
		meshmuxBin = "/tmp/meshmux"
	}
	opts := NodeApplyOptions{Root: "/", Runner: ExecRunner{}, Executable: meshmuxBin}
	switch phase {
	case "install":
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		testNodeSystemInstall(t, ctx, cfg, status.PairingCode, opts)
	case "post-reboot":
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
		defer cancel()
		testNodeSystemPostReboot(t, ctx, cfg, opts)
	}
}

type nodeFixtureStatus struct {
	HubURL      string `json:"hub_url"`
	NodeID      string `json:"node_id"`
	Role        string `json:"role"`
	VLESSPort   int    `json:"vless_port"`
	SSHPort     int    `json:"ssh_port"`
	PairingCode string `json:"pairing_code"`
}

func readNodeFixtureStatus(t *testing.T, path string) nodeFixtureStatus {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status nodeFixtureStatus
	if err := json.Unmarshal(data, &status); err != nil {
		t.Fatal("fixture status is not JSON")
	}
	return status
}

// installNodeFixtureCA trusts the disposable fixture CA in the VM system
// store so preflight, pairing and downloads use the same system roots as
// production. The VM is disposable; nothing here touches a real host.
func installNodeFixtureCA(t *testing.T, caPath string) {
	t.Helper()
	pemData, err := os.ReadFile(caPath)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("fixture CA is not PEM")
	}
	if _, err := x509.ParseCertificate(block.Bytes); err != nil {
		t.Fatalf("fixture CA is invalid: %v", err)
	}
	runner := ExecRunner{}
	ctx := context.Background()
	dest := "/usr/local/share/ca-certificates/meshmux-node-fixture.crt"
	if err := os.WriteFile(dest, pemData, 0644); err != nil {
		if _, aptErr := runner.Run(ctx, "apt-get", "install", "-y", "ca-certificates"); aptErr != nil {
			t.Fatalf("fixture CA directory unavailable: %v", err)
		}
		if err := os.WriteFile(dest, pemData, 0644); err != nil {
			t.Fatal(err)
		}
	}
	if out, err := runner.Run(ctx, "update-ca-certificates"); err != nil {
		t.Fatalf("update-ca-certificates failed: %v %s", err, out)
	}
}

func mustNodeState(t *testing.T, nodeID string) InstallState {
	t.Helper()
	state, exists, err := ReadState("/")
	if err != nil || !exists || state.Status != "installed" || state.Node == nil || state.Node.NodeID != nodeID {
		t.Fatal("node ledger is not installed")
	}
	return state
}

func nodeSystemReadback(t *testing.T, ctx context.Context, cfg node.Config, role node.Role) {
	t.Helper()
	rb, err := node.ReadbackLocal(ctx, cfg, "/", node.ExecRunner{})
	if err != nil {
		t.Fatalf("node readback failed: %v", err)
	}
	if !rb.LocalActive {
		t.Fatal("node readback is not locally active")
	}
	if role == node.RoleOut && !rb.OutDefaultDeny {
		t.Fatal("Out readback lost default-deny evidence")
	}
	if err := rb.Validate(); err != nil {
		t.Fatalf("node readback invalid: %v", err)
	}
}

func requireNodeUnits(t *testing.T, ctx context.Context, runner ExecRunner, role node.Role, verb string) {
	t.Helper()
	units := []string{node.AgentUnit, node.SingBoxUnit}
	if role == node.RoleOut {
		units = append(units, node.ACLUnit)
	}
	for _, unit := range units {
		if _, err := runner.Run(ctx, "systemctl", verb, "--quiet", unit); err != nil {
			t.Fatalf("unit %s is not %s", unit, verb)
		}
	}
}

// requireNodeListeners proves the listeners and the retired-guard evidence a
// node must carry. The Out source allowlist is retired: the live
// inet meshmux_out table must be the rule-free MeshMux shell and the managed
// script must be its canonical render, so no legacy accept/drop rule survives
// to filter clients the link key now admits. An Out with configured transport
// admits clients by that link key only, so the SS guard must listen on the node
// port and the running kernel document must carry exactly the link key the
// active candidate publishes.
func requireNodeListeners(t *testing.T, ctx context.Context, runner ExecRunner, cfg node.Config) {
	t.Helper()
	out, err := runner.Run(ctx, "ss", "-H", "-lnt")
	if err != nil || !strings.Contains(string(out), ":"+strconv.Itoa(cfg.VLESSPort)) {
		t.Fatal("node TCP listener missing (Out SS guard or Line VLESS)")
	}
	out, err = runner.Run(ctx, "fail2ban-client", "get", "meshmux-node-sshd", "action", "nftables-multiport", "port")
	if err != nil || !strings.Contains(string(out), strconv.Itoa(cfg.SSHPort)) {
		t.Fatalf("SSH jail does not cover %d", cfg.SSHPort)
	}
	if cfg.Role != node.RoleOut {
		if _, err := runner.Run(ctx, "nft", "list", "table", "inet", node.ACLTable); err == nil {
			t.Fatal("edge node unexpectedly owns an Out table")
		}
		return
	}
	documentData := mustReadVM(t, node.ActiveCandidatePath)
	var document node.CandidateDocument
	if err := json.Unmarshal(documentData, &document); err != nil {
		t.Fatal("active candidate is not a node document")
	}
	if document.Out == nil || node.ValidateOutLinkKey(document.Out.Key) != nil {
		t.Fatal("Out candidate carries no Hub-issued SS link key")
	}
	// Live evidence: the retired table exists, carries the neutral input chain
	// and must have zero rules. A surviving accept or dport/drop rule would be
	// the old source allowlist, which the link key replaced.
	table, err := runner.Run(ctx, "nft", "-j", "list", "table", "inet", node.ACLTable)
	if err != nil {
		t.Fatal("retired Out ACL table is not live")
	}
	if err := node.VerifyOutACLDocument(table, cfg.VLESSPort, nil); err != nil {
		t.Fatalf("Out ACL is not the retired rule-free table: %v", err)
	}
	// File evidence: the managed script is the canonical render, so a repair or
	// hand edit cannot preserve an allowlist the live table no longer needs.
	acl := mustReadVM(t, node.ACLPath)
	expectedACL, err := node.CompileACL(document.Candidate(), nil)
	if err != nil || !bytes.Equal(acl, expectedACL) {
		t.Fatal("managed Out ACL is not the canonical rule-free render")
	}
	// The SS guard is the ingress authorization now: one shadowsocks inbound on
	// the node port whose password is exactly the active candidate's link key.
	var active struct {
		Inbounds []struct {
			Type       string `json:"type"`
			ListenPort int    `json:"listen_port"`
			Method     string `json:"method"`
			Password   string `json:"password"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(mustReadVM(t, node.ActiveConfigPath), &active); err != nil || len(active.Inbounds) != 1 {
		t.Fatal("active kernel config is not exactly one guard inbound")
	}
	guard := active.Inbounds[0]
	if guard.Type != "shadowsocks" || guard.ListenPort != cfg.VLESSPort ||
		guard.Method != node.OutLinkMethod || guard.Password != document.Out.Key {
		t.Fatal("SS guard does not admit the active candidate link key on the node port")
	}
}

func testNodeSystemInstall(t *testing.T, ctx context.Context, cfg node.Config, pairingCode string, opts NodeApplyOptions) {
	t.Helper()
	runner := ExecRunner{}
	if _, exists, err := ReadState("/"); err != nil || exists {
		t.Fatal("VM image is not clean")
	}
	opID, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	res, err := InstallNode(ctx, cfg, opID, false, pairingCode, opts)
	if err != nil || res.Status != "installed" {
		dumpGuestServiceState(t)
		t.Fatalf("first install status=%s code=%s stage=%s recovery=%s err=%v", res.Status, res.ErrorCode, res.Stage, res.Recovery, err)
	}
	state := mustNodeState(t, cfg.NodeID)
	nodeSystemReadback(t, ctx, *state.Node, cfg.Role)
	requireNodeUnits(t, ctx, runner, cfg.Role, "is-active")
	requireNodeListeners(t, ctx, runner, cfg)
	identityBefore := mustReadVM(t, node.IdentityPath)
	candidateBefore := mustReadVM(t, node.ActiveCandidatePath)
	opID, err = NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	res, err = InstallNode(ctx, cfg, opID, true, "", opts)
	if err != nil || res.Status != "installed" {
		dumpGuestServiceState(t)
		t.Fatalf("repair status=%s code=%s stage=%s recovery=%s err=%v", res.Status, res.ErrorCode, res.Stage, res.Recovery, err)
	}
	assertNodeFilesEqual(t, identityBefore, candidateBefore)
	injected := &vmOneFailureRunner{target: "restart meshmux-sing-box.service"}
	broken := opts
	broken.Runner = injected
	opID, err = NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	res, err = InstallNode(ctx, cfg, opID, true, "", broken)
	if err == nil || res.Status != "partial" || res.ErrorCode != "KERNEL_START_FAILED" {
		t.Fatalf("injected restart failure not fail-closed: status=%s code=%s err=%v", res.Status, res.ErrorCode, err)
	}
	opID, err = NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	res, err = InstallNode(ctx, cfg, opID, true, "", opts)
	if err != nil || res.Status != "installed" {
		dumpGuestServiceState(t)
		t.Fatalf("recovery repair status=%s code=%s stage=%s recovery=%s err=%v", res.Status, res.ErrorCode, res.Stage, res.Recovery, err)
	}
	nodeSystemReadback(t, ctx, *mustNodeState(t, cfg.NodeID).Node, cfg.Role)
	assertNodeFilesEqual(t, identityBefore, candidateBefore)
}

func testNodeSystemPostReboot(t *testing.T, ctx context.Context, cfg node.Config, opts NodeApplyOptions) {
	t.Helper()
	runner := ExecRunner{}
	state := mustNodeState(t, cfg.NodeID)
	nodeSystemReadback(t, ctx, *state.Node, cfg.Role)
	requireNodeUnits(t, ctx, runner, cfg.Role, "is-enabled")
	requireNodeUnits(t, ctx, runner, cfg.Role, "is-active")
	requireNodeListeners(t, ctx, runner, cfg)
	identityBefore := mustReadVM(t, node.IdentityPath)
	candidateBefore := mustReadVM(t, node.ActiveCandidatePath)
	opID, err := NewOperationID()
	if err != nil {
		t.Fatal(err)
	}
	res, err := InstallNode(ctx, cfg, opID, true, "", opts)
	if err != nil || res.Status != "installed" {
		dumpGuestServiceState(t)
		t.Fatalf("post-reboot repair status=%s code=%s stage=%s recovery=%s err=%v", res.Status, res.ErrorCode, res.Stage, res.Recovery, err)
	}
	assertNodeFilesEqual(t, identityBefore, candidateBefore)
}

func assertNodeFilesEqual(t *testing.T, identityBefore, candidateBefore []byte) {
	t.Helper()
	if !bytes.Equal(identityBefore, mustReadVM(t, node.IdentityPath)) {
		t.Fatal("repair rotated the persisted identity")
	}
	if !bytes.Equal(candidateBefore, mustReadVM(t, node.ActiveCandidatePath)) {
		t.Fatal("repair replaced the active candidate")
	}
}
