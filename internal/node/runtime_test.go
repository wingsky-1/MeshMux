package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

type runtimeTestController struct {
	candidate CandidateDocument
	tasks     []protocol.Task
	reports   []protocol.TaskResult
	onReport  func(protocol.TaskResult) error
}

func (c *runtimeTestController) Candidate(context.Context, int64) (CandidateDocument, error) {
	return c.candidate, nil
}

func (*runtimeTestController) Heartbeat(context.Context, protocol.HeartbeatRequest) error { return nil }

func (c *runtimeTestController) Tasks(context.Context) ([]protocol.Task, error) {
	return append([]protocol.Task(nil), c.tasks...), nil
}

func (c *runtimeTestController) Report(_ context.Context, result protocol.TaskResult) error {
	c.reports = append(c.reports, result)
	if c.onReport != nil {
		return c.onReport(result)
	}
	return nil
}

type runtimeTestRunner struct {
	root         string
	pid          int
	listenPort   int
	nextPID      int
	execStart    string
	restartFail  bool
	nftRules     []string
	restartCount int
	// aclApplied records the ACL script text the Agent pushed with nft -f.
	aclApplied string
	// unauthorizedAccept is one source injected into the live table for the
	// next readback only, emulating a table tampered with during the
	// verification window. The rollback's nft -f restores the canonical LKG,
	// so the injected accept does not survive it.
	unauthorizedAccept string
}

func (r *runtimeTestRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	switch name {
	case "/usr/bin/systemctl":
		if len(args) > 0 && args[0] == "show" && len(args) > 1 && args[1] == SingBoxUnit {
			for _, arg := range args[2:] {
				if arg == "--value" {
					if r.execStart != "" {
						return []byte(r.execStart + "\n"), nil
					}
					return []byte(`{ path=/usr/local/libexec/meshmux-sing-box ; argv[]=/usr/local/libexec/meshmux-sing-box run -c /var/lib/meshmux-singbox/config.json ; ignore_errors=no }` + "\n"), nil
				}
			}
			return []byte("ActiveState=active\nSubState=running\nMainPID=" + strconv.Itoa(r.pid) + "\n"), nil
		}
		if len(args) > 0 && args[0] == "restart" {
			r.restartCount++
			if r.restartFail {
				r.restartFail = false
				return nil, errors.New("restart failed")
			}
			if r.nextPID > 0 {
				r.pid = r.nextPID
				r.nextPID = 0
			} else {
				r.pid++
			}
			if r.root != "" {
				if err := materializeTestProc(r.root, r.pid); err != nil {
					return nil, err
				}
			}
		}
		return []byte("ActiveState=active\nSubState=running\nMainPID=" + strconv.Itoa(r.pid) + "\n"), nil
	case "/usr/bin/ss":
		return []byte(`tcp LISTEN 0 4096 *:` + strconv.Itoa(r.listenPort) +
			` *:* users:(("sing-box",pid=` + strconv.Itoa(r.pid) + `,fd=3))` + "\n"), nil
	case "/usr/sbin/nft":
		if len(args) > 0 && args[0] == "-f" && len(args) > 1 && r.root != "" {
			// The fake data plane reflects the exact script the Agent
			// applied, so an ACL whose accept set drifted from the
			// authorization is caught by the readback instead of being
			// masked by a hard-coded fixture.
			if data, err := os.ReadFile(args[1]); err == nil {
				r.aclApplied = string(data)
				r.nftRules = nftRulesFromScript(r.aclApplied, r.listenPort)
			}
			return nil, nil
		}
		if len(args) > 0 && args[0] == "-j" {
			if len(r.nftRules) == 0 {
				r.nftRules = validNFTRules(r.listenPort)
			}
			rules := r.nftRules
			if r.unauthorizedAccept != "" {
				// Inject the out-of-band accept after the table and chain
				// entries, before the first drop. It is one-shot: the
				// rollback re-applies the canonical LKG, and that apply
				// must be able to prove itself again.
				injected := make([]string, 0, len(rules)+1)
				injected = append(injected, rules[:2]...)
				injected = append(injected, nftAcceptRule("ip", r.unauthorizedAccept, r.listenPort))
				injected = append(injected, rules[2:]...)
				rules = injected
				r.unauthorizedAccept = ""
			}
			return []byte("{\"nftables\":[" + strings.Join(rules, ",") + "]}"), nil
		}
		return nil, nil
	default:
		return nil, nil
	}
}

// nftRulesFromScript translates one rendered ACL script into the nft -j shape
// the kernel would print for it.
func nftRulesFromScript(script string, port int) []string {
	rules := []string{
		`{"table":{"family":"inet","name":"meshmux_out"}}`,
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}`,
	}
	for _, line := range strings.Split(script, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 7 && (fields[0] == "ip" || fields[0] == "ip6") && fields[1] == "saddr" &&
			fields[3] == "tcp" && fields[4] == "dport" && fields[6] == "accept" {
			rules = append(rules, nftAcceptRule(fields[0], fields[2], port))
			continue
		}
		if len(fields) == 4 && fields[1] == "dport" && fields[3] == "drop" &&
			(fields[0] == "tcp" || fields[0] == "udp") {
			rules = append(rules, nftPortRule(fields[0], port))
		}
	}
	return rules
}

func nftPortRule(proto string, port int) string {
	return `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"` + proto + `","field":"dport"}},` +
		`"right":` + strconv.Itoa(port) + `}},{"drop":null}]}}`
}

// nftAcceptRule renders one accept rule the way nft prints a source prefix:
// a bare address for a host prefix and a prefix object for a network.
func nftAcceptRule(family, source string, port int) string {
	right := `"` + source + `"`
	if address, bits, ok := strings.Cut(source, "/"); ok {
		if hostBits := map[string]string{"ip": "32", "ip6": "128"}[family]; bits == hostBits {
			right = `"` + address + `"`
		} else {
			right = `{"prefix":{"addr":"` + address + `","len":` + bits + `}}`
		}
	}
	return `{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"` + family + `","field":"saddr"}},"right":` + right + `}},` +
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":` + strconv.Itoa(port) + `}},` +
		`{"accept":null}]}}`
}

func validNFTRules(port int) []string {
	return []string{
		`{"table":{"family":"inet","name":"meshmux_out"}}`,
		`{"chain":{"family":"inet","table":"meshmux_out","name":"input","type":"filter","hook":"input","prio":-10,"policy":"accept"}}`,
		nftPortRule("tcp", port),
		nftPortRule("udp", port),
	}
}

func testConfig(role Role) Config {
	cfg := validConfig()
	cfg.Role = role
	cfg.NodeID = strings.Repeat("a", 32)
	cfg.VLESSPort = 8443
	cfg.SSHPort = 2222
	return cfg
}

func testCandidate(revision int64) CandidateDocument {
	candidate := validCandidate()
	candidate.Role = RoleEdge
	candidate.Revision = revision
	return NewCandidateDocument(candidate)
}

func createRuntimeFixture(t *testing.T, role Role, revision int64) (string, Config, Identity, *runtimeTestRunner) {
	t.Helper()
	root := t.TempDir()
	cfg := testConfig(role)
	identity := Identity{NodeID: cfg.NodeID, IdentityToken: strings.Repeat("A", 43)}
	runner := &runtimeTestRunner{root: root, pid: os.Getpid(), listenPort: cfg.VLESSPort}
	runner.nextPID = os.Getpid() + 1
	runner.execStart = "{ path=" + rooted(root, SingBoxBinaryPath) +
		" ; argv[]=" + rooted(root, SingBoxBinaryPath) + " run -c " + rooted(root, ActiveConfigPath) +
		" ; ignore_errors=no }"
	procDir := filepath.Join(root, "proc", strconv.Itoa(os.Getpid()))
	if err := os.MkdirAll(procDir, 0700); err != nil {
		t.Fatal(err)
	}
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(procDir, "exe"), exe, 0700); err != nil {
		t.Fatal(err)
	}
	cmdline := rooted(root, SingBoxBinaryPath) + "\x00run\x00-c\x00" + rooted(root, ActiveConfigPath) + "\x00"
	if err = os.WriteFile(filepath.Join(procDir, "cmdline"), []byte(cmdline), 0600); err != nil {
		t.Fatal(err)
	}
	procHash := sha256.Sum256(exe)
	cfg.KernelSHA256 = hex.EncodeToString(procHash[:])
	if err = os.MkdirAll(rooted(root, "/usr/local/libexec"), 0755); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rooted(root, AgentBinaryPath), exe, 0755); err != nil {
		t.Fatal(err)
	}
	cfg.AgentSHA256 = hex.EncodeToString(procHash[:])
	candidate := testCandidate(revision)
	candidate.Role = role
	data, err := json.Marshal(candidate)
	if err != nil {
		t.Fatal(err)
	}
	config, err := CompileCandidate(candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	agentDir := rooted(root, agentDataDir)
	if err = os.MkdirAll(agentDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rooted(root, ActiveCandidatePath), data, 0600); err != nil {
		t.Fatal(err)
	}
	activeDir := rooted(root, activeConfigDir)
	if err = os.Mkdir(activeDir, 0750); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(rooted(root, ActiveConfigPath), config, 0640); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(rooted(root, ActiveConfigPath), 0640); err != nil {
		t.Fatal(err)
	}
	// The installer writes the default-deny Out ACL before the Agent can
	// bootstrap, so a RoleOut fixture must carry it too.
	if role == RoleOut {
		acl, err := CompileACL(candidate.Candidate(), nil)
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(rooted(root, ACLPath), acl, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return root, cfg, identity, runner
}

func materializeTestProc(root string, pid int) error {
	procDir := filepath.Join(root, "proc", strconv.Itoa(pid))
	if err := os.MkdirAll(procDir, 0700); err != nil {
		return err
	}
	exe, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(procDir, "exe"), exe, 0700); err != nil {
		return err
	}
	return nil
}

func newTestRuntime(t *testing.T, root string, cfg Config, identity Identity, runner CommandRunner, controller Controller) *Runtime {
	t.Helper()
	runtime, err := NewRuntime(cfg, identity, RuntimeOptions{
		Root: root, Runner: runner, Controller: controller,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func task(kind string, operationID, key string, revision, configRevision int64) protocol.Task {
	params := json.RawMessage(`{}`)
	if kind == protocol.KindConfigCheck || kind == protocol.KindConfigStage ||
		kind == protocol.KindConfigApply || kind == protocol.KindConfigReadback {
		params, _ = json.Marshal(map[string]int64{"revision": configRevision})
	}
	return protocol.Task{
		Schema: protocol.Schema, Version: protocol.Version,
		OperationID: operationID, Revision: revision, IdempotencyKey: key,
		NodeID: strings.Repeat("a", 32), Kind: kind, Params: params,
	}
}

func TestReadbackLocalFreshInstallIsReadOnly(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	readback, err := ReadbackLocal(context.Background(), cfg, root, runner)
	if err != nil {
		t.Fatal(err)
	}
	if readback.ActiveRevision != 7 || !readback.LocalActive {
		t.Fatalf("unexpected readback: %+v", readback)
	}
	if _, err = os.Lstat(rooted(root, RuntimeStatePath)); !os.IsNotExist(err) {
		t.Fatalf("fresh readback wrote runtime state: %v", err)
	}
}

func TestReadbackLocalExistingStateFailsClosed(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	if err := os.WriteFile(rooted(root, RuntimeStatePath), []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadbackLocal(context.Background(), cfg, root, runner); err == nil {
		t.Fatal("invalid existing runtime state was accepted")
	}
}

func TestReadbackStartupConfigMismatchRejected(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	cmdline := "/usr/local/libexec/meshmux-sing-box\x00run\x00-c\x00/var/lib/meshmux-singbox/other.json\x00"
	if err := os.WriteFile(filepath.Join(root, "proc", strconv.Itoa(runner.pid), "cmdline"), []byte(cmdline), 0600); err != nil {
		t.Fatal(err)
	}
	runtime := &Runtime{cfg: cfg, root: root, runner: runner, procRoot: filepath.Join(root, "proc"), enforceProcArgs: true}
	candidate := testCandidate(7).Candidate()
	if _, err := runtime.readbackFor(context.Background(), cfg.Role, candidate, "", aclExpectation{}); err == nil {
		t.Fatal("same binary started with another config accepted")
	}
}

// TestReadbackSupervisorStartingIsDistinct pins the systemd 257 case: the
// MainPID can transiently be the systemd-executor supervisor that has not
// execed into sing-box yet. That is "not running yet", never a wrong
// binary, so it gets its own code that the installer retries.
// TestTransientReadbackSignals pins which live-readback failures may be
// retried: only the kernel-still-starting signals. Anything deterministic
// must fail fast instead of burning the startup budget.
func TestTransientReadbackSignals(t *testing.T) {
	transient := []string{
		"SINGBOX_NOT_RUNNING",
		"SINGBOX_SUPERVISOR_STARTING",
		"SINGBOX_PID_CHANGED",
		"LISTENER_PID_PORT_MISMATCH",
		"LISTENER_QUERY_FAILED",
	}
	for _, code := range transient {
		if !TransientReadback(errors.New(code)) {
			t.Errorf("%s should be retriable", code)
		}
	}
	deterministic := []string{
		"ACTIVE_CONFIG_MISMATCH",
		"AGENT_EXECUTABLE_MISMATCH",
		"SINGBOX_RUNNING_BINARY_MISMATCH",
		"OUT_DEFAULT_DENY_MISSING",
		"HOST_REJECTED",
		"",
	}
	for _, code := range deterministic {
		if TransientReadback(errors.New(code)) {
			t.Errorf("%q should fail fast", code)
		}
	}
	if TransientReadback(nil) {
		t.Error("nil error should fail fast")
	}
}

func TestReadbackSupervisorStartingIsDistinct(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleEdge, 7)
	exePath := filepath.Join(root, "proc", strconv.Itoa(runner.pid), "exe")
	if err := os.Remove(exePath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/usr/lib/systemd/systemd-executor", exePath); err != nil {
		t.Fatal(err)
	}
	_, err := ReadbackLocal(context.Background(), cfg, root, runner)
	if err == nil || !strings.Contains(err.Error(), "SINGBOX_SUPERVISOR_STARTING") {
		t.Fatalf("supervisor exe readback = %v", err)
	}
}

func TestOutACLRequiresExactRulePairs(t *testing.T) {
	root, cfg, _, runner := createRuntimeFixture(t, RoleOut, 7)
	cfg.Role = RoleOut
	cfg.VLESSPort = 8443
	runner.listenPort = 8443
	runner.nftRules = validNFTRules(8443)
	if _, err := ReadbackLocal(context.Background(), cfg, root, runner); err != nil {
		t.Fatal(err)
	}
	cases := [][]string{
		{
			runner.nftRules[0], runner.nftRules[1],
			`{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[{"accept":null}]}}`,
			runner.nftRules[2], runner.nftRules[3],
		},
		{
			runner.nftRules[0], runner.nftRules[1],
			`{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}}]}}`,
			runner.nftRules[3],
		},
		{
			runner.nftRules[0], runner.nftRules[1],
			`{"rule":{"family":"inet","table":"meshmux_out","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}},{"drop":null},{"accept":null}]}}`,
			runner.nftRules[3],
		},
		{
			runner.nftRules[0],
			strings.Replace(runner.nftRules[1], `"policy":"accept"`, `"policy":"drop"`, 1),
			runner.nftRules[2], runner.nftRules[3],
		},
	}
	for i, rules := range cases {
		runner.nftRules = rules
		if _, err := ReadbackLocal(context.Background(), cfg, root, runner); err == nil {
			t.Fatalf("mutated ACL %d accepted", i)
		}
	}
}

func TestTaskRevisionAndOperationReuseAcrossRestart(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	first := task(protocol.KindHealthStatus, strings.Repeat("1", 32), strings.Repeat("2", 32), 10, 7)
	result := runtime.Execute(context.Background(), first)
	if result.Status != "healthy" {
		t.Fatalf("first result = %+v", result)
	}
	runtime = newTestRuntime(t, root, cfg, identity, runner, controller)
	if got := runtime.Execute(context.Background(), first); got != result {
		t.Fatalf("exact replay = %+v, want %+v", got, result)
	}
	reuse := first
	reuse.IdempotencyKey = strings.Repeat("3", 32)
	if got := runtime.Execute(context.Background(), reuse); got.ErrorCode != "OPERATION_REUSE_CONFLICT" {
		t.Fatalf("operation reuse = %+v", got)
	}
	stale := task(protocol.KindHealthStatus, strings.Repeat("4", 32), strings.Repeat("5", 32), 9, 7)
	if got := runtime.Execute(context.Background(), stale); got.ErrorCode != "TASK_REVISION_STALE" {
		t.Fatalf("stale revision = %+v", got)
	}
}

func TestConfigApplyReportsProgressBeforeRestart(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "healthy" || result.Detail == "" {
		t.Fatalf("apply result = %+v", result)
	}
	if len(controller.reports) != 2 || controller.reports[0].Status != "applying" || controller.reports[1].Status != "verifying" {
		t.Fatalf("reports = %+v", controller.reports)
	}
	if runner.restartCount != 1 {
		t.Fatalf("restarts = %d", runner.restartCount)
	}
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	for operationID, cached := range state.FinalResults {
		if cached.Status == "pending" || cached.Status == "applying" || cached.Status == "verifying" {
			t.Fatalf("operation %s left nonterminal %s", operationID, cached.Status)
		}
	}
}

func TestFourTaskCycleLeavesNoNonterminalOutbox(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	controller.tasks = []protocol.Task{
		task(protocol.KindConfigCheck, strings.Repeat("1", 32), strings.Repeat("a", 32), 10, 9),
		task(protocol.KindConfigStage, strings.Repeat("2", 32), strings.Repeat("b", 32), 11, 9),
		task(protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("c", 32), 12, 9),
		task(protocol.KindConfigReadback, strings.Repeat("4", 32), strings.Repeat("d", 32), 13, 9),
	}
	runtime.cycle(context.Background())
	state, err := runtime.loadStateForExecution()
	if err != nil {
		t.Fatal(err)
	}
	for operationID, result := range state.FinalResults {
		if !terminalTaskResult(result.Status) {
			t.Fatalf("operation %s left nonterminal %s", operationID, result.Status)
		}
	}
	for _, report := range controller.reports {
		if report.Status == "healthy" &&
			report.OperationID != strings.Repeat("1", 32) &&
			report.OperationID != strings.Repeat("2", 32) &&
			report.Detail == "" {
			t.Fatalf("healthy result %s lacked readback detail", report.OperationID)
		}
	}
	restarts := runner.restartCount
	runtime.cycle(context.Background())
	if runner.restartCount != restarts {
		t.Fatalf("idempotent replay restarted kernel: before=%d after=%d", restarts, runner.restartCount)
	}
}

func TestApplyingReportFailureDoesNotTouchDataPlane(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{
		candidate: testCandidate(9),
		onReport: func(result protocol.TaskResult) error {
			if result.Status == "applying" {
				return errors.New("offline")
			}
			return nil
		},
	}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "failed" || result.ErrorCode != "APPLYING_REPORT_FAILED" {
		t.Fatalf("apply = %+v", result)
	}
	if runner.restartCount != 0 {
		t.Fatal("restart happened before applying report acknowledgement")
	}
	active, err := os.ReadFile(rooted(root, ActiveConfigPath))
	if err != nil {
		t.Fatal(err)
	}
	original, _ := CompileCandidate(testCandidate(7).Candidate())
	if string(active) != string(original) {
		t.Fatal("LKG changed after applying report failure")
	}
}

func TestRestartFailureRestoresLKG(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	runner.restartFail = true
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9)
	result := runtime.Execute(context.Background(), apply)
	if result.Status != "rolled_back" || result.ErrorCode != "SINGBOX_RESTART_FAILED" {
		t.Fatalf("apply = %+v", result)
	}
	original, _ := CompileCandidate(testCandidate(7).Candidate())
	active, _ := os.ReadFile(rooted(root, ActiveConfigPath))
	if string(active) != string(original) {
		t.Fatal("restart failure overwrote LKG")
	}
}

func TestCachedResultReplayAndAlreadyFinalClear(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	operationID := strings.Repeat("1", 32)
	apply := task(protocol.KindConfigApply, operationID, strings.Repeat("2", 32), 12, 7)
	state, _ := runtime.loadStateForExecution()
	payload, _ := json.Marshal(apply)
	state.LastTaskRevision = apply.Revision
	state.Idempotency[apply.IdempotencyKey] = idempotencyItem{
		PayloadDigest: sha256Hex(payload), TaskRevision: apply.Revision,
		OperationID: operationID, Result: protocol.TaskResult{OperationID: operationID, Status: "failed", ErrorCode: "TEST_FAILURE"},
	}
	state.FinalResults[operationID] = state.Idempotency[apply.IdempotencyKey].Result
	if err := runtime.persistState(&state); err != nil {
		t.Fatal(err)
	}
	controller.onReport = func(result protocol.TaskResult) error {
		if result.Status == "failed" {
			return &ClientError{Code: "TASK_ALREADY_FINAL", StatusCode: 409}
		}
		return nil
	}
	controller.tasks = []protocol.Task{apply}
	runtime.cycle(context.Background())
	state, _ = runtime.loadStateForExecution()
	if _, exists := state.FinalResults[operationID]; exists {
		t.Fatal("TASK_ALREADY_FINAL left the outbox blocked")
	}
}

func TestOutboxLimitDoesNotDropUnacknowledgedResults(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})
	state, _ := runtime.loadStateForExecution()
	for i := range maxFinalCache {
		id := fmt.Sprintf("%032x", i+1)
		state.FinalResults[id] = protocol.TaskResult{OperationID: id, Status: "failed", ErrorCode: "TEST_FAILURE"}
	}
	if err := runtime.persistState(&state); err != nil {
		t.Fatal(err)
	}
	result := runtime.Execute(context.Background(), task(protocol.KindHealthStatus, strings.Repeat("f", 32), strings.Repeat("e", 32), 12, 7))
	if result.ErrorCode != "FINAL_OUTBOX_FULL" {
		t.Fatalf("execute = %+v", result)
	}
	state, _ = runtime.loadStateForExecution()
	if len(state.FinalResults) != maxFinalCache {
		t.Fatalf("outbox size = %d", len(state.FinalResults))
	}
}

func TestStatePersistenceFailureCannotReportHealthy(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(9)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	runtime.writeState = func(*runtimeState) error { return errors.New("disk full") }
	apply := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 11, 9)
	result := runtime.Execute(context.Background(), apply)
	if result.Status == "healthy" || result.ErrorCode == "" {
		t.Fatalf("apply persistence failure = %+v", result)
	}
	for _, report := range controller.reports {
		if report.Status == "healthy" {
			t.Fatal("persistence failure was reported healthy")
		}
	}
}

func TestFinalPersistFailureDowngradesHealthy(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})
	runtime.writeState = func(*runtimeState) error { return errors.New("disk full") }
	state, _ := runtime.loadStateForExecution()
	task := task(protocol.KindConfigApply, strings.Repeat("3", 32), strings.Repeat("4", 32), 12, 7)
	result := runtime.finishApply(context.Background(), &state, task, strings.Repeat("5", 64), protocol.TaskResult{
		OperationID: task.OperationID, Status: "healthy", Detail: `{"local_active":true}`,
	})
	if result.Status != "partial" || result.ErrorCode != "STATE_PERSIST_FAILED" || result.Detail != "" {
		t.Fatalf("persisted healthy result = %+v", result)
	}
}

func TestOrdinaryPersistFailureReturnsFailed(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	runtime := newTestRuntime(t, root, cfg, identity, runner, &runtimeTestController{candidate: testCandidate(7)})
	runtime.writeState = func(*runtimeState) error { return errors.New("disk full") }
	status := task(protocol.KindHealthStatus, strings.Repeat("6", 32), strings.Repeat("7", 32), 12, 7)
	result := runtime.Execute(context.Background(), status)
	if result.Status != "failed" || result.ErrorCode != "STATE_PERSIST_FAILED" {
		t.Fatalf("persist failure = %+v", result)
	}
}

func TestCrashJournalRestoresLKGAndKeepsRevisionBoundary(t *testing.T) {
	root, cfg, identity, runner := createRuntimeFixture(t, RoleEdge, 7)
	controller := &runtimeTestController{candidate: testCandidate(7)}
	runtime := newTestRuntime(t, root, cfg, identity, runner, controller)
	journalTask := task(protocol.KindConfigApply, strings.Repeat("1", 32), strings.Repeat("2", 32), 22, 9)
	payload, _ := json.Marshal(journalTask)
	state, _ := runtime.loadStateForExecution()
	bad, _ := CompileCandidate(testCandidate(9).Candidate())
	state.Journal = &applyJournal{
		Schema: journalTXNSchema, OperationID: strings.Repeat("1", 32),
		Idempotency: strings.Repeat("2", 32), Payload: sha256Hex(payload),
		TaskRevision: 22, Revision: 9, Digest: sha256Hex(bad), Config: bad,
		Reported: true,
	}
	state.LastTaskRevision = 22
	if err := runtime.persistState(&state); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(rooted(root, ActiveConfigPath), bad, 0640)
	runtime = newTestRuntime(t, root, cfg, identity, runner, controller)
	original, _ := CompileCandidate(testCandidate(7).Candidate())
	active, _ := os.ReadFile(rooted(root, ActiveConfigPath))
	if string(active) != string(original) {
		t.Fatal("crash recovery did not restore LKG")
	}
	state, _ = runtime.loadStateForExecution()
	if state.LastTaskRevision != 22 || state.Journal != nil {
		t.Fatalf("recovery state = %+v", state)
	}
	replay := journalTask
	if got := runtime.Execute(context.Background(), replay); got.Status != "rolled_back" {
		t.Fatalf("journal result replay = %+v", got)
	}
	changedParams := journalTask
	changedParams.Params = json.RawMessage(`{"revision":10}`)
	if got := runtime.Execute(context.Background(), changedParams); got.ErrorCode != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("changed config ref replay = %+v", got)
	}
	changedEnvelope := journalTask
	changedEnvelope.Kind = protocol.KindConfigCheck
	if got := runtime.Execute(context.Background(), changedEnvelope); got.ErrorCode != "IDEMPOTENCY_CONFLICT" {
		t.Fatalf("changed task envelope replay = %+v", got)
	}
}

func TestRunCommandIsExportedAndRejectsArguments(t *testing.T) {
	var output strings.Builder
	if got := RunCommand([]string{"arbitrary"}, &output); got != 2 {
		t.Fatalf("exit = %d", got)
	}
	if !strings.Contains(output.String(), "USAGE") {
		t.Fatalf("output = %q", output.String())
	}
}

func TestRuntimeLockSerializesAgentAndRepair(t *testing.T) {
	root := t.TempDir()
	first, err := AcquireRuntimeLock(context.Background(), root)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err = AcquireRuntimeLock(ctx, root); err == nil {
		t.Fatal("concurrent runtime writer acquired the shared lock")
	}
}
