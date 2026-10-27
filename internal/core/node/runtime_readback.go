package node

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

func (r *Runtime) readback(ctx context.Context, revision int64) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: currentOperation(ctx), Status: "failed"}
	state, err := r.loadStateForExecution()
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	if state.Revision != revision || len(state.LKG) == 0 {
		return failedResult(result, "REVISION_NOT_ACTIVE"), errors.New("REVISION_NOT_ACTIVE")
	}
	candidateData, err := r.loadLKGCandidate(revision)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	candidate := candidateFromStaged(candidateData)
	if candidate == nil {
		return failedResult(result, "LKG_CANDIDATE_INVALID"), errors.New("LKG_CANDIDATE_INVALID")
	}
	// The live readback is the verdict. Everything after it is a side effect of
	// that acceptance, never a second verdict (spec §4.6/§4.16).
	readback, err := r.readbackFor(ctx, r.cfg.Role, *candidate, state.LKGDigest)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	detail, err := json.Marshal(readback)
	if err != nil {
		return failedResult(result, "READBACK_DETAIL_FAILED"), errors.New("READBACK_DETAIL_FAILED")
	}
	result.Status = "healthy"
	result.Detail = boundedDetail(detail)
	// The readback is the anchor. It is also the only place a crash-window
	// claim may be settled: once the on-disk agent.json and Agent binary are a
	// consistent pair, the claim (kept by an in-memory adoption) is obsolete.
	// When the pair is still old and no outside writer is wired, the claim
	// stays for the next install --repair; this never fails the readback.
	r.settleHandoffClaim(ctx)
	// The health-gated finalize is a SIDE EFFECT of this accepted readback, not
	// a second verdict (spec §4.6): it advances a surviving marker to the
	// readback step's frozen `verifying` phase, finishes it once the on-disk
	// pair is proven, and confirms the rollback record so the older generation
	// is released to GC. It never changes the healthy result.
	r.finalizeUpgradeReadback(ctx, readback)
	return result, nil
}

func (r *Runtime) status(ctx context.Context) (protocol.TaskResult, error) {
	result := protocol.TaskResult{OperationID: currentOperation(ctx), Status: "failed"}
	readback, err := ReadbackLocal(ctx, r.cfg, r.root, r.runner)
	if err != nil {
		return failedResult(result, errorCode(err)), err
	}
	detail, err := json.Marshal(readback)
	if err != nil {
		return failedResult(result, "READBACK_DETAIL_FAILED"), err
	}
	result.Status = "healthy"
	result.Detail = boundedDetail(detail)
	return result, nil
}

// ReadbackLocal returns evidence from the live systemd process, kernel, socket
// and active files. Disk state alone never produces a successful result.
func ReadbackLocal(ctx context.Context, cfg Config, root string, runner CommandRunner) (Readback, error) {
	if err := cfg.ValidateInstalled(); err != nil {
		return Readback{}, err
	}
	if _, ok := KernelReleaseFor(runtime.GOARCH); !ok {
		return Readback{}, errors.New("ARCHITECTURE_UNSUPPORTED")
	}
	absRoot, err := trustedRoot(root)
	if err != nil {
		return Readback{}, err
	}
	if runner == nil {
		runner = ExecRunner{}
	}
	runtimeInstance := &Runtime{cfg: cfg, root: absRoot, runner: runner, procRoot: rooted(absRoot, "/proc")}
	stateData, _, err := readRuntimeStateFile(rooted(absRoot, RuntimeStatePath))
	if err != nil {
		if !os.IsNotExist(err) {
			return Readback{}, errors.New("RUNTIME_STATE_UNSAFE")
		}
		return runtimeInstance.readbackBootstrap(ctx)
	}
	var state runtimeState
	if err = decodeStrictJSON(stateData, &state); err != nil || state.Schema != runtimeStateSchema ||
		state.NodeID != cfg.NodeID || state.Role != cfg.Role || state.Revision < 1 ||
		state.LKGDigest == "" || state.Journal != nil {
		return Readback{}, errors.New("RUNTIME_STATE_INVALID")
	}
	candidateData, err := runtimeInstance.loadLKGCandidate(state.Revision)
	if err != nil {
		return Readback{}, err
	}
	candidate := candidateFromStaged(candidateData)
	if candidate == nil {
		return Readback{}, errors.New("LKG_CANDIDATE_INVALID")
	}
	return runtimeInstance.readbackFor(ctx, cfg.Role, *candidate, state.LKGDigest)
}

// readbackBootstrap validates an installed node before the Agent has ever held
// runtime state. No trusted record of an applied allowlist exists in that
// state, and the managed ACL file is exactly what a tampered host would edit,
// so it must not become the expectation: only the guard shape and both VLESS
// drops are asserted here.
func (r *Runtime) readbackBootstrap(ctx context.Context) (Readback, error) {
	uid := managedFileUID(r.root)
	candidateData, _, err := readRegularFileOwnedBy(rooted(r.root, ActiveCandidatePath), 0600, uid)
	if err != nil {
		return Readback{}, errors.New("BOOTSTRAP_CANDIDATE_INVALID")
	}
	var document CandidateDocument
	if err = decodeStrictJSON(candidateData, &document); err != nil {
		return Readback{}, errors.New("BOOTSTRAP_CANDIDATE_INVALID")
	}
	if err = document.ValidateFor(r.cfg); err != nil {
		return Readback{}, errors.New("BOOTSTRAP_CANDIDATE_INVALID")
	}
	active, _, err := readRegularFileOwnedBy(rooted(r.root, ActiveConfigPath), 0640, uid)
	if err != nil {
		return Readback{}, errors.New("ACTIVE_CONFIG_INVALID")
	}
	expected, err := CompileCandidate(document.Candidate())
	if err != nil || !bytes.Equal(active, expected) {
		return Readback{}, errors.New("ACTIVE_CONFIG_INVALID")
	}
	return r.readbackFor(ctx, r.cfg.Role, document.Candidate(), sha256Hex(active))
}

type systemdProperties struct {
	ActiveState string
	SubState    string
	MainPID     int
}

func (r *Runtime) readbackFor(ctx context.Context, role Role, candidate Candidate, expectedConfigHash string) (Readback, error) {
	return r.readbackForProcess(ctx, role, candidate, expectedConfigHash, "")
}

func (r *Runtime) readbackForProcess(ctx context.Context, role Role, candidate Candidate, expectedConfigHash, expectedPID string) (Readback, error) {
	if err := verifyExecutableHash(rooted(r.root, AgentBinaryPath), r.cfg.AgentSHA256); err != nil {
		return Readback{}, errors.New("AGENT_BINARY_MISMATCH")
	}
	if release, ok := KernelReleaseFor(runtime.GOARCH); !ok || r.root == "/" && r.cfg.KernelSHA256 != release.BinarySHA256 {
		return Readback{}, errors.New("KERNEL_RELEASE_MISMATCH")
	}
	activeCandidateData, _, err := readPrivateFile(rooted(r.root, ActiveCandidatePath))
	if err != nil {
		return Readback{}, errors.New("ACTIVE_CANDIDATE_UNAVAILABLE")
	}
	var activeDocument CandidateDocument
	if err = decodeStrictJSON(activeCandidateData, &activeDocument); err != nil ||
		activeDocument.ValidateFor(r.cfg) != nil || !activeDocument.Candidate().Equal(candidate) {
		return Readback{}, errors.New("ACTIVE_CANDIDATE_MISMATCH")
	}
	props, err := r.systemdProperties(ctx)
	if err != nil || props.ActiveState != "active" || props.SubState != "running" || props.MainPID < 1 {
		return Readback{}, errors.New("SINGBOX_NOT_RUNNING")
	}
	if expectedPID != "" && strconv.Itoa(props.MainPID) != expectedPID {
		return Readback{}, errors.New("SINGBOX_PID_CHANGED")
	}
	if err = r.verifyProcessArgs(props.MainPID); err != nil {
		return Readback{}, err
	}
	if err = r.verifyUnitExecStart(ctx); err != nil {
		return Readback{}, err
	}
	// systemd 257 forks a systemd-executor supervisor that only later execs
	// into the service binary. Catching it mid-setup is not a wrong binary,
	// it is a kernel that has not finished starting. Checked before hashing
	// so a supervisor link that no longer resolves still reports starting,
	// not unreadable.
	if exeIsSupervisor(props.MainPID, r.procRoot) {
		return Readback{}, errors.New("SINGBOX_SUPERVISOR_STARTING")
	}
	kernelHash, err := runningExecutableHash(props.MainPID, r.procRoot)
	if err != nil {
		return Readback{}, err
	}
	if kernelHash != r.cfg.KernelSHA256 {
		// The code is fixed; which executable was running and both digests are
		// log fields, so a mismatch report never carries a path or a digest into
		// the operator-facing error contract.
		r.logRunningBinaryMismatch(ctx, props.MainPID, kernelHash, r.cfg.KernelSHA256)
		return Readback{}, errors.New(codeSingboxRunningBinaryMismatch)
	}
	configPath := rooted(r.root, ActiveConfigPath)
	info, err := os.Lstat(configPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0640 {
		return Readback{}, errors.New("ACTIVE_CONFIG_PERMISSIONS")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != managedFileUID(r.root) {
		return Readback{}, errors.New("ACTIVE_CONFIG_OWNER_INVALID")
	}
	configData, _, err := readRegularFile(configPath, false)
	if err != nil {
		return Readback{}, errors.New("ACTIVE_CONFIG_UNAVAILABLE")
	}
	configHash := sha256Hex(configData)
	if configHash != expectedConfigHash {
		return Readback{}, errors.New("ACTIVE_CONFIG_HASH_MISMATCH")
	}
	if err = r.verifyListeners(ctx, props.MainPID, candidate.VLESSPort); err != nil {
		return Readback{}, err
	}
	outDeny := false
	if role == RoleOut {
		if err = r.verifyOutACL(ctx); err != nil {
			return Readback{}, err
		}
		outDeny = true
	}
	readback := Readback{
		Architecture:   runtime.GOARCH,
		AgentVersion:   r.cfg.AgentVersion,
		AgentSHA256:    r.cfg.AgentSHA256,
		KernelVersion:  KernelVersion,
		KernelSHA256:   kernelHash,
		ActiveRevision: candidate.Revision,
		ConfigSHA256:   configHash,
		LocalActive:    true,
		OutDefaultDeny: outDeny,
	}
	return readback, validateReadbackEvidence(readback, role)
}

// logRunningBinaryMismatch records the diagnostic facts of a wrong running
// kernel binary. The path and both digests are log fields only: the returned
// error carries the stable code alone, so a log-safe code never has to be
// reconstructed from a formatted message.
func (r *Runtime) logRunningBinaryMismatch(ctx context.Context, pid int, running, want string) {
	if r.logger == nil {
		return
	}
	r.logger.ErrorContext(ctx, "sing-box running binary mismatch",
		"operation_id", currentOperation(ctx),
		"error_code", codeSingboxRunningBinaryMismatch,
		"pid", pid,
		"exe", runningExecutableTarget(pid, r.procRoot),
		"running_sha256", hashPrefix(running),
		"want_sha256", hashPrefix(want))
}

func (r *Runtime) verifyUnitExecStart(ctx context.Context) error {
	if !r.enforceProcArgs {
		return nil
	}
	output, err := r.runner.Run(ctx, systemctlPath, "show", SingBoxUnit,
		"--property=ExecStart", "--value", "--no-pager")
	if err != nil {
		return errors.New("SINGBOX_UNIT_UNAVAILABLE")
	}
	want := rootedOptionalBinary(r.root, SingBoxBinaryPath) + " run -c " + rooted(r.root, ActiveConfigPath)
	text := string(output)
	for line := range strings.SplitSeq(text, "\n") {
		_, after, ok := strings.Cut(line, "argv[]=")
		if !ok {
			continue
		}
		value := strings.TrimSpace(after)
		if end := strings.Index(value, " ;"); end >= 0 {
			value = strings.TrimSpace(value[:end])
		} else if end := strings.Index(value, ";"); end >= 0 {
			value = strings.TrimSpace(value[:end])
		}
		if value == want {
			return nil
		}
	}
	return errors.New("SINGBOX_UNIT_EXECSTART_MISMATCH")
}

func (r *Runtime) verifyProcessArgs(pid int) error {
	if !r.enforceProcArgs {
		return nil
	}
	argv, err := processArgv(pid, r.procRoot)
	if err != nil {
		return errors.New("SINGBOX_CMDLINE_UNAVAILABLE")
	}
	if len(argv) != 4 || argv[0] != rootedOptionalBinary(r.root, SingBoxBinaryPath) ||
		argv[1] != "run" || argv[2] != "-c" ||
		argv[3] != rooted(r.root, ActiveConfigPath) {
		return errors.New("SINGBOX_ARGS_MISMATCH")
	}
	return nil
}

func (r *Runtime) systemdProperties(ctx context.Context) (systemdProperties, error) {
	output, err := r.runner.Run(ctx, systemctlPath,
		"show", SingBoxUnit, "--property=ActiveState", "--property=SubState", "--property=MainPID", "--no-pager")
	if err != nil {
		return systemdProperties{}, errors.New("SYSTEMD_QUERY_FAILED")
	}
	var props systemdProperties
	scanner := bufio.NewScanner(bytes.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		switch key {
		case "ActiveState":
			props.ActiveState = value
		case "SubState":
			props.SubState = value
		case "MainPID":
			props.MainPID, _ = strconv.Atoi(value)
		}
	}
	if scanner.Err() != nil {
		return systemdProperties{}, errors.New("SYSTEMD_QUERY_FAILED")
	}
	return props, nil
}

// TransientReadback reports whether a live-readback failure looks like a
// kernel that has not finished starting yet: the process is absent, still
// the systemd-executor supervisor, or listening nowhere yet. Anything else
// (config bytes, ownership, hashes, table content) is deterministic and must
// fail fast instead of being mistaken for slowness.
func TransientReadback(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "SINGBOX_NOT_RUNNING") ||
		strings.Contains(msg, "SINGBOX_SUPERVISOR_STARTING") ||
		strings.Contains(msg, "SINGBOX_PID_CHANGED") ||
		strings.Contains(msg, "LISTENER_")
}

func (r *Runtime) verifyListeners(ctx context.Context, pid, port int) error {
	output, err := r.runner.Run(ctx, ssPath, "-H", "-lntup")
	if err != nil {
		return errors.New("LISTENER_QUERY_FAILED")
	}
	wantPID := "pid=" + strconv.Itoa(pid) + ","
	wantPort := ":" + strconv.Itoa(port)
	for line := range strings.SplitSeq(string(output), "\n") {
		if !strings.Contains(line, wantPID) {
			continue
		}
		fields := strings.FieldsSeq(line)
		for field := range fields {
			if strings.HasSuffix(field, wantPort) {
				return nil
			}
		}
	}
	return errors.New("LISTENER_PID_PORT_MISMATCH")
}

type nftJSON struct {
	NFTables []nftObject `json:"nftables"`
}

type nftObject struct {
	Table *struct {
		Family string `json:"family"`
		Name   string `json:"name"`
	} `json:"table,omitempty"`
	Chain *struct {
		Family string `json:"family"`
		Table  string `json:"table"`
		Name   string `json:"name"`
		Hook   string `json:"hook"`
		Policy string `json:"policy"`
		Prio   int    `json:"prio"`
		Device string `json:"device"`
		Type   string `json:"type"`
	} `json:"chain,omitempty"`
	Rule *struct {
		Family string            `json:"family"`
		Table  string            `json:"table"`
		Chain  string            `json:"chain"`
		Expr   []json.RawMessage `json:"expr"`
	} `json:"rule,omitempty"`
}

func (r *Runtime) verifyOutACL(ctx context.Context) error {
	output, err := r.runner.Run(ctx, nftPath, "-j", "list", "table", "inet", ACLTable)
	if err != nil {
		return errors.New("OUT_ACL_UNAVAILABLE")
	}
	return verifyACLDocument(output)
}

// VerifyOutACLDocument checks one parsed `nft -j list table inet meshmux_out`
// document against the retired guard: the MeshMux-owned table and its input
// chain must exist, and the table must carry no rule at all. It is exported so
// the installer can assert the same evidence without reimplementing the parser.
//
// The allowed and port arguments are retained for source compatibility and are
// ignored: the Out source allowlist is retired, so a table that still names a
// source or the VLESS port is a legacy guard and is rejected.
func VerifyOutACLDocument(output []byte, _ int, _ []string) error {
	return verifyACLDocument(output)
}

// VerifyOutACLShapeDocument checks the same neutral shape. It is kept as the
// no-trusted-record spelling the installer used before the allowlist was
// retired; both spellings now assert exactly the same thing.
func VerifyOutACLShapeDocument(output []byte, _ int) error {
	return verifyACLDocument(output)
}

func verifyACLDocument(output []byte) error {
	var document nftJSON
	if err := json.Unmarshal(output, &document); err != nil {
		return errors.New("OUT_ACL_INVALID")
	}
	tableFound, chainFound := false, false
	for _, item := range document.NFTables {
		if item.Table != nil {
			if item.Table.Family != "inet" || item.Table.Name != ACLTable {
				return errors.New("OUT_ACL_FOREIGN_TABLE")
			}
			tableFound = true
			continue
		}
		if item.Chain != nil {
			if item.Chain.Family != "inet" || item.Chain.Table != ACLTable || item.Chain.Name != "input" ||
				item.Chain.Hook != "input" || item.Chain.Prio != -10 || item.Chain.Type != "filter" ||
				item.Chain.Policy != "accept" {
				return errors.New("OUT_ACL_INPUT_HOOK_INVALID")
			}
			chainFound = true
			continue
		}
		if item.Rule != nil {
			// The allowlist is retired: a surviving accept or dport drop
			// still filters clients the link key admits.
			return errors.New("OUT_ACL_RULE_INVALID")
		}
	}
	if !tableFound || !chainFound {
		return errors.New("OUT_ACL_TABLE_RETIRED_INCOMPLETE")
	}
	return nil
}

func validateReadbackEvidence(readback Readback, role Role) error {
	if err := readback.Validate(); err != nil {
		return err
	}
	if readback.AgentSHA256 == "" || readback.KernelSHA256 == "" || !readback.LocalActive {
		return errors.New("READBACK_INCOMPLETE")
	}
	if role == RoleOut && !readback.OutDefaultDeny {
		return errors.New("OUT_ACL_DEFAULT_DENY_REQUIRED")
	}
	return nil
}
