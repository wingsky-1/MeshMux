package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	nodePlanTimeout  = 20 * time.Second
	nodeApplyTimeout = 15 * time.Minute
	pairingCodeLimit = 43
)

var pairingCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// operationIDPattern mirrors the installer's operation ID rule so a carried
// chain ID is validated before it reaches any ledger or journal path.
var operationIDPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// runInternalAgentVersion is the zero-argument service probe used by the Node
// installer. It deliberately exposes neither a public version command nor any
// caller-controlled paths or arguments.
func runInternalAgentVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-agent-version")
		return 2
	}
	fmt.Fprintln(stdout, node.CurrentAgentVersion())
	return 0
}

// nodeRunner is the CLI-facing seam around the installer. Production calls the
// package functions directly; tests can prove that rejected input never reaches
// a host-mutating call.
type nodeRunner interface {
	PreflightNode(context.Context, node.Config, bool) ([]install.Check, []int)
	BuildNodePlanForRoot(string, string, node.Config, string, []install.Check, []int) install.NodePlan
	InstallNode(context.Context, node.Config, string, bool, string, install.NodeApplyOptions) (install.InstallResult, error)
	RepairNodeFail2banBaseline(context.Context, string, install.Fail2banBaselineRepair) error
	ReadNodeState(string) (install.InstallState, bool, error)
}

type productionNodeRunner struct{}

func (productionNodeRunner) PreflightNode(ctx context.Context, cfg node.Config, allowManaged bool) ([]install.Check, []int) {
	return install.PreflightNode(ctx, cfg, allowManaged)
}

func (productionNodeRunner) BuildNodePlanForRoot(root, id string, cfg node.Config, architecture string, checks []install.Check, ssh []int) install.NodePlan {
	return install.BuildNodePlanForRoot(root, id, cfg, architecture, checks, ssh)
}

func (productionNodeRunner) InstallNode(ctx context.Context, cfg node.Config, operationID string, repair bool, pairingCode string, opts install.NodeApplyOptions) (install.InstallResult, error) {
	return install.InstallNode(ctx, cfg, operationID, repair, pairingCode, opts)
}

// RepairNodeFail2banBaseline applies only the repair the operator confirmed.
// The CLI installs the root layout, so the ledger and journal are resolved by
// the installer itself.
func (productionNodeRunner) RepairNodeFail2banBaseline(ctx context.Context, operationID string, repair install.Fail2banBaselineRepair) error {
	return install.RepairNodeFail2banBaseline(ctx, "/", operationID, repair, nil)
}

// ReadNodeState reads the Node ledger this host actually owns. On a
// co-located Hub host that is the local-Line ledger, never the Hub ledger.
func (productionNodeRunner) ReadNodeState(root string) (install.InstallState, bool, error) {
	return install.ReadNodeState(root)
}

type agentService interface {
	RunCommand([]string, io.Writer) int
}

type productionAgentService struct{}

func (productionAgentService) RunCommand(args []string, stderr io.Writer) int {
	return node.RunCommand(args, stderr)
}

func runNodeInstall(role node.Role, args []string, stdin io.Reader, stdout, stderr io.Writer, runner nodeRunner) int {
	flags := flag.NewFlagSet("install "+string(role), flag.ContinueOnError)
	// flag's diagnostics can contain an unrecognized flag and its following
	// value. Treat all parser failures as one generic, secret-free error.
	flags.SetOutput(io.Discard)
	var cfg node.Config
	cfg.Role = role
	planOnly := flags.Bool("plan", false, "show a read-only installation plan")
	yes := flags.Bool("yes", false, "confirm installation after displaying the plan")
	repair := flags.Bool("repair", false, "repair an existing node without deleting identity or data")
	// nonInteractive is set only by the Web-driven handoff, which has no
	// operator at the terminal.
	nonInteractive := flags.Bool("non-interactive", false, "refuse any prompt; used by the Web-driven handoff")
	// operationID carries the upgrade chain's operation ID into the new
	// package's own ledger, so the handoff and the install share one audit ID.
	// It is validated with the installer's own 32-hex rule; an empty value
	// generates a fresh local ID as before.
	operationIDFlag := flags.String("operation-id", "", "operation ID of the upgrade chain")
	// fromRecordedState is the hidden handoff family's only input mode: every
	// configuration value and the identity come from the recorded ledger, so
	// the transient unit never has to carry them. It is deliberately absent
	// from the public usage text.
	fromRecordedState := flags.Bool("from-recorded-state", false, "reuse the recorded Node installation")
	// pairingCodeFile is the operator-placed fresh code of the same hidden
	// family. There is no automatic delivery: a missing file means the identity
	// is lost, and the run ends terminally.
	pairingCodeFile := flags.String("pairing-code-file", "", "root-owned 0600 file holding one pairing code")
	flags.StringVar(&cfg.HubURL, "hub", "", "Hub HTTPS origin")
	flags.StringVar(&cfg.NodeID, "node", "", "32-character lowercase node ID")
	flags.IntVar(&cfg.VLESSPort, "vless-port", 0, "VLESS listening port")
	flags.IntVar(&cfg.SSHPort, "ssh-port", 0, "SSH listening port")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "CONFIG_INVALID: unknown or unexpected install options")
		return 2
	}
	// The hidden inputs exist only for the recorded-state handoff. Refusing
	// them on the public surface keeps `install` a single mode and keeps a
	// hand-placed secret from being read by an interactive run.
	if *pairingCodeFile != "" && !*fromRecordedState {
		fmt.Fprintln(stderr, "CONFIG_INVALID: --pairing-code-file is reserved for the recorded-state handoff")
		return 2
	}
	if *planOnly && (*yes || *repair) {
		fmt.Fprintln(stderr, "CONFIG_INVALID: --plan cannot be combined with --yes or --repair")
		return 2
	}
	if *fromRecordedState {
		// The recorded-state family is one fixed shape: a plan-only run would
		// exit 0 without installing, which the unit would record as success,
		// and anything less than a non-interactive repair could still wait for
		// an operator.
		if *planOnly {
			fmt.Fprintln(stderr, "CONFIG_INVALID: --from-recorded-state cannot be combined with --plan")
			return handoffExitForCode("CONFIG_INVALID")
		}
		if !*nonInteractive || !*repair {
			fmt.Fprintln(stderr, "UPDATE_INTERACTIVE_REFUSED: --from-recorded-state requires --repair --non-interactive")
			return handoffExitForCode("UPDATE_INTERACTIVE_REFUSED")
		}
	} else if *nonInteractive && (!*yes || !*repair) {
		// The public gate is unchanged: a non-interactive run is still a
		// confirmed repair, and it still says so in the same words.
		fmt.Fprintln(stderr, "UPDATE_INTERACTIVE_REFUSED: --non-interactive requires --yes --repair")
		return 3
	}
	if *fromRecordedState && *operationIDFlag == "" {
		// The whole point of the handoff is one auditable operation ID from
		// approval to readback, so it is mandatory here and refused before any
		// state or journal path is derived from it.
		fmt.Fprintln(stderr, "OPERATION_REQUIRED: --from-recorded-state requires --operation-id")
		return handoffExitForCode("OPERATION_REQUIRED")
	}
	if !*fromRecordedState {
		if err := cfg.Validate(); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
	}
	operationID := *operationIDFlag
	if operationID != "" && !operationIDPattern.MatchString(operationID) {
		fmt.Fprintln(stderr, "OPERATION_ID_INVALID: need 32 lowercase hex characters")
		if *fromRecordedState {
			// The ID is unusable, so the structured result carries no operation
			// identity: never echo the rejected value back.
			handoffRefusal(stdout, "", "preflight", "OPERATION_ID_INVALID",
				"Carry the upgrade chain's 32 lowercase hex operation ID.")
			return handoffExitForCode("OPERATION_ID_INVALID")
		}
		return 2
	}

	// refusal is the one pre-plan stop that still carries the structured
	// result on the recorded-state path: the unit records only an exit code, so
	// without the JSON the stable code would be lost from the audit trail.
	refusal := func(stage, code, recovery string, fallback int) int {
		if *fromRecordedState {
			handoffRefusal(stdout, operationID, stage, code, recovery)
			return handoffExitForCode(code)
		}
		return fallback
	}
	state, exists, err := runner.ReadNodeState("/")
	if err != nil {
		code := "INSTALL_STATE_INVALID"
		var ie *install.InstallError
		if errors.As(err, &ie) && ie.Code != "" {
			code = ie.Code
		}
		fmt.Fprintf(stderr, "%s: inspect the recorded installer state; do not delete application data\n", code)
		return refusal("preflight", code, "Inspect the recorded installer state; do not delete application data.", 1)
	}
	if *fromRecordedState {
		// The ledger is the only source of configuration and identity in this
		// mode; the positional role is cross-checked against it instead of
		// being trusted. Nothing is read from stdin.
		if !exists || state.Node == nil {
			fmt.Fprintln(stderr, "REPAIR_STATE_MISSING: a recorded-state handoff needs a recorded Node installation")
			return refusal("preflight", "REPAIR_STATE_MISSING", "A recorded-state handoff needs a Node ledger created by MeshMux; enroll the node first.", 3)
		}
		if state.Node.Role != role {
			fmt.Fprintln(stderr, "CONFIG_CONFLICT: this host recorded a different node role; a recorded-state repair never changes it")
			return refusal("preflight", "CONFIG_CONFLICT", "The recorded node role differs from this handoff; a recorded-state repair never changes the role.", 3)
		}
		cfg = *state.Node
		if err := cfg.Validate(); err != nil {
			fmt.Fprintln(stderr, "CONFIG_INVALID: the recorded node configuration is not usable")
			return refusal("preflight", "CONFIG_INVALID", "The recorded node configuration is not usable; enroll the node again.", 2)
		}
	}
	if *repair && (!exists || state.Node == nil) {
		fmt.Fprintln(stderr, "REPAIR_STATE_MISSING: --repair is allowed only for a recorded node installation")
		return 3
	}
	if state.Node != nil && !install.SameNodeConfig(*state.Node, cfg) {
		fmt.Fprintln(stderr, "CONFIG_CONFLICT: this host has a different recorded node configuration; changing it is not an in-place repair")
		return refusal("preflight", "CONFIG_CONFLICT", "Repair only supports the recorded Hub URL, node, role and ports; create a new node enrollment for migration.", 3)
	}

	if operationID == "" {
		operationID, err = install.NewOperationID()
		if err != nil {
			fmt.Fprintln(stderr, "OPERATION_ID_FAILED")
			return 1
		}
	}

	pairingCode := ""
	if *fromRecordedState {
		// The only accepted fresh code is the one an operator placed on the
		// host. A missing, public or malformed file is refused before any host
		// work: there is no automatic fetch and no prompt to fall back on.
		if *pairingCodeFile != "" {
			var ok bool
			pairingCode, ok = readPairingCodeFile(*pairingCodeFile, stderr)
			if !ok {
				return refusal("preflight", "PAIRING_CODE_INVALID", "Place one root-owned 0600 file holding a current 43-character code, or re-enroll the node.", 2)
			}
		}
	}
	reader := bufio.NewReader(stdin)
	preflight := func() ([]install.Check, []int) {
		ctx, cancel := context.WithTimeout(context.Background(), nodePlanTimeout)
		defer cancel()
		return runner.PreflightNode(ctx, cfg, state.Node != nil)
	}
	checks, sshPorts := preflight()
	// A broken Fail2ban baseline is the one preflight failure the installer
	// can repair, but only after an explicit operator confirmation: the repair
	// either installs rsyslog or writes a MeshMux-owned backend override for
	// the packaged sshd jail. --yes and the Web handoff never prompt; they stop
	// with the check's next_action instead.
	if recovery, blocked := fail2banBaselineOnlyFailure(checks); blocked &&
		!*planOnly && !*yes && !*nonInteractive && !*fromRecordedState {
		if offerFail2banBaselineRepair(reader, stdout, stderr, runner, operationID) {
			checks, sshPorts = preflight()
		} else {
			fmt.Fprintf(stderr, "%s: no host changes were made. %s\n", install.CodeFail2banBaselineInvalid, recovery)
			return 3
		}
	}
	plan := runner.BuildNodePlanForRoot("/", operationID, cfg, runtime.GOARCH, checks, sshPorts)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(plan); err != nil {
		fmt.Fprintln(stderr, "PLAN_OUTPUT_FAILED")
		return 1
	}
	if plan.Status == "preflight_blocked" || !plan.ApplyAvailable {
		if *fromRecordedState {
			// The plan already carries the per-check codes; the unit still needs
			// one stable result code, and the first failing check is the cause.
			code, recovery := "preflight_blocked", "Resolve the failed Node preflight check and retry."
			for _, check := range plan.Checks {
				if check.Status == "fail" {
					code, recovery = check.Code, check.Recovery
					break
				}
			}
			return refusal("preflight", code, recovery, 3)
		}
		for _, check := range plan.Checks {
			if check.Status == "fail" && check.Code == install.CodeFail2banBaselineInvalid {
				// --yes must still carry the exact repair instruction, because
				// it deliberately refuses the interactive repair prompt.
				fmt.Fprintf(stderr, "%s: %s\n", check.Code, check.Recovery)
				break
			}
		}
		return 3
	}
	if *planOnly {
		return 0
	}

	confirmed := *yes || *fromRecordedState
	if !confirmed {
		fmt.Fprintf(stdout, "Type 'install %s' to apply this plan, or anything else to stop:\n", role)
		answer, readErr := reader.ReadString('\n')
		if (readErr != nil && answer == "") || strings.TrimSpace(answer) != "install "+string(role) {
			fmt.Fprintln(stderr, "INSTALL_CANCELLED: no host changes were made")
			return 3
		}
	}

	if !*repair && !*nonInteractive {
		var ok bool
		pairingCode, ok = readPairingCode(reader, stdout, stderr)
		if !ok {
			return 2
		}
	}
	opts := install.NodeApplyOptions{NonInteractive: *nonInteractive, FromRecordedState: *fromRecordedState}
	result, applyErr := applyNode(runner, cfg, operationID, *repair, pairingCode, opts, reader, stdout, stderr, !*yes)
	if applyErr != nil {
		if ie, ok := errors.AsType[*install.InstallError](applyErr); ok {
			result.ErrorCode, result.Stage, result.Recovery = ie.Code, ie.Stage, ie.Recovery
		} else {
			result.ErrorCode, result.Stage = "INSTALL_FAILED", "apply"
		}
	}
	if result.OperationID == "" {
		result.OperationID = operationID
	}
	if result.Status == "" {
		result.Status = "failed"
	}
	enc = json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(result); err != nil {
		fmt.Fprintln(stderr, "RESULT_OUTPUT_FAILED")
		return 1
	}
	if *fromRecordedState {
		// The JSON error_code above is the contract; the exit code is only the
		// coarse bucket the transient unit records.
		if applyErr != nil || result.Status != "installed" {
			fmt.Fprintf(stderr, "%s: %s\n", result.ErrorCode, result.Recovery)
		}
		return handoffResultExit(result)
	}
	if applyErr != nil {
		fmt.Fprintf(stderr, "%s: %s\n", result.ErrorCode, result.Recovery)
		return 1
	}
	if result.Status == "partial" || result.Status == "failed" {
		return 1
	}
	return 0
}

// handoffResultExit collapses one recorded-state result into the coarse exit
// map of spec §4.10 (I14/I15): 0 installed only, 3 interaction/state class, 4
// UPDATE_REENROLL_REQUIRED, 5 precondition failure, 6 retry exhausted. The JSON
// error_code stays the contract; this bucket only tells the unit's result file
// what broad class of failure happened.
func handoffResultExit(result install.InstallResult) int {
	if result.Status == "installed" && result.ErrorCode == "" {
		return 0
	}
	return handoffExitForCode(result.ErrorCode)
}

// handoffExitForCode maps one stable code onto the coarse bucket. An empty or
// unknown code is a precondition failure (5): it is never 0.
func handoffExitForCode(code string) int {
	switch code {
	case "UPDATE_REENROLL_REQUIRED":
		return 4
	case "UPDATE_RETRY_EXHAUSTED":
		return 6
	case "UPDATE_INTERACTIVE_REFUSED", "INSTALL_CANCELLED", "UPDATE_CONFIRM_REQUIRED",
		"REPAIR_STATE_MISSING", "INSTALL_PARTIAL_REPAIR_REQUIRED", "HOST_LAYOUT_CONFLICT",
		"REINSTALL_REJECTED", "preflight_blocked":
		return 3
	default:
		return 5
	}
}

// handoffRefusal writes the one structured refusal of a recorded-state run that
// stops before the plan is printed. It never echoes a caller value: the fields
// are the stable code, the fixed next action and the already-validated
// operation ID.
func handoffRefusal(stdout io.Writer, operationID, stage, code, recovery string) {
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(install.InstallResult{
		OperationID: operationID, Stage: stage, Status: "failed",
		ErrorCode: code, Recovery: recovery,
	})
}

// readPairingCodeFile reads the one operator-placed fresh code of the hidden
// handoff family. The file must be a root-owned regular 0600 file: MeshMux never
// fetches a code, never invents one and never reads it from stdin here.
func readPairingCodeFile(path string, stderr io.Writer) (string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 {
		fmt.Fprintln(stderr, "PAIRING_CODE_INVALID: --pairing-code-file must be a root-owned regular 0600 file")
		return "", false
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || int(stat.Uid) != os.Geteuid() {
		fmt.Fprintln(stderr, "PAIRING_CODE_INVALID: --pairing-code-file must be owned by the invoking user")
		return "", false
	}
	data, err := os.ReadFile(path)
	if err != nil || len(data) > pairingCodeLimit+2 {
		fmt.Fprintln(stderr, "PAIRING_CODE_INVALID: --pairing-code-file is unreadable")
		return "", false
	}
	code := strings.TrimSuffix(strings.TrimSuffix(string(data), "\n"), "\r")
	if !pairingCodePattern.MatchString(code) {
		fmt.Fprintln(stderr, "PAIRING_CODE_INVALID: the file must hold one 43-character code")
		return "", false
	}
	return code, true
}

func applyNode(runner nodeRunner, cfg node.Config, operationID string, repair bool, pairingCode string, opts install.NodeApplyOptions, reader *bufio.Reader, stdout, stderr io.Writer, allowRepair bool) (install.InstallResult, error) {
	attempt := func() (install.InstallResult, error) {
		ctx, cancel := context.WithTimeout(context.Background(), nodeApplyTimeout)
		defer cancel()
		return runner.InstallNode(ctx, cfg, operationID, repair, pairingCode, opts)
	}
	result, err := attempt()
	if err != nil && allowRepair && isFail2banBaselineError(err) {
		// The stage gate repeats the self-test once the fixed Debian packages
		// (including python3-systemd) are installed. Nothing has consumed the
		// pairing code at that point, so a confirmed repair retries the same
		// operation with the same code instead of asking for a fresh one.
		if offerFail2banBaselineRepair(reader, stdout, stderr, runner, operationID) {
			result, err = attempt()
		}
	}
	if !repair || !pairingRequired(err) || opts.NonInteractive {
		return result, err
	}
	// The first attempt deliberately reuses the persisted identity. The
	// installer asks for a fresh code only when that identity cannot be reused.
	fmt.Fprintln(stdout, "This repair needs a fresh pairing code. Reissue it in Hub Web and paste it below.")
	code, ok := readPairingCode(reader, stdout, stderr)
	if !ok {
		return result, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeApplyTimeout)
	defer cancel()
	return runner.InstallNode(ctx, cfg, operationID, true, code, opts)
}

// fail2banBaselineOnlyFailure reports the next_action of the one preflight
// failure the installer can repair. Any other blocking check means editing
// Fail2ban would not unblock this host, so no repair is offered.
func fail2banBaselineOnlyFailure(checks []install.Check) (string, bool) {
	recovery := ""
	for _, check := range checks {
		if check.Status != "fail" {
			continue
		}
		if check.Code != install.CodeFail2banBaselineInvalid || recovery != "" {
			return "", false
		}
		recovery = check.Recovery
	}
	return recovery, recovery != ""
}

func isFail2banBaselineError(err error) bool {
	var ie *install.InstallError
	return errors.As(err, &ie) && ie.Code == install.CodeFail2banBaselineInvalid
}

// offerFail2banBaselineRepair asks for one explicit choice and applies only
// that repair. Empty input, any other answer and a failed repair all leave the
// host unchanged and report why the install stopped.
func offerFail2banBaselineRepair(reader *bufio.Reader, stdout, stderr io.Writer, runner nodeRunner, operationID string) bool {
	fmt.Fprintln(stdout, "Fail2ban baseline self-test failed (fail2ban-client -t). No pairing code has been used.")
	fmt.Fprintln(stdout, "Choose a repair; nothing is changed without your answer:")
	fmt.Fprintln(stdout, "  1) install rsyslog so /var/log/auth.log exists")
	fmt.Fprintln(stdout, "  2) override only backend=systemd for the packaged sshd jail")
	fmt.Fprint(stdout, "Repair [1/2, empty=stop]: ")
	answer, err := readLineLimited(reader, 8)
	if err != nil {
		return false
	}
	var repair install.Fail2banBaselineRepair
	switch strings.TrimSpace(answer) {
	case "1":
		repair = install.Fail2banRepairRsyslog
	case "2":
		repair = install.Fail2banRepairSystemdBackend
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodeApplyTimeout)
	defer cancel()
	if err := runner.RepairNodeFail2banBaseline(ctx, operationID, repair); err != nil {
		var ie *install.InstallError
		if errors.As(err, &ie) {
			fmt.Fprintf(stderr, "%s: %s\n", ie.Code, ie.Recovery)
		} else {
			fmt.Fprintf(stderr, "%s: the repair did not complete; no jail was changed without proof.\n", install.CodeFail2banRepairFailed)
		}
		return false
	}
	fmt.Fprintln(stdout, "Fail2ban baseline repaired; re-running the baseline check.")
	return true
}

func pairingRequired(err error) bool {
	if err == nil {
		return false
	}
	if ie, ok := errors.AsType[*install.InstallError](err); ok {
		switch ie.Code {
		case "PAIRING_CODE_REQUIRED", "PAIRING_REQUIRED":
			return true
		}
	}
	return false
}

func readPairingCode(reader *bufio.Reader, stdout, stderr io.Writer) (string, bool) {
	fmt.Fprintln(stdout, "Pairing code (43 characters from Hub Web):")
	code, err := readLineLimited(reader, pairingCodeLimit)
	if err != nil || !pairingCodePattern.MatchString(code) {
		fmt.Fprintln(stderr, "PAIRING_CODE_INVALID: enter one 43-character code from Hub Web")
		return "", false
	}
	return code, true
}

func readLineLimited(reader *bufio.Reader, limit int) (string, error) {
	var value strings.Builder
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) && value.Len() > 0 {
				return value.String(), nil
			}
			return "", err
		}
		if b == '\n' {
			return value.String(), nil
		}
		if b == '\r' {
			continue
		}
		if value.Len() >= limit {
			if drainErr := drainLine(reader); drainErr != nil {
				return "", drainErr
			}
			return "", errors.New("line too long")
		}
		value.WriteByte(b)
	}
}

func drainLine(reader *bufio.Reader) error {
	for {
		b, err := reader.ReadByte()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if b == '\n' {
			return nil
		}
	}
}
