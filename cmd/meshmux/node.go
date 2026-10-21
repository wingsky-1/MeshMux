package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
)

const (
	nodePlanTimeout  = 20 * time.Second
	nodeApplyTimeout = 15 * time.Minute
	pairingCodeLimit = 43
)

var pairingCodePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// runInternalAgentVersion is the zero-argument service probe used by the Node
// installer. It deliberately exposes neither a public version command nor any
// caller-controlled paths or arguments.
func runInternalAgentVersion(args []string, stdout, stderr io.Writer) int {
	if len(args) != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-agent-version")
		return 2
	}
	fmt.Fprintln(stdout, node.CurrentAgentVersion)
	return 0
}

// nodeRunner is the CLI-facing seam around the installer. Production calls the
// package functions directly; tests can prove that rejected input never reaches
// a host-mutating call.
type nodeRunner interface {
	PreflightNode(context.Context, node.Config, bool) ([]install.Check, []int)
	BuildNodePlanForRoot(string, string, node.Config, string, []install.Check, []int) install.NodePlan
	InstallNode(context.Context, node.Config, string, bool, string, install.NodeApplyOptions) (install.InstallResult, error)
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
	flags.StringVar(&cfg.HubURL, "hub", "", "Hub HTTPS origin")
	flags.StringVar(&cfg.NodeID, "node", "", "32-character lowercase node ID")
	flags.IntVar(&cfg.VLESSPort, "vless-port", 0, "VLESS listening port")
	flags.IntVar(&cfg.SSHPort, "ssh-port", 0, "SSH listening port")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "CONFIG_INVALID: unknown or unexpected install options")
		return 2
	}
	if *planOnly && (*yes || *repair) {
		fmt.Fprintln(stderr, "CONFIG_INVALID: --plan cannot be combined with --yes or --repair")
		return 2
	}
	if err := cfg.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	state, exists, err := runner.ReadNodeState("/")
	if err != nil {
		code := "INSTALL_STATE_INVALID"
		var ie *install.InstallError
		if errors.As(err, &ie) && ie.Code != "" {
			code = ie.Code
		}
		fmt.Fprintf(stderr, "%s: inspect the recorded installer state; do not delete application data\n", code)
		return 1
	}
	if *repair && (!exists || state.Node == nil) {
		fmt.Fprintln(stderr, "REPAIR_STATE_MISSING: --repair is allowed only for a recorded node installation")
		return 3
	}
	if state.Node != nil && !install.SameNodeConfig(*state.Node, cfg) {
		fmt.Fprintln(stderr, "CONFIG_CONFLICT: this host has a different recorded node configuration; changing it is not an in-place repair")
		return 3
	}

	operationID, err := install.NewOperationID()
	if err != nil {
		fmt.Fprintln(stderr, "OPERATION_ID_FAILED")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), nodePlanTimeout)
	checks, sshPorts := runner.PreflightNode(ctx, cfg, state.Node != nil)
	cancel()
	plan := runner.BuildNodePlanForRoot("/", operationID, cfg, runtime.GOARCH, checks, sshPorts)
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(plan); err != nil {
		fmt.Fprintln(stderr, "PLAN_OUTPUT_FAILED")
		return 1
	}
	if plan.Status == "preflight_blocked" || !plan.ApplyAvailable {
		return 3
	}
	if *planOnly {
		return 0
	}

	reader := bufio.NewReader(stdin)
	if !*yes {
		fmt.Fprintf(stdout, "Type 'install %s' to apply this plan, or anything else to stop:\n", role)
		answer, readErr := reader.ReadString('\n')
		if (readErr != nil && answer == "") || strings.TrimSpace(answer) != "install "+string(role) {
			fmt.Fprintln(stderr, "INSTALL_CANCELLED: no host changes were made")
			return 3
		}
	}

	pairingCode := ""
	if !*repair {
		var ok bool
		pairingCode, ok = readPairingCode(reader, stdout, stderr)
		if !ok {
			return 2
		}
	}
	result, applyErr := applyNode(runner, cfg, operationID, *repair, pairingCode, reader, stdout, stderr)
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
	if applyErr != nil {
		fmt.Fprintf(stderr, "%s: %s\n", result.ErrorCode, result.Recovery)
		return 1
	}
	if result.Status == "partial" || result.Status == "failed" {
		return 1
	}
	return 0
}

func applyNode(runner nodeRunner, cfg node.Config, operationID string, repair bool, pairingCode string, reader *bufio.Reader, stdout, stderr io.Writer) (install.InstallResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), nodeApplyTimeout)
	result, err := runner.InstallNode(ctx, cfg, operationID, repair, pairingCode, install.NodeApplyOptions{})
	if !repair || !pairingRequired(err) {
		cancel()
		return result, err
	}
	// The first attempt deliberately reuses the persisted identity. The
	// installer asks for a fresh code only when that identity cannot be reused.
	cancel()
	fmt.Fprintln(stdout, "This repair needs a fresh pairing code. Reissue it in Hub Web and paste it below.")
	code, ok := readPairingCode(reader, stdout, stderr)
	if !ok {
		return result, err
	}
	ctx, cancel = context.WithTimeout(context.Background(), nodeApplyTimeout)
	defer cancel()
	return runner.InstallNode(ctx, cfg, operationID, true, code, install.NodeApplyOptions{})
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
