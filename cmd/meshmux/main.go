// meshmux exposes the operator's install-only CLI. The private Web subcommand
// is reserved for the dedicated systemd service and is not a management CLI.
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
	"runtime"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/update"
	"github.com/wingsky-1/MeshMux/internal/webcmd"
)

// installRoleHub is not a node role: a hub host is described by install.Config
// (management, subscription and Headscale domains), so the install CLI resolves
// it on the install side before node.ParseRole is consulted.
const installRoleHub = "hub"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__internal-web" {
		os.Exit(webcmd.Run(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-agent" {
		// The convergence writer is process-local: it only enqueues one
		// transient unit, so it never waits for a lock-taking repair while the
		// Agent holds the runtime flock (Task 4 carry).
		os.Exit(node.RunCommand(os.Args[2:], os.Stderr,
			node.WithHandoffConvergence(update.NewConvergenceWriter()),
			node.WithUpgradeConfirmation(update.NewRollbackStore()),
			node.WithUpgradeRevert(update.NewReverter())))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-update" {
		os.Exit(runInternalUpdate(os.Args[2:], os.Stdin, os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-update-install" {
		os.Exit(runInternalUpdateInstall(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-update-converge" {
		os.Exit(runInternalUpdateConverge(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-update-revert" {
		os.Exit(runInternalUpdateRevert(os.Args[2:], os.Stdout, os.Stderr))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-agent-version" {
		os.Exit(runInternalAgentVersion(os.Args[2:], os.Stdout, os.Stderr))
	}
	os.Exit(runWithIO(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

// run is retained for simple CLI unit tests; prompts receive EOF unless tests
// explicitly exercise runWithIO.
func run(args []string, stderr io.Writer) int {
	return runWithIO(args, strings.NewReader(""), io.Discard, stderr)
}

func runWithIO(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runWithDependencies(args, stdin, stdout, stderr, productionNodeRunner{}, productionAgentService{})
}

func runWithDependencies(args []string, stdin io.Reader, stdout, stderr io.Writer, nodes nodeRunner, agent agentService) int {
	if len(args) > 0 && args[0] == "__internal-web" {
		return webcmd.Run(args[1:])
	}
	if len(args) > 0 && args[0] == "__internal-agent" {
		return agent.RunCommand(args[1:], stderr)
	}
	if len(args) > 0 && args[0] == "__internal-update" {
		return runInternalUpdate(args[1:], stdin, stdout, stderr)
	}
	if len(args) > 0 && args[0] == "__internal-update-install" {
		return runInternalUpdateInstall(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "__internal-update-converge" {
		return runInternalUpdateConverge(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "__internal-update-revert" {
		return runInternalUpdateRevert(args[1:], stdout, stderr)
	}
	if len(args) > 0 && args[0] == "__internal-agent-version" {
		return runInternalAgentVersion(args[1:], stdout, stderr)
	}
	if len(args) < 2 || args[0] != "install" {
		fmt.Fprintln(stderr, "usage: meshmux install {hub|edge|out}")
		fmt.Fprintln(stderr, "  hub: [--management-domain NAME --subscription-domain NAME --headscale-domain NAME] [--plan|--yes] [--repair]")
		fmt.Fprintln(stderr, "  edge|out: --hub HTTPS_ORIGIN --node 32_HEX --vless-port PORT --ssh-port PORT [--plan|--yes] [--repair]")
		return 2
	}
	if args[1] == installRoleHub {
		return runHubInstall(args[2:], stdin, stdout, stderr)
	}
	role, err := node.ParseRole(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "ROLE_INVALID")
		return 2
	}
	return runNodeInstall(role, args[2:], stdin, stdout, stderr, nodes)
}

// runInternalUpdate is the private Agent-driven entry. It accepts exactly one
// fixed argv and never prompts: a terminal without --confirm-target is refused,
// because only the Agent may approve an upgrade on this host.
func runInternalUpdate(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("__internal-update", flag.ContinueOnError)
	// Never echo caller-supplied arguments: unknown flags print only the fixed
	// usage line, as the other hidden commands do.
	flags.SetOutput(io.Discard)
	var cfg update.Config
	confirm := flags.Bool("confirm-target", false, "confirm the Web-approved target")
	flags.StringVar(&cfg.Target, "target", "", "approved target version")
	flags.StringVar(&cfg.ManifestSHA256, "manifest-sha256", "", "approved manifest SHA-256")
	flags.StringVar(&cfg.OperationID, "operation-id", "", "operation ID")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-update --target SEMVER --manifest-sha256 HEX --operation-id HEX32 --confirm-target")
		return 2
	}
	if !*confirm {
		code := "UPDATE_CONFIRM_REQUIRED"
		if isTerminal(stdin) {
			code = "UPDATE_INTERACTIVE_REFUSED"
		}
		fmt.Fprintln(stderr, code+": this command is driven by the Agent; pass --confirm-target")
		return 3
	}
	cfg.WorkDir, cfg.FetchManifest = update.DefaultWorkDir, update.HubManifest
	cfg.CurrentVersion = node.CurrentAgentVersion()
	cfg.BackupSource = func() (string, error) {
		// The record must name what this host is running RIGHT NOW, including
		// the Agent's live LKG bytes, so capture/refresh the durable snapshot
		// at upgrade time. A snapshot that already describes the running release
		// is left untouched.
		if err := install.RefreshUpgradeSource("/"); err != nil {
			return "", err
		}
		return install.ReadUpgradeSource("/")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := update.Run(ctx, cfg, node.ExecRunner{})
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if enc.Encode(result) != nil {
		fmt.Fprintln(stderr, "UPDATE_RESULT_OUTPUT_FAILED")
		return 1
	}
	return 0
}

// runInternalUpdateInstall is the transient unit's entry: the new package
// installs itself, restarts the Agent and records its result. It mirrors
// __internal-update: one fixed argv, no prompts and no public surface. The
// transient unit always passes every flag; a missing --from-recorded-state is a
// refusal, not an interactive fallback.
func runInternalUpdateInstall(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("__internal-update-install", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var cfg update.Config
	flags.StringVar(&cfg.Target, "target", "", "approved target version")
	flags.StringVar(&cfg.ManifestSHA256, "manifest-sha256", "", "approved manifest SHA-256")
	flags.StringVar(&cfg.PackageSHA256, "expected-sha256", "", "verified package SHA-256")
	flags.StringVar(&cfg.OperationID, "operation-id", "", "operation ID")
	fromRecordedState := flags.Bool("from-recorded-state", false, "reuse the recorded Node installation")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-update-install --target SEMVER --manifest-sha256 HEX --expected-sha256 HEX --operation-id HEX32 --from-recorded-state")
		return 2
	}
	if !*fromRecordedState {
		fmt.Fprintln(stderr, "UPDATE_INTERACTIVE_REFUSED: __internal-update-install requires --from-recorded-state")
		return 3
	}
	cfg.WorkDir = update.DefaultWorkDir
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	result, err := update.RunInstall(ctx, cfg, node.ExecRunner{})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if err != nil {
		fmt.Fprintln(stderr, err)
		if result.ExitCode > 0 {
			return result.ExitCode
		}
		return 1
	}
	return 0
}

// runInternalUpdateConverge is the transient convergence unit's entry: it
// rewrites agent.json for the crash-window claim the Agent adopted in memory.
// It is the only hidden command that writes /etc, and it is reachable only from
// the fixed systemd-run argv in internal/update/converge.go. One fixed argv, no
// prompts, no public surface.
func runInternalUpdateConverge(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("__internal-update-converge", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	operationID := flags.String("operation-id", "", "operation ID owning the claim")
	expectedSHA256 := flags.String("expected-sha256", "", "claimed Agent binary SHA-256")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-update-converge --operation-id HEX32 --expected-sha256 HEX")
		return 2
	}
	if err := install.ConvergeHandoffConfig("/", *operationID, *expectedSHA256); err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// runInternalUpdateRevert is the transient revert unit's entry: the staged OLD
// package restores the recorded change set and writes <operation_id>.revert.json.
// One fixed argv, no prompts, no public surface.
func runInternalUpdateRevert(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("__internal-update-revert", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var cfg update.Config
	flags.StringVar(&cfg.OperationID, "operation-id", "", "operation ID")
	flags.StringVar(&cfg.FromAgentSHA256, "expected-sha256", "", "verified old Agent SHA-256")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "USAGE: meshmux __internal-update-revert --operation-id HEX32 --expected-sha256 HEX")
		return 2
	}
	cfg.WorkDir = update.DefaultWorkDir
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, err := update.RunRevert(ctx, cfg, node.ExecRunner{})
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	return 0
}

// isTerminal reports whether stdin is a terminal. ModeCharDevice alone is not
// enough: /dev/null is also a character device, so the ioctl is the test.
func isTerminal(stdin io.Reader) bool {
	file, ok := stdin.(*os.File)
	if !ok {
		return false
	}
	_, err := unix.IoctlGetTermios(int(file.Fd()), unix.TCGETS)
	return err == nil
}

func runHubInstall(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("install hub", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c install.Config
	planOnly := flags.Bool("plan", false, "show a read-only installation plan")
	yes := flags.Bool("yes", false, "confirm installation after displaying the plan")
	repair := flags.Bool("repair", false, "repair an existing MeshMux installation without deleting state")
	// nonInteractive is set only by the Web-driven handoff, which has no
	// operator at the terminal. It is refused unless the run can complete
	// without reading stdin, so it never becomes a second install mode.
	nonInteractive := flags.Bool("non-interactive", false, "refuse any prompt; used by the Web-driven handoff")
	flags.StringVar(&c.ManagementDomain, "management-domain", "", "HTTPS management hostname")
	flags.StringVar(&c.SubscriptionDomain, "subscription-domain", "", "subscription hostname")
	flags.StringVar(&c.HeadscaleDomain, "headscale-domain", "", "Headscale/DERP hostname")
	flags.BoolVar(&c.DirectCaddy, "direct-caddy", false, "enable Web Fail2ban only when Caddy is reached directly, not through a CDN/proxy")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "CONFIG_INVALID: unknown or unexpected install options")
		return 2
	}
	if *planOnly && (*yes || *repair) {
		fmt.Fprintln(stderr, "CONFIG_INVALID: --plan cannot be combined with --yes or --repair")
		return 2
	}
	if *nonInteractive && (!*yes || !*repair) {
		fmt.Fprintln(stderr, "UPDATE_INTERACTIVE_REFUSED: --non-interactive requires --yes --repair")
		return 3
	}
	if *yes && (c.ManagementDomain == "" || c.SubscriptionDomain == "" || c.HeadscaleDomain == "") {
		fmt.Fprintln(stderr, "CONFIG_REQUIRED: --yes requires all three domain flags")
		return 2
	}
	if !*yes {
		reader := bufio.NewReader(stdin)
		for _, field := range []struct {
			name string
			dst  *string
		}{
			{"Management HTTPS domain", &c.ManagementDomain},
			{"Subscription domain", &c.SubscriptionDomain},
			{"Headscale / DERP domain", &c.HeadscaleDomain},
		} {
			if *field.dst != "" {
				continue
			}
			fmt.Fprintf(stdout, "%s: ", field.name)
			value, readErr := reader.ReadString('\n')
			if readErr != nil && value == "" {
				fmt.Fprintln(stderr, "CONFIG_REQUIRED: provide all three domains")
				return 2
			}
			*field.dst = strings.TrimSpace(value)
		}
	}
	if err := c.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	state, exists, err := install.ReadState("/")
	if err != nil {
		fmt.Fprintln(stderr, "INSTALL_STATE_INVALID: inspect /var/lib/meshmux-installer/state.json; do not delete application data")
		return 1
	}
	if *repair && !exists {
		fmt.Fprintln(stderr, "REPAIR_STATE_MISSING: --repair is allowed only for a recorded MeshMux installation")
		return 3
	}
	if exists {
		if !install.SameConfig(state.Config, c) {
			fmt.Fprintln(stderr, "CONFIG_CONFLICT: this host has a recorded MeshMux configuration; changing domains is not an in-place repair")
			return 3
		}
		if state.Status != "installed" && !*repair {
			fmt.Fprintln(stderr, "INSTALL_PARTIAL_REPAIR_REQUIRED: use --repair with the same domains; data and Headscale keys are preserved")
			return 3
		}
	}
	id, err := install.NewOperationID()
	if err != nil {
		fmt.Fprintln(stderr, "OPERATION_ID_FAILED")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	checks, ssh := install.PreflightWithMode(ctx, c, exists)
	cancel()
	output := install.BuildPlan(id, c, runtime.GOARCH, checks, ssh)
	output.Stage = "plan"
	if exists && *repair {
		output.NextAction = "Explicit repair requested. Only recorded MeshMux-managed files may be replaced; SQLite, keys, and administrator identity are preserved."
	}
	enc := json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		fmt.Fprintln(stderr, "PLAN_OUTPUT_FAILED")
		return 1
	}
	if output.Status == "preflight_blocked" {
		return 3
	}
	if *planOnly {
		return 0
	}
	if !*yes {
		fmt.Fprintln(stdout, "External checks remain pending where indicated. Type 'install hub' to apply this plan, or anything else to stop:")
		reader := bufio.NewReader(stdin)
		answer, readErr := reader.ReadString('\n')
		if readErr != nil && answer == "" || strings.TrimSpace(answer) != "install hub" {
			fmt.Fprintln(stderr, "INSTALL_CANCELLED: no host changes were made")
			return 3
		}
	}
	ctx, cancel = context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	result, applyErr := install.InstallHub(ctx, c, id, *repair, install.ApplyOptions{NonInteractive: *nonInteractive})
	if applyErr != nil {
		if ie, ok := errors.AsType[*install.InstallError](applyErr); ok {
			result.ErrorCode, result.Stage, result.Recovery = ie.Code, ie.Stage, ie.Recovery
		} else {
			result.ErrorCode, result.Stage = "INSTALL_FAILED", "apply"
		}
	}
	enc = json.NewEncoder(stdout)
	enc.SetIndent("", "  ")
	_ = enc.Encode(result)
	if applyErr != nil {
		fmt.Fprintf(stderr, "%s: %s\n", result.ErrorCode, result.Recovery)
		return 1
	}
	return 0
}
