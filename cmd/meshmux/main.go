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

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/node"
	"github.com/wingsky-1/MeshMux/internal/product"
	"github.com/wingsky-1/MeshMux/internal/webcmd"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "__internal-web" {
		os.Exit(webcmd.Run(os.Args[2:]))
	}
	if len(os.Args) > 1 && os.Args[1] == "__internal-agent" {
		os.Exit(node.RunCommand(os.Args[2:], os.Stderr))
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
	if len(args) > 0 && args[0] == "__internal-agent-version" {
		return runInternalAgentVersion(args[1:], stdout, stderr)
	}
	if len(args) < 2 || args[0] != "install" {
		fmt.Fprintln(stderr, "usage: meshmux install {hub|edge|out}")
		fmt.Fprintln(stderr, "  hub: [--management-domain NAME --subscription-domain NAME --headscale-domain NAME] [--plan|--yes] [--repair]")
		fmt.Fprintln(stderr, "  edge|out: --hub HTTPS_ORIGIN --node 32_HEX --vless-port PORT --ssh-port PORT [--plan|--yes] [--repair]")
		return 2
	}
	role, err := product.ParseRole(args[1])
	if err != nil {
		fmt.Fprintln(stderr, "ROLE_INVALID")
		return 2
	}
	if role == product.RoleHub {
		return runHubInstall(args[2:], stdin, stdout, stderr)
	}
	return runNodeInstall(node.Role(role), args[2:], stdin, stdout, stderr, nodes)
}

func runHubInstall(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("install hub", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c install.Config
	planOnly := flags.Bool("plan", false, "show a read-only installation plan")
	yes := flags.Bool("yes", false, "confirm installation after displaying the plan")
	repair := flags.Bool("repair", false, "repair an existing MeshMux installation without deleting state")
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
	result, applyErr := install.InstallHub(ctx, c, id, *repair, install.ApplyOptions{})
	if applyErr != nil {
		var ie *install.InstallError
		if errors.As(applyErr, &ie) {
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
