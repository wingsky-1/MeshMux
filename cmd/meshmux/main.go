// meshmux is an install-only operator CLI. The current Hub PR is read-only:
// --plan performs preflight; host mutations remain closed until reviewed PR B.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/wingsky-1/MeshMux/internal/install"
	"github.com/wingsky-1/MeshMux/internal/product"
)

func run(args []string, stderr io.Writer) int {
	if len(args) < 2 || args[0] != "install" {
		fmt.Fprintln(stderr, "usage: meshmux install {hub|edge|out} [--plan --management-domain NAME --subscription-domain NAME --headscale-domain NAME]")
		return 2
	}
	role, err := product.ParseRole(args[1])
	if err != nil {
		fmt.Fprintf(stderr, "invalid role: %v\n", err)
		return 2
	}
	if role != product.RoleHub {
		fmt.Fprintln(stderr, "NOT READY TO INSTALL: Line/Out installation is reserved for Issue #6; no host changes were made.")
		return 3
	}
	flags := flag.NewFlagSet("install hub", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var c install.Config
	plan := flags.Bool("plan", false, "perform read-only checks and emit the Hub installation plan")
	flags.StringVar(&c.ManagementDomain, "management-domain", "", "HTTPS management hostname")
	flags.StringVar(&c.SubscriptionDomain, "subscription-domain", "", "subscription hostname")
	flags.StringVar(&c.HeadscaleDomain, "headscale-domain", "", "Headscale/DERP hostname")
	if err := flags.Parse(args[2:]); err != nil || flags.NArg() != 0 {
		fmt.Fprintln(stderr, "CONFIG_INVALID: unknown or unexpected install options")
		return 2
	}
	if !*plan {
		fmt.Fprintln(stderr, "NOT READY TO INSTALL: Host apply remains disabled until the audited Phase B; run 'meshmux install hub --plan ...' to inspect preflight safely.")
		return 3
	}
	if err := c.Validate(); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	id, err := install.NewOperationID()
	if err != nil {
		fmt.Fprintln(stderr, "OPERATION_ID_FAILED")
		return 1
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	checks, ssh := install.Preflight(ctx, c)
	output := install.BuildPlan(id, c, runtime.GOARCH, checks, ssh)
	enc := json.NewEncoder(stderr)
	enc.SetIndent("", "  ")
	if err := enc.Encode(output); err != nil {
		return 1
	}
	if output.Status == "preflight_blocked" {
		return 3
	}
	// Plan mode is explicitly read-only; success means checks passed, not installation.
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}
