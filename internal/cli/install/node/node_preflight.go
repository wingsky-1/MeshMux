package node

import (
	"context"
	"errors"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// The read-only plan inputs: OS/architecture/root/clock/network/package and
// Out-table checks. BuildNodePlanForRoot turns their results into the plan.

func PreflightNode(ctx context.Context, cfg corenode.Config, allowManaged bool) ([]core.Check, []int) {
	return preflightNode(ctx, cfg, allowManaged, "/", core.ExecRunner{})
}

const (
	// nodeBaselineDebianRelease is the only Node release with v1.0.0 acceptance
	// evidence and therefore the baseline every plan claims unless preflight
	// proved otherwise.
	nodeBaselineDebianRelease = "13"
	// nodeExperimentalDebianRelease is bookworm. Its pinned Node artifacts were
	// exercised, but its Debian package set was not part of the v1.0.0
	// acceptance run, so it installs as experimental support, not baseline.
	nodeExperimentalDebianRelease = "12"
	// nodeOSRecovery is the single next action for every refused Node release.
	nodeOSRecovery = "Use Debian 13 for the supported baseline, or Debian 12 (bookworm) on amd64 or arm64 as experimental support; older releases are refused."
)

// debianLabel names a Debian release with the codename the host published.
func debianLabel(release, codename string) string {
	if codename == "" {
		return "Debian " + release
	}
	return "Debian " + release + " (" + codename + ")"
}

// nodeOSCheck classifies /etc/os-release for a Node host. Debian 13 is the
// v1.0.0 baseline and passes plainly. Debian 12 (bookworm) passes with a
// recorded warning because its Debian packages lack v1.0.0 acceptance
// evidence; anything older (or newer than the baseline) is refused so a plan
// never claims support that was not tested.
func nodeOSCheck(data string) core.Check {
	release, codename, ok := core.DebianRelease(data)
	if !ok {
		return core.Check{Name: "os", Status: "fail", Code: "OS_UNSUPPORTED", Detail: "host is not Debian or does not publish a numeric VERSION_ID", Recovery: nodeOSRecovery}
	}
	label := debianLabel(release, codename)
	switch release {
	case nodeBaselineDebianRelease:
		return core.Check{Name: "os", Status: "pass", Detail: label + " baseline"}
	case nodeExperimentalDebianRelease:
		return core.Check{Name: "os", Status: "pass", Detail: label + ": experimental Node support; v1.0.0 baseline and acceptance evidence remain Debian 13"}
	}
	return core.Check{Name: "os", Status: "fail", Code: "OS_UNSUPPORTED", Detail: label + " is not a supported Node release", Recovery: nodeOSRecovery}
}

func preflightNode(ctx context.Context, cfg corenode.Config, allowManaged bool, root string, runner core.CommandRunner) ([]core.Check, []int) {
	if runner == nil {
		runner = core.ExecRunner{}
	}
	var checks []core.Check
	checks = append(checks, core.NewCheck("node_config", "CONFIG_INVALID", "Supply a valid HTTPS Hub URL, node identity, role, VLESS port and SSH port.", cfg.Validate()))
	osCheck := core.Check{Name: "os", Status: "fail", Code: "OS_UNSUPPORTED", Detail: "os-release unavailable", Recovery: nodeOSRecovery}
	if data, err := os.ReadFile(core.Rooted(root, "/etc/os-release")); err == nil {
		osCheck = nodeOSCheck(string(data))
	}
	checks = append(checks, osCheck)

	actualArch, archErr := dpkgArchitecture(ctx, runner)
	archRelease, archOK := corenode.KernelReleaseFor(actualArch)
	if archErr != nil {
		archErr = errors.New("dpkg architecture unavailable")
	} else if runtime.GOOS != "linux" || runtime.GOARCH != actualArch {
		archErr = errors.New("runtime binary architecture differs from dpkg architecture")
	} else if !archOK || archRelease.Version != corenode.KernelVersion {
		archErr = errors.New("unsupported architecture")
	}
	checks = append(checks, core.NewCheck("architecture", "ARCH_UNSUPPORTED", "Use a MeshMux binary and pinned Node artifact for the host's actual amd64 or arm64 dpkg architecture.", archErr))
	var rootErr error
	if os.Geteuid() != 0 {
		rootErr = errors.New("root needed for apply")
	}
	checks = append(checks, core.NewCheck("privileges", "ROOT_REQUIRED", "Run the installer as root; the Agent runs as constrained root and sing-box as the non-root meshmux-singbox account.", rootErr))
	checks = append(checks, core.NewCheck("free_disk", "DISK_INSUFFICIENT", "Free at least 1 GiB on the root filesystem.", core.DiskAvailable("/", 1<<30)))

	systemdErr := errors.New("systemd unavailable")
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		_, systemdErr = runner.Run(ctx, "systemctl", "--version")
	}
	checks = append(checks, core.NewCheck("systemd", "SYSTEMD_UNAVAILABLE", "Boot with systemd as PID 1.", systemdErr))
	// NTP is eventually consistent after boot: under QEMU TCG the clock can
	// take a minute to synchronize (TSC unstable, switched to hpet), so a
	// single-shot timedatectl check flakes. Poll with a bounded deadline
	// instead (Google SRE retry-with-deadline; systemd time-sync.target
	// semantics); deterministic failures still fail fast elsewhere.
	ntpErr := waitForClockSync(ctx, runner)
	checks = append(checks, core.NewCheck("clock", "TIME_UNSYNCED", "Enable NTP and verify timedatectl before pairing.", ntpErr))
	_, caErr := os.Stat("/etc/ssl/certs/ca-certificates.crt")
	checks = append(checks, core.NewCheck("system_roots", "CA_BUNDLE_UNAVAILABLE", "Install and populate ca-certificates before pairing.", caErr))

	checks = append(checks, nodeHTTPSPreflight(ctx, cfg.HubURL))
	checks = append(checks, nodePortPreflight(ctx, cfg, allowManaged, root, runner)...)
	ssh, sshErr := sshPortsWithRunner(ctx, runner)
	if sshErr == nil && !core.ContainsPort(ssh, cfg.SSHPort) {
		sshErr = errors.New("configured SSH port is not an actual listener")
	}
	if sshErr == nil && core.ContainsPort(ssh, cfg.VLESSPort) {
		sshErr = errors.New("VLESS port collides with SSH")
	}
	checks = append(checks, core.NewCheck("ssh_listening_ports", "SSH_LISTENER_MISMATCH", "Compare ssh.socket, sshd -T and ss; VLESS must not collide with any actual SSH port.", sshErr))

	fail2ban := packageAvailability(ctx, runner, "fail2ban")
	checks = append(checks, fail2ban)
	// The packaged baseline must satisfy its own self-test before any pairing
	// code is consumed; a broken jail/logpath configuration otherwise only
	// surfaces in apply/verify after files were already replaced.
	checks = append(checks, nodeFail2banBaselineCheck(ctx, runner))
	nftPackage := packageAvailability(ctx, runner, "nftables")
	checks = append(checks, nftPackage)
	if nftPackage.Detail == "installed" {
		checks = append(checks, nodeTableOwnership(ctx, root, runner, cfg, allowManaged).checkName("out_acl_table"))
	} else {
		checks = append(checks, core.Check{
			Name: "out_acl_table", Status: "pending", Code: "PACKAGE_INSTALL_PENDING",
			Detail:   "nft is missing; install only the fixed Debian nftables package, then re-run ownership readback before apply.",
			Recovery: "The installer will query and install only nftables, then list inet meshmux_out again; unrelated tables are never adopted or deleted.",
		})
	}
	checks = append(checks, core.Check{Name: "public_reachability", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After local readback, verify the VLESS TCP/UDP ports from another network and cloud security-group ingress separately."})
	checks = append(checks, core.Check{Name: "protocol_handshake", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "Run an authorized client handshake after Hub-side authorization; local listeners do not prove protocol usability."})
	return checks, ssh
}

// clockSyncTimeout bounds the NTP wait so a broken time service still fails
// instead of hanging the install; clockSyncInterval spaces the polls.
const (
	clockSyncTimeout  = 90 * time.Second
	clockSyncInterval = 3 * time.Second
)

// waitForClockSync polls timedatectl until NTPSynchronized=yes or the
// deadline/context expires. A missing timedatectl binary or a "no" answer
// is transient (time service still starting); only the timeout is fatal.
func waitForClockSync(ctx context.Context, runner core.CommandRunner) error {
	deadline := time.Now().Add(clockSyncTimeout)
	for {
		ntp, err := runner.Run(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
		if err == nil && strings.TrimSpace(string(ntp)) == "yes" {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("clock not synchronized")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(clockSyncInterval):
		}
	}
}

func nodeHTTPSPreflight(ctx context.Context, hubURL string) core.Check {
	return nodeHTTPSPreflightWithClient(ctx, hubURL, nil)
}

func nodeHTTPSPreflightWithClient(ctx context.Context, hubURL string, base *http.Client) core.Check {
	client := &http.Client{
		Timeout: 6 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	if base != nil {
		cloned := *base
		client = &cloned
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
		// A preflight probe must stay bounded even when the caller
		// supplies a client without a timeout.
		if client.Timeout <= 0 {
			client.Timeout = 6 * time.Second
		}
	}
	redirectStatus := func(status int) bool {
		return status >= 300 && status < 400
	}
	var lastErr error
	for _, target := range []string{"https://github.com/", hubURL + "/"} {
		req, err := http.NewRequestWithContext(ctx, http.MethodHead, target, nil)
		if err != nil {
			lastErr = err
			continue
		}
		res, err := client.Do(req)
		if err == nil {
			res.Body.Close()
			if redirectStatus(res.StatusCode) {
				lastErr = errors.New("HTTPS endpoint redirected")
				continue
			}
			if res.StatusCode < 400 || target == hubURL+"/" {
				continue
			}
			err = errors.New("upstream returned status")
		}
		lastErr = err
	}
	return core.NewCheck("hub_and_github_https", "NETWORK_UNAVAILABLE", "Check DNS, system trust roots, time and outbound HTTPS to the Hub and official GitHub assets.", lastErr)
}

func packageAvailability(ctx context.Context, runner core.CommandRunner, pkg string) core.Check {
	out, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
	if err == nil && strings.Contains(string(out), "install ok installed") {
		return core.Check{Name: pkg, Status: "pass", Detail: "installed"}
	}
	return core.Check{Name: pkg, Status: "pass", Detail: "missing; install will query and install only this fixed Debian package"}
}

// nodeTableOwnership classifies the existing inet meshmux_out table of this
// host.
//
// A table that is present is only ever adopted when allowManaged is set and
// the effective Node ledger of this host provably records exactly cfg
// (nodeLedgerBindsConfig). The Hub ledger is never used as Node ownership
// evidence: on a co-located host it is a different ledger, and its Node
// record is nil by construction. An unreadable ledger stays a stable
// state/ownership failure instead of being downgraded to "no ledger".
func nodeTableOwnership(ctx context.Context, root string, runner core.CommandRunner, cfg corenode.Config, allowManaged bool) tableOwnershipResult {
	if runner == nil {
		runner = core.ExecRunner{}
	}
	out, err := runner.Run(ctx, "nft", "list", "table", "inet", corenode.ACLTable)
	if err != nil {
		if missingTableOutput(string(out), err) {
			return tableOwnershipResult{Kind: tableAbsent}
		}
		return tableOwnershipResult{Kind: tableProbeFailed, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: "ACL_TABLE_PROBE_FAILED",
			Recovery: "Fix nft permissions, kernel support or command errors, then rerun the read-only preflight; MeshMux will not delete or adopt an unverified table.",
		}}
	}
	if !strings.Contains(string(out), "table inet "+corenode.ACLTable) {
		return tableOwnershipResult{Kind: tableProbeFailed, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: "ACL_TABLE_PROBE_FAILED",
			Recovery: "nft returned success without the exact table; fail closed and inspect nft output manually.",
		}}
	}
	if cfg.Role != corenode.RoleOut {
		return tableOwnershipResult{Kind: tableConflict, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: "ACL_TABLE_CONFLICT",
			Recovery: "An existing inet meshmux_out table is Out-only; inspect and remove it manually only if it is not managed by MeshMux.",
		}}
	}
	if !allowManaged {
		return tableOwnershipResult{Kind: tableConflict, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: "ACL_TABLE_CONFLICT",
			Recovery: "An inet meshmux_out table exists without an installer ledger; inspect it manually. MeshMux will not adopt or overwrite it.",
		}}
	}
	bound, err := core.NodeLedgerBindsConfig(root, cfg)
	if err != nil {
		code, recovery := core.CodeInstallStateInvalid, "Inspect the effective Node ledger; do not delete MeshMux state."
		var ie *core.InstallError
		if errors.As(err, &ie) {
			if ie.Code == core.NodeOwnershipUnverified || ie.Code == core.CodeInstallStateInvalid {
				code = ie.Code
			}
			if ie.Recovery != "" {
				recovery = ie.Recovery
			}
		}
		return tableOwnershipResult{Kind: tableProbeFailed, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: code, Recovery: recovery,
		}}
	}
	if !bound {
		return tableOwnershipResult{Kind: tableConflict, Check: core.Check{
			Name: "out_acl_table", Status: "fail", Code: "ACL_TABLE_CONFLICT",
			Recovery: "An inet meshmux_out table exists but the effective Node ledger of this host does not record this exact Node configuration; inspect it manually. MeshMux will not adopt or overwrite it.",
		}}
	}
	return tableOwnershipResult{Kind: tableManaged, Check: core.Check{Name: "out_acl_table", Status: "pass", Detail: "recorded MeshMux Out table; its exact guard content is replaced and proven during apply/readback, not by this ownership probe"}}
}

type tableOwnershipKind int

const (
	tableAbsent tableOwnershipKind = iota
	tableManaged
	tableConflict
	tableProbeFailed
)

type tableOwnershipResult struct {
	Kind  tableOwnershipKind
	Check core.Check
}

func (r tableOwnershipResult) checkName(name string) core.Check {
	if r.Kind == tableAbsent {
		return core.Check{Name: name, Status: "pass", Detail: "table absent; first install may create only the MeshMux-owned table"}
	}
	r.Check.Name = name
	return r.Check
}

func missingTableOutput(output string, err error) bool {
	text := strings.ToLower(output)
	if err == nil || strings.TrimSpace(text) == "" {
		return false
	}
	return strings.Contains(text, "no such file or directory") ||
		strings.Contains(text, "could not process rule: not found") ||
		strings.Contains(text, "object not found")
}
