package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

var processExecutableOf = func(pid string) (string, error) {
	path, err := os.Readlink("/proc/" + pid + "/exe")
	if err != nil {
		return "", err
	}
	return strings.TrimSuffix(path, " (deleted)"), nil
}

var processExecutableHashOf = func(pid string) (string, error) {
	return core.SHA256File("/proc/" + pid + "/exe")
}

type NodePlan struct {
	OperationID  string           `json:"operation_id"`
	Stage        string           `json:"stage"`
	Status       string           `json:"status"`
	OS           string           `json:"os"`
	Architecture string           `json:"architecture"`
	Config       corenode.Config  `json:"config"`
	Checks       []core.Check     `json:"checks"`
	Artifacts    []core.Artifact  `json:"artifacts"`
	Components   []core.Component `json:"components"`
	Ports        []core.Port      `json:"ports"`
	Units        []string         `json:"systemd_units"`
	Paths        []string         `json:"managed_paths"`
	SSHPPorts    []int            `json:"ssh_listening_ports,omitempty"`
	ACLTable     string           `json:"acl_table,omitempty"`
	// ReusedPaths lists fixed paths this Node operation proves and uses but
	// never writes. A co-located Line reuses the Hub-owned runtime binary
	// and the Hub's Fail2ban SSH jail, so neither appears in Paths.
	ReusedPaths     []string               `json:"reused_paths,omitempty"`
	ApplyAvailable  bool                   `json:"apply_available"`
	NextAction      string                 `json:"next_action"`
	ExternalPending []string               `json:"external_checks_pending,omitempty"`
	Kernel          corenode.KernelRelease `json:"kernel"`
}

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

// nodeOSLabel records the release the os check actually saw so a Debian 12 plan
// never advertises the Debian 13 baseline. Synthetic plans without an os check
// keep the baseline.
func nodeOSLabel(checks []core.Check) string {
	for _, c := range checks {
		if c.Name != "os" {
			continue
		}
		rest, found := strings.CutPrefix(c.Detail, "Debian ")
		if !found {
			continue
		}
		release, _, _ := strings.Cut(rest, " ")
		if release != "" {
			return "Debian " + release
		}
	}
	return "Debian " + nodeBaselineDebianRelease
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

// BuildNodePlanForRoot builds the read-only plan from the host's own recorded
// layout. A co-located Line never writes the Hub-owned runtime binary or a
// second SSH jail, so those belong in ReusedPaths instead of Paths. A host
// whose layout cannot be resolved fails closed through a blocking check rather
// than advertising standalone writes it cannot prove.
func BuildNodePlanForRoot(root, id string, cfg corenode.Config, architecture string, checks []core.Check, ssh []int) NodePlan {
	layout, err := core.ResolveNodeLayout(root)
	if err == nil && layout.HubHost && !layout.CoLocated {
		err = core.NodeOwnershipError(
			"This host records a Hub layout that cannot host a co-located Line because the Hub does not publish a pinned reusable MeshMux runtime. Repair the Hub layout first; a Line never falls back to the Hub ledger.")
	}
	if err != nil {
		code, recovery := core.CodeInstallStateInvalid, "Inspect the recorded installer state; do not delete MeshMux data."
		var ie *core.InstallError
		if errors.As(err, &ie) {
			code = ie.Code
			if ie.Recovery != "" {
				recovery = ie.Recovery
			}
		}
		blocked := append(append([]core.Check(nil), checks...), core.Check{
			Name: "node_layout", Status: "fail", Code: code, Recovery: recovery,
		})
		return buildNodePlan(id, cfg, architecture, blocked, ssh, core.NodeLayout{})
	}
	return buildNodePlan(id, cfg, architecture, checks, ssh, layout)
}

func buildNodePlan(id string, cfg corenode.Config, architecture string, checks []core.Check, ssh []int, layout core.NodeLayout) NodePlan {
	ready := true
	var pending []string
	for _, c := range checks {
		if c.Status == "fail" {
			ready = false
		}
		if c.Status == "pending" {
			pending = append(pending, c.Name)
		}
	}
	status := "preflight_passed"
	if !ready {
		status = "preflight_blocked"
	}
	release, _ := corenode.KernelReleaseFor(architecture)
	artifacts := core.PinnedNodeArtifacts(architecture)
	osLabel := nodeOSLabel(checks)
	agentDistribution := "same executable as the invoked CLI; self-copy SHA-256 verified"
	if layout.CoLocated {
		agentDistribution = "reuses the Hub-owned runtime binary verbatim; SHA-256 verified, never written by the Line"
	}
	plan := NodePlan{
		OperationID: id, Stage: "plan", Status: status, OS: osLabel,
		Architecture: architecture, Config: cfg, Checks: checks,
		Artifacts: artifacts,
		Components: []core.Component{
			{Name: "MeshMux Agent", Version: corenode.CurrentAgentVersion(), Distribution: agentDistribution},
			{Name: "sing-box", Version: corenode.KernelVersion, Distribution: "pinned official GitHub archive; archive and binary SHA-256 verified"},
			{Name: "Fail2ban", Version: osLabel + " package", Distribution: "official Debian repository"},
			{Name: "nftables", Version: osLabel + " package", Distribution: "official Debian repository"},
		},
		Ports: []core.Port{
			{Protocol: "tcp", Port: cfg.VLESSPort, Service: "sing-box VLESS"},
			{Protocol: "udp", Port: cfg.VLESSPort, Service: "sing-box VLESS"},
			{Protocol: "tcp", Port: cfg.SSHPort, Service: "SSH rescue listener (unchanged)"},
		},
		Units: []string{corenode.AgentUnit, corenode.SingBoxUnit},
		Paths: []string{
			corenode.SingBoxBinaryPath, corenode.AgentConfigPath,
			"/var/lib/meshmux-agent/", "/var/lib/meshmux-singbox/",
			core.UnitPath(corenode.AgentUnit), core.UnitPath(corenode.SingBoxUnit),
		},
		ApplyAvailable: ready, NextAction: "Review the fixed Node layout, then run the install with the one-time code entered on stdin. Pairing is consumed only after local staging and checks pass.",
		ExternalPending: pending, Kernel: release,
	}
	if !layout.CoLocated {
		plan.Paths = append([]string{corenode.AgentBinaryPath}, plan.Paths...)
	} else if layout.SharedAgent != "" {
		plan.ReusedPaths = append(plan.ReusedPaths, layout.SharedAgent)
	}
	if layout.ReuseHubSSHJail {
		plan.ReusedPaths = append(plan.ReusedPaths, core.HubSSHJailPath)
	} else {
		plan.Paths = append(plan.Paths, core.NodeSSHJailPath)
	}
	// The journald quota is host-level, so a co-located Line never claims it.
	if !layout.CoLocated {
		plan.Paths = append(plan.Paths, core.JournaldDropInPath)
	}
	if cfg.Role == corenode.RoleOut {
		plan.Units = append([]string{corenode.ACLUnit}, plan.Units...)
		plan.Paths = append(plan.Paths, corenode.ACLPath, core.UnitPath(corenode.ACLUnit))
		plan.ACLTable = corenode.ACLTable
	}
	return plan
}

func dpkgArchitecture(ctx context.Context, runner core.CommandRunner) (string, error) {
	out, err := runner.Run(ctx, "dpkg", "--print-architecture")
	if err != nil {
		return "", err
	}
	arch := strings.TrimSpace(string(out))
	if !versions.IsSupportedArchitecture(arch) {
		return "", errors.New("unsupported dpkg architecture")
	}
	return arch, nil
}

// sshPortsWithRunner is the fixture-safe counterpart of SSHPorts. It keeps
// the same socket/ss/sshd evidence rules while letting isolated tests provide
// all command output without touching the running host.
func sshPortsWithRunner(ctx context.Context, runner core.CommandRunner) ([]int, error) {
	ports := map[int]bool{}
	_, socketErr := runner.Run(ctx, "systemctl", "is-active", "--quiet", "ssh.socket")
	isActive := socketErr == nil
	if isActive {
		out, err := runner.Run(ctx, "systemctl", "show", "ssh.socket", "-p", "Listen", "--value")
		if err != nil {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
		for _, port := range core.SocketPorts(string(out)) {
			ports[port] = true
		}
		if len(ports) == 0 {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
	}
	out, err := runner.Run(ctx, "ss", "-H", "-lntp")
	if err != nil {
		return nil, errors.New("SSH_LISTENERS_UNKNOWN")
	}
	actual := core.ParseSSHListeners(string(out))
	for _, port := range actual {
		ports[port] = true
	}
	if !isActive && len(actual) == 0 {
		return nil, errors.New("SSH_LISTENER_UNKNOWN")
	}
	if !isActive {
		config, err := runner.Run(ctx, "sshd", "-T")
		if err != nil {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		configured := core.ParseSSHDPorts(string(config))
		if len(configured) == 0 {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		for _, port := range actual {
			if !core.ContainsPort(configured, port) {
				return nil, errors.New("SSH_LISTENER_MISMATCH")
			}
		}
	}
	result := make([]int, 0, len(ports))
	for port := range ports {
		result = append(result, port)
	}
	sort.Ints(result)
	return result, nil
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

func nodePortPreflight(ctx context.Context, cfg corenode.Config, allowManaged bool, root string, runner core.CommandRunner) []core.Check {
	if runner == nil {
		runner = core.ExecRunner{}
	}
	// A managed repair reads ownership evidence only from the effective Node
	// ledger of this host, bound to cfg, never from the Hub ledger. A missing
	// or unreadable ledger is a stable ownership/state failure for both VLESS
	// checks: reporting the listener as a third-party PORT_CONFLICT would
	// either blame MeshMux's own kernel or adopt an unverified process.
	if allowManaged && cfg.KernelSHA256 == "" {
		digest, err := core.EffectiveNodeKernelDigest(root, cfg)
		if err != nil {
			code := core.CodeInstallStateInvalid
			recovery := "Inspect the effective Node ledger; do not delete MeshMux state."
			var ie *core.InstallError
			if errors.As(err, &ie) {
				if ie.Code == core.NodeOwnershipUnverified || ie.Code == core.CodeInstallStateInvalid {
					code = ie.Code
				}
				if ie.Recovery != "" {
					recovery = ie.Recovery
				}
			}
			return []core.Check{
				{Name: "vless_tcp", Status: "fail", Code: code, Recovery: recovery},
				{Name: "vless_udp", Status: "fail", Code: code, Recovery: recovery},
			}
		}
		cfg.KernelSHA256 = digest
	}
	if !allowManaged {
		return []core.Check{
			nodeCanBind("vless_tcp", "tcp", cfg.VLESSPort),
			nodeCanBind("vless_udp", "udp", cfg.VLESSPort),
		}
	}
	listeners, err := runner.Run(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return []core.Check{
			{Name: "vless_tcp", Status: "fail", Code: "PORT_OWNER_UNVERIFIED", Recovery: "Inspect ss and confirm the recorded sing-box listener."},
			{Name: "vless_udp", Status: "fail", Code: "PORT_OWNER_UNVERIFIED", Recovery: "Inspect ss and confirm the recorded sing-box listener."},
		}
	}
	return []core.Check{
		nodeManagedPort(ctx, string(listeners), "vless_tcp", "tcp", cfg.VLESSPort, cfg.KernelSHA256),
		nodeManagedPort(ctx, string(listeners), "vless_udp", "udp", cfg.VLESSPort, cfg.KernelSHA256),
	}
}

func nodeCanBind(name, protocol string, port int) core.Check {
	err := core.CanBind(protocol, net.JoinHostPort("0.0.0.0", strconv.Itoa(port)))
	if err == nil && protocol == "tcp" {
		if err6 := core.CanBind("tcp6", net.JoinHostPort("::", strconv.Itoa(port))); err6 != nil &&
			!errors.Is(err6, syscall.EAFNOSUPPORT) && !errors.Is(err6, syscall.EADDRNOTAVAIL) &&
			!errors.Is(err6, syscall.EPROTONOSUPPORT) {
			err = err6
		}
	} else if err == nil {
		if err6 := core.CanBind("udp6", net.JoinHostPort("::", strconv.Itoa(port))); err6 != nil &&
			!errors.Is(err6, syscall.EAFNOSUPPORT) && !errors.Is(err6, syscall.EADDRNOTAVAIL) &&
			!errors.Is(err6, syscall.EPROTONOSUPPORT) {
			err = err6
		}
	}
	return core.NewCheck(name, "PORT_CONFLICT", "Choose a VLESS port not owned by another service; MeshMux never replaces a third-party listener.", err)
}

func nodeManagedPort(ctx context.Context, listeners, name, protocol string, port int, expectedHash string) core.Check {
	var pids []string
	for _, line := range strings.Split(listeners, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || !strings.HasPrefix(fields[0], protocol) {
			continue
		}
		addr := core.SsLocalAddress(fields)
		pos := strings.LastIndex(addr, ":")
		if pos < 0 {
			continue
		}
		n, _ := strconv.Atoi(strings.Trim(addr[pos+1:], "]"))
		if n != port {
			continue
		}
		matches := core.ListenerPID.FindAllStringSubmatch(line, -1)
		for _, match := range matches {
			if !containsStringValue(pids, match[1]) {
				pids = append(pids, match[1])
			}
		}
	}
	if len(pids) == 0 {
		return nodeCanBind(name, protocol, port)
	}
	if len(pids) != 1 {
		return core.Check{Name: name, Status: "fail", Code: "PORT_OWNER_UNVERIFIED", Recovery: "More than one process owns the recorded VLESS listener; inspect ss and do not repair until ownership is unique."}
	}
	if !processInUnitAndHash(ctx, pids[0], corenode.SingBoxUnit, expectedHash) {
		return core.Check{Name: name, Status: "fail", Code: "PORT_CONFLICT", Recovery: "The recorded VLESS listener is not in the MeshMux kernel unit cgroup with the fixed executable; inspect it manually."}
	}
	return core.Check{Name: name, Status: "pass"}
}

func processInUnitAndHash(ctx context.Context, pid, unit, expectedHash string) bool {
	if ctx == nil {
		return false
	}
	if n, err := strconv.Atoi(pid); err != nil || n < 1 {
		return false
	}
	cgroup, err := core.CgroupOf(pid)
	if err != nil || !containsSystemdUnit(string(cgroup), unit) {
		return false
	}
	if !singletonUnitOwner(string(cgroup), unit) {
		return false
	}
	exe, err := processExecutableOf(pid)
	if err != nil || filepath.Clean(exe) != corenode.SingBoxBinaryPath {
		return false
	}
	if !core.ValidDigest.MatchString(expectedHash) {
		return false
	}
	hash, err := processExecutableHashOf(pid)
	return err == nil && hash == expectedHash
}

func containsSystemdUnit(cgroup, unit string) bool {
	for _, line := range strings.Split(cgroup, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		for _, component := range strings.Split(strings.TrimPrefix(fields[2], "/"), "/") {
			if component == unit {
				return true
			}
		}
	}
	return false
}

func singletonUnitOwner(cgroup, unit string) bool {
	found := false
	for _, line := range strings.Split(cgroup, "\n") {
		fields := strings.SplitN(line, ":", 3)
		if len(fields) != 3 {
			continue
		}
		for _, component := range strings.Split(strings.TrimPrefix(fields[2], "/"), "/") {
			if !strings.HasSuffix(component, ".service") {
				continue
			}
			if component != unit || found {
				return false
			}
			found = true
		}
	}
	return found
}

func containsStringValue(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
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

func sortedInts(values []int) []int {
	out := append([]int(nil), values...)
	sort.Ints(out)
	return out
}

func ValidateNodeArchitecture(arch string) error {
	if !versions.IsSupportedArchitecture(arch) {
		return fmt.Errorf("ARCH_UNSUPPORTED")
	}
	return nil
}
