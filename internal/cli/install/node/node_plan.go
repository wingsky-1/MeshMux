package node

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

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
