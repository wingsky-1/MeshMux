package install

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/versions"
)

func check(name, code, action string, err error) Check {
	if err == nil {
		return Check{Name: name, Status: "pass"}
	}
	return Check{Name: name, Status: "fail", Code: code, Detail: "validation failed", Recovery: action}
}

func osSupported(data string) bool {
	id, version := "", ""
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ID=") {
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"'")
		}
		if strings.HasPrefix(line, "VERSION_ID=") {
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"'")
		}
	}
	return id == "debian" && version == "13"
}

func DiskAvailable(path string, minimum uint64) error {
	var fs syscall.Statfs_t
	if err := syscall.Statfs(path, &fs); err != nil {
		return err
	}
	if uint64(fs.Bavail)*uint64(fs.Bsize) < minimum {
		return errors.New("insufficient disk space")
	}
	return nil
}

func command(ctx context.Context, name string, args ...string) (string, error) {
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return "", err // never expose raw command output (could contain secrets)
	}
	return string(out), nil
}

// SSHPorts looks at active systemd socket activation before sshd -T. Never
// assume the server uses port 22, and never modify sshd or close a socket.
func SSHPorts(ctx context.Context) ([]int, error) {
	ports := map[int]bool{}
	isActive := exec.CommandContext(ctx, "systemctl", "is-active", "--quiet", "ssh.socket").Run() == nil
	if isActive {
		out, err := command(ctx, "systemctl", "show", "ssh.socket", "-p", "Listen", "--value")
		if err != nil {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
		for _, n := range socketPorts(out) {
			ports[n] = true
		}
		if len(ports) == 0 {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
	}
	out, err := command(ctx, "ss", "-H", "-lntp")
	if err != nil {
		return nil, errors.New("SSH_LISTENERS_UNKNOWN")
	}
	actual := parseSSHListeners(out)
	for _, p := range actual {
		ports[p] = true
	}
	if !isActive && len(actual) == 0 {
		return nil, errors.New("SSH_LISTENER_UNKNOWN")
	}
	// A conventional sshd listener must agree with its effective port config.
	if !isActive {
		conf, err := command(ctx, "sshd", "-T")
		if err != nil {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		configured := parseSSHDPorts(conf)
		if len(configured) == 0 {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		for _, port := range actual {
			if !containsPort(configured, port) {
				return nil, errors.New("SSH_LISTENER_MISMATCH")
			}
		}
	}
	result := make([]int, 0, len(ports))
	for p := range ports {
		result = append(result, p)
	}
	sort.Ints(result)
	return result, nil
}

func containsPort(ports []int, p int) bool {
	for _, port := range ports {
		if port == p {
			return true
		}
	}
	return false
}

func parseSSHDPorts(text string) []int {
	var ports []int
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "port" {
			n, err := strconv.Atoi(f[1])
			if err == nil && n > 0 && n <= 65535 && !containsPort(ports, n) {
				ports = append(ports, n)
			}
		}
	}
	return ports
}

var socketPort = regexp.MustCompile(`(?:^|[:\s])(\d{1,5})\s*\(Stream\)`)

func socketPorts(s string) []int {
	var ports []int
	for _, m := range socketPort.FindAllStringSubmatch(s, -1) {
		p, _ := strconv.Atoi(m[1])
		if p > 0 && p <= 65535 && !containsPort(ports, p) {
			ports = append(ports, p)
		}
	}
	return ports
}

func parseSSHListeners(s string) []int {
	var ports []int
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, "(\"sshd\"") && !strings.Contains(line, "(\"sshd-session\"") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := ssLocalAddress(fields)
		pos := strings.LastIndex(addr, ":")
		if pos < 0 {
			continue
		}
		n, err := strconv.Atoi(addr[pos+1:])
		if err == nil && n > 0 && n <= 65535 && !containsPort(ports, n) {
			ports = append(ports, n)
		}
	}
	return ports
}

func CanBind(protocol, address string) error {
	if strings.HasPrefix(protocol, "udp") {
		pc, err := net.ListenPacket(protocol, address)
		if err != nil {
			return err
		}
		return pc.Close()
	}
	l, err := net.Listen(protocol, address)
	if err != nil {
		return err
	}
	return l.Close()
}

// checkPorts distinguishes an absent IPv6 stack from a real port collision.
// A disabled IPv6 family must not prevent an IPv4-only Hub from installing.

func checkPorts() error {
	return probePorts(CanBind)
}

// probePorts accepts an injected binder so no privileged host environment is
// needed to test IPv4-only and occupied-port behavior.
func probePorts(bind func(string, string) error) error {
	ipv6 := true
	if err := bind("tcp6", "[::1]:0"); err != nil {
		if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) ||
			errors.Is(err, syscall.EPROTONOSUPPORT) {
			ipv6 = false
		} else {
			return err
		}
	}
	for _, p := range Ports() {
		host := "127.0.0.1"
		if p.Port == 80 || p.Port == 443 || p.Protocol == "udp" {
			host = "0.0.0.0"
		}
		if err := bind(p.Protocol, net.JoinHostPort(host, strconv.Itoa(p.Port))); err != nil {
			return err
		}
		if !ipv6 {
			continue
		}
		host6 := "::1"
		if host == "0.0.0.0" {
			host6 = "::"
		}
		family := "tcp6"
		if p.Protocol == "udp" {
			family = "udp6"
		}
		if err := bind(family, net.JoinHostPort(host6, strconv.Itoa(p.Port))); err != nil {
			return err
		}
	}
	return nil
}

// PreflightWithMode only tolerates ports occupied by the recorded MeshMux
// services when an existing installation is being verified or repaired.
func PreflightWithMode(ctx context.Context, c Config, allowManagedListeners bool) ([]Check, []int) {
	var checks []Check
	checks = append(checks, check("domains", "DOMAIN_INVALID", "Supply three distinct valid public DNS names.", c.Validate()))
	osRelease, err := os.ReadFile("/etc/os-release")
	if err == nil && !osSupported(string(osRelease)) {
		err = errors.New("not Debian 13")
	}
	checks = append(checks, check("os", "OS_UNSUPPORTED", "Use a clean Debian 13 host.", err))
	var archErr error
	if !versions.IsSupportedArchitecture(runtime.GOARCH) || runtime.GOOS != "linux" {
		archErr = errors.New("unsupported architecture")
	}
	checks = append(checks, check("architecture", "ARCH_UNSUPPORTED", "Use Linux amd64 or arm64.", archErr))
	var rootErr error
	if os.Geteuid() != 0 {
		rootErr = errors.New("root needed for apply")
	}
	checks = append(checks, check("privileges", "ROOT_REQUIRED", "Use root for installation; no Web process runs as root.", rootErr))
	checks = append(checks, check("free_disk", "DISK_INSUFFICIENT", "Free at least 1 GiB on the root filesystem.", DiskAvailable("/", 1<<30)))
	_, err = os.Stat("/run/systemd/system")
	if err == nil {
		_, err = command(ctx, "systemctl", "--version")
	}
	checks = append(checks, check("systemd", "SYSTEMD_UNAVAILABLE", "Boot with systemd as PID 1.", err))
	ntp, err := command(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err == nil && strings.TrimSpace(ntp) != "yes" {
		err = errors.New("clock not synchronized")
	}
	checks = append(checks, check("clock", "TIME_UNSYNCED", "Enable NTP and verify timedatectl before requesting ACME certificates.", err))
	dnsOK := true
	for _, domain := range []string{c.ManagementDomain, c.SubscriptionDomain, c.HeadscaleDomain} {
		if _, err := net.DefaultResolver.LookupIPAddr(ctx, domain); err != nil {
			dnsOK = false
		}
	}
	if !dnsOK {
		checks = append(checks, check("dns", "DNS_UNAVAILABLE", "Publish A or AAAA records for all domains and wait for resolution.", errors.New("lookup failed")))
	} else {
		checks = append(checks, check("dns", "", "", nil))
	}
	client := &http.Client{Timeout: 6 * time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://github.com/", nil)
	res, networkErr := client.Do(req)
	if networkErr == nil {
		res.Body.Close()
		if res.StatusCode >= 400 {
			networkErr = fmt.Errorf("upstream returned status")
		}
	}
	checks = append(checks, check("network_tls", "NETWORK_UNAVAILABLE", "Check outbound HTTPS and DNS for official GitHub assets.", networkErr))
	portErr := checkPorts()
	if allowManagedListeners {
		portErr = checkPortsWithManaged(ctx)
	}
	portCode, portAction := "PORT_CONFLICT", "Stop conflicting services manually; MeshMux never overwrites third-party services."
	var pe *portError
	if errors.As(portErr, &pe) {
		portCode, portAction = pe.code, pe.action
	}
	checks = append(checks, check("port_ownership", portCode, portAction, portErr))
	ssh, sshErr := SSHPorts(ctx)
	checks = append(checks, check("ssh_listening_ports", "SSH_LISTENER_MISMATCH", "Compare systemctl show ssh.socket, sshd -T and ss -lntp; do not change SSH remotely.", sshErr))
	// Local checks cannot establish ingress through the cloud provider.
	checks = append(checks, Check{Name: "public_https", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, probe TCP 443, HTTP ACME and TLS from another network, including IPv6."})
	checks = append(checks, Check{Name: "public_stun", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, validate UDP 3478 from another network; local listening is insufficient."})
	return checks, ssh
}

func checkPortsWithManaged(ctx context.Context) error {
	listeners, err := command(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return &portError{"PORT_OWNERS_UNKNOWN", "Run ss -H -lntup manually and confirm every MeshMux port owner before applying."}
	}
	for _, p := range Ports() {
		host := "127.0.0.1"
		if p.Port == 80 || p.Port == 443 || p.Protocol == "udp" {
			host = "0.0.0.0"
		}
		if err := CanBind(p.Protocol, net.JoinHostPort(host, strconv.Itoa(p.Port))); err != nil {
			if !errors.Is(err, syscall.EADDRINUSE) {
				return &portError{"PORT_PROBE_FAILED", "Inspect the probe error; a socket-family or permission failure is not a port conflict."}
			}
			switch listenerOwnership(listeners, p.Port) {
			case ownershipManaged:
			case ownershipUnknown:
				return &portError{"PORT_OWNER_UNVERIFIED", "Confirm manually which process holds the port; ss and /proc did not identify its owner."}
			default:
				return &portError{"PORT_CONFLICT", "Stop conflicting services manually; MeshMux never overwrites third-party services."}
			}
		}
		family := "tcp6"
		if p.Protocol == "udp" {
			family = "udp6"
		}
		host6 := "::1"
		if host == "0.0.0.0" {
			host6 = "::"
		}
		if err := CanBind(family, net.JoinHostPort(host6, strconv.Itoa(p.Port))); err != nil {
			if errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EPROTONOSUPPORT) {
				continue
			}
			if !errors.Is(err, syscall.EADDRINUSE) {
				return &portError{"PORT_PROBE_FAILED", "Inspect the probe error; a socket-family or permission failure is not a port conflict."}
			}
			switch listenerOwnership(listeners, p.Port) {
			case ownershipManaged:
			case ownershipUnknown:
				return &portError{"PORT_OWNER_UNVERIFIED", "Confirm manually which process holds the port; ss and /proc did not identify its owner."}
			default:
				return &portError{"PORT_CONFLICT", "Stop conflicting services manually; MeshMux never overwrites third-party services."}
			}
		}
	}
	return nil
}

// portError carries a stable error code and next action so a failed port check
// reports the real reason instead of blaming a third party for every case.
type portError struct {
	code   string
	action string
}

func (e *portError) Error() string { return e.code }

// portOwnership separates a MeshMux-owned listener from a genuine third-party
// conflict and from a listener whose owner cannot be verified. Collapsing the
// last two into "conflict" permanently blocks repair of a MeshMux-owned port.
type portOwnership int

const (
	ownershipConflict portOwnership = iota
	ownershipManaged
	ownershipUnknown
)

var listenerPID = regexp.MustCompile(`pid=(\d+)`)

// cgroupOf is the single /proc seam the ownership check depends on, so tests
// can feed real cgroup content without a privileged host.
var cgroupOf = func(pid string) ([]byte, error) {
	return os.ReadFile("/proc/" + pid + "/cgroup")
}

// listenerOwnership classifies every ss line binding port. A bind failure with
// no visible ss line is unverified, not a third-party conflict.
func listenerOwnership(output string, port int) portOwnership {
	ownership := ownershipUnknown
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := ssLocalAddress(fields)
		pos := strings.LastIndex(local, ":")
		if pos < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(local[pos+1:], "]"))
		if err != nil || n != port {
			continue
		}
		// A listener with no PID in ss, or whose /proc cgroup vanished, cannot be
		// attributed. Treat it as unverified instead of a third-party conflict.
		m := listenerPID.FindStringSubmatch(line)
		if len(m) != 2 {
			ownership = ownershipUnknown
			continue
		}
		cgroup, err := cgroupOf(m[1])
		if err != nil {
			ownership = ownershipUnknown
			continue
		}
		unit := meshMuxUnitForPort(port)
		if unit == "" || !strings.Contains(string(cgroup), unit) {
			return ownershipConflict
		}
		ownership = ownershipManaged
	}
	return ownership
}

func meshMuxUnitForPort(port int) string {
	switch port {
	case 80, 443:
		return "meshmux-caddy.service"
	case 3478, HeadscalePort, 50443:
		return headscaleUnitName
	case WebPort:
		return versions.WebUnitName
	}
	return ""
}

// ss -H can include a leading Netid column ("tcp"/"udp"). On Debian 13
// ss -H -lntup uses: Netid State Recv-Q Send-Q Local Peer Process.
// Older test fixtures may omit Netid and begin with LISTEN instead.
func ssLocalAddress(fields []string) string {
	if len(fields) >= 5 && (strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp")) {
		return fields[4]
	}
	if len(fields) >= 4 && (fields[0] == "LISTEN" || fields[0] == "UNCONN") {
		return fields[3]
	}
	return ""
}
