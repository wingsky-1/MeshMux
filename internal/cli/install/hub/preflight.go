package hub

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// hubDebianRelease is the only release the v1.0.0 Hub accepts. Node hosts use
// nodeOSCheck, which admits one experimental predecessor in addition.
const hubDebianRelease = "13"

// osSupported is the Hub gate: the v1.0.0 Hub is accepted only on Debian 13.
func osSupported(data string) bool {
	release, _, ok := core.DebianRelease(data)
	return ok && release == hubDebianRelease
}

// checkPorts distinguishes an absent IPv6 stack from a real port collision.
// A disabled IPv6 family must not prevent an IPv4-only Hub from installing.

func checkPorts() error {
	return probePorts(core.CanBind)
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
	for _, p := range core.Ports() {
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
func PreflightWithMode(ctx context.Context, c core.Config, allowManagedListeners bool) ([]core.Check, []int) {
	var checks []core.Check
	checks = append(checks, core.NewCheck("domains", "DOMAIN_INVALID", "Supply three distinct valid public DNS names.", c.Validate()))
	osRelease, err := os.ReadFile("/etc/os-release")
	if err == nil && !osSupported(string(osRelease)) {
		err = errors.New("not Debian 13")
	}
	checks = append(checks, core.NewCheck("os", "OS_UNSUPPORTED", "Use a clean Debian 13 host.", err))
	var archErr error
	if !versions.IsSupportedArchitecture(runtime.GOARCH) || runtime.GOOS != "linux" {
		archErr = errors.New("unsupported architecture")
	}
	checks = append(checks, core.NewCheck("architecture", "ARCH_UNSUPPORTED", "Use Linux amd64 or arm64.", archErr))
	var rootErr error
	if os.Geteuid() != 0 {
		rootErr = errors.New("root needed for apply")
	}
	checks = append(checks, core.NewCheck("privileges", "ROOT_REQUIRED", "Use root for installation; no Web process runs as root.", rootErr))
	checks = append(checks, core.NewCheck("free_disk", "DISK_INSUFFICIENT", "Free at least 1 GiB on the root filesystem.", core.DiskAvailable("/", 1<<30)))
	_, err = os.Stat("/run/systemd/system")
	if err == nil {
		_, err = core.RunCommand(ctx, "systemctl", "--version")
	}
	checks = append(checks, core.NewCheck("systemd", "SYSTEMD_UNAVAILABLE", "Boot with systemd as PID 1.", err))
	ntp, err := core.RunCommand(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if err == nil && strings.TrimSpace(ntp) != "yes" {
		err = errors.New("clock not synchronized")
	}
	checks = append(checks, core.NewCheck("clock", "TIME_UNSYNCED", "Enable NTP and verify timedatectl before requesting ACME certificates.", err))
	dnsOK := true
	for _, domain := range []string{c.ManagementDomain, c.SubscriptionDomain, c.HeadscaleDomain} {
		if _, err := net.DefaultResolver.LookupIPAddr(ctx, domain); err != nil {
			dnsOK = false
		}
	}
	if !dnsOK {
		checks = append(checks, core.NewCheck("dns", "DNS_UNAVAILABLE", "Publish A or AAAA records for all domains and wait for resolution.", errors.New("lookup failed")))
	} else {
		checks = append(checks, core.NewCheck("dns", "", "", nil))
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
	checks = append(checks, core.NewCheck("network_tls", "NETWORK_UNAVAILABLE", "Check outbound HTTPS and DNS for official GitHub assets.", networkErr))
	portErr := checkPorts()
	if allowManagedListeners {
		portErr = checkPortsWithManaged(ctx)
	}
	portCode, portAction := "PORT_CONFLICT", "Stop conflicting services manually; MeshMux never overwrites third-party services."
	var pe *portError
	if errors.As(portErr, &pe) {
		portCode, portAction = pe.code, pe.action
	}
	checks = append(checks, core.NewCheck("port_ownership", portCode, portAction, portErr))
	ssh, sshErr := core.SSHPorts(ctx)
	checks = append(checks, core.NewCheck("ssh_listening_ports", "SSH_LISTENER_MISMATCH", "Compare systemctl show ssh.socket, sshd -T and ss -lntp; do not change SSH remotely.", sshErr))
	// Local checks cannot establish ingress through the cloud provider.
	checks = append(checks, core.Check{Name: "public_https", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, probe TCP 443, HTTP ACME and TLS from another network, including IPv6."})
	checks = append(checks, core.Check{Name: "public_stun", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, validate UDP 3478 from another network; local listening is insufficient."})
	return checks, ssh
}

func checkPortsWithManaged(ctx context.Context) error {
	listeners, err := core.RunCommand(ctx, "ss", "-H", "-lntup")
	if err != nil {
		return &portError{"PORT_OWNERS_UNKNOWN", "Run ss -H -lntup manually and confirm every MeshMux port owner before applying."}
	}
	for _, p := range core.Ports() {
		host := "127.0.0.1"
		if p.Port == 80 || p.Port == 443 || p.Protocol == "udp" {
			host = "0.0.0.0"
		}
		if err := core.CanBind(p.Protocol, net.JoinHostPort(host, strconv.Itoa(p.Port))); err != nil {
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
		if err := core.CanBind(family, net.JoinHostPort(host6, strconv.Itoa(p.Port))); err != nil {
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

// listenerOwnership classifies every ss line binding port. A bind failure with
// no visible ss line is unverified, not a third-party conflict.
func listenerOwnership(output string, port int) portOwnership {
	ownership := ownershipUnknown
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}
		local := core.SsLocalAddress(fields)
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
		m := core.ListenerPID.FindStringSubmatch(line)
		if len(m) != 2 {
			ownership = ownershipUnknown
			continue
		}
		cgroup, err := core.CgroupOf(m[1])
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
	case 3478, core.HeadscalePort, 50443:
		return core.HeadscaleUnitName
	case core.WebPort:
		return versions.WebUnitName
	}
	return ""
}
