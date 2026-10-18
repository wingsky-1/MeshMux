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
		addr := fields[3]
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

func checkPorts() error {
	for _, p := range Ports() {
		host := "127.0.0.1"
		if p.Port == 80 || p.Port == 443 || p.Protocol == "udp" {
			host = "0.0.0.0"
		}
		if err := CanBind(p.Protocol, net.JoinHostPort(host, strconv.Itoa(p.Port))); err != nil {
			return err
		}
		host6 := "::1"
		if host == "0.0.0.0" {
			host6 = "::"
		}
		family := "tcp6"
		if p.Protocol == "udp" {
			family = "udp6"
		}
		if err := CanBind(family, net.JoinHostPort(host6, strconv.Itoa(p.Port))); err != nil {
			return err
		}
	}
	return nil
}

// Preflight is read-only: probing ephemeral sockets is not persistent
// installation or firewall modification. Every failed check blocks apply.
func Preflight(ctx context.Context, c Config) ([]Check, []int) {
	var checks []Check
	checks = append(checks, check("domains", "DOMAIN_INVALID", "Supply three distinct valid public DNS names.", c.Validate()))
	osRelease, err := os.ReadFile("/etc/os-release")
	if err == nil && !osSupported(string(osRelease)) {
		err = errors.New("not Debian 13")
	}
	checks = append(checks, check("os", "OS_UNSUPPORTED", "Use a clean Debian 13 host.", err))
	var archErr error
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" || runtime.GOOS != "linux" {
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
	client := &http.Client{Timeout: 6*time.Second}
	req, _ := http.NewRequestWithContext(ctx, http.MethodHead, "https://github.com/", nil)
	res, networkErr := client.Do(req)
	if networkErr == nil {
		res.Body.Close()
		if res.StatusCode >= 400 {
			networkErr = fmt.Errorf("upstream returned status")
		}
	}
	checks = append(checks, check("network_tls", "NETWORK_UNAVAILABLE", "Check outbound HTTPS and DNS for official GitHub assets.", networkErr))
	checks = append(checks, check("port_ownership", "PORT_CONFLICT", "Stop conflicting services manually; MeshMux never overwrites third-party services.", checkPorts()))
	ssh, sshErr := SSHPorts(ctx)
	checks = append(checks, check("ssh_listening_ports", "SSH_LISTENER_MISMATCH", "Compare systemctl show ssh.socket, sshd -T and ss -lntp; do not change SSH remotely.", sshErr))
	// Local checks cannot establish ingress through the cloud provider.
	checks = append(checks, Check{Name: "public_https", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, probe TCP 443, HTTP ACME and TLS from another network, including IPv6."})
	checks = append(checks, Check{Name: "public_stun", Status: "pending", Code: "EXTERNAL_CHECK_PENDING", Recovery: "After activation, validate UDP 3478 from another network; local listening is insufficient."})
	return checks, ssh
}
