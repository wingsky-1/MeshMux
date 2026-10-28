package core

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
)

// Shared host probes used by both preflight paths. The Hub and the Node channel
// ask the same questions (Debian release, free disk, SSH listeners, port
// ownership), so the parsers and the bind probe live here instead of in one
// channel; hub/preflight.go keeps the Hub-only port ownership policy and the
// check list it publishes.

func NewCheck(name, code, action string, err error) Check {
	if err == nil {
		return Check{Name: name, Status: "pass"}
	}
	return Check{Name: name, Status: "fail", Code: code, Detail: "validation failed", Recovery: action}
}

// debianRelease parses /etc/os-release into the Debian major release and its
// codename. ok is false for any non-Debian host and for content without a
// numeric VERSION_ID, so an unparseable file never looks supported.
func DebianRelease(data string) (release, codename string, ok bool) {
	id, version, code := "", "", ""
	for _, line := range strings.Split(data, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ID="):
			id = strings.Trim(strings.TrimPrefix(line, "ID="), "\"'")
		case strings.HasPrefix(line, "VERSION_ID="):
			version = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), "\"'")
		case strings.HasPrefix(line, "VERSION_CODENAME="):
			code = strings.Trim(strings.TrimPrefix(line, "VERSION_CODENAME="), "\"'")
		}
	}
	if id != "debian" {
		return "", "", false
	}
	major, _, _ := strings.Cut(version, ".")
	if major == "" {
		return "", "", false
	}
	for _, r := range major {
		if r < '0' || r > '9' {
			return "", "", false
		}
	}
	return major, code, true
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
func RunCommand(ctx context.Context, name string, args ...string) (string, error) {
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
		out, err := RunCommand(ctx, "systemctl", "show", "ssh.socket", "-p", "Listen", "--value")
		if err != nil {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
		for _, n := range SocketPorts(out) {
			ports[n] = true
		}
		if len(ports) == 0 {
			return nil, errors.New("SSH_SOCKET_UNKNOWN")
		}
	}
	out, err := RunCommand(ctx, "ss", "-H", "-lntp")
	if err != nil {
		return nil, errors.New("SSH_LISTENERS_UNKNOWN")
	}
	actual := ParseSSHListeners(out)
	for _, p := range actual {
		ports[p] = true
	}
	if !isActive && len(actual) == 0 {
		return nil, errors.New("SSH_LISTENER_UNKNOWN")
	}
	// A conventional sshd listener must agree with its effective port config.
	if !isActive {
		conf, err := RunCommand(ctx, "sshd", "-T")
		if err != nil {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		configured := ParseSSHDPorts(conf)
		if len(configured) == 0 {
			return nil, errors.New("SSH_EFFECTIVE_CONFIG_UNKNOWN")
		}
		for _, port := range actual {
			if !ContainsPort(configured, port) {
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
func ContainsPort(ports []int, p int) bool {
	for _, port := range ports {
		if port == p {
			return true
		}
	}
	return false
}
func ParseSSHDPorts(text string) []int {
	var ports []int
	for _, l := range strings.Split(text, "\n") {
		f := strings.Fields(l)
		if len(f) == 2 && f[0] == "port" {
			n, err := strconv.Atoi(f[1])
			if err == nil && n > 0 && n <= 65535 && !ContainsPort(ports, n) {
				ports = append(ports, n)
			}
		}
	}
	return ports
}
func SocketPorts(s string) []int {
	var ports []int
	for _, m := range socketPort.FindAllStringSubmatch(s, -1) {
		p, _ := strconv.Atoi(m[1])
		if p > 0 && p <= 65535 && !ContainsPort(ports, p) {
			ports = append(ports, p)
		}
	}
	return ports
}
func ParseSSHListeners(s string) []int {
	var ports []int
	for _, line := range strings.Split(s, "\n") {
		if !strings.Contains(line, "(\"sshd\"") && !strings.Contains(line, "(\"sshd-session\"") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := SsLocalAddress(fields)
		pos := strings.LastIndex(addr, ":")
		if pos < 0 {
			continue
		}
		n, err := strconv.Atoi(addr[pos+1:])
		if err == nil && n > 0 && n <= 65535 && !ContainsPort(ports, n) {
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

var socketPort = regexp.MustCompile(`(?:^|[:\s])(\d{1,5})\s*\(Stream\)`)
var ListenerPID = regexp.MustCompile(`pid=(\d+)`)

// cgroupOf is the single /proc seam the ownership check depends on, so tests
// can feed real cgroup content without a privileged host.
var CgroupOf = func(pid string) ([]byte, error) {
	return os.ReadFile("/proc/" + pid + "/cgroup")
}

// ss -H can include a leading Netid column ("tcp"/"udp"). On Debian 13
// ss -H -lntup uses: Netid State Recv-Q Send-Q Local Peer Process.
// Older test fixtures may omit Netid and begin with LISTEN instead.
func SsLocalAddress(fields []string) string {
	if len(fields) >= 5 && (strings.HasPrefix(fields[0], "tcp") || strings.HasPrefix(fields[0], "udp")) {
		return fields[4]
	}
	if len(fields) >= 4 && (fields[0] == "LISTEN" || fields[0] == "UNCONN") {
		return fields[3]
	}
	return ""
}
