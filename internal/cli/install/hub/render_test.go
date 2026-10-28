package hub

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	"github.com/wingsky-1/MeshMux/internal/core/mesh"
)

// jailValue parses a Fail2ban INI the way fail2ban does: "[name]" opens a
// section and every other non-empty line is "key = value". A raw
// strings.Contains over the rendered text cannot detect a jail whose newlines
// were lost, because "enabled = false" then appears inside one giant line that
// fail2ban silently discards.
func jailValue(t *testing.T, ini, section, key string) string {
	t.Helper()
	in := false
	for _, line := range strings.Split(ini, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			in = line == "["+section+"]"
			continue
		}
		if !in || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name, value, found := strings.Cut(line, "=")
		if found && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("key %q missing from section [%s]", key, section)
	return ""
}

func iniValue(t *testing.T, text, key string) string {
	t.Helper()
	for _, line := range strings.Split(text, "\n") {
		// An empty value ("ignoreregex =") is still a present key.
		if name, value, found := strings.Cut(strings.TrimSpace(line), "="); found && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	t.Fatalf("key %q missing", key)
	return ""
}

// TestWebUnitWatchdogAndStartLimit pins the D2 hardening of the Web unit: a
// bounded restart budget, a watchdog that only the main process may feed, and a
// declared boot directory for the process-level crash-loop guard.
func TestWebUnitWatchdogAndStartLimit(t *testing.T) {
	files, err := CandidateFiles(hubFixtureConfig(), []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	web := files["/etc/systemd/system/meshmux-web.service"]
	for _, line := range []string{
		"WatchdogSec=120",
		"NotifyAccess=main",
		"StartLimitIntervalSec=300",
		"StartLimitBurst=3",
		"ReadWritePaths=/run/meshmux-hub/boot",
	} {
		if !strings.Contains(web, line+"\n") {
			t.Fatalf("web unit is missing %q:\n%s", line, web)
		}
	}
	tmpfiles := files[hubTmpfilesPath]
	if !strings.Contains(tmpfiles, "d /run/meshmux-hub/boot 0730 root meshmux\n") {
		t.Fatalf("tmpfiles does not create the boot directory:\n%s", tmpfiles)
	}
}

func TestWebJailRendersRealNewlines(t *testing.T) {
	base := core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}
	files, err := candidateFiles(base, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	jail := files["/etc/fail2ban/jail.d/meshmux-web.local"]
	if !strings.Contains(jail, "[meshmux-web]\n") {
		t.Fatalf("section header is not followed by a real newline: %q", jail)
	}
	// The pre-fix renderer produced one line holding literal \n sequences, so
	// this count is the regression guard.
	if n := strings.Count(jail, "\n"); n < 11 {
		t.Fatalf("jail has %d newlines; fail2ban needs one per directive", n)
	}
	if got := jailValue(t, jail, "meshmux-web", "enabled"); got != "false" {
		t.Fatalf("web jail must stay disabled behind an unverified proxy, got enabled = %q", got)
	}
	for _, key := range []string{"filter", "backend", "port", "protocol", "banaction", "maxretry", "findtime", "bantime", "usedns"} {
		if jailValue(t, jail, "meshmux-web", key) == "" {
			t.Fatalf("jail key %q lost its value; the INI parser would discard it", key)
		}
	}

	direct := base
	direct.DirectCaddy = true
	directFiles, err := candidateFiles(direct, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	if got := jailValue(t, directFiles["/etc/fail2ban/jail.d/meshmux-web.local"], "meshmux-web", "enabled"); got != "true" {
		t.Fatalf("direct-Caddy opt-in must enable the web jail, got enabled = %q", got)
	}
	if !strings.Contains(directFiles["/etc/systemd/system/meshmux-web.service"], "--direct-caddy") {
		t.Fatal("direct-Caddy opt-in did not enable the trusted-client mode")
	}
}

func TestSSHJailRendersRealNewlines(t *testing.T) {
	files, err := candidateFiles(core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{60794, 60795}, false)
	if err != nil {
		t.Fatal(err)
	}
	jail := files["/etc/fail2ban/jail.d/meshmux-ssh.local"]
	if got := jailValue(t, jail, "meshmux-sshd", "port"); got != "60794,60795" {
		t.Fatalf("SSH jail port = %q", got)
	}
	if got := jailValue(t, jail, "meshmux-sshd", "enabled"); got != "true" {
		t.Fatalf("SSH jail must be enabled, got %q", got)
	}
	if got := jailValue(t, jail, "meshmux-sshd", "filter"); got != "sshd" {
		t.Fatalf("SSH jail filter = %q", got)
	}
}

// webFailregex compiles the rendered failregex with fail2ban's <ADDR>
// placeholder expanded to an address alternation, so the test exercises the
// same expression fail2ban will.
func webFailregex(t *testing.T, filter string) *regexp.Regexp {
	t.Helper()
	raw := iniValue(t, filter, "failregex")
	if strings.Contains(raw, `\\{`) || strings.Contains(raw, `\\}`) {
		t.Fatal(`rendered failregex escapes the JSON braces as "\\{"; slog lines start with "{"`)
	}
	addr := `(?:[0-9]{1,3}(?:\.[0-9]{1,3}){3}|\[[0-9A-Fa-f:.]+\]|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]*)`
	return regexp.MustCompile(strings.ReplaceAll(raw, "<ADDR>", addr))
}

func TestWebFilterFailregexMatchesRealLogs(t *testing.T) {
	files, err := candidateFiles(core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	re := webFailregex(t, files["/etc/fail2ban/filter.d/meshmux-web.conf"])

	data, err := os.ReadFile("../../../web/testdata/fail2ban.log")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != 6 {
		t.Fatalf("expected the 6 fixture lines, got %d", len(lines))
	}
	// Only line 1 (no fraction) and line 2 (6-digit fraction, IPv6 client) are
	// ban candidates; the fixture deliberately includes INFO, ban_candidate:false
	// and a non-IP client.
	wantMatch := map[int]bool{0: true, 1: true}
	for i, line := range lines {
		if got := re.MatchString(line); got != wantMatch[i] {
			t.Errorf("line %d match = %v, want %v\n  line: %s", i+1, got, wantMatch[i], line)
		}
	}
	for _, line := range []string{
		`{"time":"2026-10-18T12:00:06Z","level":"WARN","msg":"authentication_failed","operation_id":"short","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":true,"client_ip":"192.0.2.10"}`,
		`{"time":"2026-10-18T12:00:07Z","level":"WARN","msg":"web_event","operation_id":"abcdefghijklmnopqrstuv","stage":"web","error_code":"AUTH_RATE_LIMITED","ban_candidate":true,"client_ip":"192.0.2.11"}`,
		`{"time":"2026-10-18T12:00:08Z","level":"WARN","msg":"authentication_failed","operation_id":"abcdefghijklmnopqrstuv","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":false,"client_ip":"192.0.2.12"}`,
	} {
		if re.MatchString(line) {
			t.Errorf("failregex must reject: %s", line)
		}
	}
	// Go slog writes RFC3339Nano, so 7-9 fractional digits are the norm.
	for _, line := range []string{
		`{"time":"2026-10-18T12:00:09.1234567Z","level":"WARN","msg":"authentication_failed","operation_id":"abcdefghijklmnopqrstuv","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":true,"client_ip":"192.0.2.13"}`,
		`{"time":"2026-10-18T12:00:10.123456789Z","level":"WARN","msg":"authentication_failed","operation_id":"abcdefghijklmnopqrstuv","stage":"auth","error_code":"AUTH_FAILED","ban_candidate":true,"client_ip":"2001:db8::1"}`,
	} {
		if !re.MatchString(line) {
			t.Errorf("failregex must accept RFC3339Nano timestamps: %s", line)
		}
	}
}

func TestWebFilterDatepatternAcceptsNanoseconds(t *testing.T) {
	files, err := candidateFiles(core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	pattern := iniValue(t, files["/etc/fail2ban/filter.d/meshmux-web.conf"], "datepattern")
	if strings.Contains(pattern, "%%f") {
		t.Fatalf("datepattern still uses the microsecond directive, which fail2ban caps at 6 fractional digits: %q", pattern)
	}
	// Go slog emits up to 9 fractional digits; fail2ban must be able to consume
	// them instead of silently truncating the timestamp.
	if !strings.Contains(pattern, `(?:\.\d{1,9})?`) {
		t.Fatalf("datepattern does not allow an optional 1-9 digit fraction: %q", pattern)
	}
	for _, directive := range []string{"%%Y", "%%m", "%%d", "%%H", "%%M", "%%S", "%%z"} {
		if !strings.Contains(pattern, directive) {
			t.Fatalf("datepattern lost %s: %q", directive, pattern)
		}
	}
	if !strings.Contains(pattern, "{UNB}") {
		t.Fatalf("datepattern must stay unanchored to the line beginning: %q", pattern)
	}
}

// TestWebFilterMatchesDeployedReference pins the renderer against the reviewed
// deploy artifact so the two cannot drift apart again.
func TestWebFilterMatchesDeployedReference(t *testing.T) {
	reference, err := os.ReadFile("../../../../deploy/fail2ban/meshmux-web.conf")
	if err != nil {
		t.Fatal(err)
	}
	files, err := candidateFiles(core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	rendered := files["/etc/fail2ban/filter.d/meshmux-web.conf"]
	for _, key := range []string{"failregex", "ignoreregex", "journalmatch"} {
		if got, want := iniValue(t, rendered, key), iniValue(t, string(reference), key); got != want {
			t.Fatalf("renderer %s = %q, reference = %q", key, got, want)
		}
	}
	// The reference ships the same nanosecond-tolerant pattern the renderer
	// emits: fail2ban caps %f at 6 fractional digits while slog writes up to 9.
	if got, want := iniValue(t, rendered, "datepattern"), iniValue(t, string(reference), "datepattern"); got != want {
		t.Fatalf("renderer datepattern = %q, reference = %q", got, want)
	}
}

func TestWebJailMatchesDeployedReference(t *testing.T) {
	reference, err := os.ReadFile("../../../../deploy/fail2ban/meshmux-web.local.example")
	if err != nil {
		t.Fatal(err)
	}
	files, err := candidateFiles(core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	rendered := files["/etc/fail2ban/jail.d/meshmux-web.local"]
	for _, key := range []string{"enabled", "filter", "backend", "port", "protocol", "banaction", "maxretry", "findtime", "bantime", "usedns"} {
		if got, want := jailValue(t, rendered, "meshmux-web", key), jailValue(t, string(reference), "meshmux-web", key); got != want {
			t.Fatalf("renderer %s = %q, reference = %q", key, got, want)
		}
	}
}

// TestListenerOwnershipParsesRealSSOutput feeds real `ss -H -lntup` output
// captured on this host, both with the Debian 13 Netid column and without it,
// and the headscale-shaped line the installer must recognize as its own.
func TestListenerOwnershipParsesRealSSOutput(t *testing.T) {
	cgroups := map[string]string{
		"42":   "0::/system.slice/meshmux-headscale.service\n",
		"100":  "0::/system.slice/meshmux-web.service\n",
		"999":  "0::/system.slice/caddy.service\n",
		"1234": "0::/system.slice/meshmux-caddy.service\n",
		"1015": "0::/user.slice/user-1000.slice/session-3.scope\n",
		"789":  "0::/system.slice/ssh.service\n",
	}
	restore := core.CgroupOf
	core.CgroupOf = func(pid string) ([]byte, error) {
		if v, ok := cgroups[pid]; ok {
			return []byte(v), nil
		}
		return nil, os.ErrNotExist
	}
	defer func() { core.CgroupOf = restore }()

	cases := []struct {
		name string
		ss   string
		port int
		want portOwnership
	}{
		{
			name: "debian13 netid headscale stun",
			ss:   `udp UNCONN 0      0                                0.0.0.0:3478  0.0.0.0:* users:(("headscale",pid=42,fd=4))`,
			port: 3478, want: ownershipManaged,
		},
		{
			name: "debian13 netid web loopback",
			ss:   `tcp LISTEN 0      4096                          127.0.0.1:9080  0.0.0.0:* users:(("meshmuxd",pid=100,fd=5))`,
			port: core.WebPort, want: ownershipManaged,
		},
		{
			name: "debian13 netid ipv6 wildcard caddy",
			ss:   "tcp LISTEN 0      4096                                   [::]:443       [::]:* users:((\"caddy\",pid=1234,fd=6))",
			port: 443, want: ownershipManaged,
		},
		{
			name: "ipv6 wildcard third party",
			ss:   "tcp LISTEN 0      4096                                        *:3430        *:* users:((\"magpie\",pid=1015,fd=5))",
			port: 3430, want: ownershipConflict,
		},
		{
			name: "no netid sshd",
			ss:   `LISTEN 0      128                           0.0.0.0:60794 0.0.0.0:* users:(("sshd",pid=789,fd=6))`,
			port: 60794, want: ownershipConflict,
		},
		{
			name: "third party on managed port",
			ss:   `tcp LISTEN 0      511                                    0.0.0.0:443   0.0.0.0:* users:(("caddy",pid=999,fd=6))`,
			port: 443, want: ownershipConflict,
		},
		{
			name: "listener without pid",
			ss:   `tcp LISTEN 0      4096                          127.0.0.1:9080  0.0.0.0:*`,
			port: core.WebPort, want: ownershipUnknown,
		},
		{
			name: "pid whose cgroup vanished",
			ss:   `tcp LISTEN 0      4096                          127.0.0.1:9080  0.0.0.0:* users:(("meshmuxd",pid=555,fd=5))`,
			port: core.WebPort, want: ownershipUnknown,
		},
		{
			name: "port not present",
			ss:   `udp UNCONN 0      0                                0.0.0.0:3478  0.0.0.0:* users:(("headscale",pid=42,fd=4))`,
			port: 443, want: ownershipUnknown,
		},
		{
			name: "empty output",
			ss:   "", port: 443, want: ownershipUnknown,
		},
		{
			name: "unparsable output",
			ss:   "garbage\nnot an ss line\n", port: 443, want: ownershipUnknown,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := listenerOwnership(tc.ss, tc.port); got != tc.want {
				t.Fatalf("ownership = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestMeshMuxUnitForPort(t *testing.T) {
	for _, tc := range []struct {
		port int
		want string
	}{
		{80, "meshmux-caddy.service"},
		{443, "meshmux-caddy.service"},
		{3478, "meshmux-headscale.service"},
		{core.HeadscalePort, "meshmux-headscale.service"},
		{50443, "meshmux-headscale.service"},
		{core.WebPort, "meshmux-web.service"},
		{60794, ""},
	} {
		if got := meshMuxUnitForPort(tc.port); got != tc.want {
			t.Fatalf("unit for port %d = %q, want %q", tc.port, got, tc.want)
		}
	}
}

// TestPortErrorCodesSurviveCheck ensures a failed port probe reports the real
// stable error code instead of blaming a third party for every case.
func TestPortErrorCodesSurviveCheck(t *testing.T) {
	codes := []string{"PORT_OWNERS_UNKNOWN", "PORT_PROBE_FAILED", "PORT_CONFLICT", "PORT_OWNER_UNVERIFIED"}
	for _, code := range codes {
		got := core.NewCheck("port_ownership", code, "act", &portError{code, "act"})
		if got.Status != "fail" || got.Code != code {
			t.Fatalf("check() changed the port code: %+v", got)
		}
		var pe *portError
		if !errors.As(&portError{code, "act"}, &pe) || pe.code != code {
			t.Fatalf("errors.As lost the code for %s", code)
		}
	}
	// A nil port error must keep the default conflict code.
	got := core.NewCheck("port_ownership", "PORT_CONFLICT", "act", nil)
	if got.Status != "pass" {
		t.Fatalf("nil error must pass: %+v", got)
	}
}

func TestCandidateBoundaries(t *testing.T) {
	c := core.Config{ManagementDomain: "console.example.org", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}
	files, err := candidateFiles(c, []int{60794}, false)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 12 {
		t.Fatalf("unexpected files: %d", len(files))
	}
	caddy := files["/etc/meshmux/Caddyfile"]
	headscale := files["/etc/meshmux/headscale.yaml"]
	web := files["/etc/systemd/system/meshmux-web.service"]
	jail := files["/etc/fail2ban/jail.d/meshmux-ssh.local"]
	for _, s := range []string{"console.example.org", "sub.example.org", "mesh.example.org", "reverse_proxy 127.0.0.1:9080", "respond @private 404"} {
		if !strings.Contains(caddy, s) {
			t.Fatalf("missing Caddy protection: %s", s)
		}
	}
	for _, s := range []string{"server_url: https://mesh.example.org", "enabled: true", "stun_listen_addr: \"0.0.0.0:3478\"", "urls: []", "auto_update_enabled: false", "grpc_listen_addr: 127.0.0.1:50443", "trusted_proxies: []"} {
		if !strings.Contains(headscale, s) {
			t.Fatalf("missing Headscale control: %s", s)
		}
	}
	if strings.Contains(web, "User=root") || !strings.Contains(web, "User=meshmux") || !strings.Contains(web, "/usr/local/libexec/meshmuxd __internal-web") ||
		!strings.Contains(web, "--origin https://console.example.org") ||
		!strings.Contains(jail, "port = 60794") || strings.Contains(jail, "port = 22") {
		t.Fatal("unsafe service or SSH jail candidate")
	}
	// The Web service reaches the 0770 Headscale socket through supplementary
	// group membership; the Headscale data directory itself stays 0700 and is
	// not exposed by that membership.
	if !strings.Contains(web, "SupplementaryGroups=meshmux-headscale") {
		t.Fatalf("web unit lacks the Headscale socket group:\n%s", web)
	}
	if !strings.Contains(headscale, "unix_socket_permission: \"0770\"") {
		t.Fatal("headscale config lost the 0770 socket permission the web group depends on")
	}
	// The tailnet ranges come from the mesh domain constants, which also refuse
	// them as subnet routes: one source of truth for both sides.
	for _, want := range []string{"  v4: " + mesh.TailnetIPv4Prefix + "\n", "  v6: " + mesh.TailnetIPv6Prefix + "\n"} {
		if !strings.Contains(headscale, want) {
			t.Fatalf("headscale prefixes missing %q", strings.TrimSpace(want))
		}
	}
	if strings.Contains(web, "Group=meshmux-headscale") || strings.Contains(web, "ReadWritePaths=/var/lib/meshmux-headscale") {
		t.Fatal("web unit gained direct access to the Headscale data directory")
	}
	if files["/etc/fail2ban/jail.d/meshmux-web.local"] == "" || files["/etc/fail2ban/filter.d/meshmux-web.conf"] == "" {
		t.Fatal("Web Fail2ban candidates missing")
	}
	c.DirectCaddy = false
	if _, err := candidateFiles(c, nil, false); err == nil {
		t.Fatal("SSH listen port is mandatory")
	}
	if _, err := candidateFiles(core.Config{ManagementDomain: "x.example.org\nadmin off", SubscriptionDomain: "sub.example.org", HeadscaleDomain: "mesh.example.org", DirectCaddy: false}, []int{22}, false); err == nil {
		t.Fatal("candidate renderer accepted injection")
	}
}
