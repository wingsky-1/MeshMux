package install

import (
	"strings"
	"testing"
)

func TestCandidateBoundaries(t *testing.T) {
	c := Config{"console.example.org", "sub.example.org", "mesh.example.org", false}
	files, err := CandidateFiles(c, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 8 {
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
	if files["/etc/fail2ban/jail.d/meshmux-web.local"] == "" || files["/etc/fail2ban/filter.d/meshmux-web.conf"] == "" || !strings.Contains(files["/etc/fail2ban/jail.d/meshmux-web.local"], "enabled = false") {\n\t\tt.Fatal("Web Fail2ban must remain disabled behind an unverified proxy")\n\t}\n\tc.DirectCaddy = true\n\tdirectFiles, err := CandidateFiles(c, []int{60794})\n\tif err != nil || !strings.Contains(directFiles["/etc/fail2ban/jail.d/meshmux-web.local"], "enabled = true") || !strings.Contains(directFiles["/etc/systemd/system/meshmux-web.service"], "--direct-caddy") {\n\t\tt.Fatal("direct-Caddy opt-in did not enable the trusted-client mode")\n\t}\n\tc.DirectCaddy = false\n\tif _, err := CandidateFiles(c, nil); err == nil {
		t.Fatal("SSH listen port is mandatory")
	}
	if _, err := CandidateFiles(Config{"x.example.org\nadmin off", "sub.example.org", "mesh.example.org", false}, []int{22}); err == nil {
		t.Fatal("candidate renderer accepted injection")
	}
}
