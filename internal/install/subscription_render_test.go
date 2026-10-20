package install

import (
	"regexp"
	"strings"
	"testing"
)

// siteOpen matches the first line of a Caddy site block: a bare hostname
// followed by "{". Nested blocks such as "route {" carry a space and never
// match.
var siteOpen = regexp.MustCompile(`^[a-z0-9]([a-z0-9.-]*[a-z0-9])? \{$`)

// caddyVhost returns the rendered Caddy site block for one hostname. The
// block ends at the next line that opens another site, so nested route
// blocks stay inside the returned text.
func caddyVhost(t *testing.T, caddyfile, host string) string {
	t.Helper()
	lines := strings.Split(caddyfile, "\n")
	start := -1
	for i, line := range lines {
		if strings.TrimSpace(line) == host+" {" {
			start = i
			break
		}
	}
	if start < 0 {
		t.Fatalf("no site block for %q", host)
	}
	end := len(lines)
	for i := start + 1; i < len(lines); i++ {
		// A site block opens with a bare hostname followed by "{".
		if siteOpen.MatchString(lines[i]) {
			end = i
			break
		}
	}
	return strings.Join(lines[start:end], "\n")
}

// TestSubscriptionVhostProxiesOnlySubscriptionPath pins the subscription
// hostname: the two fixed download routes are proxied to the loopback Web,
// and every other path stays a plain 404. The management hostname must not
// grow the download routes, and the Headscale hostname must stay untouched.
func TestSubscriptionVhostProxiesOnlySubscriptionPath(t *testing.T) {
	files, err := CandidateFiles(Config{"console.example.org", "sub.example.org", "mesh.example.org", false}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	caddy := files["/etc/meshmux/Caddyfile"]
	sub := caddyVhost(t, caddy, "sub.example.org")

	if !strings.Contains(sub, "@subscription path /subscription/*") {
		t.Fatalf("subscription vhost does not match the download path: %s", sub)
	}
	if !strings.Contains(sub, "reverse_proxy @subscription 127.0.0.1:9080") {
		t.Fatalf("subscription vhost does not proxy to the loopback Web: %s", sub)
	}
	if !strings.Contains(sub, "respond 404") {
		t.Fatalf("subscription vhost does not answer 404 for other paths: %s", sub)
	}
	// The old placeholder response is gone: the subscription host now serves
	// the real download routes.
	if strings.Contains(caddy, "Subscription service is not yet installed") {
		t.Fatal("subscription host still answers the placeholder 404")
	}
	// The proxy must be the first handler inside route so the 404 fallback
	// can never shadow the download routes.
	proxyAt := strings.Index(sub, "reverse_proxy @subscription")
	respondAt := strings.Index(sub, "respond 404")
	if proxyAt < 0 || respondAt < 0 || proxyAt > respondAt {
		t.Fatalf("subscription proxy must precede the 404 fallback: %s", sub)
	}
	if !strings.Contains(sub, "route {") {
		t.Fatalf("subscription vhost needs route to keep the handler order: %s", sub)
	}
	// The subscription host must not expose the management surface or the
	// Headscale surface.
	for _, forbidden := range []string{"/api/*", "/swagger*", "/metrics*", "/debug/*", "127.0.0.1:8080"} {
		if strings.Contains(sub, forbidden) {
			t.Fatalf("subscription vhost exposes %q: %s", forbidden, sub)
		}
	}
	// The management host keeps its own surface and gains no download route.
	management := caddyVhost(t, caddy, "console.example.org")
	if strings.Contains(management, "/subscription/*") {
		t.Fatalf("management host must not serve the subscription routes: %s", management)
	}
	if !strings.Contains(management, "reverse_proxy 127.0.0.1:9080") {
		t.Fatalf("management host lost its proxy: %s", management)
	}
	// The Headscale host keeps only its private-path guard.
	mesh := caddyVhost(t, caddy, "mesh.example.org")
	if strings.Contains(mesh, "/subscription/*") {
		t.Fatalf("Headscale host must not serve the subscription routes: %s", mesh)
	}
	if !strings.Contains(mesh, "respond @private 404") || !strings.Contains(mesh, "reverse_proxy 127.0.0.1:8080") {
		t.Fatalf("Headscale host lost its private guard: %s", mesh)
	}
}

// TestSubscriptionVhostDropsClientSuppliedClientIP makes sure a client cannot
// forge the trusted client-IP header through the public subscription host.
// The header is only meaningful on the management host, which Caddy sets
// itself from the transport peer.
func TestSubscriptionVhostDropsClientSuppliedClientIP(t *testing.T) {
	files, err := CandidateFiles(Config{"console.example.org", "sub.example.org", "mesh.example.org", false}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	sub := caddyVhost(t, files["/etc/meshmux/Caddyfile"], "sub.example.org")
	if !strings.Contains(sub, "header_up -X-MeshMux-Client-IP") {
		t.Fatalf("subscription vhost does not strip the client-IP header: %s", sub)
	}
	if strings.Contains(sub, "header_up X-MeshMux-Client-IP") {
		t.Fatalf("subscription vhost must not set the trusted client-IP header: %s", sub)
	}
}

// TestSubscriptionVhostKeepsRequestHost verifies the download request keeps
// its own hostname. Caddy preserves the Host header by default; an explicit
// rewrite could drop a non-default port, so the renderer must not add one.
func TestSubscriptionVhostKeepsRequestHost(t *testing.T) {
	files, err := CandidateFiles(Config{"console.example.org", "sub.example.org", "mesh.example.org", false}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	sub := caddyVhost(t, files["/etc/meshmux/Caddyfile"], "sub.example.org")
	for _, forbidden := range []string{"header_up Host", "header_up -Host"} {
		if strings.Contains(sub, forbidden) {
			t.Fatalf("subscription vhost rewrites the request host (%q): %s", forbidden, sub)
		}
	}
}

// TestSubscriptionVhostHasNoAccessLog keeps the subscription host free of
// request logging: a logged download URL would leak the bearer token.
func TestSubscriptionVhostHasNoAccessLog(t *testing.T) {
	files, err := CandidateFiles(Config{"console.example.org", "sub.example.org", "mesh.example.org", false}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	caddy := files["/etc/meshmux/Caddyfile"]
	for _, forbidden := range []string{"log {", "output file", "format json"} {
		if strings.Contains(caddy, forbidden) {
			t.Fatalf("Caddyfile enables access logging (%q); download URLs must never be logged", forbidden)
		}
	}
}

// TestWebUnitCarriesSubscriptionOrigin pins the systemd wiring: the Web
// service must receive the exact subscription origin so the two fixed
// download routes are served on the dedicated hostname only.
func TestWebUnitCarriesSubscriptionOrigin(t *testing.T) {
	files, err := CandidateFiles(Config{"console.example.org", "sub.example.org", "mesh.example.org", false}, []int{60794})
	if err != nil {
		t.Fatal(err)
	}
	unit := files["/etc/systemd/system/meshmux-web.service"]
	want := "ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080" +
		" --origin https://console.example.org --subscription-origin https://sub.example.org" +
		" --data-dir /var/lib/meshmux"
	if !strings.Contains(unit, want) {
		t.Fatalf("web unit does not carry the subscription origin:\n%s", unit)
	}
	// The management origin and the subscription origin must not be swapped.
	if strings.Contains(unit, "--origin https://sub.example.org") {
		t.Fatalf("management origin was replaced by the subscription origin:\n%s", unit)
	}
	// The unit must stay an unprivileged service.
	if strings.Contains(unit, "User=root") || !strings.Contains(unit, "User=meshmux") {
		t.Fatalf("web unit lost its unprivileged user:\n%s", unit)
	}
}
