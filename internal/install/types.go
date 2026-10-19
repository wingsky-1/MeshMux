// Package install implements the read-only Hub preflight and immutable release plan.
// Host mutations belong to the separately audited apply phase of Issue #5.
package install

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
)

const (
	WebPort       = 9080
	HeadscalePort = 8080
	STUNPort      = 3478
)

type Config struct {
	ManagementDomain   string `json:"management_domain"`
	SubscriptionDomain string `json:"subscription_domain"`
	HeadscaleDomain    string `json:"headscale_domain"`
	DirectCaddy        bool   `json:"direct_caddy,omitempty"`
}

func SameConfig(a, b Config) bool {
	return a.ManagementDomain == b.ManagementDomain &&
		a.SubscriptionDomain == b.SubscriptionDomain &&
		a.HeadscaleDomain == b.HeadscaleDomain &&
		a.DirectCaddy == b.DirectCaddy
}

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Validate rejects characters that could inject a Caddyfile, YAML, or unit directive.
func (c Config) Validate() error {
	domains := []string{c.ManagementDomain, c.SubscriptionDomain, c.HeadscaleDomain}
	seen := map[string]bool{}
	for _, name := range domains {
		if len(name) < 4 || len(name) > 253 || name != strings.ToLower(name) ||
			strings.HasSuffix(name, ".") || strings.ContainsAny(name, ":/\\ \t\n\r\"'") ||
			net.ParseIP(name) != nil || name == "localhost" {
			return errors.New("DOMAIN_INVALID: supply three lowercase public DNS names")
		}
		parts := strings.Split(name, ".")
		if len(parts) < 2 || len(parts[len(parts)-1]) < 2 {
			return errors.New("DOMAIN_INVALID: a domain must contain a nonempty public suffix")
		}
		for _, part := range parts {
			if !label.MatchString(part) {
				return fmt.Errorf("DOMAIN_INVALID: invalid DNS label")
			}
		}
		if seen[name] {
			return errors.New("DOMAIN_DUPLICATE: use separate management, subscription and Headscale domains")
		}
		seen[name] = true
	}
	return nil
}

type Check struct {
	Name     string `json:"name"`
	Status   string `json:"status"` // pass, fail, pending
	Code     string `json:"error_code,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Recovery string `json:"next_action,omitempty"`
}

type Port struct {
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Service  string `json:"service"`
}

type Component struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Distribution string `json:"distribution"`
}

type Plan struct {
	OperationID     string      `json:"operation_id"`
	Stage           string      `json:"stage"`
	Status          string      `json:"status"`
	OS              string      `json:"os"`
	Architecture    string      `json:"architecture"`
	Config          Config      `json:"config"`
	Checks          []Check     `json:"checks"`
	Artifacts       []Artifact  `json:"artifacts"`
	Components      []Component `json:"components"`
	Ports           []Port      `json:"ports"`
	Units           []string    `json:"systemd_units"`
	Paths           []string    `json:"managed_paths"`
	FirewallChanges []string    `json:"firewall_changes"`
	SSHPPorts       []int       `json:"ssh_listening_ports,omitempty"`
	ApplyAvailable  bool        `json:"apply_available"`
	NextAction      string      `json:"next_action"`
}

// NewOperationID generates an ID without using environment or user data.
func NewOperationID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

func Ports() []Port {
	return []Port{
		{"tcp", 80, "Caddy ACME HTTP-01"},
		{"tcp", 443, "Caddy HTTPS / Headscale DERP"},
		{"udp", STUNPort, "Headscale embedded STUN"},
		{"tcp", WebPort, "MeshMux Web loopback"},
		{"tcp", HeadscalePort, "Headscale loopback"},
		{"tcp", 50443, "Headscale gRPC loopback"},
	}
}

func BuildPlan(id string, c Config, architecture string, checks []Check, ssh []int) Plan {
	ready := true
	for _, check := range checks {
		if check.Status == "fail" {
			ready = false
			break
		}
	}
	status := "preflight_passed"
	if !ready {
		status = "preflight_blocked"
	}
	return Plan{
		OperationID: id, Stage: "plan", Status: status, OS: "Debian 13", Architecture: architecture,
		Config: c, Checks: checks, Artifacts: PinnedArtifacts(architecture),
		Components: []Component{{"MeshMux Web", "same executable as the invoked CLI", "self-copy verified by SHA-256"}, {"Caddy", "2.11.7", "pinned upstream GitHub asset"}, {"Headscale", "0.29.5", "pinned upstream GitHub asset"}, {"sing-box", "1.14.3 (not installed in Hub phase)", "deferred to Issue #7"}, {"Fail2ban", "Debian 13 package version", "Debian official apt repository"}, {"nftables", "Debian 13 package version", "Debian official apt repository"}},
		Ports:      Ports(), SSHPPorts: ssh,
		Units:           []string{"meshmux-web.service", "meshmux-headscale.service", "meshmux-caddy.service", "fail2ban.service"},
		Paths:           []string{"/etc/meshmux/", "/var/lib/meshmux/", "/var/lib/meshmux-headscale/", "/var/lib/meshmux-caddy/", "/var/lib/meshmux-installer/state.json", "/usr/local/libexec/meshmuxd", "/usr/local/libexec/meshmux-caddy", "/usr/local/libexec/meshmux-headscale", "/etc/fail2ban/jail.d/meshmux-ssh.local", "/etc/fail2ban/filter.d/meshmux-web.conf"},
		FirewallChanges: []string{"none in preflight (do not replace the host nftables ruleset)"},
		ApplyAvailable:  ready,
		NextAction:      "After reviewing this plan, confirm with the exact prompt or pass --yes. Installation re-runs preflight, stages and validates pinned artifacts, applies only MeshMux-owned files, then verifies services and HTTPS. Public ingress and UDP reachability remain separately reported.",
	}
}
