package node

import (
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

const (
	debian13OSRelease = "ID=debian\nVERSION_ID=\"13\"\nVERSION_CODENAME=trixie\n"
	debian12OSRelease = "ID=debian\nVERSION_ID=\"12\"\nVERSION_CODENAME=bookworm\n"
	debian11OSRelease = "ID=debian\nVERSION_ID=\"11\"\nVERSION_CODENAME=bullseye\n"
)

// TestNodeOSCheck covers the Node OS gate: Debian 13 is the v1.0.0 baseline,
// Debian 12 (bookworm) passes with a recorded experimental warning, and older
// releases stay refused. The Hub gate remains osSupported (Debian 13 only).
func TestNodeOSCheck(t *testing.T) {
	cases := []struct {
		name       string
		osRelease  string
		wantStatus string
		wantCode   string
		// wantDetail lists substrings the pass detail must record; a refused
		// release instead has to name the release it saw.
		wantDetail []string
	}{
		{
			name: "Debian 13 is the baseline", osRelease: debian13OSRelease,
			wantStatus: "pass", wantDetail: []string{"Debian 13 (trixie)", "baseline"},
		},
		{
			name: "Debian 12 passes as experimental", osRelease: debian12OSRelease,
			wantStatus: "pass",
			wantDetail: []string{"Debian 12 (bookworm)", "experimental", "v1.0.0 baseline", "Debian 13"},
		},
		{
			name: "Debian 12 point release keeps the major release", osRelease: "ID=debian\nVERSION_ID=\"12.4\"\nVERSION_CODENAME=bookworm\n",
			wantStatus: "pass", wantDetail: []string{"Debian 12 (bookworm)", "experimental"},
		},
		{
			name: "Debian 11 stays refused", osRelease: debian11OSRelease,
			wantStatus: "fail", wantCode: "OS_UNSUPPORTED", wantDetail: []string{"Debian 11 (bullseye)", "not a supported Node release"},
		},
		{
			name: "a newer release is not assumed supported", osRelease: "ID=debian\nVERSION_ID=\"14\"\nVERSION_CODENAME=forky\n",
			wantStatus: "fail", wantCode: "OS_UNSUPPORTED", wantDetail: []string{"Debian 14 (forky)"},
		},
		{
			name: "Ubuntu stays refused", osRelease: "ID=ubuntu\nVERSION_ID=\"24.04\"\n",
			wantStatus: "fail", wantCode: "OS_UNSUPPORTED", wantDetail: []string{"not Debian"},
		},
		{
			name: "missing VERSION_ID is refused", osRelease: "ID=debian\nVERSION_CODENAME=bookworm\n",
			wantStatus: "fail", wantCode: "OS_UNSUPPORTED", wantDetail: []string{"VERSION_ID"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := nodeOSCheck(tc.osRelease)
			if c.Name != "os" {
				t.Fatalf("os check name = %q", c.Name)
			}
			if c.Status != tc.wantStatus || c.Code != tc.wantCode {
				t.Fatalf("os check = %+v, want status %q code %q", c, tc.wantStatus, tc.wantCode)
			}
			for _, want := range tc.wantDetail {
				if !strings.Contains(c.Detail, want) {
					t.Fatalf("os check detail %q does not record %q", c.Detail, want)
				}
			}
			if c.Status == "pass" && c.Recovery != "" {
				t.Fatalf("a passing os check must not carry a next action: %+v", c)
			}
			if c.Status == "fail" && c.Recovery == "" {
				t.Fatalf("a refused release must state the next action: %+v", c)
			}
		})
	}
}

// TestNodePlanRecordsExperimentalOS proves that accepting Debian 12 never
// mislabels the plan: the OS and the Debian-package components name the release
// that preflight actually saw, the plan stays applicable, and Debian 11 still
// blocks apply.
func TestNodePlanRecordsExperimentalOS(t *testing.T) {
	cfg := componentNodeConfig(corenode.RoleOut)
	plan := BuildNodePlanForRoot(t.TempDir(), strings.Repeat("9", 32), cfg, "amd64",
		[]core.Check{nodeOSCheck(debian12OSRelease)}, []int{2222})
	if plan.OS != "Debian 12" {
		t.Fatalf("Debian 12 plan OS = %q", plan.OS)
	}
	if plan.Status != "preflight_passed" || !plan.ApplyAvailable {
		t.Fatalf("Debian 12 plan was blocked: %+v", plan.Checks)
	}
	for _, component := range plan.Components {
		if component.Name != "Fail2ban" && component.Name != "nftables" {
			continue
		}
		if component.Version != "Debian 12 package" {
			t.Fatalf("%s component still claims %q on Debian 12", component.Name, component.Version)
		}
	}

	plan = BuildNodePlanForRoot(t.TempDir(), strings.Repeat("9", 32), cfg, "amd64",
		[]core.Check{nodeOSCheck(debian11OSRelease)}, []int{2222})
	if plan.OS != "Debian 11" {
		t.Fatalf("Debian 11 plan OS = %q", plan.OS)
	}
	if plan.Status != "preflight_blocked" || plan.ApplyAvailable {
		t.Fatalf("Debian 11 plan was not blocked: %+v", plan.Checks)
	}
}
