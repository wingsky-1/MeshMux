package node

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestBuildNodePlanForRoot covers the four layout outcomes of the only Node
// plan entry point: a standalone host, a layout that cannot be read, a Hub
// host that cannot host a co-located Line, and a co-located Line that reuses
// the Hub-owned runtime binary and SSH jail. Every case runs against an
// isolated temporary root; no host state, package or service is touched.
func TestBuildNodePlanForRoot(t *testing.T) {
	id := strings.Repeat("f", 32)
	baseChecks := []core.Check{
		{Name: "system", Status: "pass"},
		{Name: "external", Status: "pending"},
	}
	standaloneCfg := componentNodeConfig(corenode.RoleEdge)
	coLocatedCfg := corenode.Config{
		HubURL: localLineHubOrigin, NodeID: strings.Repeat("a", 32),
		Role: corenode.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
	}

	cases := []struct {
		name string
		// setup returns the isolated root this plan is built against.
		setup      func(t *testing.T) string
		cfg        corenode.Config
		wantStatus string
		wantApply  bool
		// wantCode is the blocking node_layout code, or "" when the layout
		// resolves and no blocking check may be added.
		wantCode string
		check    func(t *testing.T, plan NodePlan)
	}{
		{
			name: "standalone host plans its own binary and SSH jail",
			setup: func(t *testing.T) string {
				return t.TempDir()
			},
			cfg:        standaloneCfg,
			wantStatus: "preflight_passed",
			wantApply:  true,
			check: func(t *testing.T, plan NodePlan) {
				for _, path := range []string{corenode.AgentBinaryPath, corenode.SingBoxBinaryPath, corenode.AgentConfigPath, core.NodeSSHJailPath} {
					if !slices.Contains(plan.Paths, path) {
						t.Fatalf("standalone plan does not own %s: %v", path, plan.Paths)
					}
				}
				if slices.Contains(plan.Paths, core.HubSSHJailPath) || len(plan.ReusedPaths) != 0 {
					t.Fatalf("standalone plan reused Hub paths: paths=%v reused=%v", plan.Paths, plan.ReusedPaths)
				}
				if !slices.Contains(plan.Units, corenode.AgentUnit) || !slices.Contains(plan.Units, corenode.SingBoxUnit) {
					t.Fatalf("standalone plan units = %v", plan.Units)
				}
				if slices.Contains(plan.Units, corenode.ACLUnit) || plan.ACLTable != "" {
					t.Fatalf("Edge plan claimed Out ACL ownership: units=%v table=%q", plan.Units, plan.ACLTable)
				}
			},
		},
		{
			name: "unreadable layout fails closed through a blocking check",
			setup: func(t *testing.T) string {
				root := t.TempDir()
				path := core.Rooted(root, core.InstallerStatePath)
				if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, []byte("{not a ledger"), 0600); err != nil {
					t.Fatal(err)
				}
				return root
			},
			cfg:        standaloneCfg,
			wantStatus: "preflight_blocked",
			wantApply:  false,
			wantCode:   "INSTALL_STATE_INVALID",
			check: func(t *testing.T, plan NodePlan) {
				if len(plan.ReusedPaths) != 0 {
					t.Fatalf("unreadable layout reused Hub paths: %v", plan.ReusedPaths)
				}
			},
		},
		{
			name: "Hub host without a shared runtime refuses the Line",
			setup: func(t *testing.T) string {
				root := t.TempDir()
				// The Hub publishes no SharedBinaries, so resolveNodeLayout
				// reports HubHost without CoLocated. The Hub ledger records a
				// nil Node by construction and must never prove Node ownership.
				hub := core.InstallState{
					Schema: 1, OperationID: strings.Repeat("1", 32), Status: "installed",
					Config:       core.Config{ManagementDomain: "hub.example.invalid"},
					ManagedFiles: map[string]string{},
				}
				if err := core.WriteState(root, hub); err != nil {
					t.Fatal(err)
				}
				return root
			},
			cfg:        standaloneCfg,
			wantStatus: "preflight_blocked",
			wantApply:  false,
			wantCode:   core.NodeOwnershipUnverified,
			check: func(t *testing.T, plan NodePlan) {
				if len(plan.ReusedPaths) != 0 || slices.Contains(plan.Paths, core.HubSSHJailPath) {
					t.Fatalf("refused Line fell back to the Hub ledger: paths=%v reused=%v", plan.Paths, plan.ReusedPaths)
				}
			},
		},
		{
			name: "co-located Line reuses the Hub runtime and SSH jail",
			setup: func(t *testing.T) string {
				root := t.TempDir()
				hub, _ := writeLocalLineHubLedger(t, root, []int{2222})
				if hub.Node != nil {
					t.Fatal("fixture Hub ledger unexpectedly records a Node")
				}
				return root
			},
			cfg:        coLocatedCfg,
			wantStatus: "preflight_passed",
			wantApply:  true,
			check: func(t *testing.T, plan NodePlan) {
				for _, path := range []string{core.RuntimeBinaryPath, core.HubSSHJailPath} {
					if !slices.Contains(plan.ReusedPaths, path) {
						t.Fatalf("co-located plan does not reuse %s: %v", path, plan.ReusedPaths)
					}
				}
				for _, path := range []string{corenode.AgentBinaryPath, core.NodeSSHJailPath} {
					if slices.Contains(plan.Paths, path) {
						t.Fatalf("co-located plan claims the Hub-owned %s: %v", path, plan.Paths)
					}
				}
				if !slices.Contains(plan.Paths, corenode.SingBoxBinaryPath) {
					t.Fatalf("co-located plan lost its own kernel path: %v", plan.Paths)
				}
				if len(plan.Components) == 0 || !strings.Contains(plan.Components[0].Distribution, "reuses the Hub-owned runtime binary") {
					t.Fatalf("co-located plan does not describe the reused Agent: %+v", plan.Components)
				}
				if slices.Contains(plan.Units, corenode.ACLUnit) {
					t.Fatalf("Edge plan claimed the Out ACL unit: %v", plan.Units)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := tc.setup(t)
			plan := BuildNodePlanForRoot(root, id, tc.cfg, "amd64", baseChecks, []int{2222})

			if plan.OperationID != id || plan.Stage != "plan" || plan.OS != "Debian 13" || plan.Architecture != "amd64" {
				t.Fatalf("plan identity = %+v", plan)
			}
			if plan.Config != tc.cfg {
				t.Fatalf("plan config = %+v, want %+v", plan.Config, tc.cfg)
			}
			if plan.Status != tc.wantStatus || plan.ApplyAvailable != tc.wantApply {
				t.Fatalf("plan status = %q apply=%v, want %q apply=%v: %+v", plan.Status, plan.ApplyAvailable, tc.wantStatus, tc.wantApply, plan.Checks)
			}
			release, ok := corenode.KernelReleaseFor("amd64")
			if !ok || plan.Kernel != release {
				t.Fatalf("plan kernel = %+v, want pinned %+v", plan.Kernel, release)
			}
			if !slices.Contains(plan.ExternalPending, "external") {
				t.Fatalf("pending external evidence lost: %v", plan.ExternalPending)
			}

			if tc.wantCode == "" {
				if len(plan.Checks) != len(baseChecks) || !slices.Equal(plan.Checks, baseChecks) {
					t.Fatalf("resolved layout changed preflight checks: %+v", plan.Checks)
				}
			} else {
				if len(plan.Checks) != len(baseChecks)+1 {
					t.Fatalf("blocking plan checks = %+v", plan.Checks)
				}
				if !slices.Equal(plan.Checks[:len(baseChecks)], baseChecks) {
					t.Fatalf("blocking check replaced preflight evidence: %+v", plan.Checks)
				}
				blocked := plan.Checks[len(baseChecks)]
				if blocked.Name != "node_layout" || blocked.Status != "fail" || blocked.Code != tc.wantCode || blocked.Recovery == "" {
					t.Fatalf("blocking check = %+v, want code %q with recovery", blocked, tc.wantCode)
				}
			}

			tc.check(t, plan)
		})
	}
}
