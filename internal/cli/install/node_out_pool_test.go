package install

import (
	"slices"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestOutNodesHaveNoPoolLimit pins the Task 2 pool rule at the installer
// layer: Out enrollment is per-host and unbounded. Three distinct Out nodes
// plan, render and own their ACL guard independently; no "already have an
// Out" refusal exists anywhere in the plan or render path.
func TestOutNodesHaveNoPoolLimit(t *testing.T) {
	checks := []Check{{Name: "system", Status: "pass"}}
	ids := []string{strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 32)}
	for i, id := range ids {
		cfg := node.Config{
			HubURL: "https://hub.example.invalid", NodeID: id,
			Role: node.RoleOut, VLESSPort: 8443 + i, SSHPort: 2222,
			AgentVersion: node.CurrentAgentVersion(),
		}
		root := t.TempDir()
		plan := BuildNodePlanForRoot(root, "op-pool", cfg, "amd64", checks, []int{2222})
		if plan.Status != "preflight_passed" || !plan.ApplyAvailable {
			t.Fatalf("out %d plan status = %q apply=%v: %+v", i, plan.Status, plan.ApplyAvailable, plan.Checks)
		}
		if !slices.Contains(plan.Units, node.ACLUnit) {
			t.Fatalf("out %d plan does not own the Out ACL unit: %v", i, plan.Units)
		}
		identity := node.Identity{NodeID: id, IdentityToken: strings.Repeat("A", 43)}
		files, err := nodeManagedFilesForLayout(cfg, []int{2222}, identity, standaloneNodeLayout())
		if err != nil {
			t.Fatalf("out %d render failed: %v", i, err)
		}
		if _, ok := files[node.ACLPath]; !ok {
			t.Fatalf("out %d render has no managed ACL guard", i)
		}
	}
}
