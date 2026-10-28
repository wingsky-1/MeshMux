package node

import (
	"strings"
	"testing"

	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestRepairCandidateNotice pins the fixed repair candidate decision (#113
// 4-4): the notice exists only when a repair really kept a recorded candidate
// the Hub no longer offers, and it always names both sides.
func TestRepairCandidateNotice(t *testing.T) {
	cfg := corenode.Config{NodeID: strings.Repeat("a", 32), Role: corenode.RoleEdge, VLESSPort: 8443, SSHPort: 2222}
	base := corenode.Candidate{NodeID: cfg.NodeID, Role: cfg.Role, Revision: 1, VLESSPort: cfg.VLESSPort, KernelVersion: corenode.KernelVersion}
	recorded := corenode.NewCandidateDocument(base)
	other := base
	other.Revision = 2
	reRendered := base
	reRendered.Users = []corenode.VLESSUser{{CredentialID: strings.Repeat("a", 32), UUID: "8f1c0f9e-1d2a-4c3b-8a41-2f5b6c7d8e90"}}

	for _, tc := range []struct {
		name       string
		repair     bool
		downloaded corenode.CandidateDocument
		wantEmpty  bool
		wantText   []string
	}{
		{name: "fresh install", downloaded: corenode.NewCandidateDocument(other), wantEmpty: true},
		{name: "no candidate offered", repair: true, wantEmpty: true},
		{name: "same candidate", repair: true, downloaded: recorded, wantEmpty: true},
		{
			name: "another revision", repair: true, downloaded: corenode.NewCandidateDocument(other),
			wantText: []string{repairCandidateNotConverged, "revision 1", "revision 2"},
		},
		{
			name: "same revision, another document", repair: true, downloaded: corenode.NewCandidateDocument(reRendered),
			wantText: []string{repairCandidateNotConverged, "the different document for revision 1"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := repairCandidateNotice(tc.repair, tc.downloaded, recorded)
			if tc.wantEmpty {
				if got != "" {
					t.Fatalf("notice = %q, want none", got)
				}
				return
			}
			if !strings.HasPrefix(got, repairCandidateNotConverged) {
				t.Fatalf("notice does not start with the stable code: %q", got)
			}
			for _, want := range tc.wantText {
				if !strings.Contains(got, want) {
					t.Fatalf("notice %q is missing %q", got, want)
				}
			}
		})
	}
}
