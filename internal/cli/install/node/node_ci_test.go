package node

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

func componentNodeConfig(role corenode.Role) corenode.Config {
	return corenode.Config{
		HubURL:       "https://127.0.0.1:19443",
		NodeID:       strings.Repeat("a", 32),
		Role:         role,
		VLESSPort:    8443,
		SSHPort:      2222,
		AgentVersion: corenode.CurrentAgentVersion(),
		AgentSHA256:  strings.Repeat("b", 64),
		KernelSHA256: strings.Repeat("c", 64),
	}
}

func componentNodeCandidate(role corenode.Role) corenode.Candidate {
	return corenode.Candidate{
		NodeID:        strings.Repeat("a", 32),
		Role:          role,
		Revision:      1,
		VLESSPort:     8443,
		KernelVersion: corenode.KernelVersion,
	}
}

// TestWriteNodeComponentFixtures renders the same candidate, ACL, units and
// jail used by the installer. It is inert during ordinary go test runs.
func TestWriteNodeComponentFixtures(t *testing.T) {
	dir := os.Getenv("MESHMUX_NODE_FIXTURE_DIR")
	if dir == "" {
		t.Skip("MESHMUX_NODE_FIXTURE_DIR is not set: only used by the Debian 13 Node component integration CI")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identity := corenode.Identity{NodeID: strings.Repeat("a", 32), IdentityToken: strings.Repeat("A", 43)}
	for _, role := range []corenode.Role{corenode.RoleEdge, corenode.RoleOut} {
		roleDir := filepath.Join(dir, string(role))
		if err := os.MkdirAll(roleDir, 0700); err != nil {
			t.Fatal(err)
		}
		cfg := componentNodeConfig(role)
		candidate := componentNodeCandidate(role)
		configBody, err := corenode.CompileCandidate(candidate)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(roleDir, "candidate.json"), configBody, 0600); err != nil {
			t.Fatal(err)
		}
		document, err := json.Marshal(corenode.NewCandidateDocument(candidate))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(roleDir, "candidate-document.json"), document, 0600); err != nil {
			t.Fatal(err)
		}
		files, err := nodeManagedFilesForLayout(cfg, []int{2222}, identity, core.StandaloneNodeLayout())
		if err != nil {
			t.Fatal(err)
		}
		for path, file := range files {
			if err := os.WriteFile(filepath.Join(roleDir, filepath.Base(path)), []byte(file.Body), 0600); err != nil {
				t.Fatal(err)
			}
		}
		acl, err := corenode.CompileACL(candidate, nil)
		if err != nil {
			t.Fatal(err)
		}
		if role == corenode.RoleOut {
			if len(acl) == 0 || !bytes.Contains(acl, []byte("table inet meshmux_out")) ||
				!bytes.Contains(acl, []byte("type filter hook input priority -10; policy accept;")) ||
				bytes.Contains(acl, []byte(" saddr ")) || bytes.Contains(acl, []byte(" dport ")) {
				t.Fatalf("Out ACL is not the retired, rule-free table:\n%s", acl)
			}
			if err := os.WriteFile(filepath.Join(roleDir, "acl.nft"), acl, 0600); err != nil {
				t.Fatal(err)
			}
		} else if acl != nil {
			t.Fatal("Edge unexpectedly rendered an Out ACL")
		}
	}
	var releases strings.Builder
	releases.WriteString("architecture\tversion\tsource_url\tarchive_sha256\tbinary_sha256\n")
	for _, arch := range []string{"amd64", "arm64"} {
		release, ok := corenode.KernelReleaseFor(arch)
		if !ok {
			t.Fatalf("%s Node kernel release is not pinned", arch)
		}
		if release.Version != corenode.KernelVersion ||
			!strings.HasPrefix(release.SourceURL, "https://github.com/SagerNet/sing-box/releases/download/v") {
			t.Fatalf("%s Node release is not the fixed official version: %+v", arch, release)
		}
		if len(release.ArchiveSHA256) != 64 || len(release.BinarySHA256) != 64 {
			t.Fatalf("%s Node release digests are incomplete: %+v", arch, release)
		}
		if _, err := fmt.Fprintf(&releases, "%s\t%s\t%s\t%s\t%s\n",
			arch, release.Version, release.SourceURL, release.ArchiveSHA256, release.BinarySHA256); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "releases.tsv"), []byte(releases.String()), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestNodeComponentFixturesStayRoleAndPortBound(t *testing.T) {
	for _, role := range []corenode.Role{corenode.RoleEdge, corenode.RoleOut} {
		identity := corenode.Identity{NodeID: strings.Repeat("a", 32), IdentityToken: strings.Repeat("A", 43)}
		files, err := nodeManagedFilesForLayout(componentNodeConfig(role), []int{2222}, identity, core.StandaloneNodeLayout())
		if err != nil {
			t.Fatal(err)
		}
		jail := files["/etc/fail2ban/jail.d/meshmux-node-ssh.local"].Body
		if !strings.Contains(jail, "port = 2222") || strings.Contains(jail, "port = 22\n") {
			t.Fatalf("%s jail does not bind the actual SSH listener:\n%s", role, jail)
		}
		agent := files["/etc/systemd/system/"+corenode.AgentUnit].Body
		if !strings.Contains(agent, "ReadWritePaths=/var/lib/meshmux-agent /var/lib/meshmux-singbox\n") ||
			strings.Contains(agent, "ReadWritePaths=/var/lib/meshmux-agent /var/lib/meshmux-singbox /") ||
			!strings.Contains(agent, "CAP_SYS_PTRACE") {
			t.Fatalf("%s Agent sandbox does not expose only the required read/write roots and process inspection capability:\n%s", role, agent)
		}
		_, hasACL := files[corenode.ACLPath]
		if hasACL != (role == corenode.RoleOut) {
			t.Fatalf("%s ACL presence = %v", role, hasACL)
		}
		acl, err := corenode.CompileACL(componentNodeCandidate(role), nil)
		if err != nil {
			t.Fatal(err)
		}
		if role == corenode.RoleEdge {
			if acl != nil {
				t.Fatal("Edge unexpectedly rendered an Out ACL")
			}
			continue
		}
		if !bytes.Contains(acl, []byte("table inet meshmux_out")) ||
			!bytes.Contains(acl, []byte("type filter hook input priority -10; policy accept;")) ||
			bytes.Contains(acl, []byte(" saddr ")) || bytes.Contains(acl, []byte(" dport ")) ||
			bytes.Contains(acl, []byte(" drop")) {
			t.Fatalf("Out ACL is not the retired, rule-free table:\n%s", acl)
		}
		unit := files["/etc/systemd/system/"+corenode.ACLUnit].Body
		kernel := files["/etc/systemd/system/"+corenode.SingBoxUnit].Body
		if !strings.Contains(unit, "ExecStart=/usr/sbin/nft -f /var/lib/meshmux-agent/out.nft") ||
			!strings.Contains(kernel, "Requires=meshmux-out-acl.service\n") ||
			!strings.Contains(kernel, "After=meshmux-out-acl.service\n") {
			t.Fatalf("Out ACL unit ordering is incomplete:\nunit:\n%s\nkernel:\n%s", unit, kernel)
		}
	}
}

func TestNodePlanUsesPinnedKernelAndRoleUnits(t *testing.T) {
	for _, role := range []corenode.Role{corenode.RoleEdge, corenode.RoleOut} {
		plan := BuildNodePlanForRoot(t.TempDir(), strings.Repeat("d", 32), componentNodeConfig(role), "amd64",
			[]core.Check{{Name: "system", Status: "pass"}}, []int{2222})
		wantKernel, ok := corenode.KernelReleaseFor("amd64")
		if !ok {
			t.Fatal("amd64 kernel release is not pinned")
		}
		if plan.Kernel != wantKernel {
			t.Fatalf("%s plan kernel is not the pinned release: %+v", role, plan.Kernel)
		}
		joined := strings.Join(plan.Units, ",")
		if !strings.Contains(joined, corenode.AgentUnit) || !strings.Contains(joined, corenode.SingBoxUnit) {
			t.Fatalf("%s plan omitted required units: %s", role, joined)
		}
		if strings.Contains(joined, corenode.ACLUnit) != (role == corenode.RoleOut) {
			t.Fatalf("%s plan ACL unit membership is wrong: %s", role, joined)
		}
	}
}
