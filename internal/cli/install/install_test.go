package install

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDomains(t *testing.T) {
	good := Config{"console.example.org", "sub.example.org", "mesh.example.org", false}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, c := range []Config{
		{"console.example.org", "console.example.org", "mesh.example.org", false},
		{"console.example.org", "sub.example.org", "mesh.example.org\nadmin off", false},
		{"https://console.example.org", "sub.example.org", "mesh.example.org", false},
		{"console.example.org", "sub.example.org", "localhost", false},
		{"CONSOLE.example.org", "sub.example.org", "mesh.example.org", false},
		{"console.example.org", "sub.example.org", "192.0.2.2", false},
		{"console.example.org", "sub.example.org", "foo_.example.org", false},
	} {
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid domain accepted: %+v", c)
		}
	}
}

func TestReleaseDigestsAndImmutableCopy(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		a := PinnedArtifacts(arch)
		if len(a) != 2 {
			t.Fatalf("%s: unexpected assets %+v", arch, a)
		}
		for _, item := range a {
			if !strings.HasPrefix(item.Source, "https://github.com/") || !validDigest.MatchString(item.SHA256) {
				t.Fatalf("%s: unpinned asset %+v", arch, item)
			}
		}
		a[0].SHA256 = strings.Repeat("0", 64)
		if PinnedArtifacts(arch)[0].SHA256 == a[0].SHA256 {
			t.Fatal("manifest pointer escaped")
		}
	}
	if len(PinnedArtifacts("mips")) != 0 {
		t.Fatal("unsupported architecture has artifacts")
	}
}

func TestVerifyFileRejectsTampering(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "candidate")
	data := []byte("artifact")
	if err := os.WriteFile(file, data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if err := VerifyFile(file, hex.EncodeToString(sum[:])); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(file, strings.Repeat("0", 64)); err == nil {
		t.Fatal("modified artifact accepted")
	}
	if err := VerifyFile(file, ""); err == nil {
		t.Fatal("missing digest accepted")
	}
	if err := os.WriteFile(file, append(data, '!'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := VerifyFile(file, hex.EncodeToString(sum[:])); err == nil {
		t.Fatal("corrupted artifact accepted")
	}
}

func TestSSHListeningPorts(t *testing.T) {
	sockets := "0.0.0.0:60794 (Stream)\n[::]:60794 (Stream)\n"
	if got := socketPorts(sockets); len(got) != 1 || got[0] != 60794 {
		t.Fatalf("socket: %v", got)
	}
	ss := "LISTEN 0 128 0.0.0.0:60794 0.0.0.0:* users:((\"sshd\",pid=789,fd=6))\n" +
		"LISTEN 0 128 [::]:60794 [::]:* users:((\"sshd\",pid=789,fd=6))\n" +
		"LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:((\"caddy\",pid=999,fd=6))"
	if got := parseSSHListeners(ss); len(got) != 1 || got[0] != 60794 {
		t.Fatalf("actual SSH ports: %v", got)
	}
	if got := parseSSHDPorts("port 60794\nport 60795\n"); len(got) != 2 {
		t.Fatalf("configured SSH ports: %v", got)
	}
	if len(parseSSHListeners("LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:((\"nginx\",pid=1))")) != 0 {
		t.Fatal("unrelated listener accepted as SSH")
	}
}

func TestReadOnlyPortProbeDetectsConflict(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("cannot listen on a loopback port, network namespace or sandbox restriction: %v", err)
	}
	defer listener.Close()
	if CanBind("tcp", listener.Addr().String()) == nil {
		t.Fatal("occupied port passed")
	}
}

func TestPlanDoesNotMisreportInstallation(t *testing.T) {
	c := Config{"console.example.org", "sub.example.org", "mesh.example.org", false}
	p := BuildPlan("id", c, "amd64", []Check{{Name: "os", Status: "pass"}, {Name: "public_https", Status: "pending"}}, []int{60794})
	if !p.ApplyAvailable || p.Status == "installed" || len(p.FirewallChanges) == 0 {
		t.Fatalf("unsafe plan: %+v", p)
	}
	p = BuildPlan("id", c, "amd64", []Check{{Name: "os", Status: "fail"}}, nil)
	if p.Status != "preflight_blocked" {
		t.Fatalf("failed prerequisite passed: %+v", p)
	}
}

func TestDebianReleaseParser(t *testing.T) {
	if !osSupported("ID=debian\nVERSION_ID=\"13\"\n") || osSupported("ID=ubuntu\nVERSION_ID=\"13\"\n") ||
		osSupported("ID=debian\nVERSION_ID=\"12\"\n") {
		t.Fatal("OS release parser failed")
	}
}
