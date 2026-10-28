package node

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// TestNodeInstalledRejectsNonRepairReinstall pins the v1.0.0 rule: an
// installed Node is never overwritten in place. Operators must use --repair
// with the same Node configuration.
func TestNodeInstalledRejectsNonRepairReinstall(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	before, err := os.ReadFile(core.Rooted(f.root, corenode.ActiveConfigPath))
	if err != nil {
		t.Fatalf("active config missing after first install: %v", err)
	}
	result, err := f.install(t, false, strings.Repeat("B", 43))
	if err == nil {
		t.Fatalf("non-repair reinstall over installed state succeeded: %+v", result)
	}
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != "REINSTALL_REJECTED" {
		t.Fatalf("reinstall error = %v, want REINSTALL_REJECTED", err)
	}
	if result.Stage != "preflight" || result.Status != "failed" {
		t.Fatalf("reinstall result = %+v, want failed preflight", result)
	}
	after, err := os.ReadFile(core.Rooted(f.root, corenode.ActiveConfigPath))
	if err != nil {
		t.Fatalf("active config missing after rejected reinstall: %v", err)
	}
	if string(after) != string(before) {
		t.Fatal("rejected reinstall modified the active configuration")
	}
	state, exists, err := core.ReadState(f.root)
	if err != nil || !exists || state.Status != "installed" {
		t.Fatalf("ledger changed after rejected reinstall: %+v %v", state, err)
	}
}

// TestNodeRepairRevokedIdentityRequiresFreshCode pins the revoked-identity
// recovery path: repair without a code fails closed with PAIRING_REQUIRED
// (which the CLI retries after prompting), and repair with a fresh code
// re-pairs, persists the new identity and completes.
func TestNodeRepairRevokedIdentityRequiresFreshCode(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	compiled, err := corenode.CompileCandidate(f.candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	compiledHash := sha256.Sum256(compiled)
	f.opts.Readback = func(context.Context, corenode.Config, string, corenode.CommandRunner) (corenode.Readback, error) {
		return corenode.Readback{
			Architecture: "amd64", AgentVersion: corenode.CurrentAgentVersion(),
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: corenode.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 7,
			ConfigSHA256: hex.EncodeToString(compiledHash[:]), LocalActive: true,
		}, nil
	}
	revoked := &corenode.ClientError{Code: "AGENT_UNAUTHORIZED", StatusCode: 401}
	f.opts.Metadata = func(context.Context, corenode.Config, corenode.Identity) (corenode.Metadata, error) {
		return corenode.Metadata{}, revoked
	}
	f.opts.Candidate = func(context.Context, corenode.Config, corenode.Identity, int64) (corenode.CandidateDocument, error) {
		return corenode.CandidateDocument{}, revoked
	}
	_, err = f.install(t, true, "")
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != "PAIRING_REQUIRED" {
		t.Fatalf("revoked repair without code = %v, want PAIRING_REQUIRED", err)
	}
	fresh := corenode.Identity{NodeID: f.cfg.NodeID, IdentityToken: strings.Repeat("B", 43)}
	pairCalls := 0
	f.opts.Pair = func(_ context.Context, _ corenode.Config, code string) (corenode.Identity, error) {
		pairCalls++
		if code != strings.Repeat("C", 43) {
			return corenode.Identity{}, errors.New("repair must forward the fresh code")
		}
		return fresh, nil
	}
	f.opts.Metadata = func(context.Context, corenode.Config, corenode.Identity) (corenode.Metadata, error) {
		return f.cfg.Metadata(), nil
	}
	f.opts.Candidate = func(context.Context, corenode.Config, corenode.Identity, int64) (corenode.CandidateDocument, error) {
		return f.candidate, nil
	}
	result, err := f.install(t, true, strings.Repeat("C", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("repair with fresh code = %+v %v", result, err)
	}
	if pairCalls != 1 {
		t.Fatalf("repair with fresh code called Pair %d times, want 1", pairCalls)
	}
	stored, loaded, err := loadNodeIdentity(f.root, f.cfg)
	if err != nil || !loaded || stored.IdentityToken != fresh.IdentityToken {
		t.Fatalf("repair did not persist the fresh identity: %+v %v %v", stored, loaded, err)
	}
}

// TestNodeRepairNetworkFailureKeepsMetadataError pins the other side of the
// revocation branch: transport failures still report PAIRING_METADATA_FAILED
// and never prompt for a fresh code.
func TestNodeRepairNetworkFailureKeepsMetadataError(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	boom := errors.New("fixture network failure")
	f.opts.Metadata = func(context.Context, corenode.Config, corenode.Identity) (corenode.Metadata, error) {
		return corenode.Metadata{}, boom
	}
	f.opts.Candidate = func(context.Context, corenode.Config, corenode.Identity, int64) (corenode.CandidateDocument, error) {
		return corenode.CandidateDocument{}, boom
	}
	_, err := f.install(t, true, "")
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != "PAIRING_METADATA_FAILED" {
		t.Fatalf("network failure repair = %v, want PAIRING_METADATA_FAILED", err)
	}
}

// TestOutFirstInstallStartsACLAfterDynamicFiles emulates a clean host where
// applying the Out ACL table fails while /var/lib/meshmux-agent/out.nft is
// absent. The ACL unit must start only after installNodeDynamic writes it.
func TestOutFirstInstallStartsACLAfterDynamicFiles(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleOut)
	f.runner.aclRequiresFile = core.Rooted(f.root, corenode.ACLPath)
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("Out first install = %+v %v", result, err)
	}
	found := false
	for _, call := range f.runner.calls {
		if strings.Contains(call, corenode.ACLUnit) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Out first install never started the ACL unit")
	}
	if _, err := os.Stat(core.Rooted(f.root, corenode.ACLPath)); err != nil {
		t.Fatalf("Out ACL file missing after install: %v", err)
	}
}

// TestNodeLKGRejectsStaleOutACL pins the repair fast path for the retired Out
// guard: a last-known-good data plane must include the neutral, rule-free ACL
// render. A byte that is not the canonical render (here a trailing newline) is
// not LKG, and a missing file is not LKG either.
func TestNodeLKGRejectsStaleOutACL(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleOut)
	dir := core.Rooted(f.root, nodeKernelDataDir)
	if err := os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	if err := ensurePrivateNodeDirectory(core.Rooted(f.root, nodeAgentStateDir)); err != nil {
		t.Fatal(err)
	}
	document := f.candidate
	body, err := jsonMarshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(core.Rooted(f.root, corenode.ActiveCandidatePath), body, 0600); err != nil {
		t.Fatal(err)
	}
	compiled, err := corenode.CompileCandidate(document.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	// writeBytesAtomic sets exact modes; os.WriteFile is umask-filtered and
	// would turn 0640 into 0600 under a strict umask.
	if err := core.WriteBytesAtomic(core.Rooted(f.root, corenode.ActiveConfigPath), compiled, 0640); err != nil {
		t.Fatal(err)
	}
	acl, err := corenode.CompileACL(document.Candidate(), nil)
	if err != nil {
		t.Fatal(err)
	}
	aclPath := core.Rooted(f.root, corenode.ACLPath)
	if err := os.WriteFile(aclPath, acl, 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(f.root, f.cfg); !ok {
		t.Fatal("neutral Out data plane was not accepted as LKG")
	}
	if err := os.WriteFile(aclPath, append(append([]byte{}, acl...), '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("stale Out ACL was accepted as LKG")
	}
	if err := os.Remove(aclPath); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeValidLKG(f.root, f.cfg); ok {
		t.Fatal("missing Out ACL was accepted as LKG")
	}
}

// TestNodeFileOwnedByBoundary pins the ownership helper used by the
// production-root LKG readback: exact UID/group passes, anything else fails
// closed.
func TestNodeFileOwnedByBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "owned")
	if err := os.WriteFile(path, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	gid := os.Getgid()
	group, err := user.LookupGroupId(strconv.Itoa(gid))
	if err != nil {
		t.Fatalf("current group %d not resolvable: %v", gid, err)
	}
	if !nodeFileOwnedBy(path, uint32(os.Getuid()), group.Name) {
		t.Fatal("exact UID/group ownership was rejected")
	}
	if nodeFileOwnedBy(path, uint32(os.Getuid()), "meshmux-test-no-such-group-xyz") {
		t.Fatal("unknown group ownership was accepted")
	}
	if nodeFileOwnedBy(filepath.Join(t.TempDir(), "absent"), uint32(os.Getuid()), group.Name) {
		t.Fatal("absent path ownership was accepted")
	}
}

// TestNodeRepairPreservesRecordedBinaryHashes pins the ledger invariant
// behind repair preflight: after the first install records the verified
// binary hashes, a repair must not wipe them back to the hashless user
// config, otherwise the next repair cannot recognize its own kernel
// listener and fails with PORT_CONFLICT.
func TestNodeRepairPreservesRecordedBinaryHashes(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	if _, err := f.install(t, false, strings.Repeat("A", 43)); err != nil {
		t.Fatalf("first install failed: %v", err)
	}
	compiled, err := corenode.CompileCandidate(f.candidate.Candidate())
	if err != nil {
		t.Fatal(err)
	}
	compiledHash := sha256.Sum256(compiled)
	f.opts.Readback = func(context.Context, corenode.Config, string, corenode.CommandRunner) (corenode.Readback, error) {
		return corenode.Readback{
			Architecture: "amd64", AgentVersion: corenode.CurrentAgentVersion(),
			AgentSHA256: strings.Repeat("b", 64), KernelVersion: corenode.KernelVersion,
			KernelSHA256: strings.Repeat("c", 64), ActiveRevision: 7,
			ConfigSHA256: hex.EncodeToString(compiledHash[:]), LocalActive: true,
		}, nil
	}
	recorded, exists, err := core.ReadState(f.root)
	if err != nil || !exists || recorded.Node == nil || recorded.Node.KernelSHA256 == "" {
		t.Fatalf("first install did not record kernel hash: %+v %v", recorded.Node, err)
	}
	if _, err := f.install(t, true, ""); err != nil {
		t.Fatalf("repair failed: %v", err)
	}
	after, exists, err := core.ReadState(f.root)
	if err != nil || !exists || after.Node == nil {
		t.Fatalf("repair lost the node record: %+v %v", after.Node, err)
	}
	if after.Node.KernelSHA256 != recorded.Node.KernelSHA256 || after.Node.AgentSHA256 != recorded.Node.AgentSHA256 {
		t.Fatalf("repair wiped recorded hashes: was %q/%q, now %q/%q",
			recorded.Node.KernelSHA256, recorded.Node.AgentSHA256,
			after.Node.KernelSHA256, after.Node.AgentSHA256)
	}
}

// TestNodeAgentReferencePinsStagedBinary pins which executable the staged
// Agent must be a copy of: a real install compares against itself, while an
// explicit Executable (the VM harness stages /tmp/meshmux from install.test)
// compares against that binary instead of the test driver.
// TestNodeFail2banJailWaitRetriesSlowDaemon pins the startup race: right
// after enable/reload the daemon socket may not answer yet, so the first
// jail status probe fails and the installer waits instead of failing the
// readback with exit 255.
func TestNodeFail2banJailWaitRetriesSlowDaemon(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	f.runner.failCall = "status meshmux-node-sshd"
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("slow fail2ban start = %+v %v", result, err)
	}
}

// failNeverRunner always fails; used to prove the jail wait gives up.
type failNeverRunner struct{ calls int }

func (f *failNeverRunner) Run(context.Context, string, ...string) ([]byte, error) {
	f.calls++
	return nil, errors.New("daemon down")
}

// TestNodeFail2banJailWaitTimesOut pins the bound: a daemon that never
// answers fails the install instead of blocking forever.
func TestNodeFail2banJailWaitTimesOut(t *testing.T) {
	oldTimeout, oldInterval := fail2banReadyTimeout, fail2banReadyInterval
	fail2banReadyTimeout, fail2banReadyInterval = 60*time.Millisecond, 5*time.Millisecond
	defer func() { fail2banReadyTimeout, fail2banReadyInterval = oldTimeout, oldInterval }()
	r := &failNeverRunner{}
	if err := waitFail2banJail(context.Background(), r); err == nil {
		t.Fatal("dead daemon was accepted as ready")
	}
	if r.calls < 2 {
		t.Fatalf("waited only %d probe(s), want retries", r.calls)
	}
}

func TestNodeAgentReferencePinsStagedBinary(t *testing.T) {
	if got := core.NodeAgentReference(""); got != "/proc/self/exe" {
		t.Fatalf("empty executable resolved to %q", got)
	}
	if got := core.NodeAgentReference("/tmp/meshmux"); got != "/tmp/meshmux" {
		t.Fatalf("explicit executable resolved to %q", got)
	}
}

// TestNodeReadbackRetriesSlowKernelStart pins the startup race handling: a
// kernel that reports SINGBOX_NOT_RUNNING while it boots is re-polled until
// the readback validates, instead of failing the install.
func TestNodeReadbackRetriesSlowKernelStart(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	calls := 0
	valid := f.opts.Readback
	f.opts.Readback = func(ctx context.Context, cfg corenode.Config, root string, runner corenode.CommandRunner) (corenode.Readback, error) {
		calls++
		// First the process is absent, then it is briefly the
		// systemd-executor supervisor, then sing-box is serving.
		if calls == 1 {
			return corenode.Readback{}, errors.New("SINGBOX_NOT_RUNNING")
		}
		if calls == 2 {
			return corenode.Readback{}, errors.New("SINGBOX_SUPERVISOR_STARTING")
		}
		return valid(ctx, cfg, root, runner)
	}
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err != nil || result.Status != "installed" {
		t.Fatalf("slow kernel start = %+v %v", result, err)
	}
	if calls != 3 {
		t.Fatalf("readback polled %d times, want 3", calls)
	}
}

// TestNodeReadbackDeterministicFailureFailsFast pins the other side: a
// config-level readback failure is not a slow kernel and must fail the
// install on the first attempt without polling to the deadline.
func TestNodeReadbackDeterministicFailureFailsFast(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	calls := 0
	f.opts.Readback = func(context.Context, corenode.Config, string, corenode.CommandRunner) (corenode.Readback, error) {
		calls++
		return corenode.Readback{}, errors.New("ACTIVE_CONFIG_HASH_MISMATCH")
	}
	_, err := f.install(t, false, strings.Repeat("A", 43))
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != "NATIVE_READBACK_FAILED" {
		t.Fatalf("deterministic readback failure = %v, want NATIVE_READBACK_FAILED", err)
	}
	if calls != 1 {
		t.Fatalf("deterministic failure polled %d times, want 1", calls)
	}
}

// TestNodeSSHJailQueryFailureKeepsOuterCode pins the fail-closed contract:
// when the jail port readback itself errors, the install reports the stable
// SSH_FAIL2BAN_JAIL_UNAVAILABLE code (with the inner detail in Recovery).
func TestNodeSSHJailQueryFailureKeepsOuterCode(t *testing.T) {
	f := makeNodeFixture(t, corenode.RoleEdge)
	f.runner.failCall = "nftables-multiport port"
	_, err := f.install(t, false, strings.Repeat("A", 43))
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != "SSH_FAIL2BAN_JAIL_UNAVAILABLE" {
		t.Fatalf("jail query failure = %v, want SSH_FAIL2BAN_JAIL_UNAVAILABLE", err)
	}
}
