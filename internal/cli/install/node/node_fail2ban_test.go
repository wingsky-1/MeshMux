package node

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
	corenode "github.com/wingsky-1/MeshMux/internal/core/node"
)

// baselineRunner answers the two commands the Fail2ban baseline gates use and
// emulates an apt install by marking the named packages installed.
type baselineRunner struct {
	packages map[string]bool
	calls    []string
	// selfTest decides fail2ban-client -t; nil means the self-test fails.
	selfTest func(*baselineRunner) bool
	// skipAptInstall leaves the package set untouched even when apt runs, so a
	// test can prove the post-package gate fails closed.
	skipAptInstall bool
}

func (r *baselineRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch name {
	case "dpkg-query":
		if r.packages[args[len(args)-1]] {
			return []byte("install ok installed"), nil
		}
		return nil, errors.New("package not installed")
	case "fail2ban-client":
		if len(args) == 1 && args[0] == "-t" {
			if r.selfTest != nil && r.selfTest(r) {
				return nil, nil
			}
			return nil, errors.New("self-test failed")
		}
	case "apt-get":
		if len(args) > 0 && args[0] == "install" && !r.skipAptInstall {
			for _, arg := range args[1:] {
				if !strings.HasPrefix(arg, "-") {
					r.packages[arg] = true
				}
			}
		}
	}
	return nil, nil
}

func (r *baselineRunner) called(want string) bool {
	for _, call := range r.calls {
		if call == want {
			return true
		}
	}
	return false
}

func baselineJournalEvents(t *testing.T, root, operationID string) []core.OperationEvent {
	t.Helper()
	layout, err := core.ResolveNodeLayout(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(core.Rooted(root, layout.OperationDir+"/"+operationID+"/events.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var events []core.OperationEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		var event core.OperationEvent
		if err := json.Unmarshal([]byte(line), &event); err != nil {
			t.Fatalf("journal line %q: %v", line, err)
		}
		events = append(events, event)
	}
	return events
}

// A rejected baseline must block the plan and stop InstallNode before the
// pairing code is used: the code is one-time and must never be consumed for an
// operation whose Fail2ban configuration already fails its own self-test.
func TestNodeFail2banBaselineBlocksBeforePairing(t *testing.T) {
	runner := &baselineRunner{packages: map[string]bool{
		"fail2ban": true, fail2banSystemdBackendPackage: true,
	}}
	check := nodeFail2banBaselineCheck(context.Background(), runner)
	if check.Status != "fail" || check.Code != CodeFail2banBaselineInvalid {
		t.Fatalf("baseline check = %+v, want fail/%s", check, CodeFail2banBaselineInvalid)
	}
	if !strings.Contains(check.Recovery, "rsyslog") || !strings.Contains(check.Recovery, "backend=systemd") {
		t.Fatalf("next_action does not name both repairs: %q", check.Recovery)
	}
	cfg := corenode.Config{
		HubURL: "https://hub.example.invalid", NodeID: strings.Repeat("a", 32),
		Role: corenode.RoleEdge, VLESSPort: 8443, SSHPort: 2222,
	}
	plan := buildNodePlan(strings.Repeat("f", 32), cfg, "amd64", []core.Check{check}, []int{2222}, core.StandaloneNodeLayout())
	if plan.Status != "preflight_blocked" || plan.ApplyAvailable {
		t.Fatalf("plan with a rejected baseline = %+v", plan)
	}

	f := makeNodeFixture(t, corenode.RoleEdge)
	pairs := 0
	f.opts.Pair = func(context.Context, corenode.Config, string) (corenode.Identity, error) {
		pairs++
		return f.identity, nil
	}
	f.opts.Preflight = func(context.Context, corenode.Config, bool) ([]core.Check, []int) {
		return []core.Check{check}, []int{2222, 2200}
	}
	result, err := f.install(t, false, strings.Repeat("A", 43))
	if err == nil || result.ErrorCode != CodeFail2banBaselineInvalid {
		t.Fatalf("install = %+v %v, want %s", result, err, CodeFail2banBaselineInvalid)
	}
	if pairs != 0 {
		t.Fatal("a rejected Fail2ban baseline consumed the pairing code")
	}
}

// The fixed package set must settle a missing python3-systemd before pairing:
// preflight reports the self-test as pending and the stage gate, which runs
// after package installation, proves it. A failed install of that package
// keeps the operation blocked before pairing.
func TestNodeFail2banBaselineWaitsForFixedBackendPackage(t *testing.T) {
	t.Run("package install settles the baseline before pairing", func(t *testing.T) {
		f := makeNodeFixture(t, corenode.RoleEdge)
		runner := &baselineFixtureRunner{fakeNodeRunner: f.runner}
		f.opts.Runner = runner
		f.opts.Preflight = func(ctx context.Context, _ corenode.Config, _ bool) ([]core.Check, []int) {
			return []core.Check{nodeFail2banBaselineCheck(ctx, runner)}, []int{2222, 2200}
		}
		pairs := 0
		f.opts.Pair = func(context.Context, corenode.Config, string) (corenode.Identity, error) {
			pairs++
			return f.identity, nil
		}
		result, err := f.install(t, false, strings.Repeat("A", 43))
		if err != nil || result.Status != "installed" {
			t.Fatalf("install = %+v %v", result, err)
		}
		if pairs != 1 {
			t.Fatalf("pair calls = %d, want 1", pairs)
		}
		if !runner.backend {
			t.Fatal("the fixed package set did not install python3-systemd")
		}
		joined := strings.Join(runner.calls, "\n")
		installAt := strings.Index(joined, "apt-get install")
		testAt := strings.LastIndex(joined, "fail2ban-client -t")
		if installAt < 0 || testAt < installAt {
			t.Fatalf("self-test did not run after package installation:\n%s", joined)
		}
	})

	t.Run("package install that leaves the backend missing blocks before pairing", func(t *testing.T) {
		f := makeNodeFixture(t, corenode.RoleEdge)
		runner := &baselineFixtureRunner{fakeNodeRunner: f.runner, skipAptInstall: true}
		f.opts.Runner = runner
		f.opts.Preflight = func(ctx context.Context, _ corenode.Config, _ bool) ([]core.Check, []int) {
			return []core.Check{nodeFail2banBaselineCheck(ctx, runner)}, []int{2222, 2200}
		}
		pairs := 0
		f.opts.Pair = func(context.Context, corenode.Config, string) (corenode.Identity, error) {
			pairs++
			return f.identity, nil
		}
		result, err := f.install(t, false, strings.Repeat("A", 43))
		if err == nil || result.ErrorCode != CodeFail2banBaselineInvalid {
			t.Fatalf("install = %+v %v, want %s", result, err, CodeFail2banBaselineInvalid)
		}
		if pairs != 0 {
			t.Fatal("a baseline that still fails after package installation consumed the pairing code")
		}
	})
}

// baselineFixtureRunner keeps the Node fixture behavior and adds the one
// package the minimal-image cases need: python3-systemd starts absent, apt
// installs it, and the self-test only passes once it is present.
type baselineFixtureRunner struct {
	*fakeNodeRunner
	backend        bool
	skipAptInstall bool
	calls          []string
}

func (r *baselineFixtureRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	switch {
	case name == "dpkg-query" && args[len(args)-1] == fail2banSystemdBackendPackage:
		if r.backend {
			return []byte("install ok installed"), nil
		}
		return nil, errors.New("package not installed")
	case name == "apt-get" && len(args) > 0 && args[0] == "install" && !r.skipAptInstall:
		for _, arg := range args[1:] {
			if arg == fail2banSystemdBackendPackage {
				r.backend = true
			}
		}
	case name == "fail2ban-client" && len(args) == 1 && args[0] == "-t":
		if !r.backend {
			return nil, errors.New("Backend 'systemd' failed to initialize")
		}
		return nil, nil
	}
	return r.fakeNodeRunner.Run(ctx, name, args...)
}

func TestNodeFail2banBaselineRepairRsyslog(t *testing.T) {
	root := t.TempDir()
	operationID := strings.Repeat("1", 32)
	runner := &baselineRunner{packages: map[string]bool{
		"fail2ban": true, fail2banSystemdBackendPackage: true,
	}}
	runner.selfTest = func(r *baselineRunner) bool { return r.packages["rsyslog"] }
	if err := RepairNodeFail2banBaseline(context.Background(), root, operationID, Fail2banRepairRsyslog, runner); err != nil {
		t.Fatalf("rsyslog repair = %v", err)
	}
	for _, want := range []string{
		"apt-get update",
		"apt-get install -y --no-install-recommends rsyslog",
		"systemctl enable --now rsyslog.service",
		"fail2ban-client -t",
	} {
		if !runner.called(want) {
			t.Fatalf("rsyslog repair did not run %q: %v", want, runner.calls)
		}
	}
	if check := nodeFail2banBaselineCheck(context.Background(), runner); check.Status != "pass" {
		t.Fatalf("baseline after repair = %+v", check)
	}
	events := baselineJournalEvents(t, root, operationID)
	if len(events) != 2 {
		t.Fatalf("journal events = %+v, want confirmed then applied", events)
	}
	if events[0].Stage != "preflight" || events[0].Status != "fail2ban_repair_confirmed" || events[0].Detail != string(Fail2banRepairRsyslog) {
		t.Fatalf("confirmation event = %+v", events[0])
	}
	if events[1].Status != "fail2ban_repair_applied" || events[1].Detail != string(Fail2banRepairRsyslog) {
		t.Fatalf("applied event = %+v", events[1])
	}
}

func TestNodeFail2banBaselineRepairSystemdBackend(t *testing.T) {
	root := t.TempDir()
	operationID := strings.Repeat("2", 32)
	runner := &baselineRunner{packages: map[string]bool{
		"fail2ban": true, fail2banSystemdBackendPackage: true,
	}}
	runner.selfTest = func(*baselineRunner) bool {
		_, err := os.Stat(core.Rooted(root, fail2banBackendDropInPath))
		return err == nil
	}
	if err := RepairNodeFail2banBaseline(context.Background(), root, operationID, Fail2banRepairSystemdBackend, runner); err != nil {
		t.Fatalf("systemd backend repair = %v", err)
	}
	path := core.Rooted(root, fail2banBackendDropInPath)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0644 {
		t.Fatalf("drop-in = %v %v, want regular 0644", info, err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "[sshd]\nbackend = systemd\n") {
		t.Fatalf("drop-in does not override only the sshd backend:\n%s", body)
	}
	for _, key := range []string{"enabled =", "filter =", "port =", "protocol =", "banaction ="} {
		if strings.Contains(string(body), key) {
			t.Fatalf("drop-in changed another sshd jail key %q:\n%s", key, body)
		}
	}
	if _, statErr := os.Lstat(core.Rooted(root, core.NodeSSHJailPath)); !os.IsNotExist(statErr) {
		t.Fatal("repair wrote the Node jail instead of only the backend override")
	}
	events := baselineJournalEvents(t, root, operationID)
	if len(events) != 2 || events[0].Status != "fail2ban_repair_confirmed" || events[1].Status != "fail2ban_repair_applied" {
		t.Fatalf("journal events = %+v", events)
	}
	if events[0].Detail != string(Fail2banRepairSystemdBackend) {
		t.Fatalf("confirmation did not record the chosen repair: %+v", events[0])
	}
}

// A repair whose self-test still fails must not leave an unproven jail
// override behind, and an existing drop-in must be restored byte for byte.
func TestNodeFail2banBaselineRepairRollsBackUnprovenOverride(t *testing.T) {
	root := t.TempDir()
	operationID := strings.Repeat("3", 32)
	path := core.Rooted(root, fail2banBackendDropInPath)
	if err := core.EnsureDirectory(core.Rooted(root, core.Fail2banJailDir), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[sshd]\nbackend = polling\n"), 0644); err != nil {
		t.Fatal(err)
	}
	runner := &baselineRunner{packages: map[string]bool{
		"fail2ban": true, fail2banSystemdBackendPackage: true,
	}}
	err := RepairNodeFail2banBaseline(context.Background(), root, operationID, Fail2banRepairSystemdBackend, runner)
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != CodeFail2banBaselineInvalid {
		t.Fatalf("unproven repair = %v, want %s", err, CodeFail2banBaselineInvalid)
	}
	body, readErr := os.ReadFile(path)
	if readErr != nil || string(body) != "[sshd]\nbackend = polling\n" {
		t.Fatalf("existing drop-in was not restored: %q %v", body, readErr)
	}
	events := baselineJournalEvents(t, root, operationID)
	if len(events) != 2 || events[1].Status != "fail2ban_repair_failed" || events[1].ErrorCode != CodeFail2banBaselineInvalid {
		t.Fatalf("failed repair journal = %+v", events)
	}
}

// A missing Fail2ban package cannot be repaired by editing its configuration;
// the repair interface must refuse instead of inventing a package.
func TestNodeFail2banBaselineRepairRequiresInstalledFail2ban(t *testing.T) {
	root := t.TempDir()
	operationID := strings.Repeat("4", 32)
	runner := &baselineRunner{packages: map[string]bool{}}
	err := RepairNodeFail2banBaseline(context.Background(), root, operationID, Fail2banRepairRsyslog, runner)
	var ie *core.InstallError
	if !errors.As(err, &ie) || ie.Code != CodeFail2banBaselineInvalid {
		t.Fatalf("repair without fail2ban = %v", err)
	}
	for _, call := range runner.calls {
		if strings.HasPrefix(call, "apt-get") || strings.HasPrefix(call, "systemctl") {
			t.Fatalf("repair mutated a host without fail2ban: %v", runner.calls)
		}
	}
	if _, statErr := os.Lstat(core.Rooted(root, fail2banBackendDropInPath)); !os.IsNotExist(statErr) {
		t.Fatal("repair wrote a drop-in without fail2ban installed")
	}
}
