package update

// Task 1 of 11c-2: the handoff starts the approved install as a transient
// systemd unit. The unit is PID 1's child, not the Agent's, so the Agent
// restart the unit performs cannot kill the install, and the pre-restart
// process only starts the unit — it never claims the target is applied.

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// wantTransientArgv is the byte-exact command line of spec §6. It is written
// out by hand (not rebuilt from the implementation's helpers) so a drift in
// either the property set or the ExecStart shape fails the test.
func wantTransientArgv(cfg Config, packageSHA string) []string {
	return []string{
		"/usr/bin/systemd-run",
		"--unit=meshmux-update-" + cfg.OperationID,
		"--collect",
		"--property=Type=oneshot",
		"--property=Restart=no",
		"--property=ProtectSystem=strict",
		"--property=ReadWritePaths=/usr/local/libexec /etc/meshmux /var/lib/meshmux-agent /etc/systemd/system /var/lib/meshmux-installer /var/cache/meshmux-installer /var/lib/meshmux-singbox /etc/fail2ban /run/lock",
		"--property=NoNewPrivileges=yes",
		"--property=PrivateTmp=yes",
		"--property=ProtectHome=yes",
		"--property=RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
		"--property=CapabilityBoundingSet=CAP_CHOWN CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE",
		filepath.Join(cfg.WorkDir, "meshmuxd-"+cfg.Target+"-"+runtime.GOARCH),
		"__internal-update-install",
		"--target", cfg.Target,
		"--manifest-sha256", cfg.ManifestSHA256,
		"--expected-sha256", packageSHA,
		"--operation-id", cfg.OperationID,
		"--from-recorded-state",
	}
}

// TestTransientArgvPinned pins the transient unit contract: one fixed
// systemd-run argv built only from validated fields, with the full sandbox of
// spec §6 (strict /usr, enumerated write set, no new privileges, no home,
// empty capability set) and the staged binary as ExecStart.
func TestTransientArgvPinned(t *testing.T) {
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	op := cfg
	op.PackageSHA256 = shaOf(pkg)

	argv, err := BuildTransientArgv(op)
	if err != nil {
		t.Fatalf("build argv: %v", err)
	}
	want := wantTransientArgv(cfg, shaOf(pkg))
	if !slices.Equal(argv, want) {
		t.Fatalf("argv =\n%q\nwant\n%q", argv, want)
	}

	// The systemd-analyze verify-style allowlist: exactly the nine properties,
	// each with its fixed value, and no other unit setting.
	wantKeys := []string{"Type", "Restart", "ProtectSystem", "ReadWritePaths",
		"NoNewPrivileges", "PrivateTmp", "ProtectHome", "RestrictAddressFamilies", "CapabilityBoundingSet"}
	seen := map[string]string{}
	for _, arg := range argv {
		rest, ok := strings.CutPrefix(arg, "--property=")
		if !ok {
			continue
		}
		key, value, ok := strings.Cut(rest, "=")
		if !ok {
			t.Fatalf("property %q has no key=value shape", arg)
		}
		if _, dup := seen[key]; dup {
			t.Fatalf("property %q is set twice", key)
		}
		seen[key] = value
	}
	if len(seen) != len(wantKeys) {
		t.Fatalf("properties = %v, want exactly %v", seen, wantKeys)
	}
	for _, key := range wantKeys {
		if _, ok := seen[key]; !ok {
			t.Fatalf("missing property %q in %v", key, seen)
		}
	}
	if seen["ProtectSystem"] != "strict" {
		t.Fatalf("ProtectSystem = %q, want strict", seen["ProtectSystem"])
	}
	// The amended §6 capability set. It is not a guess: CAP_CHOWN covers
	// os.Chown/chown(1) on managed files, CAP_NET_ADMIN covers nft, and
	// CAP_DAC_READ_SEARCH + CAP_SYS_PTRACE cover reading the non-root sing-box
	// process behind ss -p and /proc/<pid>/exe in the port-ownership readback.
	if seen["CapabilityBoundingSet"] != "CAP_CHOWN CAP_NET_ADMIN CAP_DAC_READ_SEARCH CAP_SYS_PTRACE" {
		t.Fatalf("CapabilityBoundingSet = %q", seen["CapabilityBoundingSet"])
	}
	// No privilege that would widen the unit past a fixed install: no
	// DAC_OVERRIDE (the write set is explicit), no SETUID/SETGID (it never
	// drops privilege itself), no SYS_ADMIN (no mount/namespace work).
	for _, forbidden := range []string{"CAP_DAC_OVERRIDE", "CAP_SETUID", "CAP_SETGID", "CAP_SYS_ADMIN",
		"CAP_SYS_MODULE", "CAP_MKNOD", "CAP_SYS_CHROOT", "ALL"} {
		if strings.Contains(seen["CapabilityBoundingSet"], forbidden) {
			t.Fatalf("CapabilityBoundingSet carries %q: %q", forbidden, seen["CapabilityBoundingSet"])
		}
	}
	if seen["NoNewPrivileges"] != "yes" || seen["PrivateTmp"] != "yes" || seen["ProtectHome"] != "yes" {
		t.Fatalf("sandbox properties = %v", seen)
	}
	if seen["RestrictAddressFamilies"] != "AF_UNIX AF_INET AF_INET6 AF_NETLINK" {
		t.Fatalf("RestrictAddressFamilies = %q", seen["RestrictAddressFamilies"])
	}
	// AF_NETLINK is required (ss SOCK_DIAG and nft); AF_PACKET would let the
	// unit capture traffic and is not needed by any install path.
	if strings.Contains(seen["RestrictAddressFamilies"], "AF_PACKET") {
		t.Fatalf("RestrictAddressFamilies carries AF_PACKET: %q", seen["RestrictAddressFamilies"])
	}
	if seen["ReadWritePaths"] != "/usr/local/libexec /etc/meshmux /var/lib/meshmux-agent /etc/systemd/system /var/lib/meshmux-installer /var/cache/meshmux-installer /var/lib/meshmux-singbox /etc/fail2ban /run/lock" {
		t.Fatalf("ReadWritePaths = %q", seen["ReadWritePaths"])
	}

	// --scope would put the unit back in the caller's cgroup, --wait would keep
	// the caller attached to a unit that restarts the Agent, and the rest would
	// hand the unit settings or identities no caller may choose.
	for _, forbidden := range []string{"--scope", "--pty", "--wait", "--setenv", "--uid", "--gid", "--working-directory"} {
		if slices.Contains(argv, forbidden) {
			t.Fatalf("argv contains %q: %q", forbidden, argv)
		}
	}
	if argv[1] != "--unit=meshmux-update-"+cfg.OperationID || argv[2] != "--collect" {
		t.Fatalf("unit argv = %q", argv[:3])
	}
	for _, arg := range argv {
		if strings.ContainsAny(arg, "\n\r\x00") {
			t.Fatalf("argv element %q carries a control character", arg)
		}
	}
	// ExecStart is the staged package and the next element is the hidden
	// subcommand: the unit runs the verified bytes, never another executable.
	execIndex := slices.Index(argv, "__internal-update-install")
	if execIndex != len(argv)-10 {
		t.Fatalf("hidden subcommand at %d of %d: %q", execIndex, len(argv), argv)
	}
	if exec := argv[execIndex-1]; exec != filepath.Join(cfg.WorkDir, "meshmuxd-"+cfg.Target+"-"+runtime.GOARCH) {
		t.Fatalf("ExecStart = %q", exec)
	}
}

// TestTransientSandboxCoversInstallPaths is the capability audit as a test:
// each capability and socket family the unit declares must correspond to a
// real call in the install/readback code, and each one that does is listed.
// A future install path that needs a new capability fails here instead of
// failing on a host with EPERM/EPROTONOSUPPORT.
func TestTransientSandboxCoversInstallPaths(t *testing.T) {
	// (capability, reason, files that must still contain the call)
	for _, need := range []struct {
		capability string
		reason     string
		markers    []string
	}{
		{"CAP_CHOWN", "os.Chown on managed files and chown(1) on Agent directories",
			[]string{"internal/cli/install/apply_shared.go:os.Chown", "internal/cli/install/node_apply.go:restoreFileSnapshots", "internal/cli/install/apply.go:restoreFileSnapshots"}},
		{"CAP_NET_ADMIN", "nft -c / nft list table need the netfilter netlink socket",
			[]string{"internal/cli/install/node_stage.go:\"nft\", \"-c\"", "internal/cli/install/node_apply.go:\"nft\", \"-j\""}},
		{"CAP_DAC_READ_SEARCH", "ss -p reads /proc/<pid>/fd of the non-root sing-box process",
			[]string{"internal/cli/install/node_plan.go:\"ss\", \"-H\", \"-lntp\"", "internal/cli/install/node_plan.go:\"ss\", \"-H\", \"-lntup\""}},
		{"CAP_SYS_PTRACE", "/proc/<pid>/exe of that process for the ownership hash",
			[]string{"internal/cli/install/node_plan.go:os.Readlink(\"/proc/\" + pid + \"/exe\")",
				"internal/cli/install/node_plan.go:sha256File(\"/proc/\" + pid + \"/exe\")"}},
	} {
		if !strings.Contains(transientCaps, need.capability) {
			t.Fatalf("capability set %q lacks %s (%s)", transientCaps, need.capability, need.reason)
		}
		for _, marker := range need.markers {
			file, fragment, _ := strings.Cut(marker, ":")
			body, err := os.ReadFile(filepath.Join("..", "..", "..", file))
			if err != nil {
				t.Fatalf("read %s: %v", file, err)
			}
			if !strings.Contains(string(body), fragment) {
				t.Fatalf("%s no longer contains %q, so %s may be removable — re-audit the sandbox",
					file, fragment, need.capability)
			}
		}
	}
	// AF_NETLINK is what ss and nft actually speak; AF_PACKET is never needed.
	if !strings.Contains(transientAddressFamilies, "AF_NETLINK") {
		t.Fatalf("address families %q lack AF_NETLINK (ss/nft)", transientAddressFamilies)
	}
	if strings.Contains(transientAddressFamilies, "AF_PACKET") {
		t.Fatalf("address families %q carry AF_PACKET, which no install path needs", transientAddressFamilies)
	}
	// The unit must stay no-new-privileges: capabilities come from the bounding
	// set only, never from a setuid binary.
	if transientCaps == "" || strings.Contains(transientCaps, "ALL") {
		t.Fatalf("capability set %q is empty or unrestricted", transientCaps)
	}
}

// TestTransientRejectsUnvalidatedInput is the fail-closed rule: every value
// that reaches the systemd-run argv is first checked, so an unknown target,
// digest, operation, directory or architecture is refused before anything is
// spawned.
func TestTransientRejectsUnvalidatedInput(t *testing.T) {
	base := Config{Target: "1.0.1", ManifestSHA256: strings.Repeat("a", 64),
		PackageSHA256: strings.Repeat("b", 64), OperationID: strings.Repeat("c", 32),
		WorkDir: "/var/lib/meshmux-agent/update"}
	for _, tc := range []struct {
		name   string
		code   string
		mutate func(*Config)
	}{
		{"short target", "UPDATE_TARGET_INVALID", func(c *Config) { c.Target = "1.0" }},
		{"target with shell text", "UPDATE_TARGET_INVALID", func(c *Config) { c.Target = "1.0.1; reboot" }},
		{"bad manifest digest", "UPDATE_DIGEST_INVALID", func(c *Config) { c.ManifestSHA256 = "not-a-digest" }},
		{"uppercase manifest digest", "UPDATE_DIGEST_INVALID", func(c *Config) { c.ManifestSHA256 = strings.ToUpper(strings.Repeat("a", 64)) }},
		{"bad package digest", "UPDATE_DIGEST_INVALID", func(c *Config) { c.PackageSHA256 = "" }},
		{"missing operation", "OPERATION_REQUIRED", func(c *Config) { c.OperationID = "" }},
		{"bad operation", "OPERATION_ID_INVALID", func(c *Config) { c.OperationID = "not-hex" }},
		{"uppercase operation", "OPERATION_ID_INVALID", func(c *Config) { c.OperationID = strings.ToUpper(strings.Repeat("c", 32)) }},
		{"relative work dir", "UPDATE_STAGE_FAILED", func(c *Config) { c.WorkDir = "update" }},
		{"traversing work dir", "UPDATE_STAGE_FAILED", func(c *Config) { c.WorkDir = "/var/lib/../etc" }},
		{"newline in work dir", "UPDATE_STAGE_FAILED", func(c *Config) { c.WorkDir = "/var/lib/meshmux\n-agent" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			op := base
			tc.mutate(&op)
			argv, err := BuildTransientArgv(op)
			if code := codeOf(err); code != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", code, tc.code, err)
			}
			if argv != nil {
				t.Fatalf("refused build returned argv %q", argv)
			}
		})
	}

	// The architecture is the local build's, and only the supported matrix is
	// accepted: an unknown one is refused rather than guessed.
	if argv, err := buildTransientArgv(base, "mips"); codeOf(err) != "MANIFEST_ARCH_INVALID" || argv != nil {
		t.Fatalf("unknown arch: argv = %q, err = %v, want MANIFEST_ARCH_INVALID", argv, err)
	}
	if _, err := transientStagedPath("/var/lib/meshmux-agent/update", "1.0.1", "mips"); codeOf(err) != "MANIFEST_ARCH_INVALID" {
		t.Fatalf("unknown arch: code = %q, want MANIFEST_ARCH_INVALID (err %v)", codeOf(err), err)
	}
	if _, err := transientStagedPath("/var/lib/meshmux-agent/update", "1.0.1", runtime.GOARCH); err != nil {
		t.Fatalf("local arch refused: %v", err)
	}

	// A refused build never reaches the runner: the spawn seam stays untouched.
	runner := &fixtureRunner{}
	op := base
	op.PackageSHA256 = "nothex"
	argv, err := BuildTransientArgv(op)
	if codeOf(err) != "UPDATE_DIGEST_INVALID" || argv != nil {
		t.Fatalf("handoff code = %q, argv %q, want UPDATE_DIGEST_INVALID", codeOf(err), argv)
	}
	if err := handoff(context.Background(), argv, runner); codeOf(err) != "UPDATE_UNIT_START_FAILED" {
		t.Fatalf("handoff code = %q, want UPDATE_UNIT_START_FAILED (err %v)", codeOf(err), err)
	}
	if len(runner.calls) != 0 {
		t.Fatalf("refused handoff spawned %q", runner.calls)
	}

	// A refused Run leaves the host untouched as well, including the staging
	// directory: the argv gate sits before the fetch, so nothing is created,
	// staged or written and no runner call happens.
	pkg := []byte("fixture package\n")
	badDir := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	// Built by concatenation: filepath.Join would clean the ".." away.
	badDir.WorkDir = t.TempDir() + "/not/../update"
	runRunner := &fixtureRunner{}
	if _, err := Run(context.Background(), badDir, runRunner); codeOf(err) != "UPDATE_STAGE_FAILED" {
		t.Fatalf("Run code = %q, want UPDATE_STAGE_FAILED (err %v)", codeOf(err), err)
	}
	if len(runRunner.calls) != 0 {
		t.Fatalf("refused Run executed %q", runRunner.calls)
	}
	if _, statErr := os.Lstat(badDir.WorkDir); !os.IsNotExist(statErr) {
		t.Fatalf("refused Run created %s: %v", badDir.WorkDir, statErr)
	}

	// The same no-write rule for a refusal that happens later in the gate
	// order: a target with a foreign policy schema must not even create the
	// staging directory, let alone a backup pointer or a staged package.
	schemaCfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	schemaCfg.WorkDir = filepath.Join(t.TempDir(), "update")
	m := schemaCfg
	foreign := fixtureManifest(t, pkg, shaOf(pkg))
	foreign.PolicySchema++
	m.FetchManifest = func(context.Context) ([]byte, error) { return setBody(t, foreign), nil }
	pinned, err := json.Marshal(foreign)
	if err != nil {
		t.Fatal(err)
	}
	m.ManifestSHA256 = shaOf(pinned)
	if _, err := Run(context.Background(), m, &fixtureRunner{}); codeOf(err) != "UPDATE_SCHEMA_INCOMPATIBLE" {
		t.Fatalf("Run code = %q, want UPDATE_SCHEMA_INCOMPATIBLE (err %v)", codeOf(err), err)
	}
	if _, statErr := os.Lstat(schemaCfg.WorkDir); !os.IsNotExist(statErr) {
		t.Fatalf("refused Run created %s: %v", schemaCfg.WorkDir, statErr)
	}
}

// The survival fixture runs three processes, because "the unit outlives the
// process that started it" is a property of process lifetimes, not of a Go
// value:
//
//	parent test  → starts the spawner and waits for it to be killed
//	spawner      → calls Run, which starts the unit and returns at once
//	unit         → kills the spawner, then writes its result file
//
// The parent asserts the spawner died by SIGKILL *and* that the unit still
// wrote the result path afterwards. If the handoff ever waited for the unit,
// or the unit were a child the spawner had to keep alive, the result file
// could not appear. In production systemd owns the unit because the argv is a
// `systemd-run` with --collect and neither --scope nor --wait; the argv test
// above pins that half.
const (
	transientHelperEnv = "MESHMUX_TRANSIENT_HELPER"
	transientUnitEnv   = "MESHMUX_TRANSIENT_UNIT"
	transientResultEnv = "MESHMUX_TRANSIENT_RESULT"
	transientHelperDir = "MESHMUX_TRANSIENT_DIR"
	transientSpawnPID  = "MESHMUX_TRANSIENT_SPAWNER_PID"
	transientReadyEnv  = "MESHMUX_TRANSIENT_READY"
)

// TestTransientSurvivesAgentRestart is the KillMode property at fixture level.
func TestTransientSurvivesAgentRestart(t *testing.T) {
	if os.Getenv(transientHelperEnv) != "" || os.Getenv(transientUnitEnv) != "" {
		t.Skip("fixture child process")
	}
	dir := t.TempDir()
	resultPath := filepath.Join(dir, strings.Repeat("a", 32)+".result.json")
	readyPath := filepath.Join(dir, "spawner-ready")
	spawner := exec.Command(os.Args[0], "-test.run=^TestTransientSpawnerProcess$", "-test.timeout=60s")
	spawner.Env = append(os.Environ(), transientHelperEnv+"=1", transientResultEnv+"="+resultPath,
		transientHelperDir+"="+dir, transientReadyEnv+"="+readyPath)
	output, err := spawner.CombinedOutput()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("spawner was not killed by the unit: err %v, output %q", err, output)
	}
	status, ok := exit.Sys().(syscall.WaitStatus)
	if !ok || !status.Signaled() || status.Signal() != syscall.SIGKILL {
		t.Fatalf("spawner exit = %v, want SIGKILL (output %q)", exit, output)
	}
	if _, statErr := os.Stat(readyPath); statErr != nil {
		t.Fatalf("spawner never returned from the handoff before being killed: %v, output %q", statErr, output)
	}
	// The unit is a separate process: it writes after killing the spawner, so
	// the assertion waits for it rather than sampling once.
	deadline := time.Now().Add(10 * time.Second)
	for {
		data, readErr := os.ReadFile(resultPath)
		if readErr == nil && strings.Contains(string(data), `"exit_code":0`) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the unit did not write its result after the spawner died: %q, err %v", data, readErr)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestTransientSpawnerProcess is the fixture spawner: it runs the real Run
// against a runner that starts the unit, records that it returned, then blocks
// until the unit kills it. Without the environment marker it is skipped, so it
// never runs as a test.
func TestTransientSpawnerProcess(t *testing.T) {
	if os.Getenv(transientHelperEnv) != "1" {
		t.Skip("fixture child process")
	}
	pkg := []byte("fixture package\n")
	cfg := fixtureConfig(t, fixtureManifest(t, pkg, shaOf(pkg)))
	cfg.WorkDir = os.Getenv(transientHelperDir)
	runner := &processUnitRunner{resultPath: os.Getenv(transientResultEnv),
		readyPath: os.Getenv(transientReadyEnv)}
	if _, err := Run(context.Background(), cfg, runner); err != nil {
		t.Fatalf("handoff: %v", err)
	}
	if len(runner.calls) != 1 || !slices.Equal(runner.calls[0], wantTransientArgv(cfg, shaOf(pkg))) {
		t.Fatalf("spawn argv = %q", runner.calls)
	}
	// The handoff returned while the unit is still running: record that before
	// blocking, so the unit kills a process that has already reached this
	// point rather than one still inside Run.
	if err := os.WriteFile(runner.readyPath, []byte("handoff-returned\n"), 0600); err != nil {
		t.Fatalf("record handoff return: %v", err)
	}
	time.Sleep(10 * time.Second)
	t.Fatal("the unit never killed the spawner")
}

// TestTransientUnitProcess is the fixture unit: it waits for the spawner to
// record that the handoff returned, kills it, then writes the result file.
// That is the order a real unit follows — restart the Agent, then record what
// happened. It kills the PID it was given, never its parent by inference: if
// the spawner were already gone, killing "the parent" would hit another
// process.
func TestTransientUnitProcess(t *testing.T) {
	if os.Getenv(transientUnitEnv) != "1" {
		t.Skip("fixture child process")
	}
	pid, err := strconv.Atoi(os.Getenv(transientSpawnPID))
	if err != nil || pid < 2 {
		t.Fatalf("fixture spawner pid = %q", os.Getenv(transientSpawnPID))
	}
	ready := os.Getenv(transientReadyEnv)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, statErr := os.Stat(ready); statErr == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the spawner never recorded that the handoff returned")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill spawner %d: %v", pid, err)
	}
	time.Sleep(50 * time.Millisecond)
	if err := os.WriteFile(os.Getenv(transientResultEnv), []byte(`{"phase":"installed","exit_code":0}`), 0600); err != nil {
		t.Fatalf("write result: %v", err)
	}
}

// processUnitRunner starts the fixture unit as a real detached process and
// returns immediately, exactly as `systemd-run` enqueues a job.
type processUnitRunner struct {
	resultPath string
	readyPath  string
	calls      [][]string
}

func (r *processUnitRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	unit := exec.Command(os.Args[0], "-test.run=^TestTransientUnitProcess$", "-test.timeout=60s")
	unit.Env = append(os.Environ(), transientUnitEnv+"=1", transientResultEnv+"="+r.resultPath,
		transientReadyEnv+"="+r.readyPath, transientSpawnPID+"="+strconv.Itoa(os.Getpid()))
	if err := unit.Start(); err != nil {
		return nil, err
	}
	go func() { _ = unit.Wait() }()
	return []byte("Running as unit: meshmux-update\n"), nil
}

// stateRunner serves one fixed systemctl show output.
type stateRunner struct {
	out   []byte
	err   error
	calls [][]string
}

func (r *stateRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string{name}, args...))
	return r.out, r.err
}

// TestUnitActiveState pins D5's process signal: liveness is one fixed
// `systemctl show` of exactly ActiveState and ExecMainStatus, and nothing about
// success is inferred from it.
func TestUnitActiveState(t *testing.T) {
	op := strings.Repeat("d", 32)
	runner := &stateRunner{out: []byte("ActiveState=active\nExecMainStatus=0\n")}
	state, status, err := UnitActiveState(context.Background(), runner, op)
	if err != nil {
		t.Fatalf("active state: %v", err)
	}
	if state != ActiveStateActive || status != 0 {
		t.Fatalf("state = %q status = %d", state, status)
	}
	want := []string{"/usr/bin/systemctl", "show", "-p", "ActiveState", "-p", "ExecMainStatus",
		"meshmux-update-" + op}
	if len(runner.calls) != 1 || !slices.Equal(runner.calls[0], want) {
		t.Fatalf("systemctl argv = %q, want %q", runner.calls, want)
	}

	failed := &stateRunner{out: []byte("ActiveState=failed\nExecMainStatus=1\n")}
	if state, status, err = UnitActiveState(context.Background(), failed, op); err != nil ||
		state != ActiveStateFailed || status != 1 {
		t.Fatalf("failed unit = %q %d %v", state, status, err)
	}

	for _, tc := range []struct {
		name   string
		runner *stateRunner
		code   string
	}{
		{"unknown state", &stateRunner{out: []byte("ActiveState=bogus\nExecMainStatus=0\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"missing exec status", &stateRunner{out: []byte("ActiveState=inactive\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"non-numeric exec status", &stateRunner{out: []byte("ActiveState=inactive\nExecMainStatus=boom\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"negative exec status", &stateRunner{out: []byte("ActiveState=inactive\nExecMainStatus=-1\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"duplicate state", &stateRunner{out: []byte("ActiveState=active\nActiveState=failed\nExecMainStatus=0\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"duplicate exec status", &stateRunner{out: []byte("ActiveState=active\nExecMainStatus=0\nExecMainStatus=1\n")}, "UPDATE_UNIT_STATE_INVALID"},
		{"empty reply", &stateRunner{out: nil}, "UPDATE_UNIT_STATE_INVALID"},
		{"query failed", &stateRunner{err: errors.New("fixture: bus down")}, "UPDATE_UNIT_QUERY_FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := UnitActiveState(context.Background(), tc.runner, op); codeOf(err) != tc.code {
				t.Fatalf("code = %q, want %q (err %v)", codeOf(err), tc.code, err)
			}
		})
	}

	// A missing operation is refused before any systemctl call: the unit name
	// is derived from it, so an empty one cannot name a unit at all.
	empty := &stateRunner{out: []byte("ActiveState=active\nExecMainStatus=0\n")}
	if _, _, err := UnitActiveState(context.Background(), empty, ""); codeOf(err) != "OPERATION_REQUIRED" {
		t.Fatalf("empty operation: %v", err)
	}
	if len(empty.calls) != 0 {
		t.Fatalf("empty operation queried %q", empty.calls)
	}

	refused := &stateRunner{out: []byte("ActiveState=active\nExecMainStatus=0\n")}
	if _, _, err := UnitActiveState(context.Background(), refused, "nothex"); codeOf(err) != "OPERATION_ID_INVALID" {
		t.Fatalf("bad operation: %v", err)
	}
	if len(refused.calls) != 0 {
		t.Fatalf("bad operation queried %q", refused.calls)
	}
}
