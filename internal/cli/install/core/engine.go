package core

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/backup"
	"github.com/wingsky-1/MeshMux/internal/cli/buildinfo"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/node"
	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

const (
	InstallerStatePath = versions.InstallerStatePath
	// localLineStatePath is the ledger of a Line that shares the host with
	// the Hub. The path is fixed and selected internally from the recorded
	// Hub state; no caller, user or remote request may choose a path.
	LocalLineStatePath  = versions.LocalLineStatePath
	RuntimeBinaryPath   = versions.RuntimeBinaryPath
	CaddyBinaryPath     = "/usr/local/libexec/meshmux-caddy"
	HeadscaleBinaryPath = "/usr/local/libexec/meshmux-headscale"
	// maxInstallerFile is the one package/artifact byte bound shared by the
	// tar extractor, the self-copy and the artifact verifier.
	MaxInstallerFile = buildinfo.MaxExecutableBytes
)

// SharedBinary records a Hub-owned runtime binary that a co-located Line
// reuses verbatim. It is nil for every standalone layout, so Hub ledgers and
// standalone Node ledgers stay byte-for-byte compatible.
type SharedBinary struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
}

type InstallState struct {
	Schema        int               "json:\"schema\""
	OperationID   string            "json:\"operation_id\""
	Status        string            "json:\"status\""
	Stage         string            "json:\"stage\""
	Config        Config            "json:\"config\""
	Architecture  string            "json:\"architecture\""
	CreatedAt     time.Time         "json:\"created_at\""
	UpdatedAt     time.Time         "json:\"updated_at\""
	ManagedFiles  map[string]string "json:\"managed_files\""
	Artifacts     map[string]string "json:\"artifacts\""
	SSHPorts      []int             "json:\"ssh_ports\""
	ErrorCode     string            "json:\"error_code,omitempty\""
	Recovery      string            "json:\"recovery,omitempty\""
	LastOperation string            "json:\"last_operation_id,omitempty\""
	// Node is present only when this host layout is a Line or Out node.
	// Hub configurations remain byte-for-byte compatible when this is nil.
	Node *node.Config `json:"node,omitempty"`
	// SharedBinaries records the MeshMux runtime builds this layout owns
	// and that a co-located Line reuses verbatim. It is empty for every
	// standalone layout, so existing ledgers stay byte-for-byte compatible.
	SharedBinaries map[string]SharedBinary `json:"shared_binaries,omitempty"`
}

type InstallResult struct {
	OperationID string      "json:\"operation_id\""
	Stage       string      "json:\"stage\""
	Status      string      "json:\"status\""
	ErrorCode   string      "json:\"error_code,omitempty\""
	Recovery    string      "json:\"next_action,omitempty\""
	Checks      []Check     "json:\"checks,omitempty\""
	Artifacts   []Component "json:\"components,omitempty\""
}

type InstallError struct {
	Stage    string
	Code     string
	Recovery string
}

func (e *InstallError) Error() string { return e.Code }

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type ApplyOptions struct {
	// Root is "/" in production. A temporary root is accepted only by tests.
	Root             string
	Runner           CommandRunner
	HTTPClient       *http.Client
	Executable       string
	Preflight        func(context.Context, Config, bool) ([]Check, []int)
	DownloadArtifact func(context.Context, Artifact, string) (string, error)
	TLSProbe         func(context.Context, string) error
	// Test-only seam used by the isolated systemd integration test. It is not
	// exposed by the CLI and cannot be enabled through user configuration.
	InternalTLSForTest bool
	// NonInteractive marks a Web-driven handoff: the operation must never wait
	// for an operator, so a path that would need a prompt is refused with
	// UPDATE_INTERACTIVE_REFUSED instead.
	NonInteractive bool
	Artifacts      []Artifact
	Verify         func(context.Context, Config, CommandRunner, func(context.Context, string) error) error
}

type OperationEvent struct {
	OperationID string    "json:\"operation_id\""
	Stage       string    "json:\"stage\""
	Status      string    "json:\"status\""
	ErrorCode   string    "json:\"error_code,omitempty\""
	Detail      string    "json:\"detail,omitempty\""
	Time        time.Time "json:\"time\""
}

type FileSnapshot struct {
	Target string
	// Logical is the unrooted managed path recorded in state.ManagedFiles.
	Logical string
	Backup  string
	Exists  bool
	Mode    os.FileMode
	UID     int
	GID     int
}

var OperationIDPattern = backup.OperationIDPattern

func ReadState(root string) (InstallState, bool, error) {
	return ReadStateAt(root, InstallerStatePath)
}

// readStateAt reads one ledger from a fixed installer path. The path is
// always an internal constant: no caller, user input or remote request can
// select an arbitrary ledger location.
func ReadStateAt(root, logicalPath string) (InstallState, bool, error) {
	var state InstallState
	path := Rooted(root, logicalPath)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return state, false, nil
	}
	if err != nil {
		return state, false, errors.New(CodeInstallStateUnavailable)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return state, false, errors.New("INSTALL_STATE_UNSAFE")
	}
	data, err := os.ReadFile(path)
	if err != nil || decodeStrictJSON(data, &state) != nil || state.Schema != 1 || state.OperationID == "" || state.Status == "" {
		return state, false, errors.New(CodeInstallStateInvalid)
	}
	return state, true, nil
}

// decodeStrictJSON is the ledger reader shared by every fixed installer ledger
// (#11c-3 spec §4.12). It matches the Agent state reader: an unknown field is a
// fail-closed error, never silently dropped, and a second JSON document after
// the object is refused. `state.Schema != 1` stays a separate refusal in the
// caller, so a future ledger is never interpreted through today's fields.
func decodeStrictJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func FailAndRollback(result InstallResult, state, previous InstallState, hadPrevious bool, opts ApplyOptions, snapshots []FileSnapshot, haveSnapshots bool, record func(string, string, string) error, stage, code, recovery string) (InstallResult, error) {
	rollbackOK := true
	if haveSnapshots {
		rollbackOK = RollbackManaged(context.Background(), opts, snapshots, hadPrevious && previous.Status == "installed")
	}
	if hadPrevious && previous.Status == "installed" && rollbackOK {
		previous.LastOperation = state.OperationID
		previous.ErrorCode = code
		previous.Recovery = recovery
		previous.UpdatedAt = time.Now().UTC()
		_ = WriteState(opts.Root, previous)
		result.Status = "rolled_back"
	} else {
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		if haveSnapshots && rollbackOK {
			// The ledger must mirror the disk, not be emptied: rollback
			// restored every previously existing target from its snapshot and
			// removed the targets this operation created. Recompute the
			// restored files' hashes and drop the deleted entries. Clearing
			// the map would leave managed files on disk with no ownership
			// record, so the next --repair would reject them with
			// MANAGED_PATH_CONFLICT and destroy its own recovery path.
			ReconcileManagedLedger(&state, snapshots)
		}
		_ = WriteState(opts.Root, state)
		result.Status = "partial"
	}
	if !rollbackOK {
		code = "ROLLBACK_FAILED"
		recovery = "Do not delete /var/lib/meshmux or Headscale state. Inspect the operation journal and restore only recorded MeshMux-managed files."
		result.Status = "partial"
		state.Status, state.Stage, state.ErrorCode, state.Recovery = "partial", stage, code, recovery
		state.UpdatedAt = time.Now().UTC()
		_ = WriteState(opts.Root, state)
	}
	result.Stage, result.ErrorCode, result.Recovery = stage, code, recovery
	_ = record(stage, "failed", code)
	return result, &InstallError{Stage: stage, Code: code, Recovery: recovery}
}

func RollbackManaged(ctx context.Context, opts ApplyOptions, snapshots []FileSnapshot, restoreRunning bool) bool {
	// The path unit is the armed privileged surface of #11d. A failed install
	// must not leave it watching the request directory while its service file is
	// restored or removed (Task 4 review item 5). A repair rollback re-enables
	// the previously working path below.
	_, _ = opts.Runner.Run(ctx, "systemctl", "disable", "--now", HubDispatchPathUnit)
	for _, unit := range []string{"meshmux-caddy.service", "meshmux-web.service", "meshmux-headscale.service"} {
		_, _ = opts.Runner.Run(ctx, "systemctl", "stop", unit)
	}
	ok := RestoreFileSnapshots(opts.Root, snapshots)
	if _, err := opts.Runner.Run(ctx, "systemctl", "daemon-reload"); err != nil {
		ok = false
	}
	if restoreRunning && ok {
		for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service"} {
			// The failed apply already spent this unit's StartLimitBurst budget.
			// Restore must clear it before starting the previously verified
			// unit, otherwise systemd refuses the start and a recoverable
			// failure escalates to ROLLBACK_FAILED. Best-effort for the same
			// reason as the repair path.
			_, _ = opts.Runner.Run(ctx, "systemctl", "reset-failed", unit)
			if _, err := opts.Runner.Run(ctx, "systemctl", "start", unit); err != nil {
				ok = false
			}
		}
		// Only a previously installed Hub had the path unit. A pre-#11d
		// installation is restored without it, so enabling a unit the rollback
		// just removed would turn a successful repair into ROLLBACK_FAILED.
		if _, err := os.Lstat(Rooted(opts.Root, HubDispatchPathPath)); err == nil {
			if _, err := opts.Runner.Run(ctx, "systemctl", "enable", "--now", HubDispatchPathUnit); err != nil {
				ok = false
			}
		} else if !os.IsNotExist(err) {
			ok = false
		}
		_, _ = opts.Runner.Run(ctx, "fail2ban-client", "reload")
	} else if !restoreRunning {
		for _, unit := range []string{"meshmux-caddy.service", "meshmux-web.service", "meshmux-headscale.service"} {
			_, _ = opts.Runner.Run(ctx, "systemctl", "disable", unit)
		}
		_, _ = opts.Runner.Run(ctx, "fail2ban-client", "reload")
	}
	return ok
}

// reconcileManagedLedger rewrites the managed-file ledger so it matches the
// disk after a successful rollback. Rollback is "restore the recorded state",
// not "forget the records": targets that existed before the operation were
// copied back from their snapshot and are re-hashed, while targets this
// operation created were removed and therefore drop out of the ledger.
func ReconcileManagedLedger(state *InstallState, snapshots []FileSnapshot) {
	if state.ManagedFiles == nil {
		state.ManagedFiles = map[string]string{}
	}
	for _, s := range snapshots {
		if s.Logical == "" {
			continue
		}
		if !s.Exists {
			delete(state.ManagedFiles, s.Logical)
			continue
		}
		digest, err := SHA256File(s.Target)
		if err != nil {
			// Keep the last recorded digest when the restored file cannot be
			// hashed: a stale entry preserves ownership, an absent one would
			// make the file unrecoverable by --repair.
			continue
		}
		state.ManagedFiles[s.Logical] = digest
	}
}

func VerifyServices(ctx context.Context, c Config, runner CommandRunner, tlsProbe func(context.Context, string) error) error {
	for _, unit := range []string{"meshmux-headscale.service", "meshmux-web.service", "meshmux-caddy.service", "fail2ban.service"} {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
			code := "SERVICE_INACTIVE"
			if strings.Contains(unit, "headscale") {
				code = "HEADSCALE_START_FAILED"
			} else if strings.Contains(unit, "caddy") {
				code = "CADDY_START_FAILED"
			} else if strings.Contains(unit, "web") {
				code = "WEB_START_FAILED"
			} else if strings.Contains(unit, "fail2ban") {
				code = "FAIL2BAN_START_FAILED"
			}
			return &InstallError{Stage: "verify", Code: code, Recovery: "Inspect systemctl status and journalctl for the named service."}
		}
	}
	if err := waitForWebHealth(ctx, c.ManagementDomain); err != nil {
		return &InstallError{Stage: "verify", Code: "WEB_HEALTH_FAILED", Recovery: "Check meshmux-web.service, the loopback Web port, and the private SQLite directory."}
	}
	if _, err := runner.Run(ctx, HeadscaleBinaryPath, "--config", HeadscaleConfigPath, "nodes", "list"); err != nil {
		return &InstallError{Stage: "verify", Code: "HEADSCALE_HEALTH_FAILED", Recovery: "Check the Headscale Unix socket, SQLite database, and journalctl -u meshmux-headscale.service."}
	}
	listeners, err := runner.Run(ctx, "ss", "-H", "-lntup")
	if err != nil || !HasListenerPort(string(listeners), HeadscalePort) || !HasListenerPort(string(listeners), STUNPort) {
		return &InstallError{Stage: "verify", Code: "HEADSCALE_LISTENER_FAILED", Recovery: "Verify the Headscale TCP and embedded DERP STUN ports are bound by the embedded Headscale service."}
	}
	if _, err := runner.Run(ctx, "fail2ban-client", "status", "meshmux-sshd"); err != nil {
		return &InstallError{Stage: "verify", Code: "SSH_FAIL2BAN_JAIL_UNAVAILABLE", Recovery: "Verify the actual SSH listener port and MeshMux SSH jail."}
	}
	if err := tlsProbe(ctx, c.ManagementDomain); err != nil {
		return &InstallError{Stage: "verify", Code: "TLS_ISSUANCE_FAILED", Recovery: "Check public DNS A/AAAA, inbound TCP 80/443, ACME rate limits, and the provider firewall; the installer does not change cloud security groups."}
	}
	return nil
}

func waitForWebHealth(ctx context.Context, domain string) error {
	deadline := time.Now().Add(30 * time.Second)
	client := &http.Client{Timeout: 3 * time.Second}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+versions.WebListenAddress()+"/healthz", nil)
		req.Host = domain
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
	return errors.New("WEB_HEALTH_FAILED")
}

// httpsProbeAddress is the local endpoint Caddy terminates TLS on. Tests
// override it so the readiness semantics can be exercised without binding 443.
var HTTPSProbeAddress = "127.0.0.1:443"

// httpsProbeRoots lets a test trust a purpose-minted certificate. Production
// keeps it nil, which means the system root store.
var HTTPSProbeRoots *x509.CertPool

func WaitForHTTPS(ctx context.Context, domain string) error {
	deadline := time.Now().Add(180 * time.Second)
	dialer := &net.Dialer{Timeout: 3 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			ServerName: domain,
			MinVersion: tls.VersionTLS12,
			RootCAs:    HTTPSProbeRoots,
		},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, HTTPSProbeAddress)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		Timeout:   5 * time.Second,
		// The probe must observe the raw response and never follow redirects.
		// Go's default client chases the first-install 303 (/login -> /setup)
		// until "stopped after 10 redirects", which surfaces as a transport
		// error and hides an already healthy TLS termination.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	for time.Now().Before(deadline) {
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+domain+"/login", nil)
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			// Kubernetes-style readiness semantics: success is "TLS
			// terminated and the origin answered the request", i.e. any
			// 2xx/3xx. A fresh install has no administrator yet, so /login
			// legitimately answers 303 to /setup; that is business state, not
			// an unavailable service. Only 4xx/5xx (or a transport failure)
			// means Caddy/origin is not serving.
			if resp.StatusCode >= 200 && resp.StatusCode < 400 {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}
	return errors.New("TLS_ISSUANCE_FAILED")
}

func HasListenerPort(output string, port int) bool {
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		addr := SsLocalAddress(fields)
		pos := strings.LastIndex(addr, ":")
		if pos < 0 {
			continue
		}
		n, err := strconv.Atoi(strings.Trim(addr[pos+1:], "]"))
		if err == nil && n == port {
			return true
		}
	}
	return false
}

func ActivateUnit(ctx context.Context, runner CommandRunner, unit string, repair bool) error {
	if repair {
		// Repair is the documented recovery path for a broken installation, so
		// systemd's own restart limiter must not veto it: every failed start
		// (crash loop, deterministic refusal, bad flag) consumes the
		// StartLimitBurst budget, and the fourth restart within the interval is
		// rejected with "Start request repeated too quickly". Clearing the
		// counter is best-effort: a unit that is not loaded or has no recorded
		// failure makes reset-failed exit non-zero without meaning the repair
		// cannot proceed.
		_, _ = runner.Run(ctx, "systemctl", "reset-failed", unit)
		_, err := runner.Run(ctx, "systemctl", "restart", unit)
		return err
	}
	_, err := runner.Run(ctx, "systemctl", "enable", "--now", unit)
	return err
}

// architectureForRuntime selects this build's Debian architecture from the one
// supported matrix. Adding an architecture is a versions change plus a data
// entry, never a new branch here.
func ArchitectureForRuntime() string {
	if versions.IsSupportedArchitecture(runtime.GOARCH) {
		return runtime.GOARCH
	}
	return ""
}

func FindArtifact(artifacts []Artifact, name string) Artifact {
	for _, a := range artifacts {
		if a.Component == name {
			return a
		}
	}
	return Artifact{}
}

func ComponentsFor(artifacts []Artifact) []Component {
	out := []Component{{Name: "MeshMux runtime", Version: "same executable as installer", Distribution: "self-copy SHA-256 verified"}}
	for _, a := range artifacts {
		out = append(out, Component{Name: a.Component, Version: a.Version, Distribution: "pinned official GitHub asset; SHA-256 verified"})
	}
	out = append(out,
		Component{Name: "Fail2ban", Version: "Debian 13 package", Distribution: "official Debian repository"},
		Component{Name: "nftables", Version: "Debian 13 package", Distribution: "official Debian repository"},
	)
	return out
}

func ArtifactErrorCode(err error) string {
	switch {
	case strings.Contains(err.Error(), "CHECKSUM"):
		return "ARTIFACT_CHECKSUM_MISMATCH"
	case strings.Contains(err.Error(), "UNTRUSTED"), strings.Contains(err.Error(), "MANIFEST"):
		return "ARTIFACT_MANIFEST_INVALID"
	default:
		return "ARTIFACT_DOWNLOAD_FAILED"
	}
}

func VerifyBinaryVersion(ctx context.Context, runner CommandRunner, path, version string) error {
	output, err := runner.Run(ctx, path, "version")
	if err != nil {
		return errors.New("BINARY_VERSION_INVALID")
	}
	// The release is compared exactly, not searched for: a binary that merely
	// mentions the pinned version in a build tag, or carries a longer release
	// such as 1.19.320, is a different artifact.
	if _, ok := protocol.ReportedVersion(string(output), version); !ok {
		return errors.New("BINARY_VERSION_INVALID")
	}
	return nil
}

func ExtractCaddyBinary(archivePath, target string) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return errors.New("CADDY_BINARY_MISSING")
		}
		if err != nil {
			return err
		}
		if header.Name != "caddy" {
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size < 1 || header.Size > MaxInstallerFile {
			return errors.New("CADDY_ARCHIVE_INVALID")
		}
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0755)
		if err != nil {
			return err
		}
		n, copyErr := io.Copy(out, io.LimitReader(tr, MaxInstallerFile+1))
		syncErr := out.Sync()
		closeErr := out.Close()
		if copyErr != nil || syncErr != nil || closeErr != nil || n != header.Size || n > MaxInstallerFile {
			_ = os.Remove(target)
			return errors.New("CADDY_ARCHIVE_INVALID")
		}
		return os.Chmod(target, 0755)
	}
}

func CopyExecutable(source, target string) (string, error) {
	f, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxInstallerFile {
		return "", errors.New("MESHMUX_BINARY_INVALID")
	}
	if err := copyAtomicFromReader(f, target, 0755); err != nil {
		return "", err
	}
	return SHA256File(target)
}

func CopyAtomic(source, target string, mode os.FileMode) error {
	f, err := os.Open(source)
	if err != nil {
		return err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return errors.New("SOURCE_NOT_REGULAR")
	}
	return copyAtomicFromReader(f, target, mode)
}

func copyAtomicFromReader(source io.Reader, target string, mode os.FileMode) error {
	if err := EnsureNoSymlinkAncestors(filepath.Dir(target)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		return err
	}
	if info, err := os.Lstat(target); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("TARGET_NOT_REGULAR")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), ".meshmux-write-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	n, copyErr := io.Copy(tmp, io.LimitReader(source, MaxInstallerFile+1))
	syncErr := tmp.Sync()
	closeErr := tmp.Close()
	if copyErr != nil || syncErr != nil || closeErr != nil || n > MaxInstallerFile {
		return errors.New("FILE_WRITE_FAILED")
	}
	if err := os.Rename(tmpName, target); err != nil {
		return err
	}
	if dir, err := os.Open(filepath.Dir(target)); err == nil {
		_ = dir.Sync()
		_ = dir.Close()
	}
	return nil
}

func WriteState(root string, state InstallState) error {
	return WriteStateAt(root, InstallerStatePath, state)
}

// EncodeState returns the exact bytes every installer ledger is written with
// (#11d Task 6 re-pins the two ledgers directly; the encoder must not drift
// from the installer's own).
func EncodeState(state InstallState) ([]byte, error) {
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

// writeStateAt persists one ledger to a fixed installer path. The path is
// always an internal constant selected from the recorded layout.
func WriteStateAt(root, logicalPath string, state InstallState) error {
	data, err := EncodeState(state)
	if err != nil {
		return err
	}
	return WriteBytesAtomic(Rooted(root, logicalPath), data, 0600)
}

func WriteBytesAtomic(path string, data []byte, mode os.FileMode) error {
	if err := EnsureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("TARGET_NOT_REGULAR")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".meshmux-state-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(mode.Perm()); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	return nil
}

func AppendOperationEvent(path string, event OperationEvent) error {
	if err := EnsureDirectory(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		return err
	}
	return f.Sync()
}

func EnsureDirectory(path string, mode os.FileMode) error {
	if err := EnsureNoSymlinkAncestors(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("DIRECTORY_UNSAFE")
	}
	return os.Chmod(path, mode.Perm())
}

func EnsureNoSymlinkAncestors(path string) error {
	clean := filepath.Clean(path)
	for current := clean; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("SYMLINK_PATH_REJECTED")
		}
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
	}
	return nil
}

func Rooted(root, absolute string) string {
	if root == "" || root == "/" {
		return absolute
	}
	return filepath.Join(root, strings.TrimPrefix(filepath.Clean(absolute), string(filepath.Separator)))
}

func ManagedTargets(configs map[string]string) []string {
	out := []string{RuntimeBinaryPath, CaddyBinaryPath, HeadscaleBinaryPath}
	for path := range configs {
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

func CheckTargetOwnership(root string, targets []string, state InstallState, hasState bool) error {
	for _, target := range targets {
		info, err := os.Lstat(Rooted(root, target))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_UNSAFE", Recovery: "Inspect the existing target path; MeshMux refuses symlinks and non-regular managed files."}
		}
		if !hasState {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_CONFLICT", Recovery: "A target file already exists without MeshMux ownership state; inspect it manually instead of overwriting it."}
		}
		if _, ok := state.ManagedFiles[target]; !ok {
			return &InstallError{Stage: "preflight", Code: "MANAGED_PATH_CONFLICT", Recovery: "This file is not recorded as MeshMux-managed; inspect it manually instead of overwriting it."}
		}
		// An administrator's subsequent edits are not silently overwritten by
		// install --repair. First inspect and deliberately reconcile the drift.
		digest, digestErr := SHA256File(Rooted(root, target))
		if digestErr != nil || digest != state.ManagedFiles[target] {
			return &InstallError{Stage: "preflight", Code: "MANAGED_FILE_DRIFT", Recovery: "A recorded MeshMux file has changed outside the installer. Back it up and reconcile it manually before repair."}
		}
	}
	return nil
}

func CheckDataOwnership(root string, hasState bool) error {
	if hasState {
		return nil
	}
	for _, dir := range []string{"/var/lib/meshmux", "/var/lib/meshmux-headscale", "/var/lib/meshmux-caddy"} {
		path := Rooted(root, dir)
		info, err := os.Lstat(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return &InstallError{Stage: "preflight", Code: "DATA_PATH_UNSAFE", Recovery: "Inspect the existing data path; MeshMux will not follow symlinks or replace non-directories."}
		}
		entries, readErr := os.ReadDir(path)
		if readErr != nil || len(entries) > 0 {
			return &InstallError{Stage: "preflight", Code: "DATA_STATE_CONFLICT", Recovery: "Data already exists without an installer state record; back it up and inspect it manually. MeshMux will not adopt or delete it."}
		}
	}
	return nil
}

func CheckSystemUsers(ctx context.Context, runner CommandRunner, hasState bool) error {
	for _, user := range []string{"meshmux", "meshmux-headscale", "meshmux-caddy"} {
		output, err := runner.Run(ctx, "getent", "passwd", user)
		if err == nil && len(strings.TrimSpace(string(output))) > 0 && !hasState {
			return &InstallError{Stage: "preflight", Code: "ACCOUNT_CONFLICT", Recovery: "A service account already exists without MeshMux ownership state; do not adopt it automatically."}
		}
	}
	return nil
}

// missingDebianPackages returns only the packages that are not fully
// configured on this host. "install ok installed" is dpkg's success state;
// any other answer (or a query failure) means the package must be installed.
func MissingDebianPackages(ctx context.Context, runner CommandRunner, packages ...string) []string {
	var missing []string
	for _, pkg := range packages {
		output, err := runner.Run(ctx, "dpkg-query", "-W", "-f=${Status}", pkg)
		if err != nil || !strings.Contains(string(output), "install ok installed") {
			missing = append(missing, pkg)
		}
	}
	return missing
}

func EnsureSystemUsers(ctx context.Context, runner CommandRunner, root string, hasState bool) error {
	for _, item := range []struct{ name, home string }{
		{"meshmux", "/var/lib/meshmux"},
		{"meshmux-headscale", "/var/lib/meshmux-headscale"},
		{"meshmux-caddy", "/var/lib/meshmux-caddy"},
	} {
		output, err := runner.Run(ctx, "getent", "passwd", item.name)
		if err == nil && len(strings.TrimSpace(string(output))) > 0 {
			if !hasState {
				return &InstallError{Stage: "apply", Code: "ACCOUNT_CONFLICT", Recovery: "A service account exists without MeshMux ownership state; inspect it manually."}
			}
			continue
		}
		_, err = runner.Run(ctx, "useradd", "--system", "--user-group", "--home-dir", item.home, "--create-home", "--shell", "/usr/sbin/nologin", item.name)
		if err != nil {
			return &InstallError{Stage: "apply", Code: "ACCOUNT_CREATE_FAILED", Recovery: "Check useradd availability and whether a conflicting account exists."}
		}
	}
	return nil
}

func EnsureDataDirectories(ctx context.Context, opts ApplyOptions) error {
	for _, item := range []struct{ path, owner string }{
		{"/var/lib/meshmux", "meshmux:meshmux"},
		{"/var/lib/meshmux-headscale", "meshmux-headscale:meshmux-headscale"},
		{"/var/lib/meshmux-caddy", "meshmux-caddy:meshmux-caddy"},
	} {
		path := Rooted(opts.Root, item.path)
		if err := EnsureDirectory(path, 0700); err != nil {
			return err
		}
		if opts.Root == "/" {
			if _, err := opts.Runner.Run(ctx, "chown", item.owner, item.path); err != nil {
				return err
			}
		}
	}
	return nil
}

func SnapshotTargets(root string, targets []string, state InstallState, hasState bool, backupDir string) ([]FileSnapshot, error) {
	var snapshots []FileSnapshot
	for _, target := range targets {
		path := Rooted(root, target)
		info, err := os.Lstat(path)
		snapshot := FileSnapshot{Target: path, Logical: target, Backup: filepath.Join(backupDir, strings.TrimPrefix(strings.ReplaceAll(target, "/", "_"), "_"))}
		if os.IsNotExist(err) {
			snapshots = append(snapshots, snapshot)
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_UNSAFE", Recovery: "Stop and inspect the target path; symlinks and non-regular files are never replaced."}
		}
		if !hasState {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_CONFLICT", Recovery: "The target file is not recorded as MeshMux-managed."}
		}
		if _, ok := state.ManagedFiles[target]; !ok {
			return snapshots, &InstallError{Stage: "apply", Code: "MANAGED_PATH_CONFLICT", Recovery: "The target file is not recorded as MeshMux-managed."}
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return snapshots, errors.New("TARGET_OWNER_UNKNOWN")
		}
		if err := CopyAtomic(path, snapshot.Backup, info.Mode().Perm()); err != nil {
			return snapshots, err
		}
		snapshot.Exists, snapshot.Mode, snapshot.UID, snapshot.GID = true, info.Mode(), int(stat.Uid), int(stat.Gid)
		snapshots = append(snapshots, snapshot)
	}
	return snapshots, nil
}

func FilePolicy(path string) (os.FileMode, string) {
	switch path {
	case CaddyConfigPath:
		return 0640, "root:meshmux-caddy"
	case HeadscaleConfigPath:
		return 0640, "root:meshmux-headscale"
	case RuntimeBinaryPath, CaddyBinaryPath, HeadscaleBinaryPath:
		return 0755, "root:root"
	default:
		return 0644, "root:root"
	}
}

func SHA256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > MaxInstallerFile {
		return "", errors.New("FILE_SIZE_INVALID")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func CloneInstallState(source InstallState) InstallState {
	copyState := source
	copyState.ManagedFiles = make(map[string]string, len(source.ManagedFiles))
	for key, value := range source.ManagedFiles {
		copyState.ManagedFiles[key] = value
	}
	copyState.Artifacts = make(map[string]string, len(source.Artifacts))
	for key, value := range source.Artifacts {
		copyState.Artifacts[key] = value
	}
	copyState.SharedBinaries = make(map[string]SharedBinary, len(source.SharedBinaries))
	for key, value := range source.SharedBinaries {
		copyState.SharedBinaries[key] = value
	}
	copyState.SSHPorts = append([]int(nil), source.SSHPorts...)
	return copyState
}
