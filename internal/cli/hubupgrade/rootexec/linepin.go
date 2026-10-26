package rootexec

// The four-pin Line re-pin of #11d Task 6 (spec §5.6 step 3 and step 6, MF-3).
//
// A Hub upgraded in place must move the co-located Line with it in the same
// operation. Five facts prove that host is quiescent before any write:
//
//	Hub ledger shared_binaries["meshmuxd"]              == installed binary
//	Line ledger shared_binaries["meshmuxd"]             == installed binary
//	Line ledger state.Node.AgentVersion/AgentSHA256     == from_version / installed
//	Line ledger managed_files["/etc/meshmux/agent.json"] == agent.json bytes
//	agent.json agent_version/agent_sha256               == from_version / installed
//
// Missing the Line ledger's state.Node pair is the subtle dead-end: the next
// `--from-recorded-state` handoff reads it through checkRecordedAgentConfig and
// refuses with CONFIG_CONFLICT even though the two ledgers and agent.json look
// right. The write side is therefore one set of three atomic file replacements
// (Hub ledger, Line ledger, agent.json); if any of them cannot be staged, none
// is renamed, and a failure after the first rename restores every pin from the
// old set (never only the files already changed).

import (
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/hubupgrade"
	"github.com/wingsky-1/MeshMux/internal/cli/install"
	"github.com/wingsky-1/MeshMux/internal/cli/versions"
	"github.com/wingsky-1/MeshMux/internal/core/node"
)

// Pins is the hubupgrade pin-set document this executor reads and writes.
type Pins = hubupgrade.Pins

// lineLedgerFilePath mirrors internal/install's unexported constant; the Hub
// ledger path is shared with ledger.go. The privileged executor may not import
// a caller-selected path here.
const lineLedgerFilePath = versions.LocalLineStatePath

// renamePinFile is the one rename point of the pin publisher. It exists as a
// variable so a B-level test can inject a rename-time failure without relying
// on a permission trick that root would ignore.
var renamePinFile = os.Rename

// readPins reads and cross-checks the complete pre-swap pin set for the given
// running digest. Any missing, malformed, foreign-owned or disagreeing source
// is HUB_SHARED_BINARY_PRECHECK_FAILED: the caller must make no write.
func readPins(root string, expectedOwner int, fromVersion, currentSHA string) (Pins, error) {
	var pins Pins
	if !ledgerDigestRE.MatchString(currentSHA) {
		return pins, fail(codePrecheck, "the current installed binary digest is not SHA-256 hex")
	}
	hubPath := rootedPath(root, hubLedgerPath)
	hub, found, err := install.ReadState(root)
	if err != nil || !found {
		return pins, fail(codePrecheck, "the Hub installer ledger is not readable")
	}
	if err := requireOwnedFile(hubPath, expectedOwner); err != nil {
		return pins, err
	}
	hubShared, ok := hub.SharedBinaries[sharedAgentKey]
	if !ok || hubShared.Path != node.AgentBinaryPath || hubShared.SHA256 != currentSHA {
		return pins, fail(codePrecheck, "the Hub ledger shared-binary pin does not name the installed binary")
	}
	hubManaged, ok := hub.ManagedFiles[node.AgentBinaryPath]
	if !ok || !ledgerDigestRE.MatchString(hubManaged) {
		return pins, fail(codePrecheck, "the Hub ledger does not record the installed binary digest")
	}
	pins.HubSharedSHA, pins.HubManagedSHA = hubShared.SHA256, hubManaged

	linePath := rootedPath(root, lineLedgerFilePath)
	line, hasLine, err := install.ReadLocalLineState(root)
	if err != nil {
		return pins, fail(codePrecheck, "the co-located Line ledger is not readable")
	}
	if !hasLine {
		// A standalone Hub has no Line half: the Hub ledger is the whole pin
		// set. agent.json is deliberately not consulted in that layout.
		return pins, nil
	}
	if err := requireOwnedFile(linePath, expectedOwner); err != nil {
		return pins, err
	}
	lineShared, ok := line.SharedBinaries[sharedAgentKey]
	if !ok || lineShared.Path != node.AgentBinaryPath || lineShared.SHA256 != currentSHA {
		return pins, fail(codePrecheck, "the Line ledger shared-binary pin does not name the installed binary")
	}
	if line.Node == nil || line.Node.AgentVersion != fromVersion || line.Node.AgentSHA256 != currentSHA {
		return pins, fail(codePrecheck, "the Line ledger state.Node does not name the running release")
	}
	agentCfg, agentBody, err := readAgentConfig(rootedPath(root, node.AgentConfigPath), expectedOwner)
	if err != nil {
		return pins, err
	}
	if agentCfg.AgentVersion != fromVersion || agentCfg.AgentSHA256 != currentSHA {
		return pins, fail(codePrecheck, "agent.json does not name the running release")
	}
	lineManaged, ok := line.ManagedFiles[node.AgentConfigPath]
	if !ok || lineManaged != sha256Of(agentBody) {
		return pins, fail(codePrecheck, "the Line ledger does not record the current agent.json bytes")
	}
	pins.LineSharedSHA = lineShared.SHA256
	pins.LineAgentVersion = line.Node.AgentVersion
	pins.LineAgentSHA = line.Node.AgentSHA256
	pins.LineAgentManagedSHA = lineManaged
	pins.AgentJSONVersion = agentCfg.AgentVersion
	pins.AgentJSONSHA = agentCfg.AgentSHA256
	return pins, nil
}

// writePins moves the whole set from next to old's shape. It stages all three
// documents before renaming any; a staging failure changes nothing, and a
// rename failure restores the old set through the same staging path. The
// returned error says whether any target may still differ (repinError.mutated).
func writePins(root string, next, old Pins) error {
	if err := validatePinSet(next); err != nil {
		return &repinError{err: err}
	}
	if old.HasLine() && !old.CompleteLine() {
		return &repinError{err: fail(codeRepinFailed, "the old Line pin set is incomplete")}
	}
	if next.HasLine() != old.HasLine() {
		return &repinError{err: fail(codeRepinFailed, "the Line pin set changed shape")}
	}
	// Capture the exact pre-write bytes. A rename-time failure is restored from
	// these bytes (not by re-rendering the old Pins), so the rollback is
	// byte-identical to the previous ledgers and agent.json.
	snapshots, err := capturePinBodies(root, old.HasLine())
	if err != nil {
		return &repinError{err: err}
	}
	if err := writePinSet(root, next); err != nil {
		var staged *pinStageError
		if errors.As(err, &staged) {
			// Nothing was renamed: every target still holds the old bytes.
			return &repinError{err: err}
		}
		// At least one rename happened. Restore the complete old set, not only
		// the files this call already touched.
		if restoreErr := publishPinBodies(snapshots); restoreErr != nil {
			return &repinError{err: restoreErr, mutated: true}
		}
		return &repinError{err: err}
	}
	return nil
}

func validatePinSet(pins Pins) error {
	if !ledgerDigestRE.MatchString(pins.HubSharedSHA) || !ledgerDigestRE.MatchString(pins.HubManagedSHA) {
		return fail(codeRepinFailed, "the new Hub pin set is incomplete")
	}
	if pins.HasLine() && !pins.CompleteLine() {
		return fail(codeRepinFailed, "the new Line pin set is incomplete")
	}
	if pins.HasLine() && (pins.LineAgentVersion != pins.AgentJSONVersion) {
		return fail(codeRepinFailed, "the two Line version pins disagree")
	}
	if pins.HasLine() && (pins.LineAgentSHA != pins.AgentJSONSHA) {
		return fail(codeRepinFailed, "the two Line digest pins disagree")
	}
	return nil
}

// repinError is a pin-set write failure. mutated says a target may still differ
// from the old set; RunUpdate then writes a partial receipt instead of claiming
// a clean rollback.
type repinError struct {
	err     error
	mutated bool
}

func (e *repinError) Error() string { return e.err.Error() }
func (e *repinError) Unwrap() error { return e.err }

// pinStageError marks a failure before any rename: the old bytes are intact.
type pinStageError struct{ err error }

func (e *pinStageError) Error() string { return e.err.Error() }
func (e *pinStageError) Unwrap() error { return e.err }

// lease is one fully staged replacement waiting for its rename.
type lease struct {
	target string
	temp   string
	dir    string
}

// writePinSet stages the three documents of one pin set and then renames them.
// A staging failure returns *pinStageError after removing every scratch file.
func writePinSet(root string, pins Pins) error {
	owner := os.Geteuid()
	hubPath := rootedPath(root, hubLedgerPath)
	hub, found, err := install.ReadState(root)
	if err != nil || !found {
		return &pinStageError{err: fail(codeRepinFailed, "the Hub ledger could not be re-read for the pin write")}
	}
	if err := requireOwnedFile(hubPath, owner); err != nil {
		return &pinStageError{err: err}
	}
	if hub.SharedBinaries == nil {
		hub.SharedBinaries = map[string]install.SharedBinary{}
	}
	shared := hub.SharedBinaries[sharedAgentKey]
	shared.Path, shared.SHA256 = node.AgentBinaryPath, pins.HubSharedSHA
	hub.SharedBinaries[sharedAgentKey] = shared
	if hub.ManagedFiles == nil {
		hub.ManagedFiles = map[string]string{}
	}
	hub.ManagedFiles[node.AgentBinaryPath] = pins.HubManagedSHA
	hubBody, err := install.EncodeState(hub)
	if err != nil {
		return &pinStageError{err: fail(codeRepinFailed, "the Hub ledger could not be encoded")}
	}
	bodies := []pinBody{{path: hubPath, body: hubBody, mode: 0600}}

	if pins.HasLine() {
		linePath := rootedPath(root, lineLedgerFilePath)
		line, found, err := install.ReadLocalLineState(root)
		if err != nil || !found {
			return &pinStageError{err: fail(codeRepinFailed, "the Line ledger could not be re-read for the pin write")}
		}
		if err := requireOwnedFile(linePath, owner); err != nil {
			return &pinStageError{err: err}
		}
		if line.Node == nil {
			return &pinStageError{err: fail(codeRepinFailed, "the Line ledger has no state.Node to re-pin")}
		}
		agentPath := rootedPath(root, node.AgentConfigPath)
		agentCfg, _, err := readAgentConfig(agentPath, owner)
		if err != nil {
			return &pinStageError{err: err}
		}
		agentCfg.AgentVersion, agentCfg.AgentSHA256 = pins.AgentJSONVersion, pins.AgentJSONSHA
		agentBody, err := renderAgentConfig(agentCfg)
		if err != nil {
			return &pinStageError{err: err}
		}
		if got := sha256Of(agentBody); got != pins.LineAgentManagedSHA {
			return &pinStageError{err: fail(codeRepinFailed, "the rendered agent.json does not match the Line managed pin")}
		}
		if line.SharedBinaries == nil {
			line.SharedBinaries = map[string]install.SharedBinary{}
		}
		lineShared := line.SharedBinaries[sharedAgentKey]
		lineShared.Path, lineShared.SHA256 = node.AgentBinaryPath, pins.LineSharedSHA
		line.SharedBinaries[sharedAgentKey] = lineShared
		line.Node.AgentVersion, line.Node.AgentSHA256 = pins.LineAgentVersion, pins.LineAgentSHA
		line.UpdatedAt = time.Now().UTC()
		if line.ManagedFiles == nil {
			line.ManagedFiles = map[string]string{}
		}
		line.ManagedFiles[node.AgentConfigPath] = pins.LineAgentManagedSHA
		lineBody, err := install.EncodeState(line)
		if err != nil {
			return &pinStageError{err: fail(codeRepinFailed, "the Line ledger could not be encoded")}
		}
		bodies = append(bodies,
			pinBody{path: linePath, body: lineBody, mode: 0600},
			pinBody{path: agentPath, body: agentBody, mode: 0600})
	}

	return publishPinBodies(bodies)
}

// capturePinBodies reads the exact pre-write bytes of every file the pin set
// owns. It is the rollback source for a rename-time failure.
func capturePinBodies(root string, hasLine bool) ([]pinBody, error) {
	paths := []string{rootedPath(root, hubLedgerPath)}
	if hasLine {
		paths = append(paths, rootedPath(root, lineLedgerFilePath), rootedPath(root, node.AgentConfigPath))
	}
	bodies := make([]pinBody, 0, len(paths))
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, fail(codeRepinFailed, "a pin target is not a regular file")
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil, fail(codeRepinFailed, "a pin target could not be read for rollback")
		}
		bodies = append(bodies, pinBody{path: path, body: body, mode: info.Mode().Perm()})
	}
	return bodies, nil
}

// publishPinBodies stages every body first and only then renames. A stage
// failure returns *pinStageError (no rename happened); a rename failure leaves
// the caller to restore the captured bytes.
func publishPinBodies(bodies []pinBody) error {
	leases := make([]lease, 0, len(bodies))
	cleanup := func() {
		for _, item := range leases {
			if item.temp != "" {
				_ = os.Remove(item.temp)
			}
		}
	}
	for _, body := range bodies {
		item, err := stagePinBody(body)
		if err != nil {
			cleanup()
			return &pinStageError{err: err}
		}
		leases = append(leases, item)
	}
	for i, item := range leases {
		if err := renamePinFile(item.temp, item.target); err != nil {
			for _, rest := range leases[i:] {
				_ = os.Remove(rest.temp)
			}
			return fail(codeRepinFailed, "a pin file could not be published")
		}
		leases[i].temp = ""
	}
	synced := map[string]bool{}
	for _, item := range leases {
		if synced[item.dir] {
			continue
		}
		synced[item.dir] = true
		if err := syncDirEntry(item.dir); err != nil {
			return fail(codeRepinFailed, "a pin directory could not be flushed")
		}
	}
	return nil
}

type pinBody struct {
	path string
	body []byte
	mode os.FileMode
}

func stagePinBody(body pinBody) (lease, error) {
	dir := filepath.Dir(body.path)
	info, err := os.Lstat(body.path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return lease{}, fail(codeRepinFailed, "a pin target is not a regular file")
	}
	scratch, err := os.CreateTemp(dir, ".pin-"+filepath.Base(body.path)+".part-*")
	if err != nil {
		return lease{}, fail(codeRepinFailed, "a pin scratch file could not be created")
	}
	name := scratch.Name()
	cleanup := func() {
		_ = scratch.Close()
		_ = os.Remove(name)
	}
	if err := scratch.Chmod(body.mode); err != nil {
		cleanup()
		return lease{}, fail(codeRepinFailed, "a pin scratch file could not be made private")
	}
	if _, err := scratch.Write(body.body); err != nil {
		cleanup()
		return lease{}, fail(codeRepinFailed, "a pin scratch file could not be written")
	}
	if err := scratch.Sync(); err != nil {
		cleanup()
		return lease{}, fail(codeRepinFailed, "a pin scratch file could not be flushed")
	}
	if err := scratch.Close(); err != nil {
		_ = os.Remove(name)
		return lease{}, fail(codeRepinFailed, "a pin scratch file could not be closed")
	}
	return lease{target: body.path, temp: name, dir: dir}, nil
}

// requireOwnedFile enforces the ledger file's shape: a real 0600 file owned by
// the named account. Byte reachability is not authorization.
func requireOwnedFile(path string, expectedOwner int) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || !statOwnedBy(info, expectedOwner) {
		return fail(codePrecheck, "an installer ledger is not a private root-owned 0600 file")
	}
	return nil
}

// rootedPath joins a fixed absolute installer path to a fixture root.
func rootedPath(root, absolute string) string {
	if root == "" || root == "/" {
		return absolute
	}
	return filepath.Join(root, absolute)
}
