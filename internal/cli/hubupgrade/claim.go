package hubupgrade

// The crash claim of #11d Task 6 (plan Task 6; oracle R1 addition to §5.6 —
// this file is not part of the r6 spec text).
//
// A binary swap and the four-pin re-pin are two different writes. A power loss
// between them leaves the host running the NEW binary while the Hub ledger, the
// co-located Line ledger and agent.json still name the OLD digest. That state is
// invisible to a journal-only reconcile: the operation is `applying`/`restarting`
// and would wait out the 30 minute orphan bound before restore becomes legal,
// even though the next Line start is already blocked by SHARED_BINARY_MISMATCH.
//
// The claim is the root-written anchor that closes that window. It is written
// BEFORE the binary is renamed and deleted after the last pin moved:
//
//   - phase "swapping": the anchor is a whole swap→re-pin section. Boot
//     reconcile pairs it with the running identity: running the target digest
//     means the crash happened after the swap and before/inside the re-pin
//     (HUB_SHARED_BINARY_REPIN_INCOMPLETE, immediately); running the old digest
//     means the swap never became the running image (inert, normal timeout).
//   - phase "repinned": the four pins are in place; only the cleanup of this
//     file did not happen. It is inert.
//
// The claim is evidence, never an authorization: it names no executable, grants
// no write, and a forged one can at most move one already-owned journal
// operation to an honest terminal code. The Web can read it (0640
// root:meshmux) because the boot reconcile runs there; only root writes it.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

const (
	// ClaimDir is the fixed root-owned upgrade directory: the same tree the
	// dispatcher uses for exec copies and the root pre-places manifests in.
	ClaimDir = versions.InstallerUpgradeDir
	// claimName is the fixed claim file inside ClaimDir.
	claimName = "upgrade-claim.json"
	// ClaimSchema is the frozen claim document schema.
	ClaimSchema = 1
	// claimMaxBytes bounds the one document a reader parses.
	claimMaxBytes = 64 << 10

	// ClaimPhaseSwapping covers the whole swap → four-pin re-pin section.
	ClaimPhaseSwapping = "swapping"
	// ClaimPhaseRepinned means every pin moved; only cleanup may be missing.
	ClaimPhaseRepinned = "repinned"

	codeClaimInvalid = "HUB_UPGRADE_CLAIM_INVALID"
	codeClaimWrite   = "HUB_UPGRADE_CLAIM_FAILED"
)

// The two seams exist so the B-level fixture can prove the production root
// branch (group resolution and pre-rename ownership) without running as root.
var (
	claimEUID    = os.Geteuid
	claimGroupID = meshmuxGroupID
)

// Pins is the complete four-source pin set of spec §5.6 step 6 plus the two
// managed_files entries that must move with them:
//
//	Hub ledger      shared_binaries["meshmuxd"].sha256 + managed_files[binary]
//	Line ledger     shared_binaries["meshmuxd"].sha256 + state.Node.AgentVersion/AgentSHA256
//	Line ledger     managed_files["/etc/meshmux/agent.json"]
//	agent.json      agent_version / agent_sha256
//
// Empty Line fields mean this host has no co-located Line: the Hub ledger is
// then the only file a re-pin owns.
type Pins struct {
	HubSharedSHA  string `json:"hub_shared_sha256"`
	HubManagedSHA string `json:"hub_managed_sha256"`

	LineSharedSHA       string `json:"line_shared_sha256,omitempty"`
	LineAgentVersion    string `json:"line_agent_version,omitempty"`
	LineAgentSHA        string `json:"line_agent_sha256,omitempty"`
	LineAgentManagedSHA string `json:"line_agent_managed_sha256,omitempty"`

	AgentJSONVersion string `json:"agent_json_version,omitempty"`
	AgentJSONSHA     string `json:"agent_json_sha256,omitempty"`
}

// HasLine reports whether this pin set owns a co-located Line. A partial
// set is never accepted as "no Line": every write path treats it as a corrupt
// claim rather than silently skipping half of the write set.
func (p Pins) HasLine() bool {
	return p.LineSharedSHA != "" || p.LineAgentVersion != "" || p.LineAgentSHA != "" ||
		p.LineAgentManagedSHA != "" || p.AgentJSONVersion != "" || p.AgentJSONSHA != ""
}

// CompleteLine reports a fully populated Line half. It is the only shape the
// re-pin accepts when HasLine is true.
func (p Pins) CompleteLine() bool {
	return digestRE.MatchString(p.LineSharedSHA) &&
		targetRE.MatchString(p.LineAgentVersion) &&
		digestRE.MatchString(p.LineAgentSHA) &&
		digestRE.MatchString(p.LineAgentManagedSHA) &&
		targetRE.MatchString(p.AgentJSONVersion) &&
		digestRE.MatchString(p.AgentJSONSHA)
}

// Claim is the crash anchor of one update execution. OldPins is the complete
// pre-swap set, so a reboot can compare both sides without trusting any file
// that may already have moved.
type Claim struct {
	Schema        int       `json:"schema"`
	Phase         string    `json:"phase"`
	OperationID   string    `json:"operation_id"`
	TargetVersion string    `json:"target_version"`
	FromVersion   string    `json:"from_version"`
	NewSHA256     string    `json:"new_sha256"`
	OldPins       Pins      `json:"old_pins"`
	CreatedAt     time.Time `json:"created_at"`
}

// ReadClaim returns the claim of this upgrade directory. A missing file is
// (zero, false, nil); a malformed, loose or symlinked one is an error. The Web
// (meshmux) reads it: the owner may be root or the calling account, but the
// mode is exactly 0640 and the file is never a link.
func ReadClaim(dir string) (Claim, bool, error) {
	var claim Claim
	if dir == "" || !filepath.IsAbs(dir) {
		return claim, false, fail(codeClaimInvalid, "the claim directory is not absolute")
	}
	path := filepath.Join(dir, claimName)
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return claim, false, nil
	}
	if err != nil {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim could not be inspected")
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0640 || !claimReaderOwns(info) ||
		info.Size() < 1 || info.Size() > claimMaxBytes {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim is not a private-enough 0640 file")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim could not be opened without following a link")
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim changed while it was being opened")
	}
	body, err := io.ReadAll(io.LimitReader(file, claimMaxBytes+1))
	if err != nil || len(body) > claimMaxBytes {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim could not be read within its bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claim); err != nil {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim is not valid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return claim, false, fail(codeClaimInvalid, "the upgrade claim carries trailing data")
	}
	if err := validateClaim(claim); err != nil {
		return claim, false, err
	}
	return claim, true, nil
}

func validateClaim(claim Claim) error {
	switch {
	case claim.Schema != ClaimSchema:
		return fail(codeClaimInvalid, "the upgrade claim does not carry this schema")
	case claim.Phase != ClaimPhaseSwapping && claim.Phase != ClaimPhaseRepinned:
		return fail(codeClaimInvalid, "the upgrade claim phase is not swapping or repinned")
	case !opIDRE.MatchString(claim.OperationID):
		return fail(codeClaimInvalid, "the upgrade claim operation id is not 32 lowercase hex")
	case !targetRE.MatchString(claim.TargetVersion) || !targetRE.MatchString(claim.FromVersion):
		return fail(codeClaimInvalid, "the upgrade claim version is not a SemVer release")
	case !digestRE.MatchString(claim.NewSHA256):
		return fail(codeClaimInvalid, "the upgrade claim does not name the new digest")
	case !digestRE.MatchString(claim.OldPins.HubSharedSHA) || !digestRE.MatchString(claim.OldPins.HubManagedSHA):
		return fail(codeClaimInvalid, "the upgrade claim does not name the old Hub pins")
	case claim.OldPins.HasLine() && !claim.OldPins.CompleteLine():
		return fail(codeClaimInvalid, "the upgrade claim carries a partial Line pin set")
	case claim.CreatedAt.IsZero():
		return fail(codeClaimInvalid, "the upgrade claim has no creation time")
	}
	return nil
}

// WriteClaim publishes one claim atomically as 0640. In production the process
// is root and the group is set to meshmux so the Web's boot reconcile can read
// it; a fixture or a host without the account stays root:root, which is
// stricter, not weaker.
func WriteClaim(dir string, claim Claim) error {
	if err := validateClaim(claim); err != nil {
		return err
	}
	if dir == "" || !filepath.IsAbs(dir) {
		return fail(codeClaimWrite, "the claim directory is not absolute")
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fail(codeClaimWrite, "the claim directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fail(codeClaimWrite, "the claim directory is not a real directory")
	}
	body, err := marshalIndentNoHTML(claim)
	if err != nil {
		return fail(codeClaimInvalid, "the upgrade claim could not be encoded")
	}
	// Root must publish the file Web-readable from the first instant it exists.
	// A missing meshmux group is a broken install, not a reason to fall back to
	// a root:root claim the boot reconcile could never read: fail closed before
	// creating any scratch file.
	gid, isRoot := 0, claimEUID() == 0
	if isRoot {
		resolved, ok := claimGroupID()
		if !ok {
			return fail(codeClaimWrite, "the meshmux group is unavailable; the claim would not be Web-readable")
		}
		gid = resolved
	}
	target := filepath.Join(dir, claimName)
	scratch, err := os.CreateTemp(dir, "."+claimName+".part-*")
	if err != nil {
		return fail(codeClaimWrite, "the upgrade claim scratch file could not be created")
	}
	scratchName := scratch.Name()
	cleanup := func() {
		_ = scratch.Close()
		_ = os.Remove(scratchName)
	}
	if err := scratch.Chmod(0640); err != nil {
		cleanup()
		return fail(codeClaimWrite, "the upgrade claim could not be made group-readable")
	}
	if _, err := scratch.Write(body); err != nil {
		cleanup()
		return fail(codeClaimWrite, "the upgrade claim could not be written")
	}
	// Ownership is fixed on the scratch inode BEFORE the rename, so the target
	// name is never visible with the wrong group even for one instant.
	if isRoot {
		if err := scratch.Chown(0, gid); err != nil {
			cleanup()
			return fail(codeClaimWrite, "the upgrade claim ownership could not be fixed before publication")
		}
	}
	// The sync is after chown: the persisted inode must already carry the final
	// owner/mode.
	if err := scratch.Sync(); err != nil {
		cleanup()
		return fail(codeClaimWrite, "the upgrade claim could not be flushed")
	}
	if err := scratch.Close(); err != nil {
		_ = os.Remove(scratchName)
		return fail(codeClaimWrite, "the upgrade claim could not be closed")
	}
	if err := os.Rename(scratchName, target); err != nil {
		_ = os.Remove(scratchName)
		return fail(codeClaimWrite, "the upgrade claim could not be published")
	}
	if err := syncDirectory(dir); err != nil {
		return fail(codeClaimWrite, "the claim directory could not be flushed")
	}
	return nil
}

// RemoveClaim deletes the claim and flushes its directory. A missing claim is
// success (the cleanup is idempotent).
func RemoveClaim(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return fail(codeClaimWrite, "the claim directory is not absolute")
	}
	if err := os.Remove(filepath.Join(dir, claimName)); err != nil && !os.IsNotExist(err) {
		return fail(codeClaimWrite, "the upgrade claim could not be removed")
	}
	if err := syncDirectory(dir); err != nil {
		return fail(codeClaimWrite, "the claim directory could not be flushed")
	}
	return nil
}

// claimReaderOwns accepts the production root owner and the current account
// (a fixture or a root process). Being able to read a claim is never treated as
// authority: the claim only names a terminal code for an operation the reader
// already owns.
func claimReaderOwns(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(stat.Uid) == 0 || int(stat.Uid) == os.Geteuid()
}
