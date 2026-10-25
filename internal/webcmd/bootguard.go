package webcmd

// The boot-attempt guard of #11d Task 7 (D2).
//
// systemd's StartLimitBurst stops a crash-looping unit, but it counts every
// start, including ordinary configuration refusals. This guard adds the fact
// systemd cannot know: how many times the same release started and never became
// healthy. The Web clears the file as soon as it is listening; a process that
// dies before that leaves the attempt behind. After three unhealthy starts of
// one version inside ten minutes the next start exits with
// HUB_UPGRADE_BOOT_CRASH_LOOP instead of burning another restart budget.
//
// The file lives in /run (tmpfs): a host reboot resets the evidence, which is
// correct — a host that boots cleanly has not proven a crash loop. The guard is
// availability hardening, never authorization: a malformed file is reset, and a
// missing writable directory must not prevent the Web from starting.

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

const (
	// BootDir is the fixed runtime directory the installer creates 0730
	// root:meshmux and the Web declares writable.
	BootDir = "/run/meshmux-hub/boot"
	// BootAttemptsName is the one attempt document.
	BootAttemptsName = "boot-attempts.json"
	// BootWindow is the observation window of a crash loop.
	BootWindow = 10 * time.Minute
	// BootMaxAttempts is the number of unhealthy starts after which the next
	// start is refused.
	BootMaxAttempts = 3
	// CodeBootCrashLoop is the stable code the caller logs and exits with.
	CodeBootCrashLoop = "HUB_UPGRADE_BOOT_CRASH_LOOP"
)

type bootAttempts struct {
	Schema   int         `json:"schema"`
	Version  string      `json:"version"`
	Attempts []time.Time `json:"attempts"`
}

// BootGuard records one start attempt for version and reports whether this
// start must be refused. A successful start calls ClearBootAttempts, which
// removes the file.
func BootGuard(dir string, now time.Time, version string) (refuse bool, err error) {
	if dir == "" || !filepath.IsAbs(dir) {
		return false, errors.New("BOOT_GUARD_INVALID: the boot directory is not absolute")
	}
	if version == "" {
		return false, errors.New("BOOT_GUARD_INVALID: the running version is unknown")
	}
	if err := ensureBootDir(dir); err != nil {
		return false, err
	}
	path := filepath.Join(dir, BootAttemptsName)
	attempts := readBootAttempts(path)
	if attempts.Version != version {
		attempts = bootAttempts{}
	}
	pruned := attempts.Attempts[:0]
	for _, attempt := range attempts.Attempts {
		if now.Sub(attempt) <= BootWindow {
			pruned = append(pruned, attempt)
		}
	}
	if len(pruned) >= BootMaxAttempts {
		// Do not append: every further restart inside the window is refused for
		// the same reason until an operator intervenes or the window expires.
		return true, nil
	}
	attempts.Schema, attempts.Version = 1, version
	attempts.Attempts = append(pruned, now.UTC())
	if err := writeBootAttempts(path, attempts); err != nil {
		return false, err
	}
	return false, nil
}

// ClearBootAttempts is the healthy-start signal. A missing file is success.
func ClearBootAttempts(dir string) error {
	if dir == "" || !filepath.IsAbs(dir) {
		return nil
	}
	path := filepath.Join(dir, BootAttemptsName)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return syncBootDir(dir)
}

func ensureBootDir(dir string) error {
	if err := os.MkdirAll(dir, 0730); err != nil {
		return errors.New("BOOT_GUARD_UNAVAILABLE: the boot directory is unavailable")
	}
	info, err := os.Lstat(dir)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm()&0002 != 0 {
		return errors.New("BOOT_GUARD_UNAVAILABLE: the boot directory is not a safe real directory")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (int(stat.Uid) != 0 && int(stat.Uid) != os.Geteuid()) {
		return errors.New("BOOT_GUARD_UNAVAILABLE: the boot directory belongs to another account")
	}
	return nil
}

// readBootAttempts treats an unreadable or malformed document as no evidence:
// the guard must not brick a service whose tmpfs was tampered with. The next
// write replaces it atomically.
func readBootAttempts(path string) bootAttempts {
	var attempts bootAttempts
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() ||
		info.Mode().Perm() != 0600 || info.Size() <= 0 || info.Size() > 64<<10 {
		return bootAttempts{}
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return bootAttempts{}
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&attempts); err != nil {
		return bootAttempts{}
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return bootAttempts{}
	}
	if attempts.Schema != 1 {
		return bootAttempts{}
	}
	return attempts
}

func writeBootAttempts(path string, attempts bootAttempts) error {
	body, err := json.MarshalIndent(attempts, "", "  ")
	if err != nil {
		return errors.New("BOOT_GUARD_WRITE_FAILED: the attempt document could not be encoded")
	}
	dir := filepath.Dir(path)
	part := path + ".part"
	_ = os.Remove(part)
	file, err := os.OpenFile(part, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("BOOT_GUARD_WRITE_FAILED: the attempt document could not be written")
	}
	_, writeErr := file.Write(body)
	if writeErr == nil {
		writeErr = file.Sync()
	}
	if closeErr := file.Close(); writeErr == nil {
		writeErr = closeErr
	}
	if writeErr != nil {
		_ = os.Remove(part)
		return errors.New("BOOT_GUARD_WRITE_FAILED: the attempt document could not be flushed")
	}
	if err := os.Rename(part, path); err != nil {
		_ = os.Remove(part)
		return errors.New("BOOT_GUARD_WRITE_FAILED: the attempt document could not be published")
	}
	return syncBootDir(dir)
}

func syncBootDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer handle.Close()
	_ = handle.Sync()
	return nil
}
