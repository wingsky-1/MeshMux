package node

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func runningExecutableHash(pid int, procRoot string) (string, error) {
	if pid < 1 {
		return "", errors.New("PROCESS_PID_INVALID")
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	path := filepath.Join(procRoot, strconv.Itoa(pid), "exe")
	// procfs exposes an executable through a symlink. Open once so the
	// descriptor remains tied to this PID while its bytes are hashed.
	file, err := os.Open(path)
	if err != nil {
		return "", errors.New("PROCESS_EXECUTABLE_UNAVAILABLE")
	}
	defer file.Close()
	if filepath.Clean(procRoot) == "/proc" {
		info, statErr := file.Stat()
		if statErr != nil || !info.Mode().IsRegular() {
			return "", errors.New("PROCESS_EXECUTABLE_UNSAFE")
		}
	}
	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return "", errors.New("PROCESS_EXECUTABLE_READ_FAILED")
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// runningExecutableTarget reports which file a PID was started from. Only
// the link target is exposed, never file contents; used to tell a wrong
// binary apart from a corrupt one when the running hash mismatches.
func runningExecutableTarget(pid int, procRoot string) string {
	if pid < 1 {
		return "none"
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	target, err := os.Readlink(filepath.Join(procRoot, strconv.Itoa(pid), "exe"))
	if err != nil {
		return "unresolvable"
	}
	return target
}

// hashPrefix keeps mismatch diagnostics short: twelve hex chars identify
// a binary without printing full digests into logs.
func hashPrefix(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// exeIsSupervisor reports whether a PID is still the systemd executor that
// has not execed into the service binary yet. systemd 257 forks
// systemd-executor per service to apply sandboxing before exec; catching it
// means "not running yet", never "wrong binary".
func exeIsSupervisor(pid int, procRoot string) bool {
	target := runningExecutableTarget(pid, procRoot)
	base := target
	if i := strings.LastIndex(target, "/"); i >= 0 {
		base = target[i+1:]
	}
	return strings.HasPrefix(base, "systemd-executor")
}

func processRunning(pid int) bool {
	if pid < 1 {
		return false
	}
	_, err := os.Stat(filepath.Join("/proc", strconv.Itoa(pid)))
	return err == nil
}

func processArgv(pid int, procRoot string) ([]string, error) {
	if pid < 1 {
		return nil, errors.New("PROCESS_PID_INVALID")
	}
	if procRoot == "" {
		procRoot = "/proc"
	}
	data, err := os.ReadFile(filepath.Join(procRoot, strconv.Itoa(pid), "cmdline"))
	if err != nil || len(data) == 0 || data[len(data)-1] != 0 {
		return nil, errors.New("PROCESS_CMDLINE_UNAVAILABLE")
	}
	argv := strings.Split(string(data[:len(data)-1]), "\x00")
	for _, arg := range argv {
		if arg == "" || strings.ContainsRune(arg, 0) {
			return nil, errors.New("PROCESS_CMDLINE_INVALID")
		}
	}
	return argv, nil
}
