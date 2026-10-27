package install

import (
	"os"
	"path/filepath"
	"testing"
)

const testLockRecovery = "Check /run/lock ownership and symlinks."

func TestInstallLockBranches(t *testing.T) {
	t.Run("busy then released", func(t *testing.T) {
		root := t.TempDir()
		first, lockErr := acquireInstallLock(root, testLockRecovery)
		if lockErr != nil {
			t.Fatalf("first acquireInstallLock: %+v", lockErr)
		}
		if first == nil {
			t.Fatal("first acquireInstallLock returned a nil lock")
		}
		t.Cleanup(first.Close)

		lockPath := filepath.Join(root, "run", "lock", "meshmux-install.lock")
		info, err := os.Stat(lockPath)
		if err != nil {
			t.Fatalf("lock file was not created under the isolated root: %v", err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("lock file mode = %v, want regular 0600", info.Mode())
		}

		second, busyErr := acquireInstallLock(root, testLockRecovery)
		if second != nil {
			second.Close()
			t.Fatal("second acquireInstallLock returned a lock while the first was held")
		}
		if busyErr == nil {
			t.Fatal("second acquireInstallLock returned no error")
		}
		if busyErr.Stage != "preflight" || busyErr.Code != "INSTALL_BUSY" {
			t.Fatalf("busy error = %+v, want preflight/INSTALL_BUSY", busyErr)
		}
		const busyRecovery = "Another MeshMux installation is running; wait for it to finish."
		if busyErr.Recovery != busyRecovery {
			t.Fatalf("busy recovery = %q, want %q", busyErr.Recovery, busyRecovery)
		}

		first.Close()
		third, thirdErr := acquireInstallLock(root, testLockRecovery)
		if thirdErr != nil {
			t.Fatalf("acquire after release: %+v", thirdErr)
		}
		if third == nil {
			t.Fatal("acquire after release returned a nil lock")
		}
		third.Close()
	})

	t.Run("lock parent blocked by a file", func(t *testing.T) {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "run"), []byte("not a directory"), 0600); err != nil {
			t.Fatal(err)
		}
		assertLockUnavailable(t, root, testLockRecovery, "Check /run/lock permissions and retry.")
	})

	t.Run("symlink ancestor keeps caller recovery", func(t *testing.T) {
		root := t.TempDir()
		runDir := filepath.Join(root, "run")
		if err := os.Mkdir(runDir, 0755); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(root, "elsewhere")
		if err := os.Mkdir(target, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, filepath.Join(runDir, "lock")); err != nil {
			t.Fatal(err)
		}
		assertLockUnavailable(t, root, testLockRecovery, testLockRecovery)
	})

	t.Run("lock path blocked by a directory", func(t *testing.T) {
		root := t.TempDir()
		if err := os.MkdirAll(filepath.Join(root, "run", "lock", "meshmux-install.lock"), 0755); err != nil {
			t.Fatal(err)
		}
		assertLockUnavailable(t, root, testLockRecovery, "Check /run/lock permissions and retry.")
	})
}

func assertLockUnavailable(t *testing.T, root, symlinkRecovery, wantRecovery string) {
	t.Helper()
	lock, err := acquireInstallLock(root, symlinkRecovery)
	if lock != nil {
		lock.Close()
		t.Fatal("acquireInstallLock returned a lock for an unavailable location")
	}
	if err == nil {
		t.Fatal("acquireInstallLock returned no error for an unavailable location")
	}
	if err.Stage != "preflight" || err.Code != "INSTALL_LOCK_UNAVAILABLE" {
		t.Fatalf("error = %+v, want preflight/INSTALL_LOCK_UNAVAILABLE", err)
	}
	if err.Recovery != wantRecovery {
		t.Fatalf("recovery = %q, want %q", err.Recovery, wantRecovery)
	}
}
