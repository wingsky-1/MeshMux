package backup

// Payload hashing and copying for both payload kinds.
//
// A tree payload (the Node installer snapshot) is digested as a sorted tree of
// relative path, size and content, so a 0755 installer binary and its 0600 store
// copy are the same bytes. A single-database payload (one Hub operation's
// database copy) is digested as the raw SHA-256 of the one database file,
// because that is exactly what a restore re-hashes before it opens the copy
// (spec §5.7-2); a tree digest there would prove the wrong thing.
//
// Every function enforces the private-store rule on what it reads back: 0700
// directories, 0600 files, no symlinks, owned by the account the caller names.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

// hashPayloadTree hashes one payload tree without following symlinks. The digest
// covers relative path, size and content of every regular file, sorted by path;
// it deliberately excludes modes so a 0755 installer binary and its 0600 store
// copy are the same bytes. private also enforces the store rule on every
// directory (0700) and file (0600) and requires ownership by owner.
//
// limit bounds one file. A value <= 0 means "no per-file bound": a
// single-database payload is streamed through its raw file digest instead, and
// its size is a deployment property rather than a package-cap property.
func hashPayloadTree(dir string, private bool, limit int64, owner int) (string, int, error) {
	if dir == "" {
		sum := sha256.Sum256(nil)
		return hex.EncodeToString(sum[:]), 0, nil
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", 0, errPayloadUnsafe
	}
	if private && (info.Mode().Perm() != 0700 || !ownedBy(owner, info)) {
		return "", 0, errPayloadUnsafe
	}
	var entries []string
	files := 0
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == dir {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errPayloadUnsafe
		}
		if info.IsDir() {
			if private && (info.Mode().Perm() != 0700 || !ownedBy(owner, info)) {
				return errPayloadUnsafe
			}
			return nil
		}
		if !info.Mode().IsRegular() || (limit > 0 && info.Size() > limit) {
			return errPayloadUnsafe
		}
		if private && (info.Mode().Perm() != 0600 || !ownedBy(owner, info)) {
			return errPayloadUnsafe
		}
		relative, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		fileDigest, err := hashFile(path)
		if err != nil {
			return err
		}
		files++
		entries = append(entries, fmt.Sprintf("%s\x00%d\x00%s", filepath.ToSlash(relative), info.Size(), fileDigest))
		return nil
	})
	if err != nil {
		return "", 0, err
	}
	sort.Strings(entries)
	outer := sha256.New()
	for _, entry := range entries {
		_, _ = io.WriteString(outer, entry+"\n")
	}
	return hex.EncodeToString(outer.Sum(nil)), files, nil
}

// hashSingleDB digests the one database copy of a single-database payload. The
// returned digest is the raw file SHA-256, not a tree digest, and the file count
// is always 1: a payload that holds anything else is not the shape this store
// writes and is refused rather than summarized.
func hashSingleDB(dir string, owner int) (string, int, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return "", 0, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() ||
		info.Mode().Perm() != 0700 || !ownedBy(owner, info) {
		return "", 0, errPayloadUnsafe
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return "", 0, err
	}
	if len(entries) != 1 || entries[0].Name() != SingleDBName {
		return "", 0, errPayloadUnsafe
	}
	path := filepath.Join(dir, SingleDBName)
	fileInfo, err := os.Lstat(path)
	if err != nil {
		return "", 0, err
	}
	if fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() ||
		fileInfo.Mode().Perm() != 0600 || !ownedBy(owner, fileInfo) {
		return "", 0, errPayloadUnsafe
	}
	digest, err := hashFile(path)
	if err != nil {
		return "", 0, err
	}
	return digest, 1, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}

// copyPayloadTree copies regular files and directories only, normalizing every
// copy to the private store mode. A symlink or device node anywhere in the
// snapshot is refused instead of followed.
func copyPayloadTree(src, dst string) error {
	if err := os.MkdirAll(dst, 0700); err != nil {
		return err
	}
	if src == "" {
		return nil
	}
	info, err := os.Lstat(src)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return errPayloadUnsafe
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == src {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if d.Type()&os.ModeSymlink != 0 || info.Mode()&os.ModeSymlink != 0 {
			return errPayloadUnsafe
		}
		relative, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, relative)
		if info.IsDir() {
			return os.MkdirAll(target, 0700)
		}
		if !info.Mode().IsRegular() || info.Size() > TreeFileMaxBytes {
			return errPayloadUnsafe
		}
		return copyPrivateFile(path, target)
	})
}

// copyPrivateFile copies one file into the private store, bounded by the tree
// file cap and fsynced before it is reported as copied.
func copyPrivateFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, io.LimitReader(in, TreeFileMaxBytes+1))
	if copyErr == nil {
		info, statErr := out.Stat()
		if statErr != nil || info.Size() > TreeFileMaxBytes {
			copyErr = errPayloadUnsafe
		}
	}
	if copyErr == nil {
		copyErr = out.Sync()
	}
	if closeErr := out.Close(); copyErr == nil {
		copyErr = closeErr
	}
	if copyErr != nil {
		_ = os.Remove(dst)
		return copyErr
	}
	return nil
}
