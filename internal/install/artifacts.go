package install

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

type Artifact struct {
	Component string `json:"component"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	SHA256    string `json:"sha256"`
	Format    string `json:"format"`
}

// Digests copied from the upstream GitHub release asset SHA-256 metadata.
// No "latest" or user-supplied release URL is permitted in a host operation.
var artifacts = map[string][]Artifact{
	"amd64": {
		{Component: "caddy", Version: "2.11.7", Source: "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_amd64.tar.gz", SHA256: "727b91701a392de6ebc5027509f548bf39979e5216340d0faed8fa5e69c84f8b", Format: "tar.gz"},
		{Component: "headscale", Version: "0.29.5", Source: "https://github.com/juanfont/headscale/releases/download/v0.29.5/headscale_0.29.5_linux_amd64", SHA256: "e979d27fe17d924d33bb6ab7504f6338d0635989a0cfdcfbc0ceb637dbcbe980", Format: "elf"},
	},
	"arm64": {
		{Component: "caddy", Version: "2.11.7", Source: "https://github.com/caddyserver/caddy/releases/download/v2.11.7/caddy_2.11.7_linux_arm64.tar.gz", SHA256: "d8fc6d179a5d283028a472a5618564f6ad8a86fed513e64f032b3b0b7cc45e42", Format: "tar.gz"},
		{Component: "headscale", Version: "0.29.5", Source: "https://github.com/juanfont/headscale/releases/download/v0.29.5/headscale_0.29.5_linux_arm64", SHA256: "3afddd207b89ac22cfad4235cc163c6e538cc59ada139e7c0bf47640c5d9e945", Format: "elf"},
	},
}

func PinnedArtifacts(arch string) []Artifact {
	a := artifacts[arch]
	out := make([]Artifact, len(a))
	copy(out, a)
	return out
}

var validDigest = regexp.MustCompile(`^[0-9a-f]{64}$`)

// VerifyFile checks exact byte content, not a filename, URL or upstream-provided header.
func VerifyFile(path string, expected string) error {
	if !validDigest.MatchString(expected) {
		return errors.New("ARTIFACT_DIGEST_INVALID")
	}
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("ARTIFACT_UNAVAILABLE: %w", err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() == 0 || info.Size() > 128<<20 {
		return errors.New("ARTIFACT_TYPE_OR_SIZE_INVALID")
	}
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return fmt.Errorf("ARTIFACT_READ_FAILED: %w", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != expected {
		return errors.New("ARTIFACT_CHECKSUM_MISMATCH")
	}
	return nil
}

// DownloadVerified stages a fixed release into a 0700 scratch directory.
// A bad or incomplete download is deleted and never returned to a caller.
func DownloadVerified(ctx context.Context, client *http.Client, a Artifact, dir string) (string, error) {
	if !validDigest.MatchString(a.SHA256) || a.Source == "" {
		return "", errors.New("ARTIFACT_MANIFEST_INVALID")
	}
	found := false
	for _, list := range artifacts {
		for _, pinned := range list {
			if pinned == a {
				found = true
			}
		}
	}
	if !found {
		return "", errors.New("ARTIFACT_SOURCE_UNTRUSTED")
	}
	if client == nil {
		client = &http.Client{Timeout: 90 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.Source, nil)
	if err != nil {
		return "", errors.New("ARTIFACT_REQUEST_INVALID")
	}
	res, err := client.Do(req)
	if err != nil {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK || res.ContentLength > 128<<20 {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	f, err := os.CreateTemp(dir, ".meshmux-artifact-*")
	if err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	defer os.Remove(f.Name())
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(res.Body, 128<<20+1))
	if err != nil || n == 0 || n > 128<<20 {
		return "", errors.New("ARTIFACT_DOWNLOAD_FAILED")
	}
	if hex.EncodeToString(h.Sum(nil)) != a.SHA256 {
		return "", errors.New("ARTIFACT_CHECKSUM_MISMATCH")
	}
	if err := f.Sync(); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	name := strings.ReplaceAll(a.Component+"-"+a.Version+"-"+filepath.Base(a.Source), "/", "_")
	final := filepath.Join(dir, name)
	if _, err := os.Lstat(final); err == nil {
		if err := VerifyFile(final, a.SHA256); err != nil {
			return "", errors.New("ARTIFACT_EXISTING_CONFLICT")
		}
		return final, nil
	} else if !os.IsNotExist(err) {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	// Atomic link avoids accidentally replacing an already staged artifact.
	if err := os.Link(f.Name(), final); err != nil {
		return "", errors.New("ARTIFACT_STAGE_FAILED")
	}
	return final, nil
}
