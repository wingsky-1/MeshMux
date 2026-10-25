package update

// Durable ordering of the staged package (#11d Task 3): FetchVerifiedSource
// must fsync the private .part file before the rename publishes the final
// executable name. The Node fetch path uses the same function, so this also
// pins that a Docker-less Node never executes a page-cache-only package after
// a crash.

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/upgrade"
)

func TestFetchVerifiedSourceSyncsBeforeRename(t *testing.T) {
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "package")
	body := []byte("verified package bytes")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	component := upgrade.Component{
		Name: "meshmuxd", Version: "dev-1.0.1", Architecture: "amd64",
		Source: "file://" + source, SHA256: hexDigest(body), Dev: true,
	}
	dir := t.TempDir()
	old := stagedFileSync
	defer func() { stagedFileSync = old }()

	var syncedPath string
	stagedFileSync = func(file *os.File) error {
		syncedPath = file.Name()
		if _, err := os.Lstat(filepath.Join(dir, "meshmuxd-1.0.1-amd64")); err == nil {
			t.Error("the final name existed before the staged file was fsynced")
		}
		return file.Sync()
	}
	final, err := FetchVerifiedSource(context.Background(), dir, "meshmuxd-1.0.1-amd64", component)
	if err != nil {
		t.Fatalf("FetchVerifiedSource: %v", err)
	}
	if want := filepath.Join(dir, "meshmuxd-1.0.1-amd64"); final != want {
		t.Fatalf("final path %q want %q", final, want)
	}
	if want := final + ".part"; syncedPath != want {
		t.Fatalf("fsync path %q want %q", syncedPath, want)
	}
	got, err := os.ReadFile(final)
	if err != nil || string(got) != string(body) {
		t.Fatalf("published bytes: %q, %v", got, err)
	}
	if _, err := os.Lstat(final + ".part"); !os.IsNotExist(err) {
		t.Fatal("the scratch name survived a successful publish")
	}
}

func TestFetchVerifiedSourceSyncFailurePublishesNothing(t *testing.T) {
	sourceDir := t.TempDir()
	source := filepath.Join(sourceDir, "package")
	body := []byte("verified package bytes")
	if err := os.WriteFile(source, body, 0600); err != nil {
		t.Fatal(err)
	}
	component := upgrade.Component{
		Name: "meshmuxd", Version: "dev-1.0.1", Architecture: "amd64",
		Source: "file://" + source, SHA256: hexDigest(body), Dev: true,
	}
	dir := t.TempDir()
	old := stagedFileSync
	defer func() { stagedFileSync = old }()
	stagedFileSync = func(*os.File) error { return errors.New("fsync failed") }

	_, err := FetchVerifiedSource(context.Background(), dir, "meshmuxd-1.0.1-amd64", component)
	if err == nil || codeOf(err) != "UPDATE_STAGE_FAILED" {
		t.Fatalf("sync failure = %v", err)
	}
	for _, name := range []string{"meshmuxd-1.0.1-amd64", "meshmuxd-1.0.1-amd64.part"} {
		if _, err := os.Lstat(filepath.Join(dir, name)); !os.IsNotExist(err) {
			t.Fatalf("%s survived a failed sync", name)
		}
	}
}
