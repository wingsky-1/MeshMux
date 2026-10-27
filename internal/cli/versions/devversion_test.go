package versions

import "testing"

// TestIsDevVersion pins the one dev-build predicate every layer reads: the
// SemVer pre-release form of the #12e dev lane, and the transitional dev-<stamp>
// pin that predates it. A release candidate is not a dev build, and a version
// that merely starts with the letters "dev" is refused rather than guessed.
func TestIsDevVersion(t *testing.T) {
	dev := []string{
		"1.0.0-dev.0",
		"1.0.0-dev.20261027",
		"1.0.0-dev.20261027.2",
		"2.0.0-dev.1",
		"dev-20261023",
	}
	for _, version := range dev {
		if !IsDevVersion(version) {
			t.Fatalf("IsDevVersion(%q) = false, want a dev build", version)
		}
	}
	release := []string{
		"1.0.0",
		"1.0.1",
		"1.0.0-rc.1",
		"1.0.0-alpha.2",
		"1.0.0-devfoo",
		"dev-",
		"",
		"latest",
	}
	for _, version := range release {
		if IsDevVersion(version) {
			t.Fatalf("IsDevVersion(%q) = true, want not a dev build", version)
		}
	}
}
