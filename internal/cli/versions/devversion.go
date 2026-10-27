package versions

import "strings"

// IsDevVersion reports whether a version names a development pre-release of the
// #12e dev lane rather than a published release.
//
// Two shapes are accepted, and both are refused as a release component by the
// manifest gates:
//
//   - the current SemVer pre-release `X.Y.Z-dev.N` (for example
//     `1.0.0-dev.20261027`), whose N is a UTC date or a date plus a sequence;
//   - the transitional `dev-<stamp>` form the first dev pin used before the
//     build started injecting a real SemVer identity.
//
// A version is a dev build exactly when its pre-release part is `dev` or starts
// with `dev.`. That keeps `1.0.0-rc.1` a release candidate, not a dev build, and
// refuses `1.0.0-devfoo` rather than guessing.
//
// The helper lives in this zero-internal-import leaf because three layers must
// agree on it and none of them may import another: internal/cli/install builds
// the pin table, internal/cli/upgrade projects it into a manifest, and
// internal/cli/update re-derives the source class of a target component.
func IsDevVersion(version string) bool {
	if strings.HasPrefix(version, "dev-") {
		return len(version) > len("dev-")
	}
	_, prerelease, found := strings.Cut(version, "-")
	if !found || prerelease == "" {
		return false
	}
	return prerelease == "dev" || strings.HasPrefix(prerelease, "dev.")
}
