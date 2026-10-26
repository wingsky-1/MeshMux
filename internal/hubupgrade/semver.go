package hubupgrade

// SemVer 2.0.0 precedence for release comparison (spec §5.8: the target
// manifest must be strictly newer than the running build). Build metadata is
// not accepted by targetRE, so only the numeric core and the optional
// prerelease identifiers are compared.

import (
	"strconv"
	"strings"

	"github.com/wingsky-1/MeshMux/internal/versions"
)

type releaseVersion struct {
	core       [3]uint64
	prerelease []string
}

func parseRelease(version string) (releaseVersion, bool) {
	if !targetRE.MatchString(version) {
		return releaseVersion{}, false
	}
	core, pre, _ := strings.Cut(version, "-")
	parts := strings.Split(core, ".")
	if len(parts) != 3 {
		return releaseVersion{}, false
	}
	var out releaseVersion
	for i, part := range parts {
		n, err := strconv.ParseUint(part, 10, 64)
		if err != nil {
			return releaseVersion{}, false
		}
		out.core[i] = n
	}
	if pre != "" {
		out.prerelease = strings.Split(pre, ".")
	}
	return out, true
}

// compareRelease returns -1, 0 or 1 for a<b, a==b, a>b. An unparsable side is
// an error: the caller must refuse the gate, never guess an ordering.
func compareRelease(a, b string) (int, error) {
	left, ok := parseRelease(a)
	if !ok {
		return 0, fail(versions.CodeManifestUnavailable, "the candidate version is not a SemVer release")
	}
	right, ok := parseRelease(b)
	if !ok {
		return 0, fail(versions.CodeManifestUnavailable, "the running version is not a SemVer release")
	}
	for i := 0; i < 3; i++ {
		switch {
		case left.core[i] < right.core[i]:
			return -1, nil
		case left.core[i] > right.core[i]:
			return 1, nil
		}
	}
	return comparePrerelease(left.prerelease, right.prerelease), nil
}

func comparePrerelease(a, b []string) int {
	// A release without a prerelease has higher precedence than one with it.
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 {
		return 1
	}
	if len(b) == 0 {
		return -1
	}
	for i := 0; i < len(a) && i < len(b); i++ {
		if cmp := compareIdentifier(a[i], b[i]); cmp != 0 {
			return cmp
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	}
	return 0
}

func compareIdentifier(a, b string) int {
	aNum, aErr := strconv.ParseUint(a, 10, 64)
	bNum, bErr := strconv.ParseUint(b, 10, 64)
	switch {
	case aErr == nil && bErr == nil:
		switch {
		case aNum < bNum:
			return -1
		case aNum > bNum:
			return 1
		}
		return 0
	case aErr == nil:
		// Numeric identifiers always have lower precedence than alphanumeric.
		return -1
	case bErr == nil:
		return 1
	}
	return strings.Compare(a, b)
}
