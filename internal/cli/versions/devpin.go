package versions

// The dev artifact drop of the #12e development lane.
//
// A development build has no published release asset, so its executor pin names
// bytes an operator can actually verify: a root-owned artifact drop plus the
// checksum document that describes it. The drop is root-owned, so the
// unprivileged Web can read the anchor but cannot plant one:
//
//	/var/lib/meshmux-dev/meshmuxd-linux-<arch>  0755 root:root
//	/var/lib/meshmux-dev/SHA256SUMS             0644 root:root
//
// `make dev-artifacts` builds both architecture artifacts and the checksum
// document; scripts/dev-artifacts-deploy.sh installs them with those owners and
// modes and checks that the installed runtime is the drop's artifact for its
// architecture. The digest is never guessed: the build wrote it, root owns the
// file, and the fetch path re-hashes the bytes against it before anything is
// executed.
//
// DevArtifactDir is a variable only because a fixture points it at a temporary
// tree; production code never assigns it, the same contract as buildinfo.Version.
var DevArtifactDir = "/var/lib/meshmux-dev"

const (
	// DevArtifactPrefix is the fixed artifact name prefix; the architecture
	// follows, so one architecture's artifact can never be named by another's
	// pin.
	DevArtifactPrefix = "meshmuxd-linux-"
	// DevChecksumsName is the one checksum document of the drop, in `sha256sum`
	// format.
	DevChecksumsName = "SHA256SUMS"
)

// DevArtifactName is the artifact file name of one architecture.
func DevArtifactName(architecture string) string {
	return DevArtifactPrefix + architecture
}

// DevArtifactPath is the artifact path of one architecture inside the drop.
func DevArtifactPath(architecture string) string {
	return DevArtifactDir + "/" + DevArtifactName(architecture)
}

// DevChecksumsPath is the checksum document path of the drop.
func DevChecksumsPath() string {
	return DevArtifactDir + "/" + DevChecksumsName
}
