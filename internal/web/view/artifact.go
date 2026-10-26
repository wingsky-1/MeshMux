package view

// InstallArtifact is the current same-origin CLI binary made available by the
// private Web runtime. Path never enters HTTP responses or logs.
type InstallArtifact struct {
	Path         string
	Version      string
	Architecture string
	SHA256       string
}
