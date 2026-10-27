package versions

import "regexp"

// This file owns the codes that more than one layer emits or compares: a code is
// an operator-visible contract, so two packages spelling the same refusal must
// read one constant. Codes private to a single package stay next to that
// package's phase and are not listed here.
//
// Ownership: versions is a zero-internal-import leaf, so every layer — the CLI
// one-shots, the core executors and the control-plane producer — can import it
// without an edge. Do not add a per-package literal copy.
const (
	// CodeConfigConflict means an operation refuses to change recorded host
	// identity, ports or configuration in place.
	CodeConfigConflict = "CONFIG_CONFLICT"
	// CodeManifestUnavailable means the target manifest cannot be fetched or
	// authenticated on this host.
	CodeManifestUnavailable = "MANIFEST_UNAVAILABLE"
	// CodeDatabaseUnavailable means a store could not read or write its
	// database, so the refusal is unavailability rather than an answer about
	// the requested data. Both the core rule library and the control store
	// emit it, so it lives here instead of in either layer.
	CodeDatabaseUnavailable = "DATABASE_UNAVAILABLE"
)

// StableCodePattern is the frozen lexical shape of every operator-visible
// error_code: an uppercase ASCII identifier of at most 64 characters.
//
// It is a cross-layer contract, not a package detail: the Web launcher logs a
// lower layer's code, the root restore parser re-reads one from a frozen
// document, and the Node handoff writes one into a result file. Those three
// readers must accept exactly the same bytes, so the expression lives in this
// leaf instead of being compiled again in each package.
var StableCodePattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)

// IsStableCode reports whether code is one accepted operator-visible code.
func IsStableCode(code string) bool {
	return StableCodePattern.MatchString(code)
}
