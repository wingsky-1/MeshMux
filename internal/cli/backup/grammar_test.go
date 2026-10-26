package backup

import (
	"strings"
	"testing"
)

// TestGrammarIsOneDefinition freezes the three lexical shapes every upgrade
// producer and consumer imports. They were previously compiled separately in
// package backup, update, upgrade and hubupgrade; this test is the drift gate
// that keeps the single definition honest.
func TestGrammarIsOneDefinition(t *testing.T) {
	if !ValidOperationID(strings.Repeat("a", 32)) {
		t.Fatal("a 32-hex operation id must be valid")
	}
	for _, id := range []string{"", strings.Repeat("a", 31), strings.Repeat("a", 33), strings.Repeat("A", 32), strings.Repeat("g", 32)} {
		if ValidOperationID(id) {
			t.Fatalf("%q must not be a valid operation id", id)
		}
	}
	if !ValidDigest(strings.Repeat("0", 64)) {
		t.Fatal("a 64-hex digest must be valid")
	}
	for _, digest := range []string{"", strings.Repeat("0", 63), strings.Repeat("0", 65), strings.Repeat("F", 64)} {
		if ValidDigest(digest) {
			t.Fatalf("%q must not be a valid digest", digest)
		}
	}
	for _, version := range []string{"1.0.0", "1.0.0-dev", "0.29.5", "1.2.3-rc.1"} {
		if !ValidReleaseVersion(version) {
			t.Fatalf("%q must be a valid release version", version)
		}
	}
	// Build metadata and floating names are not release identities.
	for _, version := range []string{"", "latest", "v1.0.0", "1.0", "1.0.0+build", "1.0.0-"} {
		if ValidReleaseVersion(version) {
			t.Fatalf("%q must not be a valid release version", version)
		}
	}
}

// TestInternalAliasesAreTheSharedPatterns proves the package's frozen call
// sites still point at one definition rather than a private copy.
func TestInternalAliasesAreTheSharedPatterns(t *testing.T) {
	if targetRE != ReleaseVersionPattern || digestRE != DigestPattern || opIDRE != OperationIDPattern {
		t.Fatal("record.go aliases no longer point at the single grammar definition")
	}
}
