package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// This file locks the core dependency shape the 2026-10-26 refactor established
// inside the core lane. It reads the compiler's own view through `go list` and
// fails loudly if a package is missing, so a moved or merged package cannot make
// the guard pass vacuously.

// moduleRelative maps a package path to ./internal/... form.
func moduleRelative(t *testing.T, pkgPath string) string {
	t.Helper()
	const marker = "/internal/"
	index := strings.LastIndex(pkgPath, marker)
	if index < 0 {
		t.Fatalf("package %q is not under /internal/", pkgPath)
	}
	return "internal/" + pkgPath[index+len(marker):]
}

// moduleRoot walks up from the test's working directory to the governing
// go.mod, so the guard runs `go list` from the module root instead of the
// package directory.
func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatalf("no go.mod above %s", directory)
		}
		directory = parent
	}
}

// importsOf returns the module-internal imports of one package.
func importsOf(t *testing.T, pkg string) []string {
	t.Helper()
	command := exec.Command("go", "list", "-f", `{{join .Imports "\n"}}`, pkg)
	command.Dir = moduleRoot(t)
	output, err := command.Output()
	if err != nil {
		t.Fatalf("go list %s: %v", pkg, err)
	}
	var internal []string
	for _, imported := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		if strings.Contains(imported, "/internal/") {
			internal = append(internal, moduleRelative(t, strings.TrimSpace(imported)))
		}
	}
	return internal
}

// importsExactly reports whether pkg itself (not a subpackage) is imported.
func importsExactly(imports []string, pkg string) bool {
	for _, imported := range imports {
		if imported == pkg {
			return true
		}
	}
	return false
}

// importsUnder reports whether pkg or any subpackage of it is imported.
func importsUnder(imports []string, pkg string) bool {
	for _, imported := range imports {
		if imported == pkg || strings.HasPrefix(imported, pkg+"/") {
			return true
		}
	}
	return false
}

// TestCoreDependencyDirection pins the one-way core edges that the refactor
// introduced, so a later edit cannot quietly restore the old reverse import:
//
//	policy       -> subscription/ir, node/protocol  (never the subscription package)
//	subscription -> subscription/ir, node/protocol
//	ir           -> node/protocol only
//	mesh         -> subscription/ir + subscription (device documents)
//	node         -> its own protocol + buildinfo only
//
// policy not importing the subscription package is the important line: the
// merged compiler cannot call back into the composer, and the shared vocabulary
// is the leaf IR package instead of the composer package.
func TestCoreDependencyDirection(t *testing.T) {
	policyImports := importsOf(t, "./internal/core/policy")
	if importsExactly(policyImports, "internal/core/subscription") {
		t.Fatal("internal/core/policy imports internal/core/subscription; the compiler must depend on internal/core/subscription/ir only")
	}
	if !importsExactly(policyImports, "internal/core/subscription/ir") {
		t.Fatal("internal/core/policy no longer imports internal/core/subscription/ir; the shared vocabulary moved unexpectedly")
	}
	if !importsExactly(policyImports, "internal/core/node/protocol") {
		t.Fatal("internal/core/policy no longer imports internal/core/node/protocol; kernel tags must come from the wire contract")
	}

	subscriptionImports := importsOf(t, "./internal/core/subscription")
	if importsUnder(subscriptionImports, "internal/core/policy") {
		t.Fatal("internal/core/subscription imports internal/core/policy; the composer must not depend on the rule library")
	}
	if importsUnder(subscriptionImports, "internal/core/mesh") {
		t.Fatal("internal/core/subscription imports internal/core/mesh; the mesh domain imports the exporter, so this would be a cycle")
	}
	if !importsExactly(subscriptionImports, "internal/core/node/protocol") {
		t.Fatal("internal/core/subscription no longer imports internal/core/node/protocol; kernel tags must come from the wire contract")
	}

	for _, imported := range importsOf(t, "./internal/core/subscription/ir") {
		if imported != "internal/core/node/protocol" {
			t.Fatalf("internal/core/subscription/ir imports %s; the IR leaf may only use the wire contract", imported)
		}
	}

	nodeImports := importsOf(t, "./internal/core/node")
	if importsUnder(nodeImports, "internal/core/policy") || importsUnder(nodeImports, "internal/core/subscription") {
		t.Fatal("internal/core/node imports a Hub-side domain; the node package must stay below them")
	}

	if !importsExactly(importsOf(t, "./internal/core/mesh"), "internal/core/subscription") {
		t.Fatal("internal/core/mesh no longer imports internal/core/subscription; the device exporter boundary moved unexpectedly")
	}
}
