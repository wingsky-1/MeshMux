package store_test

// The split has one structural contract the compiler cannot state: every domain
// package imports only the packages below it, and the root package is the only
// place two domains meet. This test makes the contract explicit, so a later edit
// that reaches sideways is a failing test rather than a review comment.
//
// It is a boundary guard, not a behavior test: it reads the compiled import
// graph, so a new file in an existing package is covered without touching it.

import (
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/depguard"
)

// TestStorePackageBoundaries pins the dependency order.
//
// common and candidate are leaves. node is above them; policy above node (it
// also renders the gated client documents through clientdoc, a leaf);
// subscription above node; upgrade at the top. mesh is an independent leaf
// beside candidate.
//
// The node domain has its own two layers: node/line is the bottom (the Line
// transport, the candidate snapshot, the Line egress facts) and node/out is
// built on it, so the candidate builder is never imported from the other side.
// The node root meets both and is the only package that re-exports them.
//
// One real edge points the other way and is inverted instead: node declares the
// node.Subscribers port for the subscriber facts it needs.
func TestStorePackageBoundaries(t *testing.T) {
	cases := map[string][]string{
		"common":       {},
		"candidate":    {"common"},
		"mesh":         {"common"},
		"node":         {"candidate", "common", "node/line", "node/out"},
		"node/line":    {"candidate", "common"},
		"node/out":     {"candidate", "common", "node/line"},
		"policy":       {"clientdoc", "common", "node"},
		"subscription": {"candidate", "common", "node"},
		"upgrade":      {"candidate", "common", "node"},
	}
	depguard.AssertSubpackages(t, "github.com/wingsky-1/MeshMux/internal/control/store", cases, "store")
}

// TestRootStoreIsAssemblyOnly pins the shape the split was for: the root holds no
// domain table work. Every non-test file there is the package doc, the assembly
// (Store struct, open/migrate/close, session/auth), the database gate, the
// public re-export surface or the domain wiring.
func TestRootStoreIsAssemblyOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-f", "{{join .GoFiles \"\\n\"}}", ".").Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	var got []string
	for _, name := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if name != "" {
			got = append(got, name)
		}
	}
	want := []string{"doc.go", "public_api.go", "store.go", "store_database_gate.go", "wire.go"}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("root store files = %v; want %v (table work belongs to a domain package)", got, want)
	}
}
