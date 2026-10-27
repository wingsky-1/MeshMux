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
)

// TestStorePackageBoundaries pins the dependency order.
//
// common and candidate are leaves. node is above them; policy above node (it
// also renders the gated client documents through clientdoc, a leaf);
// subscription above node and policy; upgrade at the top. mesh is an
// independent leaf beside candidate. Two real edges point the other way and are
// inverted instead: node declares the node.Subscribers port for the subscriber
// facts it needs, and the Out allowlist is passed into candidate by its caller.
func TestStorePackageBoundaries(t *testing.T) {
	cases := map[string][]string{
		"common":       {},
		"candidate":    {"common"},
		"mesh":         {"common"},
		"node":         {"candidate", "common"},
		"policy":       {"candidate", "clientdoc", "common", "node"},
		"subscription": {"candidate", "common", "node", "policy"},
		"upgrade":      {"candidate", "common", "node", "policy"},
	}
	root := "github.com/wingsky-1/MeshMux/internal/control/store"

	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			out, err := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "./"+name).Output()
			if err != nil {
				t.Fatalf("go list ./%s: %v", name, err)
			}
			var got []string
			for _, line := range strings.Split(string(out), "\n") {
				line = strings.TrimSpace(line)
				if after, ok := strings.CutPrefix(line, root+"/"); ok {
					got = append(got, after)
				}
			}
			sort.Strings(got)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Fatalf("store/%s imports %v; want exactly %v (domains must not reach sideways; the root package is the only meeting point)", name, got, want)
			}
		})
	}
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
