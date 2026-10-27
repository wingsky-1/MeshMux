package handler

// The handler split has one structural contract that the compiler cannot state:
// a domain package imports infra and (only where it truly needs a sibling) that
// one sibling, but the root package is the only place the domains meet. This
// test makes the contract explicit, so a later edit that reaches sideways is a
// failing test rather than a review comment.
//
// It is a boundary guard, not a behavior test: it reads the compiled import
// graph, so a new file in an existing package is covered without touching it.

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

func TestHandlerPackageBoundaries(t *testing.T) {
	cases := map[string][]string{
		"infra":        {},
		"subscription": {"infra"},
		"node":         {"infra"},
		"mesh":         {"infra"},
		"policy":       {"infra"},
		"upgrade":      {"infra"},
		// The wizard needs the rule library and the publication verifier from
		// policy and the public origin from the download boundary. Both edges
		// point at a package this one does not import back, so no cycle exists.
		"subscriber": {"infra", "subscription"},
	}
	root := "github.com/wingsky-1/MeshMux/internal/web/handler"

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
				t.Fatalf("handler/%s imports %v; want exactly %v (domains must not reach sideways; the root package is the only meeting point)", name, got, want)
			}
		})
	}
}

// TestRootHandlerIsAssemblyOnly pins the shape the split was for: the root
// package holds no route body. Every non-test file there is the package doc, the
// assembly (router, constructor, lifecycle) or the cross-domain bridges, so a
// handler added back to the root is visible as a new file rather than an
// unnoticed helper.
func TestRootHandlerIsAssemblyOnly(t *testing.T) {
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
	want := []string{"backends.go", "doc.go", "server.go"}
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("root handler files = %v; want %v (route bodies belong to a domain package)", got, want)
	}
}
