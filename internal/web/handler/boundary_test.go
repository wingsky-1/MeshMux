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

	"github.com/wingsky-1/MeshMux/internal/depguard"
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
	// handlertest and internal/web/testhttp are test support, not domains: they
	// exist so a domain's tests can drive the assembled root, so they import it
	// and the domains they build fixtures from. Guarding their edges would pin
	// the fixture layering instead of the production dependency direction.
	depguard.AssertSubpackages(t, "github.com/wingsky-1/MeshMux/internal/web/handler", cases, "handler")
}

// TestRootHandlerIsAssemblyOnly pins the shape the split was for: the root
// package holds no route body. Every non-test file there is the package doc, the
// assembly (router, constructor, lifecycle) or the cross-domain bridges, so a
// handler added back to the root is visible as a new file rather than an
// unnoticed helper. The root's tests follow the same rule by hand: it keeps only
// the ones that need two domains at once, and fixtures_test.go is the shared
// fixture those need.
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
