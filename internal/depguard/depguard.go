// Package depguard pins subpackage import direction in tests.
//
// Both the web handler split and the control store split keep their domain
// packages acyclic by construction: every domain only imports leaves or
// packages below it, and the area root is the only meeting point. This helper
// runs the same `go list` assertion for any area so the two boundary tests
// cannot drift into duplicated logic (and trip the dupl gate).
package depguard

import (
	"os/exec"
	"sort"
	"strings"
	"testing"
)

// AssertSubpackages fails when any named subpackage of root imports a sibling
// outside its allowed set. Only the area root may meet the domains.
func AssertSubpackages(t *testing.T, root string, cases map[string][]string, subject string) {
	t.Helper()
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
				t.Fatalf("%s/%s imports %v; want exactly %v (domains must not reach sideways; the root package is the only meeting point)", subject, name, got, want)
			}
		})
	}
}
