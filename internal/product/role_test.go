package product

import "testing"

func TestParseRole(t *testing.T) {
	for _, name := range []string{"hub", "edge", "out"} {
		role, err := ParseRole(name)
		if err != nil || string(role) != name {
			t.Fatalf("ParseRole(%q) = %q, %v", name, role, err)
		}
	}
	for _, name := range []string{"", "nas", "line", "root", "hub;rm -rf /"} {
		if _, err := ParseRole(name); err == nil {
			t.Fatalf("ParseRole(%q) unexpectedly succeeded", name)
		}
	}
}
