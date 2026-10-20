package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestCLIRejectsUnsupportedRolesAndCommands(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"install", "hub"}, 2},
		{[]string{"install", "edge"}, 2},
		{[]string{"install", "out"}, 2},
		{[]string{"install", "nas"}, 2},
		{[]string{"update"}, 2},
		{[]string{"install"}, 2},
		{nil, 2},
	} {
		var b bytes.Buffer
		if got := run(tc.args, &b); got != tc.want {
			t.Fatalf("run(%v)=%d, want %d", tc.args, got, tc.want)
		}
		if strings.Contains(b.String(), "NOT READY TO INSTALL") {
			t.Fatalf("obsolete installation notice for %v", tc.args)
		}
	}
}
