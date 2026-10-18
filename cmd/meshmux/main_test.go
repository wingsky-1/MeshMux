package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStubInstallerFailClosed(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"install", "hub"}, 3},
		{[]string{"install", "edge"}, 3},
		{[]string{"install", "out"}, 3},
		{[]string{"install", "nas"}, 2},
		{[]string{"update"}, 2},
		{[]string{"install"}, 2},
		{nil, 2},
	} {
		var b bytes.Buffer
		if got := run(tc.args, &b); got != tc.want {
			t.Fatalf("run(%v)=%d, want %d", tc.args, got, tc.want)
		}
		if len(tc.args) == 2 && tc.args[0] == "install" && tc.want == 3 &&
			!strings.Contains(b.String(), "NOT READY TO INSTALL") {
			t.Fatalf("missing safety notice for %v", tc.args)
		}
	}
}
