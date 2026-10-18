// MeshMux is not installable yet. This stub exists only to bootstrap CI safely.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/wingsky-1/MeshMux/internal/product"
)

func run(args []string, stderr io.Writer) int {
	if len(args) == 0 || args[0] != "install" || len(args) != 2 {
		fmt.Fprintln(stderr, "usage: meshmux install {hub|edge|out}")
		return 2
	}
	if _, err := product.ParseRole(args[1]); err != nil {
		fmt.Fprintf(stderr, "invalid role: %v\n", err)
		return 2
	}
	fmt.Fprintln(stderr, "NOT READY TO INSTALL: MeshMux currently contains only a design and CI scaffold; no host changes were made.")
	return 3
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}
