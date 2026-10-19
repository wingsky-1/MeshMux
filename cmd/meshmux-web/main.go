// meshmux-web is the development entry point. Production uses the same code
// through the hidden __internal-web command in the installed meshmux runtime.
package main

import (
	"os"

	"github.com/wingsky-1/MeshMux/internal/webcmd"
)

func run() int { return webcmd.Run(os.Args[1:]) }

func main() {
	os.Exit(run())
}
