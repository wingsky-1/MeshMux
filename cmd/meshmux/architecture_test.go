package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// This file guards the internal package DAG of
// docs/superpowers/plans/2026-10-26-internal-regroup.md (C0). It asks the Go
// toolchain for the import graph instead of scanning source text, so the
// assertion is the compiler's own view: a leaf package never grows an internal
// dependency, the privileged installer never reaches the web layer, node keeps
// its narrow dependency set, and ./internal/... stays acyclic.
//
// A guard that silently checks nothing is worse than no guard, so every lookup
// fails loudly when its package is missing. When a package is deliberately
// moved or merged, update this file in the same commit as the move.

// internalDAGLeafs are the packages that must import no other package under
// internal/. Each entry lists every layout the package may have during the
// regroup: at least one candidate must exist, and every existing candidate must
// stay a leaf.
var internalDAGLeafs = []struct {
	name       string
	candidates []string
}{
	// protocol moves to internal/node/protocol (Task 5); the zero-internal
	// import contract holds at either path.
	{"protocol", []string{"internal/protocol", "internal/node/protocol"}},
	// route was merged into internal/compiler (Task 3) and later into
	// internal/policy (Task 4); its pin code is no longer a leaf package.
	{"headscale", []string{"internal/headscale"}},
	{"backup", []string{"internal/backup"}},
	{"jobs", []string{"internal/jobs"}},
	{"buildinfo", []string{"internal/buildinfo"}},
}

// internalDAGHubUpgradeCandidates are the layouts of the Web upgrade producer.
// It must never import the installer or the web layer (C6/C19).
var internalDAGHubUpgradeCandidates = []string{"internal/hubupgrade", "internal/upgrade/hub"}

// internalDAGNodeAllowed is node's complete internal dependency set: the frozen
// protocol contract (at either path) and the build identity. Anything else
// means node reached into a domain it does not own.
var internalDAGNodeAllowed = []string{"internal/protocol", "internal/node/protocol", "internal/buildinfo"}

// internalPackageGraph is the ./internal/... production import graph. Test-only
// imports are excluded: a _test.go import may legally point back at a package
// that imports the tested one, and it is not part of the shipped binary.
type internalPackageGraph struct {
	module   string
	packages map[string][]string // package path -> import paths
	errors   map[string]string   // package path -> go list error, when any
}

// full resolves a module-relative path such as "internal/route".
func (g internalPackageGraph) full(relative string) string {
	return g.module + "/" + relative
}

// internalImports returns the package's imports that live in this module.
func (g internalPackageGraph) internalImports(path string) []string {
	var internal []string
	for _, imported := range g.packages[path] {
		if strings.HasPrefix(imported, g.module+"/") {
			internal = append(internal, imported)
		}
	}
	sort.Strings(internal)
	return internal
}

func (g internalPackageGraph) has(path string) bool {
	_, ok := g.packages[path]
	return ok
}

// sortedPaths returns every package path in deterministic order.
func (g internalPackageGraph) sortedPaths() []string {
	paths := make([]string, 0, len(g.packages))
	for path := range g.packages {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

func TestArchitectureDAG(t *testing.T) {
	graph := loadInternalPackageGraph(t)

	// A package the toolchain cannot build hides its edges, so anything other
	// than a cycle (reported by the acyclic subtest with a path) fails here.
	for _, path := range graph.sortedPaths() {
		if message := graph.errors[path]; message != "" && !strings.Contains(message, "import cycle") {
			t.Fatalf("%s: go list error: %s", path, message)
		}
	}

	t.Run("leaf packages have no internal imports", func(t *testing.T) {
		for _, leaf := range internalDAGLeafs {
			var existing []string
			for _, candidate := range leaf.candidates {
				if graph.has(graph.full(candidate)) {
					existing = append(existing, candidate)
				}
			}
			if len(existing) == 0 {
				t.Fatalf("%s package missing: none of %v is under ./internal/...; if it was moved or merged, update internalDAGLeafs in the same commit",
					leaf.name, leaf.candidates)
			}
			for _, candidate := range existing {
				imports := graph.internalImports(graph.full(candidate))
				if len(imports) != 0 {
					t.Errorf("%s must stay a leaf but imports %v", candidate, imports)
				}
			}
		}
	})

	t.Run("hubupgrade does not import install or web", func(t *testing.T) {
		found := false
		for _, candidate := range internalDAGHubUpgradeCandidates {
			path := graph.full(candidate)
			if !graph.has(path) {
				continue
			}
			found = true
			for _, imported := range graph.internalImports(path) {
				if isPackageOrSubpackage(imported, graph.full("internal/install")) {
					t.Errorf("%s imports the installer (%s); the Web upgrade producer must not reach the privileged ledger", candidate, imported)
				}
				if isPackageOrSubpackage(imported, graph.full("internal/web")) {
					t.Errorf("%s imports the web layer (%s); the producer must stay below its consumer", candidate, imported)
				}
			}
		}
		if !found {
			t.Fatalf("hubupgrade package missing: none of %v exists; update internalDAGHubUpgradeCandidates in the same commit",
				internalDAGHubUpgradeCandidates)
		}
	})

	t.Run("install does not import web", func(t *testing.T) {
		path := graph.full("internal/install")
		if !graph.has(path) {
			t.Fatalf("internal/install is missing from ./internal/...")
		}
		for _, imported := range graph.internalImports(path) {
			if isPackageOrSubpackage(imported, graph.full("internal/web")) {
				t.Errorf("internal/install imports the web layer (%s); the installer must stay usable without it", imported)
			}
		}
	})

	t.Run("node imports only protocol and buildinfo", func(t *testing.T) {
		path := graph.full("internal/node")
		if !graph.has(path) {
			t.Fatalf("internal/node is missing from ./internal/...")
		}
		allowed := make(map[string]bool, len(internalDAGNodeAllowed))
		for _, relative := range internalDAGNodeAllowed {
			allowed[graph.full(relative)] = true
		}
		for _, imported := range graph.internalImports(path) {
			if !allowed[imported] {
				t.Errorf("internal/node imports %s; its internal dependencies are frozen to protocol and buildinfo", imported)
			}
		}
	})

	t.Run("internal imports stay under ./internal", func(t *testing.T) {
		// An edge to a package the pattern does not list would make the cycle
		// check below incomplete, so it is a failure of its own.
		for _, path := range graph.sortedPaths() {
			for _, imported := range graph.internalImports(path) {
				if !graph.has(imported) {
					t.Errorf("%s imports %s, which ./internal/... does not list", path, imported)
				}
			}
		}
	})

	t.Run("graph is acyclic", func(t *testing.T) {
		indegree := make(map[string]int, len(graph.packages))
		edges := make(map[string][]string, len(graph.packages))
		for path := range graph.packages {
			indegree[path] = 0 // register every node, including isolated ones
		}
		for _, path := range graph.sortedPaths() {
			seen := make(map[string]bool)
			for _, imported := range graph.internalImports(path) {
				if !graph.has(imported) || seen[imported] {
					continue
				}
				seen[imported] = true
				edges[path] = append(edges[path], imported)
				indegree[imported]++
			}
		}

		var queue []string
		for _, path := range graph.sortedPaths() {
			if indegree[path] == 0 {
				queue = append(queue, path)
			}
		}
		ordered := 0
		for len(queue) > 0 {
			node := queue[0]
			queue = queue[1:]
			ordered++
			dependencies := append([]string(nil), edges[node]...)
			sort.Strings(dependencies)
			for _, dependency := range dependencies {
				indegree[dependency]--
				if indegree[dependency] == 0 {
					queue = append(queue, dependency)
				}
			}
		}
		if ordered == len(graph.packages) {
			return
		}

		var remaining []string
		for _, path := range graph.sortedPaths() {
			if indegree[path] > 0 {
				remaining = append(remaining, path)
			}
		}
		t.Fatalf("internal import graph has a cycle: %s", strings.Join(findInternalCycle(remaining, edges), " -> "))
	})
}

// isPackageOrSubpackage reports whether path is base or lives below it.
func isPackageOrSubpackage(path, base string) bool {
	return path == base || strings.HasPrefix(path, base+"/")
}

// findInternalCycle returns one cycle among nodes, or a description of the
// unorderable remainder when the walk finds none (which would mean a bug here,
// not in the graph).
func findInternalCycle(nodes []string, edges map[string][]string) []string {
	const (
		unvisited = 0
		onStack   = 1
		done      = 2
	)
	state := make(map[string]int, len(nodes))
	inCycle := make(map[string]bool, len(nodes))
	for _, node := range nodes {
		inCycle[node] = true
	}

	var stack, cycle []string
	var visit func(string) bool
	visit = func(node string) bool {
		state[node] = onStack
		stack = append(stack, node)
		dependencies := append([]string(nil), edges[node]...)
		sort.Strings(dependencies)
		for _, dependency := range dependencies {
			if !inCycle[dependency] {
				continue
			}
			switch state[dependency] {
			case onStack:
				start := 0
				for index, onPath := range stack {
					if onPath == dependency {
						start = index
						break
					}
				}
				cycle = append(append([]string(nil), stack[start:]...), dependency)
				return true
			case unvisited:
				if visit(dependency) {
					return true
				}
			}
		}
		stack = stack[:len(stack)-1]
		state[node] = done
		return false
	}

	sorted := append([]string(nil), nodes...)
	sort.Strings(sorted)
	for _, node := range sorted {
		if state[node] == unvisited && visit(node) {
			return cycle
		}
	}
	return []string{"unorderable packages without a detectable cycle: " + strings.Join(sorted, ", ")}
}

// loadInternalPackageGraph runs `go list -e` over ./internal/... from the module
// root and parses `importPath|import import ...|error` lines. -e keeps a package
// with a broken dependency in the listing so the cycle check can name the cycle
// instead of dying at the first load error.
func loadInternalPackageGraph(t *testing.T) internalPackageGraph {
	t.Helper()
	root := moduleRoot(t)

	command := exec.Command("go", "list", "-e", "-f", `{{.ImportPath}}|{{join .Imports " "}}|{{if .Error}}{{.Error.Err}}{{end}}`, "./internal/...")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		var stderr string
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("go list ./internal/... failed: %v\n%s", err, stderr)
	}

	graph := internalPackageGraph{
		packages: make(map[string][]string),
		errors:   make(map[string]string),
	}
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "|", 3)
		if len(fields) != 3 {
			t.Fatalf("unexpected go list line %q", line)
		}
		path, imports, listErr := fields[0], fields[1], fields[2]
		if path == "" {
			t.Fatalf("go list returned an empty import path")
		}
		graph.packages[path] = strings.Fields(imports)
		if listErr != "" {
			graph.errors[path] = listErr
		}
	}
	if len(graph.packages) == 0 {
		t.Fatalf("go list ./internal/... returned no packages; the DAG guard would otherwise pass vacuously")
	}

	// Every listed package is under /internal/, so its prefix is the module
	// path. A mixed prefix means the pattern is not what this guard assumes.
	for path := range graph.packages {
		index := strings.Index(path, "/internal/")
		if index <= 0 {
			t.Fatalf("package %q is not under a /internal/ segment", path)
		}
		module := path[:index]
		if graph.module == "" {
			graph.module = module
			continue
		}
		if graph.module != module {
			t.Fatalf("packages span two modules: %q and %q", graph.module, module)
		}
	}
	return graph
}

// moduleRoot walks up from the test's working directory to the go.mod that
// governs this repository.
func moduleRoot(t *testing.T) string {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(directory, "go.mod")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			t.Fatalf("no go.mod above %s", directory)
		}
		directory = parent
	}
}
