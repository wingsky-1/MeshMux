package hub

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// This file resolves package-level string constants so the recovery-text guard
// can keep reading the apply functions after the codes moved to their single
// source (codes.go, internal/versions, internal/backup) instead of being inline
// literals.
//
// The guard's purpose is unchanged: it must still see the exact operator-visible
// code and recovery sentence emitted by InstallNode and InstallHub. Only the
// lookup changed — an identifier or one imported selector is resolved by reading
// the declaring package's own source, never by keeping a second table of values
// in the test.

// constantIndex resolves string constants of this package and of the internal
// packages it imports by reading their declarations.
type constantIndex struct {
	local         map[string]string              // name -> literal
	aliases       map[string]ast.Expr            // name -> declared expression (a cross-package alias)
	imports       map[string]string              // local alias -> import path
	remote        map[string]map[string]string   // import path -> name -> literal
	remoteAliases map[string]map[string]ast.Expr // import path -> name -> declared expression
	remoteImports map[string]map[string]string   // import path -> alias -> import path
	directory     map[string]string              // import path -> source directory
}

// newConstantIndex parses this package's non-test sources once, recording its
// literal constants and its import aliases.
func newConstantIndex(t *testing.T) *constantIndex {
	t.Helper()
	index := &constantIndex{
		local:         map[string]string{},
		aliases:       map[string]ast.Expr{},
		imports:       map[string]string{},
		remote:        map[string]map[string]string{},
		remoteAliases: map[string]map[string]ast.Expr{},
		remoteImports: map[string]map[string]string{},
		directory:     map[string]string{},
	}
	// The recovery texts of InstallHub live in this package and those of
	// InstallNode in the sibling node channel, so both source sets are indexed.
	for _, dir := range []string{".", "../node"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read package directory %s: %v", dir, err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, parser.ImportsOnly)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			for _, imported := range file.Imports {
				path, err := strconv.Unquote(imported.Path.Value)
				if err != nil || !strings.HasPrefix(path, "github.com/wingsky-1/MeshMux/internal/") {
					continue
				}
				alias := filepath.Base(path)
				if imported.Name != nil {
					alias = imported.Name.Name
				}
				index.imports[alias] = path
			}
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(dir, name), nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", name, err)
			}
			collectStringConstants(file, index.local, index.aliases)
		}
	}
	return index
}

// collectStringConstants records every `const Name = "literal"` of one file and
// keeps the declared expression of a constant that aliases another package's
// value, so a thin re-export still resolves to the one real definition.
func collectStringConstants(file *ast.File, into map[string]string, aliases map[string]ast.Expr) {
	for _, declaration := range file.Decls {
		general, ok := declaration.(*ast.GenDecl)
		if !ok || general.Tok != token.CONST {
			continue
		}
		for _, specification := range general.Specs {
			spec, ok := specification.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, identifier := range spec.Names {
				if index >= len(spec.Values) {
					continue
				}
				literal, ok := spec.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					if aliases != nil {
						aliases[identifier.Name] = spec.Values[index]
					}
					continue
				}
				text, err := strconv.Unquote(literal.Value)
				if err != nil {
					continue
				}
				into[identifier.Name] = text
			}
		}
	}
}

// resolve returns the literal text of a string expression that is a literal, a
// constant of this package, or a constant of one imported internal package.
func (index *constantIndex) resolve(t *testing.T, expression ast.Expr) (string, bool) {
	t.Helper()
	switch value := expression.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(value.Value)
		return text, err == nil
	case *ast.Ident:
		if text, ok := index.local[value.Name]; ok {
			return text, true
		}
		alias, ok := index.aliases[value.Name]
		if !ok {
			return "", false
		}
		// One level of indirection is what a re-export looks like; refuse a
		// longer chain rather than pretending to resolve it.
		switch aliased := alias.(type) {
		case *ast.SelectorExpr:
			qualifier, ok := aliased.X.(*ast.Ident)
			if !ok {
				return "", false
			}
			path, ok := index.imports[qualifier.Name]
			if !ok {
				return "", false
			}
			return index.remoteConstant(t, path, aliased.Sel.Name)
		default:
			return "", false
		}
	case *ast.SelectorExpr:
		qualifier, ok := value.X.(*ast.Ident)
		if !ok {
			return "", false
		}
		path, ok := index.imports[qualifier.Name]
		if !ok {
			return "", false
		}
		return index.remoteConstant(t, path, value.Sel.Name)
	default:
		return "", false
	}
}

// remoteConstant reads one constant from an internal package's source,
// following a one-package alias chain (a leaf-owned value re-exported by the
// installer's own code table) so the role texts still resolve to one literal.
func (index *constantIndex) remoteConstant(t *testing.T, importPath, name string) (string, bool) {
	t.Helper()
	return index.remoteConstantDepth(t, importPath, name, 0)
}

func (index *constantIndex) remoteConstantDepth(t *testing.T, importPath, name string, depth int) (string, bool) {
	t.Helper()
	values, aliases, imports := index.remotePackage(t, importPath)
	if text, ok := values[name]; ok {
		return text, true
	}
	alias, ok := aliases[name]
	if !ok || depth >= 3 {
		return "", false
	}
	selector, ok := alias.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	qualifier, ok := selector.X.(*ast.Ident)
	if !ok {
		return "", false
	}
	next, ok := imports[qualifier.Name]
	if !ok {
		return "", false
	}
	return index.remoteConstantDepth(t, next, selector.Sel.Name, depth+1)
}

// remotePackage parses one internal package once and returns its literal
// constants, cross-package aliases and import table.
func (index *constantIndex) remotePackage(t *testing.T, importPath string) (map[string]string, map[string]ast.Expr, map[string]string) {
	t.Helper()
	if values, ok := index.remote[importPath]; ok {
		return values, index.remoteAliases[importPath], index.remoteImports[importPath]
	}
	directory, ok := index.directory[importPath]
	if !ok {
		output, err := exec.Command("go", "list", "-f", "{{.Dir}}", importPath).Output()
		if err != nil {
			t.Fatalf("locate %s: %v", importPath, err)
		}
		directory = strings.TrimSpace(string(output))
		index.directory[importPath] = directory
	}
	values := map[string]string{}
	aliases := map[string]ast.Expr{}
	imports := map[string]string{}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read %s: %v", importPath, err)
	}
	for _, entry := range entries {
		entryName := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(entryName, ".go") || strings.HasSuffix(entryName, "_test.go") {
			continue
		}
		path := filepath.Join(directory, entryName)
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", entryName, err)
		}
		for _, imported := range file.Imports {
			importedPath, err := strconv.Unquote(imported.Path.Value)
			if err != nil || !strings.HasPrefix(importedPath, "github.com/wingsky-1/MeshMux/internal/") {
				continue
			}
			alias := filepath.Base(importedPath)
			if imported.Name != nil {
				alias = imported.Name.Name
			}
			imports[alias] = importedPath
		}
		collectStringConstants(file, values, aliases)
	}
	index.remote[importPath] = values
	index.remoteAliases[importPath] = aliases
	index.remoteImports[importPath] = imports
	return values, aliases, imports
}
