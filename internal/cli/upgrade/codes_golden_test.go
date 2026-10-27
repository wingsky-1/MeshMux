package upgrade

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file freezes the stable error_code values of the domains that the
// internal regroup (docs/superpowers/plans/2026-10-26-internal-regroup.md, C1)
// moves around: route, jobs, policy, hubupgrade, update, node and web.
// A code is compared by VALUE only, never by identifier or by the package that
// declares it, so a rename, a package move or a package merge cannot silently
// change what an operator, a log line or a client sees. Adding, removing or
// editing a value requires an explicit edit of goldenErrorCodeValues in the
// same commit as the behaviour change.
//
// The scan parses source rather than importing the packages: internal/upgrade is
// imported by internal/web, so importing web here would be an import cycle. It
// also means the test keeps working when a domain is physically moved.

// errorCodeDomains is the set of package names whose Code* constants are
// frozen. Package names, not paths: the regroup moves route into policy
// (Tasks 3-4), jobs into upgrade (Task 6), update and hubupgrade under
// upgrade (Task 7), and protocol under node (Task 5), and in every case the
// constant keeps its value. internal/web is not a single package any more, so
// its handler/store/view packages are listed by name as well.
//
// agent, hub and upgrade are the destination package names Task 6/7 plan to
// use, listed up front so a moved constant stays frozen without a second edit
// here. internal/upgrade/backup is deliberately absent: the backup record codes
// are not part of this golden.
//
// A domain that is renamed to something not listed loses all of its values at
// once, which the diff below reports as removals: coverage cannot disappear
// quietly.
var errorCodeDomains = map[string]bool{
	"route":      true,
	"jobs":       true,
	"policy":     true,
	"hubupgrade": true,
	"update":     true,
	"node":       true,
	"web":        true,
	"handler":    true,
	"store":      true,
	"view":       true,
	"agent":      true,
	"hub":        true,
	"upgrade":    true,
}

// goldenErrorCodeValues is the frozen, sorted, de-duplicated set of Code*
// constant values declared by errorCodeDomains. Values only: the identifier and
// the declaring package are deliberately absent, so the regroup may rename or
// move a constant without touching this list, while any change to what a
// client, a log line or an operator sees is a visible diff here.
var goldenErrorCodeValues = []string{
	"DATABASE_UNAVAILABLE",
	// The Hub self-upgrade shared codes moved into internal/hubupgrade/codes.go
	// so the Web producer and the root executor name one value each; they are
	// frozen here from this commit on.
	"HUB_BACKUP_IDENTITY_MISSING",
	"HUB_HANDOFF_BUSY",
	"HUB_HANDOFF_INVALID_STATE",
	"HUB_HANDOFF_REQUEST_INVALID",
	"HUB_MANIFEST_PACKAGE_MISMATCH",
	"HUB_RESTORE_BINARY_MISSING",
	"HUB_RESTORE_DIGEST_MISMATCH",
	"HUB_RESTORE_UNIT_SHAPE_INVALID",
	"HUB_SHARED_BINARY_REPIN_FAILED",
	"LINE_EGRESS_UNVERIFIED",
	"LINE_NOT_AUTHORIZED",
	"MESH_DEVICE_CORRUPT",
	"MESH_DEVICE_NOT_FOUND",
	"MESH_ENROLLMENT_KEY_NOT_FOUND",
	"MESH_ROUTE_CONFLICT",
	"MESH_ROUTE_CORRUPT",
	"MESH_ROUTE_NOT_FOUND",
	"MESH_ROUTE_UNTRACKED",
	"OUT_BINDING_API_RETIRED",
	"OUT_FALLBACK_UNAUDITED",
	"OUT_NOT_AUTHORIZED",
	"OUT_OFFLINE_FAIL_CLOSED",
	"OUT_REFERENCED_BY_SUBSCRIPTIONS",
	"OUT_SYNC_IN_PROGRESS",
	"OUT_SYNC_PENDING",
	"POLICY_CONFLICT",
	"POLICY_INVALID",
	"POLICY_LAYER_RETIRED",
	"POLICY_NODE_UNKNOWN",
	"POLICY_NOT_FOUND",
	"POLICY_PAYLOAD_RETIRED",
	"PUBLISH_CHECK_MIHOMO_FAILED",
	"PUBLISH_CHECK_SINGBOX_FAILED",
	"PUBLISH_MIHOMO_UNAVAILABLE",
	"PUBLISH_MIHOMO_VERSION_INVALID",
	"PUBLISH_NO_LINES",
	"PUBLISH_REVISION_CHANGED",
	"PUBLISH_SINGBOX_UNAVAILABLE",
	"RENDER_UNSUPPORTED",
	"RULESET_FETCH_FAILED",
	"RULESET_PIN_INVALID",
	"RULESET_UNPINNED",
	"RULE_CONFLICT",
	"RULE_INVALID",
	"RULE_NOT_FOUND",
	"RULE_PRESET_IMMUTABLE",
	"RULE_REFERENCED_BY_SUBSCRIPTIONS",
	"SUBSCRIPTION_ARTIFACT_DRIFT",
	"SUBSCRIPTION_ARTIFACT_NOT_APPROVED",
	"SUBSCRIPTION_GATE_FAILED",
	"SUBSCRIPTION_GATE_UNAVAILABLE",
	"SUBSCRIPTION_MIHOMO_GATE_SKIPPED",
	"SUBSCRIPTION_OUT_CONFLICT",
	"SUBSCRIPTION_SELECTION_INVALID",
	"TASKS_IN_PROGRESS",
	"UPGRADE_AGENT_INCOMPATIBLE",
	"UPGRADE_NOT_ADJACENT",
}

// errorCodeDeclaration records where a value came from, for failure messages
// only; no assertion ever depends on a name.
type errorCodeDeclaration struct {
	value string
	where string // package directory (module-relative) and identifier
}

func TestErrorCodeValuesGolden(t *testing.T) {
	declarations := collectErrorCodeDeclarations(t)

	actual := make([]string, 0, len(declarations))
	origins := make(map[string][]string, len(declarations))
	for _, declaration := range declarations {
		if _, seen := origins[declaration.value]; !seen {
			actual = append(actual, declaration.value)
		}
		origins[declaration.value] = append(origins[declaration.value], declaration.where)
	}
	sort.Strings(actual)

	if len(actual) == 0 {
		t.Fatalf("the scan matched no Code* constants in packages %v; a golden over nothing proves nothing",
			sortedDomainNames())
	}

	// A code is a contract, not a message: an added lowercase value must fail
	// even when the golden below is updated to match it.
	for _, value := range actual {
		if !isStableErrorCode(value) {
			t.Errorf("%q (%s) is not an uppercase code; a stable code must match ^[A-Z][A-Z0-9_]*$",
				value, strings.Join(origins[value], ", "))
		}
	}

	missing, added := diffCodeValues(goldenErrorCodeValues, actual)
	if len(missing) == 0 && len(added) == 0 {
		return
	}

	var report strings.Builder
	report.WriteString("stable error_code values changed.\n")
	for _, value := range missing {
		report.WriteString("  removed: " + value + " (golden)\n")
	}
	for _, value := range added {
		report.WriteString("  added:   " + value + " (" + strings.Join(origins[value], ", ") + ")\n")
	}
	report.WriteString("\nIf the change is intended, replace goldenErrorCodeValues with:\n\n")
	report.WriteString("var goldenErrorCodeValues = []string{\n")
	for _, value := range actual {
		report.WriteString("\t" + strconv.Quote(value) + ", // " + strings.Join(origins[value], ", ") + "\n")
	}
	report.WriteString("}\n")
	t.Fatal(report.String())
}

// collectErrorCodeDeclarations parses every built non-test file of every
// package under ./internal/... whose package name is an errorCodeDomains member.
func collectErrorCodeDeclarations(t *testing.T) []errorCodeDeclaration {
	t.Helper()
	root := errorCodeModuleRoot(t)

	// -e keeps a package with a load error in the listing so the failure names
	// the package instead of aborting on the first error.
	command := exec.Command("go", "list", "-e", "-f",
		`{{.ImportPath}}|{{.Name}}|{{join .GoFiles " "}}|{{if .Error}}{{.Error.Err}}{{end}}`, "./internal/...")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		var stderr string
		if exitErr, ok := err.(*exec.ExitError); ok {
			stderr = string(exitErr.Stderr)
		}
		t.Fatalf("go list ./internal/... failed: %v\n%s", err, stderr)
	}

	var declarations []errorCodeDeclaration
	modulePath := errorCodeModulePath(root)
	matched := 0
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "|", 4)
		if len(fields) != 4 {
			t.Fatalf("unexpected go list line %q", line)
		}
		importPath, packageName, files, listErr := fields[0], fields[1], fields[2], fields[3]
		if listErr != "" {
			t.Fatalf("%s: go list error: %s", importPath, listErr)
		}
		if !errorCodeDomains[packageName] {
			continue
		}
		matched++
		directory := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(importPath, modulePath+"/")))
		for _, name := range strings.Fields(files) {
			declarations = append(declarations, parseErrorCodeConstants(t, root, directory, name)...)
		}
	}
	if matched == 0 {
		t.Fatalf("no package under ./internal/... matched the domains %v", sortedDomainNames())
	}
	return declarations
}

// parseErrorCodeConstants returns the Code* string constants of one file. A
// Code* constant declared without a string literal (an expression, or a value
// inherited from the previous spec) is a failure: its value would escape the
// golden.
func parseErrorCodeConstants(t *testing.T, root, directory, name string) []errorCodeDeclaration {
	t.Helper()
	path := filepath.Join(directory, name)
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	relative, err := filepath.Rel(root, path)
	if err != nil {
		t.Fatalf("relative path for %s: %v", path, err)
	}
	relative = filepath.ToSlash(relative)

	var declarations []errorCodeDeclaration
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.CONST {
			continue
		}
		for _, specification := range generic.Specs {
			values, ok := specification.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, identifier := range values.Names {
				if !strings.HasPrefix(identifier.Name, "Code") {
					continue
				}
				position := files.Position(identifier.Pos())
				where := relative + ":" + strconv.Itoa(position.Line) + " " + identifier.Name
				if index >= len(values.Values) {
					t.Fatalf("%s: %s has no value literal; the golden cannot read it", where, identifier.Name)
				}
				literal, ok := values.Values[index].(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					value, err := strconv.Unquote(literal.Value)
					if err != nil {
						t.Fatalf("%s: unquote %s: %v", where, literal.Value, err)
					}
					declarations = append(declarations, errorCodeDeclaration{value: value, where: where})
					continue
				}
				selector, ok := values.Values[index].(*ast.SelectorExpr)
				if !ok {
					t.Fatalf("%s: %s is not a string literal; the golden cannot read it", where, identifier.Name)
				}
				pkgIdent, ok := selector.X.(*ast.Ident)
				if !ok || pkgIdent.Name != "versions" {
					t.Fatalf("%s: %s is not a string literal; the golden cannot read it", where, identifier.Name)
				}
				value := resolveVersionsCode(t, root, selector.Sel.Name)
				declarations = append(declarations, errorCodeDeclaration{value: value, where: where})
			}
		}
	}
	return declarations
}

// resolveVersionsCode follows a single-level alias like
// `versions.CodeDatabaseUnavailable` to its string literal in
// internal/cli/versions/codes.go, keeping the golden readable when a domain
// moves its literal to the shared leaf.
func resolveVersionsCode(t *testing.T, root, name string) string {
	t.Helper()
	path := filepath.Join(root, "internal", "cli", "versions", "codes.go")
	files := token.NewFileSet()
	file, err := parser.ParseFile(files, path, nil, 0)
	if err != nil {
		t.Fatalf("parse versions codes %s: %v", path, err)
	}
	for _, declaration := range file.Decls {
		generic, ok := declaration.(*ast.GenDecl)
		if !ok || generic.Tok != token.CONST {
			continue
		}
		for _, specification := range generic.Specs {
			values, ok := specification.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for index, identifier := range values.Names {
				if identifier.Name != name {
					continue
				}
				if index >= len(values.Values) {
					t.Fatalf("versions %s has no value literal", name)
				}
				literal, ok := values.Values[index].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("versions %s is not a string literal", name)
				}
				value, err := strconv.Unquote(literal.Value)
				if err != nil {
					t.Fatalf("unquote versions %s: %v", name, err)
				}
				return value
			}
		}
	}
	t.Fatalf("versions %s not found in %s", name, path)
	return ""
}

// diffCodeValues returns the golden-only and actual-only values, both sorted.
func diffCodeValues(golden, actual []string) (missing, added []string) {
	wanted := make(map[string]bool, len(golden))
	for _, value := range golden {
		wanted[value] = true
	}
	have := make(map[string]bool, len(actual))
	for _, value := range actual {
		have[value] = true
	}
	for _, value := range golden {
		if !have[value] {
			missing = append(missing, value)
		}
	}
	for _, value := range actual {
		if !wanted[value] {
			added = append(added, value)
		}
	}
	sort.Strings(missing)
	sort.Strings(added)
	return missing, added
}

// isStableErrorCode is the code shape the repository validates elsewhere
// (^[A-Z][A-Z0-9_]*$): an uppercase token, never a message.
func isStableErrorCode(value string) bool {
	if value == "" || value[0] < 'A' || value[0] > 'Z' {
		return false
	}
	for _, character := range value {
		switch {
		case character >= 'A' && character <= 'Z':
		case character >= '0' && character <= '9':
		case character == '_':
		default:
			return false
		}
	}
	return true
}

func sortedDomainNames() []string {
	names := make([]string, 0, len(errorCodeDomains))
	for name := range errorCodeDomains {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// errorCodeModuleRoot walks up from the test's working directory to the go.mod
// that governs this repository.
func errorCodeModuleRoot(t *testing.T) string {
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

// errorCodeModulePath reads the module path from go.mod, so import paths are
// stripped without a hard-coded module name.
func errorCodeModulePath(root string) string {
	body, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "module ") {
			return strings.TrimSpace(strings.TrimPrefix(line, "module "))
		}
	}
	return ""
}
