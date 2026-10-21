package install

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestApplyRecoveryTextsPinned pins the operator recovery sentences that
// InstallNode (Line) and InstallHub publish for their shared failure codes.
// The sentences are inline literals in the apply functions, so the test reads
// the package's non-test sources and attributes every failure call to the
// enclosing function by name. Moving a function to another file keeps the
// guard intact; editing either role's wording fails the test.
func TestApplyRecoveryTextsPinned(t *testing.T) {
	lineTexts := failureRecoveryTexts(t, "InstallNode")
	hubTexts := failureRecoveryTexts(t, "InstallHub")

	cases := []struct {
		code      string
		line      []string
		hub       []string
		identical bool
	}{
		{
			code: "ACCOUNT_CREATE_FAILED",
			line: []string{"Inspect meshmux-singbox and meshmux-agent accounts before retrying."},
			hub:  []string{"Inspect the three dedicated service accounts before retrying."},
		},
		{
			code: "ARCH_UNSUPPORTED",
			line: []string{"Use Debian 13 on amd64 or arm64 and run the matching MeshMux binary.", "Use Debian 13 on amd64 or arm64."},
			hub:  []string{"Use Debian 13 on amd64 or arm64."},
		},
		{
			code: "ARTIFACT_CHECKSUM_MISMATCH",
			line: []string{"Delete the staged archive and retry; never bypass archive SHA-256 verification."},
			hub:  []string{"Delete the staged download and retry; do not bypass SHA-256 verification."},
		},
		{
			code: "ARTIFACT_FORMAT_INVALID",
			line: []string{"Use the official pinned sing-box archive for this architecture."},
			hub:  []string{"Re-download the official Caddy archive; do not extract unverified archives."},
		},
		{
			code: "ARTIFACT_MANIFEST_INVALID",
			line: []string{"Use exactly the pinned sing-box release; latest and caller-supplied URLs are rejected.", "Use the pinned Node manifest for this architecture."},
			hub:  []string{"The manifest must contain the pinned Caddy and Headscale binaries.", "Use the pinned Caddy and Headscale manifest for a supported architecture."},
		},
		{
			code: "BACKUP_FAILED",
			line: []string{"Check installer state disk space.", "No managed files were replaced; inspect the operation journal."},
			hub:  []string{"Check installer state disk space before applying files.", "No managed files were replaced; inspect the operation journal."},
		},
		{
			code: "CONFIG_CONFLICT",
			line: []string{"Repair only supports the recorded Hub URL, node, role and ports; create a new node enrollment for migration."},
			hub:  []string{"Repair only supports the recorded domains and proxy trust mode; domain migration is not part of this operation."},
		},
		{
			code: "CONFIG_INVALID",
			line: []string{"Supply a valid HTTPS Hub URL, node identity, edge/out role and distinct SSH/VLESS ports."},
			hub:  []string{"Review the domains and detected SSH listener ports."},
		},
		{
			code: "DATA_DIRECTORY_FAILED",
			line: []string{"Check Agent and kernel data directory ownership; never expose the identity directory to the kernel group."},
			hub:  []string{"Check MeshMux data directory ownership; never delete SQLite or Headscale key files."},
		},
		{
			code: "FAIL2BAN_CONFIG_INVALID",
			line: []string{"Review the Node SSH jail and preserve all existing Fail2ban jails."},
			hub:  []string{"Review the MeshMux SSH jail and preserve existing Fail2ban configuration."},
		},
		{
			code: "FAIL2BAN_RELOAD_FAILED",
			line: []string{"Review Fail2ban logs and preserve existing jails."},
			hub:  []string{"Review Fail2ban logs and preserve existing jails and nftables rules."},
		},
		{
			code: "FAIL2BAN_START_FAILED",
			line: []string{"Review Fail2ban logs and the Node SSH jail; do not alter sshd or flush nftables.", "The Fail2ban service never became queryable; inspect the service and run --repair."},
			hub:  []string{"Review Fail2ban logs and SSH jail configuration; do not alter sshd or flush nftables."},
		},
		{
			code: "INSTALL_PARTIAL_REPAIR_REQUIRED",
			line: []string{"Inspect the operation journal and run --repair with the same Node configuration."},
			hub:  []string{"A previous operation is incomplete. Review its journal and run --repair with the same domains."},
		},
		{
			code: "INSTALL_STATE_INVALID",
			line: []string{"Inspect the recorded installer state before retrying.", "Inspect the recorded installer state; do not delete Agent identity or kernel data."},
			hub:  []string{"Inspect installer state before retrying.", "Inspect the recorded installer state; do not delete application data or Headscale keys."},
		},
		{
			code: "INSTALL_STATE_WRITE_FAILED",
			line: []string{"Check disk space and permissions under /var/lib/meshmux-installer.", "Check installer state disk space and permissions; preserve the private identity.", "The data plane and Agent are active but the final ledger failed; preserve them and repair state."},
			hub:  []string{"Check disk space and permissions under /var/lib/meshmux-installer.", "Do not remove state or data; inspect disk space and run --repair.", "Services were started but state readback failed; inspect the operation journal before retrying."},
		},
		{
			code: "MANAGED_PATH_CONFLICT",
			line: []string{"Inspect the fixed Node paths manually; MeshMux does not adopt third-party files or tables."},
			hub:  []string{"A target path already exists without an ownership record; inspect it manually."},
		},
		{
			code: "MESHMUX_BINARY_INVALID",
			line: []string{"Run the installer from a regular MeshMux executable and retry."},
			hub:  []string{"Run the installer from a regular, readable MeshMux executable and retry."},
		},
		{
			code:      "OPERATION_ID_INVALID",
			line:      []string{"Generate a new operation ID and retry."},
			hub:       []string{"Generate a new operation ID and retry."},
			identical: true,
		},
		{
			code: "OPERATION_LOG_FAILED",
			line: []string{"Check installer state directory permissions and run --repair.", "Restore the journal before another apply.", "The Node is active but the journal write failed; repair only state/logging.", "The validated data plane is active; restore the journal before retrying."},
			hub:  []string{"Check installer state directory permissions.", "Check private installer state directory permissions.", "Inspect the operation journal and installer state."},
		},
		{
			code: "PACKAGE_INDEX_FAILED",
			line: []string{"Check Debian repository connectivity; no package upgrade or third-party repository is used."},
			hub:  []string{"Check Debian repository connectivity; no third-party repository was added."},
		},
		{
			code: "PACKAGE_INSTALL_FAILED",
			line: []string{"Review Debian apt status; only the listed missing packages are installed."},
			hub:  []string{"Review Debian apt status and retry; do not remove existing packages or rules."},
		},
		{
			code: "REPAIR_STATE_MISSING",
			line: []string{"Repair requires a Node state record created by MeshMux."},
			hub:  []string{"Repair requires a state record created by MeshMux."},
		},
		{
			code: "ROOT_REQUIRED",
			line: []string{"Run the installer as root; the Agent service does not listen for management traffic."},
			hub:  []string{"Run the installer as root; the Web service itself runs unprivileged."},
		},
		{
			code: "SSH_LISTENER_UNKNOWN",
			line: []string{"Determine the actual SSH listener before installing Fail2ban or VLESS."},
			hub:  []string{"Determine the effective SSH listening port before installing Fail2ban."},
		},
		{
			code: "STAGE_UNAVAILABLE",
			line: []string{"Check /var/cache space and permissions; no host files were applied.", "Check temporary disk space and permissions.", "Remove only the incomplete staging directory for this operation and retry."},
			hub:  []string{"Check /var/cache space and permissions.", "Check installer staging directory permissions.", "Check temporary disk space and permissions."},
		},
		{
			code: "SYSTEMD_RELOAD_FAILED",
			line: []string{"Inspect systemd and run --repair."},
			hub:  []string{"Restore MeshMux-managed units and inspect systemd."},
		},
		{
			code: "SYSTEMD_UNIT_INVALID",
			line: []string{"Review the fixed Agent, kernel and ACL units; no Node is installed until validation succeeds."},
			hub:  []string{"Review the generated unit files; no service is considered installed until validation succeeds."},
		},
	}

	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			line, lineOK := lineTexts[tc.code]
			hub, hubOK := hubTexts[tc.code]
			if !lineOK {
				t.Fatalf("InstallNode no longer emits %s", tc.code)
			}
			if !hubOK {
				t.Fatalf("InstallHub no longer emits %s", tc.code)
			}
			if !slices.Equal(line, tc.line) {
				t.Errorf("InstallNode recovery texts for %s = %q, want %q", tc.code, line, tc.line)
			}
			if !slices.Equal(hub, tc.hub) {
				t.Errorf("InstallHub recovery texts for %s = %q, want %q", tc.code, hub, tc.hub)
			}
			if tc.identical {
				if !slices.Equal(line, hub) {
					t.Errorf("%s recovery texts diverge; both roles previously shared %q", tc.code, tc.line)
				}
			} else if slices.Equal(line, hub) {
				t.Errorf("%s recovery texts became identical; the role-specific guidance was lost", tc.code)
			}
		})
	}
}

// failureRecoveryTexts extracts every literal (code, recovery) pair emitted by
// one apply function. It follows fail* helper calls and direct InstallError
// literals, skipping dynamic arguments that cannot be pinned statically.
func failureRecoveryTexts(t *testing.T, function string) map[string][]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	texts := map[string]map[string]bool{}
	add := func(code, recovery string) {
		if texts[code] == nil {
			texts[code] = map[string]bool{}
		}
		texts[code][recovery] = true
	}
	found := false
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != function || fn.Body == nil {
				continue
			}
			found = true
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch n := node.(type) {
				case *ast.CallExpr:
					callee, ok := n.Fun.(*ast.Ident)
					if !ok || !strings.HasPrefix(callee.Name, "fail") {
						return true
					}
					stage, code, recovery, ok := literalFailureArguments(n.Args)
					if ok && isFailureStage(stage) {
						add(code, recovery)
					}
				case *ast.CompositeLit:
					ident, ok := n.Type.(*ast.Ident)
					if !ok || ident.Name != "InstallError" {
						return true
					}
					code, recovery := installErrorFields(t, n)
					if code != "" && recovery != "" {
						add(code, recovery)
					}
				}
				return true
			})
		}
	}
	if !found {
		t.Fatalf("function %s was not found in the package sources", function)
	}
	out := make(map[string][]string, len(texts))
	for code, set := range texts {
		values := make([]string, 0, len(set))
		for value := range set {
			values = append(values, value)
		}
		slices.Sort(values)
		out[code] = values
	}
	return out
}

// literalFailureArguments returns the stage, code and recovery of a fail*
// helper call. Every failure helper keeps those three as its last arguments.
func literalFailureArguments(args []ast.Expr) (stage, code, recovery string, ok bool) {
	if len(args) < 3 {
		return "", "", "", false
	}
	values := make([]string, 3)
	for i, expr := range args[len(args)-3:] {
		lit, isString := expr.(*ast.BasicLit)
		if !isString || lit.Kind != token.STRING {
			return "", "", "", false
		}
		text, err := strconv.Unquote(lit.Value)
		if err != nil {
			return "", "", "", false
		}
		values[i] = text
	}
	return values[0], values[1], values[2], true
}

func isFailureStage(stage string) bool {
	switch stage {
	case "preflight", "stage", "apply", "verify", "pairing":
		return true
	}
	return false
}

func installErrorFields(t *testing.T, lit *ast.CompositeLit) (code, recovery string) {
	t.Helper()
	for _, element := range lit.Elts {
		kv, ok := element.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		key, ok := kv.Key.(*ast.Ident)
		if !ok {
			continue
		}
		value, ok := kv.Value.(*ast.BasicLit)
		if !ok || value.Kind != token.STRING {
			continue
		}
		text, err := strconv.Unquote(value.Value)
		if err != nil {
			t.Fatalf("unquote InstallError field %s: %v", key.Name, err)
		}
		switch key.Name {
		case "Code":
			code = text
		case "Recovery":
			recovery = text
		}
	}
	return code, recovery
}
