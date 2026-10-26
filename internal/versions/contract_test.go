package versions

import "testing"

// TestContractDerivations pins the derived values of the deployment contract.
// Every one of them is consumed by a rendered unit or a health probe, so a
// silent change here would move the Web off the address Caddy proxies to.
func TestContractDerivations(t *testing.T) {
	if got, want := WebListenAddress(), "127.0.0.1:9080"; got != want {
		t.Fatalf("WebListenAddress() = %q, want %q", got, want)
	}
	if got, want := InstallerUpgradeDir, InstallerRoot+"/upgrade"; got != want {
		t.Fatalf("InstallerUpgradeDir = %q, want %q", got, want)
	}
	if got, want := HubUpgradeResultsDir, InstallerRoot+"/hub-upgrade/results"; got != want {
		t.Fatalf("HubUpgradeResultsDir = %q, want %q", got, want)
	}
	if got, want := WebUnitPath, "/etc/systemd/system/"+WebUnitName; got != want {
		t.Fatalf("WebUnitPath = %q, want %q", got, want)
	}
}

// TestSupportedArchitecturesIsAValue guards the borrowed-slice mistake: a
// caller that mutates the result must not be able to change the release matrix
// for everyone else.
func TestSupportedArchitecturesIsAValue(t *testing.T) {
	first := SupportedArchitectures()
	if len(first) != 2 {
		t.Fatalf("SupportedArchitectures() = %v, want the fixed amd64/arm64 matrix", first)
	}
	first[0] = "mips"
	if got := SupportedArchitectures()[0]; got != ArchitectureAMD64 {
		t.Fatalf("mutating the returned slice changed the contract: %q", got)
	}
	for _, architecture := range []string{ArchitectureAMD64, ArchitectureARM64} {
		if !IsSupportedArchitecture(architecture) {
			t.Fatalf("%q must be a supported architecture", architecture)
		}
	}
	if IsSupportedArchitecture("riscv64") {
		t.Fatal("riscv64 is not in the v1 release matrix")
	}
}

// TestStableCodeShape freezes the one code grammar every layer accepts.
func TestStableCodeShape(t *testing.T) {
	for _, code := range []string{"SCHEMA_TOO_NEW", "HUB_RESTORE_ARGV_INVALID", "A", "X1"} {
		if !IsStableCode(code) {
			t.Fatalf("%q must be a stable code", code)
		}
	}
	for _, code := range []string{"", "lower", "SCHEMA TOO NEW", "A-B", "A" + string(make([]byte, 64))} {
		if IsStableCode(code) {
			t.Fatalf("%q must not be a stable code", code)
		}
	}
}
