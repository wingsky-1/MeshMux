package install

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// TestLocalLineSystemVM runs only in an ephemeral Debian 13 VM with real
// systemd that already hosts an installed Hub. It is the skeleton of the
// co-located Line lifecycle acceptance:
//
//   - phase "install": snapshot the Hub ledger, run the reserved in-guest Web
//     lifecycle (Web initialization, pending Line creation, pairing, local
//     Line install, repair, Agent v2 convergence and subscription download),
//     then prove the Hub ledger, its pins and its runtime program survived.
//   - phase "post-reboot": prove the Hub ledger and the local-Line ledger
//     both survive a real reboot and still describe the same host.
//
// The Web lifecycle itself is not implemented in this increment: the reserved
// hook below skips until it lands. CI wiring is intentionally absent as well;
// until then this file only proves the gates and compiles the assertions.
//
// It never runs on a production host: it is env-gated, requires root and
// systemd, refuses non-disposable example domains, and only ever talks to
// loopback. Pairing codes, identity tokens, VLESS UUIDs and key material are
// never printed.
func TestLocalLineSystemVM(t *testing.T) {
	if os.Getenv("MESHMUX_LOCAL_LINE_VM") != "1" {
		t.Skip("requires an explicit disposable Debian 13 QEMU VM with an installed Hub; set MESHMUX_LOCAL_LINE_VM=1")
	}
	if os.Geteuid() != 0 {
		t.Fatal("isolated VM integration test requires root")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Fatal("VM did not boot with systemd")
	}
	phase := os.Getenv("MESHMUX_LOCAL_LINE_PHASE")
	if phase == "" {
		phase = "install"
	}
	switch phase {
	case "install":
		testLocalLineVMInstall(t)
	case "post-reboot":
		testLocalLineVMPostReboot(t)
	default:
		t.Fatalf("invalid VM-only phase %q: use install or post-reboot", phase)
	}
}

// localLineWebLifecycle is the reserved seam for the real in-guest Web
// lifecycle of the next increment: Web /setup + login over loopback TLS,
// create a pending Line, install the co-located Line with its one-time pairing
// code, run repair, let the Agent converge the v2 candidate and download the
// subscription over loopback. The Hub-ledger assertions after this call are
// already written for it.
func localLineWebLifecycle(t *testing.T) {
	t.Helper()
	t.Skip("web lifecycle arrives in next increment")
}

func testLocalLineVMInstall(t *testing.T) {
	t.Helper()
	hubBefore, exists, err := ReadState("/")
	if err != nil || !exists || hubBefore.Status != "installed" {
		localLineVMFatal(t, hubBefore.OperationID, "preflight", "HUB_LEDGER_MISSING",
			"the local Line lifecycle expects an already installed Hub in this disposable VM (exists=%v err=%v)", exists, err)
	}
	for _, domain := range []string{
		hubBefore.Config.ManagementDomain,
		hubBefore.Config.SubscriptionDomain,
		hubBefore.Config.HeadscaleDomain,
	} {
		if !localLineVMIsDisposableDomain(domain) {
			localLineVMFatal(t, hubBefore.OperationID, "preflight", "VM_DOMAIN_NOT_DISPOSABLE",
				"the recorded Hub layout is not a reserved example domain; refusing to run against it")
		}
	}
	// The co-located Line can only exist when the Hub publishes the pinned
	// reusable runtime build; a missing pin is a real layout gap, not a skip.
	pin, ok := hubBefore.SharedBinaries[sharedAgentKey]
	if !ok {
		localLineVMFatal(t, hubBefore.OperationID, "preflight", "HUB_SHARED_BINARY_MISSING",
			"the Hub ledger does not publish the pinned reusable %s runtime; a co-located Line cannot be installed", sharedAgentKey)
	}
	if err := localLineSharedPinOnDisk(pin); err != nil {
		localLineVMFatal(t, hubBefore.OperationID, "preflight", "HUB_SHARED_BINARY_MISSING",
			"the Hub-owned %s pin does not point at a verified existing file: %v", sharedAgentKey, err)
	}
	domainBefore := hubBefore.Config.ManagementDomain
	pinsBefore := localLineVMClonePins(hubBefore.SharedBinaries)

	localLineWebLifecycle(t) // never returns in this increment

	// The Hub ledger, its management domain and every pinned shared binary
	// must be byte-identical after the local Line lifecycle, and every pin
	// must still point at an existing file with the recorded digest.
	hubAfter, existsAfter, errAfter := ReadState("/")
	if errAfter != nil || !existsAfter || hubAfter.Status != "installed" {
		localLineVMFatal(t, hubBefore.OperationID, "verify", "HUB_LEDGER_INVALID",
			"the Hub ledger is no longer readable and installed after the local Line lifecycle (exists=%v err=%v)", existsAfter, errAfter)
	}
	if hubAfter.Config.ManagementDomain != domainBefore {
		localLineVMFatal(t, hubAfter.OperationID, "verify", "HUB_MANAGEMENT_DOMAIN_CHANGED",
			"the local Line lifecycle changed the recorded Hub management domain")
	}
	for key, before := range pinsBefore {
		after, ok := hubAfter.SharedBinaries[key]
		if !ok || after != before {
			localLineVMFatal(t, hubAfter.OperationID, "verify", "HUB_SHARED_BINARY_CHANGED",
				"the local Line lifecycle changed the Hub-owned %s pin", key)
		}
		if err := localLineSharedPinOnDisk(after); err != nil {
			localLineVMFatal(t, hubAfter.OperationID, "verify", "HUB_SHARED_BINARY_MISSING",
				"the Hub-owned %s pin no longer points at a verified existing file: %v", key, err)
		}
	}
}

func testLocalLineVMPostReboot(t *testing.T) {
	t.Helper()
	hub, hubExists, hubErr := ReadState("/")
	if hubErr != nil || !hubExists || hub.Status != "installed" {
		localLineVMFatal(t, hub.OperationID, "post-reboot", "HUB_LEDGER_MISSING",
			"the Hub ledger is not readable and installed after reboot (exists=%v err=%v)", hubExists, hubErr)
	}
	line, lineExists, lineErr := readLocalLineState("/")
	if lineErr != nil || !lineExists || line.Status != "installed" {
		localLineVMFatal(t, line.OperationID, "post-reboot", "LOCAL_LINE_LEDGER_MISSING",
			"the local-Line ledger is not readable and installed after reboot (exists=%v err=%v)", lineExists, lineErr)
	}
	if hub.Node != nil {
		localLineVMFatal(t, hub.OperationID, "post-reboot", "HUB_LEDGER_NODE_UNEXPECTED",
			"the Hub ledger unexpectedly records a Node; the Hub and Line layouts were mixed")
	}
	if line.Node == nil || line.Node.NodeID == "" {
		localLineVMFatal(t, line.OperationID, "post-reboot", "LOCAL_LINE_NODE_ID_MISSING",
			"the local-Line ledger records no node identity")
	}
	if line.Node.Role != node.RoleEdge {
		localLineVMFatal(t, line.OperationID, "post-reboot", "LOCAL_LINE_ROLE_INVALID",
			"the local-Line ledger does not record an edge Line")
	}
	if line.Node.HubURL != hubOriginFor(hub) {
		localLineVMFatal(t, line.OperationID, "post-reboot", "LOCAL_LINE_HUB_ORIGIN_MISMATCH",
			"the local-Line ledger does not point at the installed Hub origin")
	}
	// The effective Node ledger of a Hub host must resolve to this local
	// Line, and both reads must record the same node identity.
	effective, effectiveExists, effectiveErr := ReadNodeState("/")
	if effectiveErr != nil || !effectiveExists || effective.Node == nil {
		code := localLineVMStableCode(effectiveErr, "LOCAL_LINE_EFFECTIVE_LEDGER_INVALID")
		localLineVMFatal(t, line.OperationID, "post-reboot", code,
			"the effective Node ledger of this host does not resolve to the local Line")
	}
	if effective.Node.NodeID != line.Node.NodeID {
		localLineVMFatal(t, line.OperationID, "post-reboot", "LOCAL_LINE_NODE_ID_MISMATCH",
			"the effective Node ledger and the local-Line ledger record different node identities")
	}
}

// localLineVMFatal reports a VM acceptance failure in the same
// operation_id/stage/error_code shape the installer uses. It never prints
// pairing material, identity tokens, VLESS UUIDs or key bytes.
func localLineVMFatal(t *testing.T, operationID, stage, code, format string, args ...any) {
	t.Helper()
	t.Fatalf("operation_id=%q stage=%s error_code=%s: %s", operationID, stage, code, fmt.Sprintf(format, args...))
}

// localLineVMStableCode keeps a stable installer code when the error carries
// one and never lets a raw error text masquerade as a stable code.
func localLineVMStableCode(err error, fallback string) string {
	var ie *InstallError
	if errors.As(err, &ie) && ie.Code != "" {
		return ie.Code
	}
	return fallback
}

// localLineVMIsDisposableDomain accepts only RFC 2606/6761 reserved names, so
// this test can never point at a real public host.
func localLineVMIsDisposableDomain(domain string) bool {
	for _, reserved := range []string{"invalid", "test", "example", "example.org", "example.com", "example.net"} {
		if domain == reserved || strings.HasSuffix(domain, "."+reserved) {
			return true
		}
	}
	return false
}

// localLineVMClonePins snapshots the shared-binary map of the Hub ledger.
func localLineVMClonePins(pins map[string]SharedBinary) map[string]SharedBinary {
	cloned := make(map[string]SharedBinary, len(pins))
	for key, pin := range pins {
		cloned[key] = pin
	}
	return cloned
}

// localLineSharedPinOnDisk proves one shared-binary pin still points at an
// existing file whose digest is the recorded one.
func localLineSharedPinOnDisk(pin SharedBinary) error {
	if pin.Path == "" || !validDigest.MatchString(pin.SHA256) {
		return errors.New("the pin is incomplete")
	}
	digest, err := sha256File(pin.Path)
	if err != nil {
		return err
	}
	if digest != pin.SHA256 {
		return errors.New("the recorded digest does not match the file")
	}
	return nil
}
