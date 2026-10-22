package subscription

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestExportHasNoTUNOrLoopbackInbound pins the mobile default of Issue #8: the
// exported documents never introduce a TUN inbound or a TUN loopback, so an
// imported client keeps the loopback mixed proxy it already had instead of
// silently taking over the device's routing.
//
// The Out / AI decision belongs to the server side; a client-side TUN would
// also make the "Out unavailable is fail-closed" rule unenforceable, because
// the device would route around the Hub's refusal.
func TestExportHasNoTUNOrLoopbackInbound(t *testing.T) {
	lines, credentials := exportFixtures(t)
	singBox, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	mihomo, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}

	var document struct {
		Inbounds []struct {
			Type string `json:"type"`
			Tag  string `json:"tag"`
		} `json:"inbounds"`
	}
	if err := json.Unmarshal(singBox, &document); err != nil {
		t.Fatalf("the exported configuration is not valid JSON: %v", err)
	}
	if len(document.Inbounds) != 1 || document.Inbounds[0].Type != "mixed" {
		t.Fatalf("exported inbounds = %+v, want exactly one mixed inbound", document.Inbounds)
	}
	// A TUN inbound is the one thing that changes the device's routing table
	// instead of offering a local proxy, so it must never appear.
	for _, forbidden := range []string{`"tun"`, `"auto_route"`, `"auto-route"`, `"stack"`} {
		if strings.Contains(string(singBox), forbidden) {
			t.Fatalf("the exported sing-box configuration contains %q", forbidden)
		}
	}
	for _, forbidden := range []string{"tun:", "dns-hijack", "auto-route", "stack:"} {
		if strings.Contains(string(mihomo), forbidden) {
			t.Fatalf("the exported mihomo configuration contains %q", forbidden)
		}
	}
}
