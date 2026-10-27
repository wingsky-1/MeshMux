package handler

import (
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestReportedAddressOriginBadges pins the operator-visible half of the
// reported-address feature: the nodes page shows the observation, a blank Out
// or Line address is filled from it and labelled 上报, and an explicit value is
// labelled 手填.
func TestReportedAddressOriginBadges(t *testing.T) {
	app, b, lineID, outID := nodesOutTestApp(t)
	now := time.Now()
	if err := app.Store.Heartbeat(lineID, "agent", "1.14.3", "203.0.113.21", now); err != nil {
		t.Fatal(err)
	}
	if err := app.Store.Heartbeat(outID, "agent", "1.14.3", "203.0.113.31", now); err != nil {
		t.Fatal(err)
	}
	body := nodesPageBody(t, b)
	if !strings.Contains(body, "203.0.113.21") || !strings.Contains(body, "203.0.113.31") || !strings.Contains(body, "上报 IPv4") {
		t.Fatalf("nodes page misses the reported addresses: %.500s", body)
	}

	// Blank Out address: use the report and label it.
	w := b.post("/nodes/out-transport", url.Values{"out_id": {outID}, "server": {""}})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "203.0.113.31") || !strings.Contains(body, "（上报）") {
		t.Fatalf("blank out transport did not use the report: %.500s", body)
	}
	// Explicit Out address: manual always wins.
	w = b.post("/nodes/out-transport", url.Values{"out_id": {outID}, "server": {"out.example.invalid"}})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "out.example.invalid") || !strings.Contains(body, "（手填）") {
		t.Fatalf("manual out transport was not labelled: %.500s", body)
	}

	// Blank Line address: use the report and label it on the subscriber page.
	w = b.post("/lines", url.Values{
		"node_id": {lineID}, "display_name": {"line-reported"}, "sort_order": {"0"},
		"server": {""}, "port": {"8443"}, "server_name": {"line.example.invalid"},
		"handshake_server": {"handshake.example.invalid"}, "handshake_port": {"443"},
	})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "203.0.113.21") || !strings.Contains(body, "上报") {
		t.Fatalf("blank line did not use the report: %.500s", body)
	}
	// Explicit Line address: manual always wins.
	w = b.post("/lines", url.Values{
		"node_id": {lineID}, "display_name": {"line-manual"}, "sort_order": {"0"},
		"server": {"line.example.invalid"}, "port": {"8443"}, "server_name": {"line.example.invalid"},
		"handshake_server": {"handshake.example.invalid"}, "handshake_port": {"443"},
	})
	requireStatus(t, w, 200)
	body = w.Body.String()
	if !strings.Contains(body, "line.example.invalid") || !strings.Contains(body, "手填") {
		t.Fatalf("manual line was not labelled: %.500s", body)
	}
}
