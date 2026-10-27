package store_test

// Agent-reported IPv4 (feat/agent-reported-ip).
//
// The address is observation only. These tests pin the one behaviour the Hub
// promises: a blank operator field is filled from the latest report, a manual
// value always wins, and a report that changes only refreshes the fields whose
// source is still "reported". An older Agent that omits the field must never
// erase the last observation.

import (
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/control/store"
)

func TestReportedIPv4FillsDefaultsAndManualWins(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	edge, _, err := s.CreateNode("edge", "line-reported", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.CreateNode("out", "out-reported", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}

	// A heartbeat records the observation.
	if err := s.Heartbeat(edge.ID, "agent", "1.14.3", "203.0.113.21", now); err != nil {
		t.Fatal(err)
	}
	if stored, err := s.GetNodeAt(edge.ID, now); err != nil || stored.ObservedIPv4 != "203.0.113.21" {
		t.Fatalf("observed IPv4 = %q err=%v", stored.ObservedIPv4, err)
	}

	// An empty client-facing address is filled from the report and marked.
	line := testSelectionLine(t, edge.ID)
	line.Server = ""
	line.ServerName = "line.example.invalid"
	saved, err := s.SetLine(line, now)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server != "203.0.113.21" || saved.ServerSource != store.AddressSourceReported {
		t.Fatalf("reported line = %+v", saved)
	}

	// A later report refreshes only the reported address.
	if err := s.Heartbeat(edge.ID, "agent", "1.14.3", "203.0.113.22", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines, err := s.ListLines()
	if err != nil || len(lines) != 1 {
		t.Fatalf("lines = %+v err=%v", lines, err)
	}
	if lines[0].Server != "203.0.113.22" || lines[0].ServerSource != store.AddressSourceReported {
		t.Fatalf("line did not follow the report: %+v", lines[0])
	}

	// A manual value wins and is never overwritten by a later report.
	manual := testSelectionLine(t, edge.ID)
	manual.Server = "line.example.invalid"
	manual.ServerName = "line.example.invalid"
	saved, err = s.SetLine(manual, now)
	if err != nil {
		t.Fatal(err)
	}
	if saved.Server != "line.example.invalid" || saved.ServerSource != store.AddressSourceManual {
		t.Fatalf("manual line = %+v", saved)
	}
	if err := s.Heartbeat(edge.ID, "agent", "1.14.3", "203.0.113.23", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	lines, err = s.ListLines()
	if err != nil || len(lines) != 1 || lines[0].Server != "line.example.invalid" {
		t.Fatalf("manual line was overwritten: %+v err=%v", lines, err)
	}
	if lines[0].ServerSource != store.AddressSourceManual {
		t.Fatalf("manual source = %q", lines[0].ServerSource)
	}

	// A blank field again returns to the reported source.
	backToReport := testSelectionLine(t, edge.ID)
	backToReport.Server = ""
	backToReport.ServerName = "line.example.invalid"
	if _, err := s.SetLine(backToReport, now); err != nil {
		t.Fatal(err)
	}
	lines, err = s.ListLines()
	if err != nil || len(lines) != 1 || lines[0].Server != "203.0.113.23" || lines[0].ServerSource != store.AddressSourceReported {
		t.Fatalf("blank line did not return to the report: %+v err=%v", lines, err)
	}

	// An older Agent omits the field; the last observation is kept.
	if err := s.Heartbeat(edge.ID, "agent", "1.14.3", "", now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if stored, err := s.GetNodeAt(edge.ID, now); err != nil || stored.ObservedIPv4 != "203.0.113.23" {
		t.Fatalf("empty report erased the observation: %+v err=%v", stored, err)
	}

	// The same rules apply to an Out dial address.
	if err := s.Heartbeat(out.ID, "agent", "1.14.3", "203.0.113.31", now); err != nil {
		t.Fatal(err)
	}
	transport, err := s.SetOutTransport(out.ID, "", out.VlessPort, now)
	if err != nil {
		t.Fatal(err)
	}
	if transport.Server != "203.0.113.31" || transport.ServerSource != store.AddressSourceReported {
		t.Fatalf("reported out transport = %+v", transport)
	}
	if err := s.Heartbeat(out.ID, "agent", "1.14.3", "203.0.113.32", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	pool, err := s.OutPool(now)
	if err != nil || len(pool) != 1 || pool[0].Server != "203.0.113.32" || pool[0].ServerSource != store.AddressSourceReported {
		t.Fatalf("out did not follow the report: %+v err=%v", pool, err)
	}
	transport, err = s.SetOutTransport(out.ID, "out.example.invalid", out.VlessPort, now)
	if err != nil || transport.ServerSource != store.AddressSourceManual {
		t.Fatalf("manual out transport = %+v err=%v", transport, err)
	}
	if err := s.Heartbeat(out.ID, "agent", "1.14.3", "203.0.113.33", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	pool, err = s.OutPool(now)
	if err != nil || len(pool) != 1 || pool[0].Server != "out.example.invalid" || pool[0].ServerSource != store.AddressSourceManual {
		t.Fatalf("manual out was overwritten: %+v err=%v", pool, err)
	}
}

func TestReportedIPv4SurvivesSchema16Replay(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	edge, _, err := s.CreateNode("edge", "line-replay", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Heartbeat(edge.ID, "agent", "1.14.3", "203.0.113.21", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DB.Exec(`PRAGMA user_version=15`); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(); err != nil {
		t.Fatalf("schema replay: %v", err)
	}
	if stored, err := s.GetNodeAt(edge.ID, now); err != nil || stored.ObservedIPv4 != "203.0.113.21" {
		t.Fatalf("replay lost the reported address: %+v err=%v", stored, err)
	}
}

func TestBlankAddressBeforeAReportIsRefused(t *testing.T) {
	s := selectionStore(t)
	now := time.Unix(1_700_000_000, 0)
	edge, _, err := s.CreateNode("edge", "line-no-report", 8443, 2222, now)
	if err != nil {
		t.Fatal(err)
	}
	out, _, err := s.CreateNode("out", "out-no-report", 8444, 2223, now)
	if err != nil {
		t.Fatal(err)
	}

	line := testSelectionLine(t, edge.ID)
	line.Server = ""
	if _, err := s.SetLine(line, now); err == nil || !strings.HasPrefix(err.Error(), "LINE_SERVER_REQUIRED") {
		t.Fatalf("blank line before a report = %v", err)
	}
	if _, err := s.SetOutTransport(out.ID, "", out.VlessPort, now); err == nil || !strings.HasPrefix(err.Error(), "OUT_TRANSPORT_REPORTED_IP_MISSING") {
		t.Fatalf("blank transport before a report = %v", err)
	}
}
