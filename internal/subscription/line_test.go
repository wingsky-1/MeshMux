package subscription

import (
	"strings"
	"testing"
)

func validLine(t *testing.T) Line {
	t.Helper()
	pair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	return Line{
		NodeID:          strings.Repeat("a", 32),
		DisplayName:     "line-hk-01",
		Server:          "line.example.invalid",
		Port:            8443,
		SortOrder:       1,
		ServerName:      "www.example.invalid",
		HandshakeServer: "handshake.example.invalid",
		HandshakePort:   443,
		PrivateKey:      pair.PrivateKey,
		PublicKey:       pair.PublicKey,
		ShortID:         shortID,
	}
}

func TestLineValidatesLocalAndRemoteTransports(t *testing.T) {
	for _, tc := range []struct {
		name   string
		server string
		local  bool
	}{
		{"hostname", "line.example.invalid", false},
		{"uppercase hostname", "LINE.example.invalid", false},
		{"ipv4", "192.0.2.10", false},
		{"ipv6", "2001:db8::10", false},
		{"loopback local", "127.0.0.1", true},
		{"localhost local", "localhost", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := validLine(t)
			line.Server = tc.server
			line.Local = tc.local
			if err := line.Validate(); err != nil {
				t.Fatalf("valid line rejected: %v", err)
			}
		})
	}
}

func TestLineRejectsURLsPathsCredentialsAndBadServerNames(t *testing.T) {
	for _, server := range []string{
		"",
		"http://line.example.invalid",
		"https://line.example.invalid",
		"line.example.invalid/path",
		"line.example.invalid/../etc/passwd",
		"user:pass@line.example.invalid",
		"line.example.invalid:8443",
		"line.example.invalid?token=secret",
		"line.example.invalid#fragment",
		"[2001:db8::1]",
		"2001:db8::1/64",
		"fe80::1%eth0",
		"999.1.1.1",
		"-line.example.invalid",
		"line-.example.invalid",
		"line..example.invalid",
		"line_example.invalid",
		"line example.invalid",
		"line.example.invalid.",
		"line.example.invalid;rm -rf /",
		"../etc/passwd",
		strings.Repeat("a", 64) + ".example.invalid",
	} {
		line := validLine(t)
		line.Server = server
		err := line.Validate()
		if err == nil {
			t.Fatalf("unsafe server accepted: %q", server)
		}
		if server != "" && strings.Contains(err.Error(), server) {
			t.Fatalf("validation error echoed input: %v", err)
		}
	}

	line := validLine(t)
	line.Local = true
	line.Server = "https://line.example.invalid/path"
	if err := line.Validate(); err == nil {
		t.Fatal("Local bypassed transport validation")
	}
}

func TestLineRejectsMalformedFields(t *testing.T) {
	otherPair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*Line)
	}{
		{"bad node id", func(l *Line) { l.NodeID = "short" }},
		{"uppercase node id", func(l *Line) { l.NodeID = strings.ToUpper(l.NodeID) }},
		{"empty display name", func(l *Line) { l.DisplayName = "" }},
		{"long display name", func(l *Line) { l.DisplayName = strings.Repeat("界", 81) }},
		{"control in display name", func(l *Line) { l.DisplayName = "line\nname" }},
		{"zero port", func(l *Line) { l.Port = 0 }},
		{"high port", func(l *Line) { l.Port = 65536 }},
		{"negative sort order", func(l *Line) { l.SortOrder = -1 }},
		{"empty server name", func(l *Line) { l.ServerName = "" }},
		{"url server name", func(l *Line) { l.ServerName = "https://www.example.invalid" }},
		{"empty handshake server", func(l *Line) { l.HandshakeServer = "" }},
		{"credential handshake server", func(l *Line) { l.HandshakeServer = "user:pass@handshake.example.invalid" }},
		{"zero handshake port", func(l *Line) { l.HandshakePort = 0 }},
		{"high handshake port", func(l *Line) { l.HandshakePort = 65536 }},
		{"missing private key", func(l *Line) { l.PrivateKey = "" }},
		{"missing public key", func(l *Line) { l.PublicKey = "" }},
		{"padded private key", func(l *Line) { l.PrivateKey += "=" }},
		{"mismatched key pair", func(l *Line) { l.PublicKey = otherPair.PublicKey }},
		{"missing short id", func(l *Line) { l.ShortID = "" }},
		{"uppercase short id", func(l *Line) { l.ShortID = strings.ToUpper(l.ShortID) }},
		{"short id non-hex", func(l *Line) { l.ShortID = strings.Repeat("g", 16) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := validLine(t)
			tc.mutate(&line)
			if err := line.Validate(); err == nil {
				t.Fatal("invalid line accepted")
			}
		})
	}
}

func TestLineRenamePreservesIdentityAndTransport(t *testing.T) {
	line := validLine(t)
	line.Local = true
	expected := line
	expected.DisplayName = "renamed line"

	renamed, err := line.Rename("  renamed line  ")
	if err != nil {
		t.Fatal(err)
	}
	if renamed != expected {
		t.Fatalf("rename changed identity or transport:\n got %+v\nwant %+v", renamed, expected)
	}
	unchanged, err := line.Rename("\n")
	if err == nil {
		t.Fatal("invalid rename accepted")
	}
	if unchanged != line {
		t.Fatal("failed rename mutated the line")
	}
}
