package subscription

import (
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// exportFixture builds one public-only Line. The private key is left empty on
// purpose: the exporter validates and emits public fields only, so a
// downloaded public fixture must be exportable without a server secret.
func exportFixture(t *testing.T, nodeID, displayName, server string, port, sortOrder int) Line {
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
		NodeID:      nodeID,
		DisplayName: displayName,
		Server:      server,
		Port:        port,
		SortOrder:   sortOrder,
		ServerName:  "www.example.invalid",
		PublicKey:   pair.PublicKey,
		ShortID:     shortID,
	}
}

// exportCredential builds one credential for a Line and a Subscriber.
func exportCredential(t *testing.T, subscriberID, nodeID, uuid string) Credential {
	t.Helper()

	credential, err := NewCredential(subscriberID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	if uuid != "" {
		credential.UUID = uuid
	}
	return credential
}

// exportClientLabel is the client-visible label of one Line: the mutable
// display name plus the full stable NodeID.
func exportClientLabel(line Line) string {
	return line.DisplayName + " [" + line.NodeID + "]"
}

// exportLabelNodeID extracts the stable Line identity from one client label.
// The label is the only place a client sees the identity, so the identity
// part must stay derivable.
func exportLabelNodeID(label string) string {
	start := strings.Index(label, "[")
	end := strings.Index(label, "]")
	if start < 0 || end <= start {
		return ""
	}
	return label[start+1 : end]
}

// exportClientIdentity is the identity material of one exported node: the
// credential UUID, the stable Line identity and the transport the client
// dials. The display label is deliberately not part of it, because a rename
// is allowed to change the label and nothing else.
type exportClientIdentity struct {
	Label      string
	NodeID     string
	UUID       string
	Server     string
	Port       int
	ServerName string
	PublicKey  string
	ShortID    string
}

// exportFixtures builds two Lines and their two credentials. Both credentials
// belong to one subscriber, because one subscription document never mixes
// subscriber identities.
func exportFixtures(t *testing.T) ([]Line, []Credential) {
	t.Helper()

	lines := []Line{
		exportFixture(t, strings.Repeat("a", 32), "line-example-01", "example.invalid", 8443, 1),
		exportFixture(t, strings.Repeat("b", 32), "line-example-02", "example.invalid", 9443, 2),
	}
	subscriberID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	credentials := make([]Credential, 0, len(lines))
	for _, line := range lines {
		credential, err := NewCredential(subscriberID, line.NodeID)
		if err != nil {
			t.Fatal(err)
		}
		credentials = append(credentials, credential)
	}
	credentials[0].UUID = "11111111-2222-4333-8444-555555555555"
	credentials[1].UUID = "66666666-7777-4888-8999-aaaaaaaaaaaa"
	return lines, credentials
}

// TestExportSingBoxIsDeterministicAndComplete checks the exported sing-box
// document: one VLESS outbound per Line, the client label as the outbound
// tag, the loopback mixed inbound and the selector default.
func TestExportSingBoxIsDeterministicAndComplete(t *testing.T) {
	lines, credentials := exportFixtures(t)

	first, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	second, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("ExportSingBox is not deterministic")
	}

	var document struct {
		Inbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Listen     string `json:"listen"`
			ListenPort int    `json:"listen_port"`
		} `json:"inbounds"`
		Outbounds []struct {
			Type       string   `json:"type"`
			Tag        string   `json:"tag"`
			Server     string   `json:"server"`
			ServerPort int      `json:"server_port"`
			UUID       string   `json:"uuid"`
			Flow       string   `json:"flow"`
			Network    string   `json:"network"`
			Outbounds  []string `json:"outbounds"`
			Default    string   `json:"default"`
			TLS        *struct {
				Enabled    bool   `json:"enabled"`
				ServerName string `json:"server_name"`
				UTLS       *struct {
					Enabled     bool   `json:"enabled"`
					Fingerprint string `json:"fingerprint"`
				} `json:"utls"`
				Reality *struct {
					Enabled   bool   `json:"enabled"`
					PublicKey string `json:"public_key"`
					ShortID   string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
		Route struct {
			Final                 string `json:"final"`
			DefaultDomainResolver string `json:"default_domain_resolver"`
		} `json:"route"`
	}
	if err := json.Unmarshal(first, &document); err != nil {
		t.Fatalf("the exported configuration is not valid JSON: %v", err)
	}

	if len(document.Inbounds) != 1 {
		t.Fatalf("got %d inbounds, want 1", len(document.Inbounds))
	}
	inbound := document.Inbounds[0]
	if inbound.Type != "mixed" || inbound.Listen != "127.0.0.1" || inbound.ListenPort != 1080 {
		t.Fatalf("the mixed inbound is not the loopback 1080 inbound: %+v", inbound)
	}

	byTag := make(map[string]int)
	for _, outbound := range document.Outbounds {
		byTag[outbound.Tag]++
	}
	for _, line := range lines {
		label := exportClientLabel(line)
		if byTag[label] != 1 {
			t.Fatalf("the outbound tag is not the client label %q", label)
		}
	}

	vless := make(map[string]bool)
	for _, outbound := range document.Outbounds {
		if outbound.Type != "vless" {
			continue
		}
		vless[outbound.UUID] = true
		if outbound.Flow != "xtls-rprx-vision" {
			t.Fatalf("a VLESS outbound carries the wrong flow: %q", outbound.Flow)
		}
		if outbound.Network != "tcp" {
			t.Fatalf("a VLESS outbound carries the wrong network: %q", outbound.Network)
		}
		if outbound.TLS == nil || !outbound.TLS.Enabled {
			t.Fatal("a VLESS outbound does not enable TLS")
		}
		if outbound.TLS.UTLS == nil || !outbound.TLS.UTLS.Enabled || outbound.TLS.UTLS.Fingerprint != "chrome" {
			t.Fatal("a VLESS outbound does not pin the chrome uTLS fingerprint")
		}
		if outbound.TLS.Reality == nil || !outbound.TLS.Reality.Enabled {
			t.Fatal("a VLESS outbound does not enable REALITY")
		}
		if outbound.TLS.Reality.PublicKey == "" || outbound.TLS.Reality.ShortID == "" {
			t.Fatal("a VLESS outbound is missing the REALITY public material")
		}
	}
	for _, credential := range credentials {
		if !vless[credential.UUID] {
			t.Fatal("the exported configuration misses a credential UUID")
		}
	}

	selector, direct := 0, 0
	for _, outbound := range document.Outbounds {
		switch outbound.Type {
		case "selector":
			selector++
			if outbound.Default != exportClientLabel(lines[0]) {
				t.Fatalf("the selector default is not the label of the first selected Line: %q", outbound.Default)
			}
			if len(outbound.Outbounds) != len(lines) {
				t.Fatalf("the selector lists %d outbounds, want %d", len(outbound.Outbounds), len(lines))
			}
		case "direct":
			direct++
		}
	}
	if selector != 1 || direct != 1 {
		t.Fatalf("got %d selector and %d direct outbounds, want 1 and 1", selector, direct)
	}
	if document.Route.Final == "" {
		t.Fatal("the route has no final outbound")
	}
}

// TestExportMihomoIsDeterministicAndComplete checks the exported Mihomo
// document structure and that the YAML list items are well formed.
func TestExportMihomoIsDeterministicAndComplete(t *testing.T) {
	lines, credentials := exportFixtures(t)

	first, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}
	second, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}
	if string(first) != string(second) {
		t.Fatal("ExportMihomo is not deterministic")
	}

	text := string(first)
	for _, required := range []string{
		"proxies:\n",
		"proxy-groups:\n",
		"rules:\n",
		"  - name: ",
		"    type: \"vless\"",
		"    flow: \"xtls-rprx-vision\"",
		"    tls: true",
		"    servername: \"www.example.invalid\"",
		"    client-fingerprint: \"chrome\"",
		"    reality-opts:\n",
		"      public-key: ",
		"      short-id: ",
		"    network: \"tcp\"",
		"    udp: false",
		"  - name: \"PROXY\"",
		"    type: \"select\"",
		"  - \"MATCH,PROXY\"",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("the exported Mihomo configuration misses %q", required)
		}
	}
	for _, credential := range credentials {
		if !strings.Contains(text, credential.UUID) {
			t.Fatal("the exported Mihomo configuration misses a credential UUID")
		}
	}
	// Every sequence in the document must open with a list marker. A mapping
	// key directly under a sequence key is not valid YAML and the client
	// refuses to import the document.
	for _, key := range []string{"proxies:", "proxy-groups:", "rules:"} {
		if !sequenceOpensWithMarker(text, key) {
			t.Fatalf("the %q sequence does not open with a list marker", key)
		}
	}
}

// sequenceOpensWithMarker reports whether the first entry of the named
// top-level sequence carries a list marker.
func sequenceOpensWithMarker(text, key string) bool {
	lines := strings.Split(text, "\n")
	for index, line := range lines {
		if line != key {
			continue
		}
		if index+1 >= len(lines) {
			return false
		}
		return strings.HasPrefix(lines[index+1], "  - ")
	}
	return false
}

// TestExportRenameChangesLabelAndKeepsIdentity checks that a display name
// rename changes the client label and nothing else. The credential UUID, the
// stable Line identity, the REALITY public key, the server and the port stay
// exactly the same, in both client formats.
func TestExportRenameChangesLabelAndKeepsIdentity(t *testing.T) {
	lines, credentials := exportFixtures(t)

	renamed := make([]Line, len(lines))
	copy(renamed, lines)
	renamedByNodeID := map[string]Line{}
	for index := range renamed {
		var err error
		renamed[index], err = renamed[index].Rename("renamed-line")
		if err != nil {
			t.Fatal(err)
		}
		renamedByNodeID[renamed[index].NodeID] = renamed[index]
	}

	for _, format := range []struct {
		name   string
		export func([]Line, []Credential) ([]byte, error)
	}{
		{name: "sing-box", export: ExportSingBox},
		{name: "mihomo", export: ExportMihomo},
	} {
		t.Run(format.name, func(t *testing.T) {
			before, err := format.export(lines, credentials)
			if err != nil {
				t.Fatalf("the export returned an error: %v", err)
			}
			after, err := format.export(renamed, credentials)
			if err != nil {
				t.Fatalf("the export returned an error: %v", err)
			}
			if string(before) == string(after) {
				t.Fatal("a display name rename did not change the exported document")
			}

			beforeIdentities := exportIdentities(t, format.name, before)
			afterIdentities := exportIdentities(t, format.name, after)
			if len(beforeIdentities) != len(lines) || len(afterIdentities) != len(lines) {
				t.Fatalf("got %d and %d exported nodes, want %d", len(beforeIdentities), len(afterIdentities), len(lines))
			}
			for _, line := range lines {
				nodeID := line.NodeID
				beforeIdentity, exists := beforeIdentities[nodeID]
				if !exists {
					t.Fatalf("the exported document misses the node %q", nodeID)
				}
				afterIdentity, exists := afterIdentities[nodeID]
				if !exists {
					t.Fatalf("the renamed document misses the node %q", nodeID)
				}
				if beforeIdentity.Label == afterIdentity.Label {
					t.Fatalf("the rename did not change the client label of %q", nodeID)
				}
				if beforeIdentity.Label != exportClientLabel(line) {
					t.Fatalf("the client label of %q is not the display name plus the stable identity", nodeID)
				}
				// The extracted identity material must be complete, so the
				// comparison below cannot pass vacuously.
				if beforeIdentity.UUID == "" || beforeIdentity.PublicKey == "" ||
					beforeIdentity.ShortID == "" || beforeIdentity.Server == "" ||
					beforeIdentity.Port == 0 || beforeIdentity.ServerName == "" {
					t.Fatalf("the exported identity of %q is incomplete: %+v", nodeID, beforeIdentity)
				}
				if afterIdentity.Label != exportClientLabel(renamedByNodeID[nodeID]) {
					t.Fatalf("the renamed client label of %q is not the display name plus the stable identity", nodeID)
				}
				// The identity material must survive the rename unchanged.
				if beforeIdentity.UUID != afterIdentity.UUID {
					t.Fatalf("the rename changed the credential UUID of %q", nodeID)
				}
				if beforeIdentity.NodeID != afterIdentity.NodeID {
					t.Fatalf("the rename changed the stable Line identity of %q", nodeID)
				}
				if beforeIdentity.PublicKey != afterIdentity.PublicKey {
					t.Fatalf("the rename changed the REALITY public key of %q", nodeID)
				}
				if beforeIdentity.Server != afterIdentity.Server {
					t.Fatalf("the rename changed the server of %q", nodeID)
				}
				if beforeIdentity.Port != afterIdentity.Port {
					t.Fatalf("the rename changed the port of %q", nodeID)
				}
				if beforeIdentity.ServerName != afterIdentity.ServerName {
					t.Fatalf("the rename changed the server name of %q", nodeID)
				}
				if beforeIdentity.ShortID != afterIdentity.ShortID {
					t.Fatalf("the rename changed the REALITY short ID of %q", nodeID)
				}
			}
		})
	}
}

// TestExportReorderKeepsBytesEqual checks that the order in which the Lines
// are handed to the exporter does not change the exported documents.
func TestExportReorderKeepsBytesEqual(t *testing.T) {
	lines, credentials := exportFixtures(t)

	reordered := []Line{lines[1], lines[0]}

	singBoxBefore, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	singBoxAfter, err := ExportSingBox(reordered, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	if string(singBoxBefore) != string(singBoxAfter) {
		t.Fatal("reordering the selected Lines changed the exported sing-box configuration")
	}

	mihomoBefore, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}
	mihomoAfter, err := ExportMihomo(reordered, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}
	if string(mihomoBefore) != string(mihomoAfter) {
		t.Fatal("reordering the selected Lines changed the exported Mihomo configuration")
	}
}

// TestExportDisambiguatesDuplicateDisplayNames checks that two Lines with the
// same display name stay distinguishable in the client list.
func TestExportDisambiguatesDuplicateDisplayNames(t *testing.T) {
	lines, credentials := exportFixtures(t)
	lines[1].DisplayName = lines[0].DisplayName

	document, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}
	text := string(document)
	// Both Lines share one display name, so only the stable identity part can
	// tell them apart.
	labelZero := exportClientLabel(lines[0])
	labelOne := exportClientLabel(lines[1])
	if labelZero == labelOne {
		t.Fatal("two Lines with the same display name share one label")
	}
	if !strings.Contains(text, labelZero) {
		t.Fatal("the first Line label does not carry its stable identity")
	}
	if !strings.Contains(text, labelOne) {
		t.Fatal("the second Line label does not carry its stable identity")
	}
	// A label without the identity suffix would be ambiguous.
	if strings.Contains(text, "\""+lines[0].DisplayName+"\"") {
		t.Fatal("a Line is published without its stable identity suffix")
	}
}

// TestExportNeverEmitsServerSecrets checks that no server-side secret or
// server-side configuration field reaches a client document.
func TestExportNeverEmitsServerSecrets(t *testing.T) {
	lines, credentials := exportFixtures(t)
	pair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	// A real key pair is used so the Line stays valid; only the exported
	// material matters here.
	lines[0].PrivateKey = pair.PrivateKey
	lines[0].PublicKey = pair.PublicKey
	lines[0].HandshakeServer = "handshake.example.invalid"

	singBoxConfig, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	mihomoConfig, err := ExportMihomo(lines, credentials)
	if err != nil {
		t.Fatalf("ExportMihomo returned an error: %v", err)
	}

	for _, document := range [][]byte{singBoxConfig, mihomoConfig} {
		text := string(document)
		for _, forbidden := range []string{
			"private_key",
			"private-key",
			lines[0].PrivateKey,
			"handshake",
			"HandshakeServer",
		} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("the exported configuration contains the server-side value %q", forbidden)
			}
		}
	}
}

// TestExportRejectsMissingAndExtraCredentials checks that a Line without a
// credential and a credential for an unselected Line are both rejected, so a
// published subscription can never carry another identity.
func TestExportRejectsMissingAndExtraCredentials(t *testing.T) {
	lines, credentials := exportFixtures(t)

	if _, err := ExportSingBox(lines, credentials[:1]); err == nil {
		t.Fatal("a selected Line without a credential was accepted")
	}
	if _, err := ExportMihomo(lines, credentials[:1]); err == nil {
		t.Fatal("a selected Line without a credential was accepted")
	}

	extra := exportCredential(t, credentials[0].SubscriberID, strings.Repeat("c", 32), "")
	extraLines := append(append([]Line{}, lines...), exportFixture(t, strings.Repeat("c", 32), "line-example-03", "example.invalid", 10443, 3))
	if _, err := ExportSingBox(extraLines, append(append([]Credential{}, credentials...), extra)); err != nil {
		t.Fatalf("a complete credential set was rejected: %v", err)
	}

	orphan := exportCredential(t, credentials[0].SubscriberID, strings.Repeat("d", 32), "")
	if _, err := ExportSingBox(lines, append(append([]Credential{}, credentials...), orphan)); err == nil {
		t.Fatal("a credential for an unselected Line was accepted")
	}
	if _, err := ExportMihomo(lines, append(append([]Credential{}, credentials...), orphan)); err == nil {
		t.Fatal("a credential for an unselected Line was accepted")
	}
}

// TestExportRejectsEmptySubscriberID checks that a credential without a
// subscriber identity is rejected. Such a credential belongs to nobody, so
// publishing it would hand an identity to a client that no subscriber owns.
func TestExportRejectsEmptySubscriberID(t *testing.T) {
	lines, credentials := exportFixtures(t)

	mutated := append([]Credential{}, credentials...)
	mutated[0].SubscriberID = ""

	if _, err := ExportSingBox(lines, mutated); err == nil {
		t.Fatal("a credential without a subscriber identity was accepted")
	}
	if _, err := ExportMihomo(lines, mutated); err == nil {
		t.Fatal("a credential without a subscriber identity was accepted")
	}
}

// TestExportRejectsMixedSubscriberIDs checks that one document never carries
// the credentials of two subscribers, in both client formats.
func TestExportRejectsMixedSubscriberIDs(t *testing.T) {
	lines, credentials := exportFixtures(t)

	mutated := append([]Credential{}, credentials...)
	mutated[1].SubscriberID = strings.Repeat("e", 32)

	if _, err := ExportSingBox(lines, mutated); err == nil {
		t.Fatal("credentials of two subscribers were accepted in one document")
	}
	if _, err := ExportMihomo(lines, mutated); err == nil {
		t.Fatal("credentials of two subscribers were accepted in one document")
	}
}

// TestExportRejectsInvalidPublicFields checks that an unsafe public Line
// field is rejected before anything is rendered.
func TestExportRejectsInvalidPublicFields(t *testing.T) {
	lines, credentials := exportFixtures(t)

	for _, tc := range []struct {
		name   string
		mutate func(*Line)
	}{
		{"empty display name", func(l *Line) { l.DisplayName = "" }},
		{"control character in display name", func(l *Line) { l.DisplayName = "line\nname" }},
		{"url server", func(l *Line) { l.Server = "https://example.invalid" }},
		{"server with credentials", func(l *Line) { l.Server = "user:pass@example.invalid" }},
		{"port out of range", func(l *Line) { l.Port = 70000 }},
		{"negative sort order", func(l *Line) { l.SortOrder = -1 }},
		{"invalid public key", func(l *Line) { l.PublicKey = "not-a-key" }},
		{"invalid short id", func(l *Line) { l.ShortID = "short" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mutated := append([]Line{}, lines...)
			tc.mutate(&mutated[0])
			if _, err := ExportSingBox(mutated, credentials); err == nil {
				t.Fatal("an invalid public Line field was accepted")
			}
			if _, err := ExportMihomo(mutated, credentials); err == nil {
				t.Fatal("an invalid public Line field was accepted")
			}
		})
	}
}

// TestExportRejectsEmptySelection checks that an empty selection is rejected
// instead of publishing an empty subscription.
func TestExportRejectsEmptySelection(t *testing.T) {
	if _, err := ExportSingBox(nil, nil); err == nil {
		t.Fatal("an empty Line selection was accepted")
	}
	if _, err := ExportMihomo(nil, nil); err == nil {
		t.Fatal("an empty Line selection was accepted")
	}
}

// TestExportOrdersBySortOrderThenNodeID checks the deterministic Line order.
func TestExportOrdersBySortOrderThenNodeID(t *testing.T) {
	lines, credentials := exportFixtures(t)
	lines[0].SortOrder = 5
	lines[1].SortOrder = 1

	document, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}
	text := string(document)
	first := strings.Index(text, lines[1].NodeID)
	second := strings.Index(text, lines[0].NodeID)
	if first < 0 || second < 0 || first > second {
		t.Fatal("the exported Lines are not ordered by SortOrder")
	}
}

// TestExportOrdersEqualSortOrderByNodeID checks that two Lines with the same
// sort order keep a stable order, decided by the stable Line identity.
func TestExportOrdersEqualSortOrderByNodeID(t *testing.T) {
	lines, credentials := exportFixtures(t)
	lines[0].SortOrder = 3
	lines[1].SortOrder = 3

	document, err := ExportSingBox(lines, credentials)
	if err != nil {
		t.Fatalf("ExportSingBox returned an error: %v", err)
	}

	// The selector lists the chosen Lines in the exported order.
	var selector []string
	for _, outbound := range exportSingBoxOutbounds(t, document) {
		if outbound.Type != "selector" {
			continue
		}
		selector = outbound.Outbounds
	}
	if len(selector) != 2 {
		t.Fatalf("the selector lists %d outbounds, want 2", len(selector))
	}
	want := []string{exportClientLabel(lines[0]), exportClientLabel(lines[1])}
	if !slices.Equal(selector, want) {
		t.Fatalf("the exported order is %v, want %v", selector, want)
	}
	if lines[0].NodeID >= lines[1].NodeID {
		t.Fatal("the fixture does not exercise the NodeID tie breaker")
	}
}

// exportSingBoxOutbounds decodes the outbound list of an exported sing-box
// document.
func exportSingBoxOutbounds(t *testing.T, document []byte) []struct {
	Type      string   `json:"type"`
	Outbounds []string `json:"outbounds"`
} {
	t.Helper()

	var decoded struct {
		Outbounds []struct {
			Type      string   `json:"type"`
			Outbounds []string `json:"outbounds"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the exported configuration is not valid JSON: %v", err)
	}
	return decoded.Outbounds
}

// exportIdentities extracts the client identity material of one exported
// document, keyed by the stable Line identity.
func exportIdentities(t *testing.T, format string, document []byte) map[string]exportClientIdentity {
	t.Helper()

	switch format {
	case "sing-box":
		return exportSingBoxIdentities(t, document)
	case "mihomo":
		return exportMihomoIdentities(t, document)
	default:
		t.Fatalf("unknown export format %q", format)
		return nil
	}
}

// exportSingBoxIdentities extracts the identity material of an exported
// sing-box document.
func exportSingBoxIdentities(t *testing.T, document []byte) map[string]exportClientIdentity {
	t.Helper()

	var decoded struct {
		Outbounds []struct {
			Type       string `json:"type"`
			Tag        string `json:"tag"`
			Server     string `json:"server"`
			ServerPort int    `json:"server_port"`
			UUID       string `json:"uuid"`
			TLS        *struct {
				ServerName string `json:"server_name"`
				Reality    *struct {
					PublicKey string `json:"public_key"`
					ShortID   string `json:"short_id"`
				} `json:"reality"`
			} `json:"tls"`
		} `json:"outbounds"`
	}
	if err := json.Unmarshal(document, &decoded); err != nil {
		t.Fatalf("the exported configuration is not valid JSON: %v", err)
	}

	identities := map[string]exportClientIdentity{}
	for _, outbound := range decoded.Outbounds {
		if outbound.Type != "vless" {
			continue
		}
		identity := exportClientIdentity{
			Label:  outbound.Tag,
			NodeID: exportLabelNodeID(outbound.Tag),
			UUID:   outbound.UUID,
			Server: outbound.Server,
			Port:   outbound.ServerPort,
		}
		if outbound.TLS != nil {
			identity.ServerName = outbound.TLS.ServerName
			if outbound.TLS.Reality != nil {
				identity.PublicKey = outbound.TLS.Reality.PublicKey
				identity.ShortID = outbound.TLS.Reality.ShortID
			}
		}
		identities[identity.NodeID] = identity
	}
	return identities
}

// exportMihomoIdentities extracts the identity material of an exported Mihomo
// document.
func exportMihomoIdentities(t *testing.T, document []byte) map[string]exportClientIdentity {
	t.Helper()

	identities := map[string]exportClientIdentity{}
	var current *exportClientIdentity

	for _, line := range strings.Split(string(document), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "proxy-groups:" {
			break
		}
		if strings.HasPrefix(trimmed, "- name: ") {
			label := strings.Trim(strings.TrimPrefix(trimmed, "- name: "), "\"")
			current = &exportClientIdentity{Label: label, NodeID: exportLabelNodeID(label)}
			identities[current.NodeID] = *current
			continue
		}
		if current == nil {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		key, value, found := strings.Cut(trimmed, ": ")
		if !found {
			continue
		}
		value = strings.Trim(value, "\"")
		switch {
		case indent == 4 && key == "server":
			current.Server = value
		case indent == 4 && key == "port":
			if port, err := strconv.Atoi(value); err == nil {
				current.Port = port
			}
		case indent == 4 && key == "uuid":
			current.UUID = value
		case indent == 4 && key == "servername":
			current.ServerName = value
		case indent == 6 && key == "public-key":
			current.PublicKey = value
		case indent == 6 && key == "short-id":
			current.ShortID = value
		}
		identities[current.NodeID] = *current
	}
	return identities
}
