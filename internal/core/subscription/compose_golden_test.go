package subscription

import (
	"os"
	"path/filepath"
	"testing"
)

// The golden fixtures are fully literal: no random key, UUID, timestamp or
// ordering helper may enter them, otherwise the "same input, same bytes" gate
// would only compare two random runs. Regenerate with UPDATE_GOLDEN=1 after a
// deliberate byte change; the approval artifact depends on these bytes.
//
// goldenRealityPriv is a throwaway X25519 test key generated for this fixture.
// It authenticates nothing: it is never installed, never served, and the
// example.invalid endpoints do not resolve.
const (
	goldenLineOneNodeID = "11111111111111111111111111111111"
	goldenLineTwoNodeID = "44444444444444444444444444444444"
	goldenSubscriberID  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	goldenOutID         = "22222222222222222222222222222222"
	goldenDeviceID      = "33333333333333333333333333333333"
	goldenRealityPriv   = "_5PhaIMFD9Kcdl95wSVXkKdto_EhCeGcgPdImdYu2zE"
	goldenRealityPub    = "6lxPE-fyg1NgBSYXHy5NVJASmJ3E5OPwfEX2NNaUMXo"
	goldenShortID       = "0123456789abcdef"
	// goldenLinkKey is a throwaway 16-byte base64-std link key of the fixtures.
	// It authenticates nothing: it is never installed and never served.
	goldenLinkKey = "AQIDBAUGBwgJCgsMDQ4PEA=="
)

func goldenLine(nodeID, name string, sortOrder int) Line {
	return Line{
		NodeID:          nodeID,
		DisplayName:     name,
		Server:          "line.example.invalid",
		Port:            8443,
		SortOrder:       sortOrder,
		ServerName:      "www.example.invalid",
		HandshakeServer: "hs.example.invalid",
		HandshakePort:   443,
		PrivateKey:      goldenRealityPriv,
		PublicKey:       goldenRealityPub,
		ShortID:         goldenShortID,
	}
}

func goldenCredential(id, uuid, nodeID string) Credential {
	return Credential{ID: id, SubscriberID: goldenSubscriberID, NodeID: nodeID, UUID: uuid}
}

func goldenSelection() ([]ComposeLine, []ComposeOut, []ComposeRule, []ComposeNetwork) {
	lines := []ComposeLine{
		{
			Line:       goldenLine(goldenLineTwoNodeID, "东京 02", 2),
			Credential: goldenCredential("dddddddddddddddddddddddddddddddd", "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee", goldenLineTwoNodeID),
		},
		{
			Line:       goldenLine(goldenLineOneNodeID, "香港 01", 1),
			Credential: goldenCredential("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "cccccccc-cccc-4ccc-8ccc-cccccccccccc", goldenLineOneNodeID),
		},
	}
	outs := []ComposeOut{{
		OutID:       goldenOutID,
		DisplayName: "东京 Out",
		Server:      "out.example.invalid",
		Port:        443,
		LinkKey:     goldenLinkKey,
	}}
	rules := []ComposeRule{
		{StableKey: "preset-direct-cn", Version: 1, Action: ActionDirect, Kind: MatcherGeoSite,
			Values: []string{"cn"}, Pins: map[string]RuleSetPin{"cn": composePins()}},
		{StableKey: "preset-proxy-ai", Version: 1, Action: ActionProxy, Kind: MatcherRuleSet,
			Values: []string{"ai"}, Pins: map[string]RuleSetPin{"ai": composePins()}},
		{StableKey: "preset-reject-ads", Version: 1, Action: ActionReject, Kind: MatcherDomainSuffix,
			Values: []string{"ads.example.invalid", "tracker.example.invalid"}},
		{StableKey: "preset-direct-mirror", Version: 1, Action: ActionDirect, Kind: MatcherDomain,
			Values: []string{"dl.example.invalid"}},
		{StableKey: "preset-direct-jp-ip", Version: 1, Action: ActionDirect, Kind: MatcherGeoIP,
			Values: []string{"jp"}, Pins: map[string]RuleSetPin{"jp": composePins()}},
	}
	network := []ComposeNetwork{{DeviceID: goldenDeviceID, DisplayName: "iPad"}}
	return lines, outs, rules, network
}

func goldenMeshInput() MeshDeviceInput {
	lines, _, _, _ := goldenSelection()
	credentials := make([]Credential, 0, len(lines))
	baseLines := make([]Line, 0, len(lines))
	for _, entry := range lines {
		credentials = append(credentials, entry.Credential)
		baseLines = append(baseLines, entry.Line)
	}
	return MeshDeviceInput{
		DeviceID:    goldenDeviceID,
		DisplayName: "iPad",
		Hostname:    "ipad-mesh",
		Purpose:     MeshPurposeProxyMesh,
		ControlURL:  "https://headscale.example.invalid",
		AuthKey:     "tskey-auth-example",
		Lines:       baseLines,
		Credentials: credentials,
	}
}

func assertGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", "compose", name)
	if os.Getenv("UPDATE_GOLDEN") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v (run UPDATE_GOLDEN=1 go test ./internal/subscription -run TestComposeGoldenArtifacts)", name, err)
	}
	if string(got) != string(want) {
		t.Fatalf("%s drifted from the approved bytes:\n--- want ---\n%s\n--- got ---\n%s", name, want, got)
	}
}

// TestComposeGoldenArtifacts freezes the six artifact shapes and the content id.
// A byte change here invalidates every approved subscription artifact, so it
// must be a deliberate, reviewed edit with UPDATE_GOLDEN=1.
func TestComposeGoldenArtifacts(t *testing.T) {
	lines, outs, rules, network := goldenSelection()
	documents, diagnostics := ComposeSubscription(lines, outs, rules, network)
	if anyBlocking(diagnostics) {
		t.Fatalf("golden selection has blocking diagnostics: %+v", diagnostics)
	}
	assertGolden(t, "standard.singbox.json", documents.SingBox)
	assertGolden(t, "standard.mihomo.yaml", documents.Mihomo)
	assertGolden(t, "standard.content-id.txt", []byte(documents.ContentID))

	baseLines, credentials := composeBaseLines(lines)
	noRulesSingBox, err := ExportSingBox(baseLines, credentials)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "norules.singbox.json", noRulesSingBox)
	noRulesMihomo, err := ExportMihomo(baseLines, credentials)
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "norules.mihomo.yaml", noRulesMihomo)

	mesh, err := ExportMeshDevice(goldenMeshInput())
	if err != nil {
		t.Fatal(err)
	}
	assertGolden(t, "mesh.singbox.json", mesh)
}

// composeBaseLines splits a ComposeLine selection into the two public slices the
// export entry points take.
func composeBaseLines(selected []ComposeLine) ([]Line, []Credential) {
	lines := make([]Line, 0, len(selected))
	credentials := make([]Credential, 0, len(selected))
	for _, entry := range selected {
		lines = append(lines, entry.Line)
		credentials = append(credentials, entry.Credential)
	}
	return lines, credentials
}
