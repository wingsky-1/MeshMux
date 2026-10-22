package subscription

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func meshTestLine(t *testing.T, sortOrder int, server string) (Line, Credential) {
	t.Helper()
	pair, err := NewRealityKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	shortID, err := NewShortID()
	if err != nil {
		t.Fatal(err)
	}
	nodeID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	subscriberID, err := NewID()
	if err != nil {
		t.Fatal(err)
	}
	credential, err := NewCredential(subscriberID, nodeID)
	if err != nil {
		t.Fatal(err)
	}
	line := Line{
		NodeID:      nodeID,
		DisplayName: "line-" + nodeID[:6],
		Server:      server,
		Port:        8443,
		SortOrder:   sortOrder,
		ServerName:  "line.example.invalid",
		PublicKey:   pair.PublicKey,
		ShortID:     shortID,
	}
	return line, credential
}

func meshTestInput(t *testing.T) MeshDeviceInput {
	t.Helper()
	line, credential := meshTestLine(t, 1, "line.example.invalid")
	return MeshDeviceInput{
		DeviceID:    "0123456789abcdef0123456789abcdef",
		DisplayName: "alice-iphone",
		Hostname:    "mesh-alice-iphone",
		ControlURL:  "https://headscale.example.invalid",
		AuthKey:     "hskey-auth-example-once",
		Lines:       []Line{line},
		Credentials: []Credential{credential},
	}
}

func decodeMeshDocument(t *testing.T, body []byte) map[string]any {
	t.Helper()
	var document map[string]any
	if err := json.Unmarshal(body, &document); err != nil {
		t.Fatalf("mesh document is not JSON: %v\n%s", err, body)
	}
	return document
}

func TestExportMeshDeviceUsesOnly1413EndpointFields(t *testing.T) {
	input := meshTestInput(t)
	body, err := ExportMeshDevice(input)
	if err != nil {
		t.Fatal(err)
	}
	document := decodeMeshDocument(t, body)
	for _, key := range []string{"log", "dns", "inbounds", "endpoints", "outbounds", "route"} {
		if _, ok := document[key]; !ok {
			t.Fatalf("document misses %q: %s", key, body)
		}
	}
	endpoints, ok := document["endpoints"].([]any)
	if !ok || len(endpoints) != 1 {
		t.Fatalf("endpoints = %#v", document["endpoints"])
	}
	endpoint := endpoints[0].(map[string]any)
	want := map[string]any{
		"type":          "tailscale",
		"tag":           "meshmux-ts",
		"auth_key":      input.AuthKey,
		"control_url":   input.ControlURL,
		"hostname":      input.Hostname,
		"accept_routes": false,
		"ephemeral":     false,
	}
	if !reflect.DeepEqual(endpoint, want) {
		t.Fatalf("endpoint = %#v, want exactly %#v", endpoint, want)
	}
	if _, exists := endpoint["system_interface"]; exists {
		t.Fatal("endpoint carried system_interface, which is not part of the 1.14.3 contract")
	}
	for _, forbidden := range []string{"tun", "inet4_address", "inet6_address", "auto_route", "strict_route", "stack"} {
		if strings.Contains(string(body), `"`+forbidden+`"`) {
			t.Fatalf("mesh document contains TUN key %q", forbidden)
		}
	}
}

func TestExportMeshDeviceRoutesTailnetFirstAndProxiesTheRest(t *testing.T) {
	input := meshTestInput(t)
	body, err := ExportMeshDevice(input)
	if err != nil {
		t.Fatal(err)
	}
	document := decodeMeshDocument(t, body)
	route := document["route"].(map[string]any)
	if route["final"] != exportSingBoxSelectorTag {
		t.Fatalf("route.final = %#v", route["final"])
	}
	rules := route["rules"].([]any)
	if len(rules) != 1 {
		t.Fatalf("route.rules = %#v, want exactly the tailnet rule first", rules)
	}
	rule := rules[0].(map[string]any)
	wantCIDRs := []any{MeshTailnetIPv4Prefix, MeshTailnetIPv6Prefix}
	if !reflect.DeepEqual(rule["ip_cidr"], wantCIDRs) {
		t.Fatalf("first rule ip_cidr = %#v, want %#v", rule["ip_cidr"], wantCIDRs)
	}
	if rule["outbound"] != exportMeshEndpointTag {
		t.Fatalf("first rule outbound = %#v", rule["outbound"])
	}
	outbounds := document["outbounds"].([]any)
	var selector map[string]any
	for _, raw := range outbounds {
		entry := raw.(map[string]any)
		if entry["tag"] == exportSingBoxSelectorTag {
			selector = entry
		}
	}
	if selector == nil {
		t.Fatal("selector outbound is missing")
	}
	if selector["default"] != input.Lines[0].DisplayName+" ["+input.Lines[0].NodeID+"]" {
		t.Fatalf("selector default = %#v", selector["default"])
	}
}

func TestExportMeshDeviceRefusesMissingControlURLWithoutSaaSFallback(t *testing.T) {
	input := meshTestInput(t)
	input.ControlURL = ""
	if _, err := ExportMeshDevice(input); err == nil || !strings.Contains(err.Error(), CodeMeshControlURLUnavailable) {
		t.Fatalf("empty control URL accepted: %v", err)
	}
	input.ControlURL = "https://controlplane.tailscale.com"
	if _, err := ExportMeshDevice(input); err != nil {
		t.Fatalf("an explicit HTTPS control URL must be accepted: %v", err)
	}
	input.ControlURL = "http://headscale.example.invalid"
	if _, err := ExportMeshDevice(input); err == nil || !strings.Contains(err.Error(), CodeMeshControlURLInvalid) {
		t.Fatalf("non-HTTPS control URL accepted: %v", err)
	}
}

func TestExportMeshDeviceRefusesLiteralLineInsideTailnet(t *testing.T) {
	for _, server := range []string{"100.64.1.10", "fd7a:115c:a1e0::1"} {
		t.Run(server, func(t *testing.T) {
			input := meshTestInput(t)
			line, credential := meshTestLine(t, 1, server)
			input.Lines = []Line{line}
			input.Credentials = []Credential{credential}
			if _, err := ExportMeshDevice(input); err == nil || !strings.Contains(err.Error(), CodeMeshLineInTailnet) {
				t.Fatalf("literal Line address %q inside the tailnet was accepted: %v", server, err)
			}
		})
	}
}

func TestExportMeshDeviceIsDeterministicAndRequiresAuthKey(t *testing.T) {
	input := meshTestInput(t)
	first, err := ExportMeshDevice(input)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ExportMeshDevice(input)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Fatal("mesh export is not byte-deterministic")
	}
	input.AuthKey = ""
	if _, err := ExportMeshDevice(input); err == nil || !strings.Contains(err.Error(), CodeMeshAuthKeyInvalid) {
		t.Fatalf("missing auth key accepted: %v", err)
	}
}

// TestMeshConfigModelCarriesNoSecrets pins the view-first rule: the page model
// may describe what the document contains but can never carry the auth key, a
// credential UUID, a private key or a token.
func TestMeshConfigModelCarriesNoSecrets(t *testing.T) {
	model := MeshConfigModel{}
	typ := reflect.TypeOf(model)
	for i := 0; i < typ.NumField(); i++ {
		name := strings.ToLower(typ.Field(i).Name)
		for _, forbidden := range []string{"key", "secret", "token", "uuid", "private"} {
			if strings.Contains(name, forbidden) {
				t.Fatalf("MeshConfigModel field %q can carry secret-shaped data", typ.Field(i).Name)
			}
		}
	}
	input := meshTestInput(t)
	built, err := NewMeshConfigModel(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(built.TailnetPrefixes) != 2 || len(built.LineLabels) != 1 {
		t.Fatalf("model = %#v", built)
	}
	if strings.Contains(strings.Join(built.LineLabels, " "), input.AuthKey) {
		t.Fatal("model labels carry the auth key")
	}
}

func TestExportSingBoxStillOmitsMeshAndTUN(t *testing.T) {
	input := meshTestInput(t)
	body, err := ExportSingBox(input.Lines, input.Credentials)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"tailscale", "endpoints", "auth_key", `"tun"`} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("standard sing-box export changed and now contains %q:\n%s", forbidden, body)
		}
	}
}
