package meshnet

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/versions"
)

// recordedCall is one argv the fake executor observed.
type recordedCall struct {
	name string
	args []string
}

// fakeExec replaces the process boundary. It answers in order and records every
// argv, so a test asserts the exact command line without spawning a process.
type fakeExec struct {
	calls    []recordedCall
	replies  []fakeReply
	failWith error
}

type fakeReply struct {
	stdout string
	stderr string
	err    error
}

func (f *fakeExec) exec(_ context.Context, name string, args []string) ([]byte, []byte, error) {
	f.calls = append(f.calls, recordedCall{name: name, args: append([]string(nil), args...)})
	if f.failWith != nil {
		return nil, nil, f.failWith
	}
	if len(f.replies) == 0 {
		return nil, nil, errors.New("unexpected call")
	}
	reply := f.replies[0]
	f.replies = f.replies[1:]
	return []byte(reply.stdout), []byte(reply.stderr), reply.err
}

// newTestRunner builds a runner over a fake process boundary. It is the same
// type the production constructor returns, only with the executor replaced, so
// argv construction and handshake caching are the production code paths.
func newTestRunner(t *testing.T, replies ...fakeReply) (*CLIRunner, *fakeExec) {
	t.Helper()
	fake := &fakeExec{replies: append([]fakeReply{{stdout: versionJSON(HeadscaleVersion)}}, replies...)}
	return &CLIRunner{
		binary:  BinaryPath,
		config:  ConfigPath,
		timeout: commandTimeout,
		execute: fake.exec,
	}, fake
}

func versionJSON(version string) string {
	return `{"version":"` + version + `","commit":"0000000","buildTime":"2026-10-01T00:00:00Z","go":{"version":"go1.27.2","os":"linux","arch":"amd64"},"dirty":false}`
}

// TestCommandTableMatchesPinnedRelease locks the exact argv of every operation.
// These lines are the contract with Headscale 0.29.5: a flag rename, a swapped
// flag order or a dropped --config would silently change what the Hub asks the
// local control plane to do.
func TestCommandTableMatchesPinnedRelease(t *testing.T) {
	if HeadscaleVersion != "0.29.5" {
		t.Fatalf("argv table was written for 0.29.5, adapter pins %q", HeadscaleVersion)
	}
	cases := []struct {
		name   string
		op     operation
		values []string
		want   []string
	}{
		{
			name: "version omits config and is the first argument",
			op:   opVersion,
			want: []string{"version", "-o", "json"},
		},
		{
			name: "users list",
			op:   opUsersList,
			want: []string{"--config", ConfigPath, "users", "list", "-o", "json"},
		},
		{
			name:   "users create takes a positional name",
			op:     opUsersCreate,
			values: []string{"meshmux"},
			want:   []string{"--config", ConfigPath, "users", "create", "meshmux", "-o", "json"},
		},
		{
			name: "nodes list without a user filter",
			op:   opNodesList,
			want: []string{"--config", ConfigPath, "nodes", "list", "-o", "json"},
		},
		{
			name:   "nodes list filtered by user",
			op:     opNodesListByUser,
			values: []string{"meshmux"},
			want:   []string{"--config", ConfigPath, "nodes", "list", "--user", "meshmux", "-o", "json"},
		},
		{
			name:   "nodes expire by identifier",
			op:     opNodesExpire,
			values: []string{"7"},
			want:   []string{"--config", ConfigPath, "nodes", "expire", "--identifier", "7", "-o", "json"},
		},
		{
			name:   "nodes delete is forced so no prompt blocks the service",
			op:     opNodesDelete,
			values: []string{"7"},
			want:   []string{"--config", ConfigPath, "nodes", "delete", "--identifier", "7", "--force", "-o", "json"},
		},
		{
			name:   "nodes approve-routes takes the identifier and one csv list",
			op:     opNodesApproveRoutes,
			values: []string{"7", "10.0.0.0/8,192.168.0.0/24"},
			want:   []string{"--config", ConfigPath, "nodes", "approve-routes", "--identifier", "7", "--routes", "10.0.0.0/8,192.168.0.0/24", "-o", "json"},
		},
		{
			name:   "nodes clear routes is the literal empty --routes suffix",
			op:     opNodesClearRoutes,
			values: []string{"7"},
			want:   []string{"--config", ConfigPath, "nodes", "approve-routes", "--identifier", "7", "--routes=", "-o", "json"},
		},
		{
			name:   "preauthkeys create pins user and a whole-minute expiration",
			op:     opPreAuthKeysCreate,
			values: []string{"3", "15m"},
			want:   []string{"--config", ConfigPath, "preauthkeys", "create", "--user", "3", "--expiration", "15m", "-o", "json"},
		},
		{
			name:   "preauthkeys expire by id",
			op:     opPreAuthKeysExpire,
			values: []string{"11"},
			want:   []string{"--config", ConfigPath, "preauthkeys", "expire", "--id", "11", "-o", "json"},
		},
	}
	runner := NewCLIRunner()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := runner.buildArgs(tc.op, tc.values...)
			if err != nil {
				t.Fatalf("buildArgs(%s): %v", tc.op, err)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("argv mismatch\n got: %q\nwant: %q", got, tc.want)
			}
		})
	}
}

// TestNoPreAuthKeyListingOperation asserts the deliberately absent capability.
// Headscale's preauthkeys listing prints stored key material; the Hub mints one
// key for one device and never enumerates keys.
func TestNoPreAuthKeyListingOperation(t *testing.T) {
	for op := range commandTable {
		joined := strings.Join(append(commandTable[op].prefix, commandTable[op].suffix...), " ")
		if strings.Contains(joined, "preauthkeys") && strings.Contains(joined, "list") {
			t.Fatalf("operation %q exposes a preauthkeys listing", op)
		}
	}
	for _, op := range []operation{"preauthkeys list", "authkeys list"} {
		if _, ok := commandTable[op]; ok {
			t.Fatalf("operation %q must not exist", op)
		}
	}
	// There is deliberately no "nodes list-routes" operation. It would duplicate
	// `nodes list`, which already returns approved_routes, available_routes and
	// subnet_routes, and a per-node route listing would drop the node context the
	// caller needs to interpret the routes it just read.
}

// TestListNodesDropsPreAuthKeyMaterial feeds a node document that carries the
// nested pre-auth key block Headscale prints and asserts the decoded record has
// no way to retain it. The DTO has no such field, so the check is on the type
// and on the observable value.
func TestListNodesDropsPreAuthKeyMaterial(t *testing.T) {
	const secret = "hskey-auth-SECRETSECRETSECRETSECRET"
	// Shape of `headscale nodes list -o json` on 0.29.5, including the nested
	// pre_auth_key block and the key fields this adapter must not retain.
	node := `[{
		"id": 42,
		"name": "laptop-1.tail.example.invalid",
		"given_name": "laptop-1",
		"user": {"id": 3, "name": "meshmux", "created_at": {"seconds": 1759276800, "nanos": 641740434}},
		"ip_addresses": ["100.64.0.5", "fd7a:115c:a1e0::5"],
		"approved_routes": ["10.0.0.0/8"],
		"available_routes": ["10.0.0.0/8", "192.168.0.0/24"],
		"subnet_routes": ["192.168.0.0/24"],
		"online": true,
		"expiry": {"seconds": 1793491200, "nanos": 797022733},
		"pre_auth_key": {
			"user": {"id": 3, "name": "meshmux"},
			"id": 9,
			"key": "` + secret + `",
			"reusable": false,
			"ephemeral": false,
			"used": true,
			"expiration": {"seconds": 1759277700},
			"created_at": {"seconds": 1759276800}
		},
		"machine_key": "mkey:aaaa",
		"node_key": "nodekey:bbbb",
		"disco_key": "discokey:cccc"
	}]`
	runner, fake := newTestRunner(t, fakeReply{stdout: node})
	nodes, err := runner.ListNodes(context.Background(), "meshmux")
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 1 {
		t.Fatalf("nodes = %d", len(nodes))
	}
	got := nodes[0]
	if got.ID != 42 || got.GivenName != "laptop-1" || got.UserID != 3 || got.UserName != "meshmux" || !got.Online {
		t.Fatalf("decoded node = %+v", got)
	}
	if !reflect.DeepEqual(got.ApprovedRoutes, []string{"10.0.0.0/8"}) || len(got.AvailableRoutes) != 2 {
		t.Fatalf("routes = %+v", got)
	}
	if want := time.Date(2026, 11, 1, 0, 0, 0, 797022733, time.UTC); !got.Expiry.Equal(want) {
		t.Fatalf("expiry = %s, want %s", got.Expiry, want)
	}
	// The record must not carry the secret in any exported field, whether as a
	// string or as part of a rendered value.
	rendered := strings.Join([]string{
		got.Name, got.GivenName, got.UserName,
		strings.Join(got.IPAddresses, ","),
		strings.Join(got.ApprovedRoutes, ","),
		strings.Join(got.AvailableRoutes, ","),
		strings.Join(got.SubnetRoutes, ","),
	}, " ")
	if strings.Contains(rendered, "hskey") || strings.Contains(rendered, "SECRET") {
		t.Fatalf("node output retained key material: %q", rendered)
	}
	if field, ok := reflect.TypeOf(got).FieldByName("PreAuthKey"); ok {
		t.Fatalf("Node must not expose a pre-auth key field, found %q", field.Name)
	}
	// Two calls: the handshake, then the listing. Nothing else was executed.
	if len(fake.calls) != 2 {
		t.Fatalf("executed %d commands, want 2", len(fake.calls))
	}
}

// TestListUsersIsNarrow checks user decoding and that unknown provider metadata
// is dropped rather than forwarded.
func TestListUsersIsNarrow(t *testing.T) {
	doc := `[{"id":3,"name":"meshmux","display_name":"MeshMux","email":"","provider":"oidc","provider_id":"abc","profile_pic_url":"https://example.invalid/p.png"}]`
	runner, _ := newTestRunner(t, fakeReply{stdout: doc})
	users, err := runner.ListUsers(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0].ID != 3 || users[0].Name != "meshmux" || users[0].DisplayName != "MeshMux" {
		t.Fatalf("users = %+v", users)
	}
}

// TestCreatePreAuthKeyReturnsSecretOnce asserts the one-shot contract: the
// plaintext comes back as a separate return value, the PreAuthKey record has no
// field for it, and a non-reusable non-ephemeral key is what the fixed argv and
// the DTO describe.
func TestCreatePreAuthKeyReturnsSecretOnce(t *testing.T) {
	const secret = "hskey-auth-ONESHOTONESHOTONESHOT"
	doc := `{"id":11,"key":"` + secret + `","user":{"id":3,"name":"meshmux"},"reusable":false,"ephemeral":false,"used":false,"expiration":{"seconds":1792640100,"nanos":0},"created_at":{"seconds":1792639200,"nanos":0}}`
	runner, fake := newTestRunner(t, fakeReply{stdout: doc})
	key, plaintext, err := runner.CreatePreAuthKey(context.Background(), PreAuthKeyRequest{
		UserID:   3,
		Validity: 15 * time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plaintext != secret {
		t.Fatalf("plaintext = %q", plaintext)
	}
	if key.ID != 11 || key.UserID != 3 || key.Reusable || key.Ephemeral {
		t.Fatalf("key = %+v", key)
	}
	if got, want := key.Expiration, time.Date(2026, 10, 22, 3, 35, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("expiration = %s, want %s", got, want)
	}
	if got, want := key.CreatedAt, time.Date(2026, 10, 22, 3, 20, 0, 0, time.UTC); !got.Equal(want) {
		t.Fatalf("created_at = %s, want %s", got, want)
	}
	if _, ok := reflect.TypeOf(key).FieldByName("Key"); ok {
		t.Fatal("PreAuthKey must not carry the plaintext")
	}
	// The secret never reaches argv.
	for _, call := range fake.calls {
		if strings.Contains(strings.Join(call.args, " "), secret) {
			t.Fatal("pre-auth key reached the command line")
		}
	}
	if last := fake.calls[len(fake.calls)-1]; !reflect.DeepEqual(last.args, []string{
		"--config", ConfigPath, "preauthkeys", "create", "--user", "3", "--expiration", "15m", "-o", "json",
	}) {
		t.Fatalf("argv = %q", last.args)
	}
}

// TestSetApprovedRoutesUsesTheNodeResponse asserts the approve path sends one
// identifier plus one CSV list and returns the node document Headscale prints
// afterwards, decoded through the same narrow node DTO as a listing. The fixture
// is the proto snake_case shape of 0.29.5 (`SetApprovedRoutesResponse.Node`
// marshalled by encoding/json), including the fields this adapter drops.
func TestSetApprovedRoutesUsesTheNodeResponse(t *testing.T) {
	const secret = "hskey-auth-ROUTESECRETROUTESECRET"
	doc := `{
		"id": 42,
		"name": "nas-1.tail.example.invalid",
		"given_name": "nas-1",
		"user": {"id": 3, "name": "meshmux"},
		"ip_addresses": ["100.64.0.7"],
		"approved_routes": ["10.0.0.0/8", "192.168.0.0/24"],
		"available_routes": ["10.0.0.0/8", "192.168.0.0/24", "172.16.0.0/12"],
		"subnet_routes": ["10.0.0.0/8", "192.168.0.0/24"],
		"online": true,
		"pre_auth_key": {"id": 9, "key": "` + secret + `"},
		"machine_key": "mkey:aaaa",
		"node_key": "nodekey:bbbb"
	}`
	runner, fake := newTestRunner(t, fakeReply{stdout: doc})
	node, err := runner.SetApprovedRoutes(context.Background(), 42, []string{"10.0.0.0/8", "192.168.0.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != 42 || node.GivenName != "nas-1" || node.UserID != 3 || !node.Online {
		t.Fatalf("node = %+v", node)
	}
	if want := []string{"10.0.0.0/8", "192.168.0.0/24"}; !reflect.DeepEqual(node.ApprovedRoutes, want) {
		t.Fatalf("approved routes = %q, want %q", node.ApprovedRoutes, want)
	}
	if len(node.AvailableRoutes) != 3 || len(node.SubnetRoutes) != 2 {
		t.Fatalf("route fields = %+v", node)
	}
	if rendered := strings.Join(node.ApprovedRoutes, " "); strings.Contains(rendered, "hskey") || strings.Contains(rendered, "SECRET") {
		t.Fatalf("node output retained key material: %q", rendered)
	}
	last := fake.calls[len(fake.calls)-1]
	if want := []string{
		"--config", ConfigPath, "nodes", "approve-routes", "--identifier", "42",
		"--routes", "10.0.0.0/8,192.168.0.0/24", "-o", "json",
	}; !reflect.DeepEqual(last.args, want) {
		t.Fatalf("argv = %q", last.args)
	}
}

// TestClearApprovedRoutesSendsTheEmptySuffix asserts clearing is the documented
// `--routes=` form rather than an empty value in the ordinary flag-plus-value
// shape, and that the resulting node reports no approved route.
func TestClearApprovedRoutesSendsTheEmptySuffix(t *testing.T) {
	doc := `{"id":42,"given_name":"nas-1","approved_routes":[],"available_routes":["10.0.0.0/8"],"subnet_routes":[]}`
	runner, fake := newTestRunner(t, fakeReply{stdout: doc})
	node, err := runner.ClearApprovedRoutes(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if node.ID != 42 || len(node.ApprovedRoutes) != 0 {
		t.Fatalf("node = %+v", node)
	}
	// The advertised route survives the clear: only approval is withdrawn.
	if want := []string{"10.0.0.0/8"}; !reflect.DeepEqual(node.AvailableRoutes, want) {
		t.Fatalf("available routes = %q, want %q", node.AvailableRoutes, want)
	}
	last := fake.calls[len(fake.calls)-1]
	if want := []string{
		"--config", ConfigPath, "nodes", "approve-routes", "--identifier", "42", "--routes=", "-o", "json",
	}; !reflect.DeepEqual(last.args, want) {
		t.Fatalf("argv = %q", last.args)
	}
}

// TestRouteApprovalRefusesUnsafePrefixes is the adapter half of the route
// contract. An exit route, a /0 of either family and a prefix with host bits set
// are refused before any process runs; canonicalisation of the accepted values
// is the mesh domain's job, not this package's.
func TestRouteApprovalRefusesUnsafePrefixes(t *testing.T) {
	cases := []struct {
		name     string
		prefixes []string
		code     string
	}{
		{name: "ipv4 exit route", prefixes: []string{"0.0.0.0/0"}, code: CodeRouteInvalid},
		{name: "ipv6 exit route", prefixes: []string{"::/0"}, code: CodeRouteInvalid},
		{name: "exit route among subnets", prefixes: []string{"10.0.0.0/8", "0.0.0.0/0"}, code: CodeRouteInvalid},
		{name: "host bits set", prefixes: []string{"10.0.0.1/8"}, code: CodeRouteInvalid},
		{name: "ipv6 host bits set", prefixes: []string{"fd00::1/8"}, code: CodeRouteInvalid},
		{name: "bare address", prefixes: []string{"10.0.0.1"}, code: CodeRouteInvalid},
		{name: "not a prefix", prefixes: []string{"lan"}, code: CodeRouteInvalid},
		{name: "two prefixes in one value", prefixes: []string{"10.0.0.0/8,192.168.0.0/24"}, code: CodeRouteInvalid},
		{name: "empty entry", prefixes: []string{""}, code: CodeRouteInvalid},
		{name: "flag injection", prefixes: []string{"--identifier"}, code: CodeRouteInvalid},
		// An empty approval is not a route change: clearing has its own method,
		// so the caller is told its input is wrong instead of quietly clearing.
		{name: "empty list", prefixes: nil, code: CodeArgumentInvalid},
		{name: "empty slice", prefixes: []string{}, code: CodeArgumentInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExec{}
			runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
			_, err := runner.SetApprovedRoutes(context.Background(), 42, tc.prefixes)
			if CodeOf(err) != tc.code {
				t.Fatalf("err = %v, want %s", err, tc.code)
			}
			if len(fake.calls) != 0 {
				t.Fatalf("refused routes still executed %d commands: %+v", len(fake.calls), fake.calls)
			}
		})
	}

	// A zero identifier is refused whatever the route list says.
	fake := &fakeExec{}
	runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
	if _, err := runner.SetApprovedRoutes(context.Background(), 0, []string{"10.0.0.0/8"}); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero node id: %v", err)
	}
	if _, err := runner.ClearApprovedRoutes(context.Background(), 0); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero node id on clear: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused arguments executed %d commands", len(fake.calls))
	}
}

// TestApprovableRoutePrefixMatchesTheRefusal pins the exported predicate against
// the adapter's own refusal: a caller that builds a complete approved set must be
// able to drop exactly the entries SetApprovedRoutes would refuse, no more and no
// less.
func TestApprovableRoutePrefixMatchesTheRefusal(t *testing.T) {
	cases := []struct {
		prefix string
		ok     bool
	}{
		{prefix: "192.168.1.0/24", ok: true},
		{prefix: "10.0.0.0/8", ok: true},
		{prefix: "fd7a:115c:a1e0::/48", ok: true},
		{prefix: "2001:db8::/32", ok: true},
		{prefix: "0.0.0.0/0"},
		{prefix: "::/0"},
		{prefix: "10.0.0.1/8"},
		{prefix: "fd00::1/8"},
		{prefix: "10.0.0.1"},
		{prefix: "lan"},
		{prefix: ""},
		{prefix: " 10.0.0.0/8"},
		{prefix: "--identifier"},
	}
	for _, tc := range cases {
		t.Run(tc.prefix, func(t *testing.T) {
			if got := ApprovableRoutePrefix(tc.prefix); got != tc.ok {
				t.Fatalf("ApprovableRoutePrefix(%q) = %v, want %v", tc.prefix, got, tc.ok)
			}
			// The predicate and the refusal agree, so a set filtered by the
			// predicate never carries an entry the command would reject.
			err := validateRoutePrefix(tc.prefix)
			if (err == nil) != tc.ok {
				t.Fatalf("validateRoutePrefix(%q) = %v, want ok=%v", tc.prefix, err, tc.ok)
			}
		})
	}
}

// TestSetApprovedRoutesKeepsCallerOrderAndDuplicates asserts the adapter does not
// rewrite the approved set. Headscale compacts duplicates server-side; doing it
// here too would hide a caller that built its list wrongly, and the domain is the
// layer that decides what the desired set is.
func TestSetApprovedRoutesKeepsCallerOrderAndDuplicates(t *testing.T) {
	doc := `{"id":42,"approved_routes":["192.168.0.0/24","10.0.0.0/8"]}`
	runner, fake := newTestRunner(t, fakeReply{stdout: doc})
	if _, err := runner.SetApprovedRoutes(context.Background(), 42, []string{"192.168.0.0/24", "10.0.0.0/8", "10.0.0.0/8"}); err != nil {
		t.Fatal(err)
	}
	last := fake.calls[len(fake.calls)-1]
	if want := "192.168.0.0/24,10.0.0.0/8,10.0.0.0/8"; last.args[len(last.args)-3] != want {
		t.Fatalf("routes value = %q, want %q", last.args[len(last.args)-3], want)
	}
}

// TestRouteParseFailureMapping asserts Headscale's own parse refusal becomes
// HEADSCALE_ROUTE_INVALID rather than a generic command failure, and that the
// route marker wins over the not-found marker even when the offending value
// contains the word "not found".
func TestRouteParseFailureMapping(t *testing.T) {
	cases := []string{
		`{"error": "setting approved routes: rpc error: code = Unknown desc = parsing route: parsing prefix(\"not found\"): no '/' in prefix"}`,
		`{"error": "setting approved routes: rpc error: code = Unknown desc = parsing route: parsing prefix(\"10.0.0.1/8\"): prefix is not masked"}`,
	}
	for _, stderr := range cases {
		fake := &fakeExec{replies: []fakeReply{
			{stdout: versionJSON(HeadscaleVersion)},
			{stderr: stderr, err: errors.New("exit status 1")},
		}}
		runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
		_, err := runner.SetApprovedRoutes(context.Background(), 42, []string{"10.0.0.0/8"})
		if CodeOf(err) != CodeRouteInvalid {
			t.Fatalf("stderr %q mapped to %q, want %q", stderr, CodeOf(err), CodeRouteInvalid)
		}
	}
}

// TestRouteChangeRefusesUnusableNodeDocument asserts a route change that
// Headscale answered without a usable node is not reported as a new state.
func TestRouteChangeRefusesUnusableNodeDocument(t *testing.T) {
	for _, doc := range []string{`{}`, `{"given_name":"nas-1"}`, `null`, `{"id":42,"expiry":"2026-11-01T00:00:00Z"}`} {
		runner, _ := newTestRunner(t, fakeReply{stdout: doc})
		if _, err := runner.ClearApprovedRoutes(context.Background(), 42); CodeOf(err) != CodeOutputInvalid {
			t.Fatalf("document %q: %v, want %s", doc, err, CodeOutputInvalid)
		}
	}
}

// TestDeleteNodeRequiresConfirmationResult asserts that a delete which did not
// take the forced path is refused instead of reported as done.
func TestDeleteNodeRequiresConfirmationResult(t *testing.T) {
	runner, fake := newTestRunner(t, fakeReply{stdout: `{"Result":"Node not deleted"}`})
	if err := runner.DeleteNode(context.Background(), 7); CodeOf(err) != CodeOutputInvalid {
		t.Fatalf("err = %v, want %s", err, CodeOutputInvalid)
	}
	if !strings.HasSuffix(strings.Join(fake.calls[len(fake.calls)-1].args, " "), "nodes delete --identifier 7 --force -o json") {
		t.Fatalf("argv = %q", fake.calls[len(fake.calls)-1].args)
	}

	runner, _ = newTestRunner(t, fakeReply{stdout: `{"Result":"Node deleted"}`})
	if err := runner.DeleteNode(context.Background(), 7); err != nil {
		t.Fatal(err)
	}
}

// TestVersionMismatchRefusesMutation is the safety rule of this slice: an
// executable that is not the pinned release never receives a change.
func TestVersionMismatchRefusesMutation(t *testing.T) {
	cases := []struct {
		name  string
		reply fakeReply
	}{
		{name: "newer release", reply: fakeReply{stdout: versionJSON("0.30.0")}},
		{name: "older release", reply: fakeReply{stdout: versionJSON("0.29.4")}},
		{name: "dirty build", reply: fakeReply{stdout: `{"version":"0.29.5","dirty":true}`}},
		{name: "dev build", reply: fakeReply{stdout: `{"version":"dev"}`}},
		{name: "empty document", reply: fakeReply{stdout: ""}},
		{name: "not json", reply: fakeReply{stdout: "headscale version 0.29.5"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExec{replies: []fakeReply{tc.reply}}
			runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
			err := runner.DeleteNode(context.Background(), 7)
			if CodeOf(err) != CodeVersionMismatch {
				t.Fatalf("err = %v, want %s", err, CodeVersionMismatch)
			}
			// Exactly one command ran: the version probe. The delete was never
			// attempted against an unverified binary.
			if len(fake.calls) != 1 || !reflect.DeepEqual(fake.calls[0].args, []string{"version", "-o", "json"}) {
				t.Fatalf("calls = %+v", fake.calls)
			}
		})
	}
}

// TestVersionHandshakeIsCachedOnce asserts the handshake runs once per runner
// and does not hide a later failure of the operation itself.
func TestVersionHandshakeIsCachedOnce(t *testing.T) {
	runner, fake := newTestRunner(t,
		fakeReply{stdout: `[]`},
		fakeReply{stdout: `[]`},
	)
	for i := 0; i < 2; i++ {
		if _, err := runner.ListUsers(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(fake.calls) != 3 {
		t.Fatalf("executed %d commands, want 3 (one handshake + two lists)", len(fake.calls))
	}
	if !reflect.DeepEqual(fake.calls[0].args, []string{"version", "-o", "json"}) {
		t.Fatalf("first call = %q", fake.calls[0].args)
	}
}

// TestSocketUnavailableMapping covers the diagnostics the Hub must report when
// it cannot use the local Headscale socket. The strings below were captured from
// the real Headscale 0.29.5 binary:
//
//	# absent socket
//	{"error": "connecting to headscale: connecting to <socket>: context deadline exceeded"}
//	# socket present but not usable by this user
//	{"error": "connecting to headscale: unable to read/write to headscale socket \"<socket>\", do you have the correct permissions? open <socket>: permission denied"}
//
// The first one is the reason the classification is ordered: 0.29.5 reports an
// absent socket as a dial deadline, so a naive "context deadline exceeded" match
// would blame the timeout instead of the missing service.
func TestSocketUnavailableMapping(t *testing.T) {
	cases := []string{
		`{"error": "connecting to headscale: connecting to /run/meshmux-headscale/headscale.sock: context deadline exceeded"}`,
		`{"error": "connecting to headscale: unable to read/write to headscale socket \"/run/meshmux-headscale/headscale.sock\", do you have the correct permissions? open /run/meshmux-headscale/headscale.sock: permission denied"}`,
		`Error: connecting to headscale: dial unix /run/meshmux-headscale/headscale.sock: connect: connection refused`,
		`Error: connecting to headscale: dial unix /run/meshmux-headscale/headscale.sock: connect: no such file or directory`,
	}
	for _, stderr := range cases {
		fake := &fakeExec{replies: []fakeReply{
			{stdout: versionJSON(HeadscaleVersion)},
			{stderr: stderr, err: errors.New("exit status 1")},
		}}
		runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
		_, err := runner.ListUsers(context.Background())
		if CodeOf(err) != CodeSocketUnavailable {
			t.Fatalf("stderr %q mapped to %q, want %q", stderr, CodeOf(err), CodeSocketUnavailable)
		}
		// The stderr text is never part of the error value.
		if err != nil && strings.Contains(err.Error(), "headscale.sock") {
			t.Fatalf("error leaked the socket path: %v", err)
		}
	}
}

// TestRPCTimeoutStaysATimeout separates a reachable service that ran out of time
// from an unreachable one. Only the former is HEADSCALE_TIMEOUT.
func TestRPCTimeoutStaysATimeout(t *testing.T) {
	stderr := `{"error": "listing users: rpc error: code = DeadlineExceeded desc = context deadline exceeded"}`
	fake := &fakeExec{replies: []fakeReply{
		{stdout: versionJSON(HeadscaleVersion)},
		{stderr: stderr, err: errors.New("exit status 1")},
	}}
	runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
	if _, err := runner.ListUsers(context.Background()); CodeOf(err) != CodeTimeout {
		t.Fatalf("err = %v, want %s", err, CodeTimeout)
	}
}

// TestNodeNotFoundMapping covers the two wordings 0.29.5 uses for an absent
// node, captured from the real binary. A retried removal must be settleable.
func TestNodeNotFoundMapping(t *testing.T) {
	cases := []struct {
		name   string
		stderr string
		delete bool
	}{
		{
			name:   "delete",
			stderr: `{"error": "getting node: rpc error: code = NotFound desc = node not found"}`,
			delete: true,
		},
		{
			// Expiring an absent node is not the settleable retry: a delete is.
			// The expiry path must still not be mistaken for a socket failure.
			name:   "expire",
			stderr: `{"error": "expiring node: rpc error: code = Unknown desc = node no longer exists in NodeStore: 999"}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeExec{replies: []fakeReply{
				{stdout: versionJSON(HeadscaleVersion)},
				{stderr: tc.stderr, err: errors.New("exit status 1")},
			}}
			runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
			var err error
			if tc.delete {
				err = runner.DeleteNode(context.Background(), 999)
			} else {
				err = runner.ExpireNode(context.Background(), 999)
			}
			if CodeOf(err) != CodeNotFound {
				t.Fatalf("err = %v, want %s", err, CodeNotFound)
			}
		})
	}
}

// TestErrorTextIsOnlyTheStableCode asserts the diagnostic contract even when the
// child prints key material.
func TestErrorTextIsOnlyTheStableCode(t *testing.T) {
	fake := &fakeExec{replies: []fakeReply{
		{stdout: versionJSON(HeadscaleVersion)},
		{stderr: "Error: creating preauthkey: key hskey-auth-LEAKEDLEAKEDLEAKED failed", err: errors.New("exit status 1")},
	}}
	runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
	_, _, err := runner.CreatePreAuthKey(context.Background(), PreAuthKeyRequest{UserID: 3, Validity: 15 * time.Minute})
	if CodeOf(err) != CodeCommandFailed {
		t.Fatalf("err = %v", err)
	}
	if strings.Contains(err.Error(), "hskey") || strings.Contains(err.Error(), "preauthkey") {
		t.Fatalf("error leaked child output: %v", err)
	}
}

// TestArgumentValidation keeps caller values from becoming flags or extra
// arguments.
func TestArgumentValidation(t *testing.T) {
	runner := NewCLIRunner()
	cases := []struct {
		name   string
		op     operation
		values []string
	}{
		{name: "flag injection into a user name", op: opNodesListByUser, values: []string{"--force"}},
		{name: "flag injection with an equals form", op: opNodesListByUser, values: []string{"--user=root"}},
		{name: "empty value", op: opNodesExpire, values: []string{""}},
		{name: "control character", op: opNodesExpire, values: []string{"7\n8"}},
		{name: "wrong arity", op: opNodesExpire, values: []string{"7", "8"}},
		{name: "unknown operation", op: "nodes rename", values: nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := runner.buildArgs(tc.op, tc.values...); CodeOf(err) != CodeArgumentInvalid {
				t.Fatalf("err = %v, want %s", err, CodeArgumentInvalid)
			}
		})
	}

	// Zero identifiers and key lifetimes that are not whole minutes are refused
	// before any process runs.
	fake := &fakeExec{}
	blocked := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
	if err := blocked.ExpireNode(context.Background(), 0); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero node id: %v", err)
	}
	if err := blocked.DeleteNode(context.Background(), 0); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero node id: %v", err)
	}
	if err := blocked.ExpirePreAuthKey(context.Background(), 0); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero key id: %v", err)
	}
	if _, _, err := blocked.CreatePreAuthKey(context.Background(), PreAuthKeyRequest{UserID: 0, Validity: 15 * time.Minute}); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero user id: %v", err)
	}
	if _, _, err := blocked.CreatePreAuthKey(context.Background(), PreAuthKeyRequest{UserID: 3, Validity: 90 * time.Second}); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("sub-minute validity: %v", err)
	}
	if _, _, err := blocked.CreatePreAuthKey(context.Background(), PreAuthKeyRequest{UserID: 3, Validity: 48 * time.Hour}); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("two-day validity: %v", err)
	}
	if _, err := blocked.CreateUser(context.Background(), "MeshMux"); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("non-canonical user name: %v", err)
	}
	if len(fake.calls) != 0 {
		t.Fatalf("refused arguments still executed %d commands", len(fake.calls))
	}
}

// TestOutputInvalidIsRefused asserts a malformed or empty document never
// becomes a zero-valued success.
func TestOutputInvalidIsRefused(t *testing.T) {
	cases := []struct{ name, stdout string }{
		{name: "empty", stdout: ""},
		{name: "whitespace", stdout: "  \n\t "},
		{name: "not json", stdout: "Error: something happened"},
		{name: "truncated", stdout: `[{"id":1`},
		{name: "wrong shape", stdout: `{"id":1}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner, _ := newTestRunner(t, fakeReply{stdout: tc.stdout})
			if _, err := runner.ListNodes(context.Background(), ""); CodeOf(err) != CodeOutputInvalid {
				t.Fatalf("err = %v, want %s", err, CodeOutputInvalid)
			}
		})
	}

	// A node without an id is not a usable reference.
	runner, _ := newTestRunner(t, fakeReply{stdout: `[{"name":"x"}]`})
	if _, err := runner.ListNodes(context.Background(), ""); CodeOf(err) != CodeOutputInvalid {
		t.Fatalf("missing node id: %v", err)
	}
}

// TestDeadlineIsBounded asserts a hung child is killed and reported as a
// timeout, not as an indefinite wait.
func TestDeadlineIsBounded(t *testing.T) {
	fake := &fakeExec{}
	runner := &CLIRunner{
		binary:  BinaryPath,
		config:  ConfigPath,
		timeout: 30 * time.Millisecond,
		execute: func(ctx context.Context, _ string, _ []string) ([]byte, []byte, error) {
			fake.calls = append(fake.calls, recordedCall{name: BinaryPath})
			<-ctx.Done()
			return nil, nil, ctx.Err()
		},
	}
	start := time.Now()
	err := runner.VerifyVersion(context.Background())
	if CodeOf(err) != CodeTimeout {
		t.Fatalf("err = %v, want %s", err, CodeTimeout)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline was not enforced: %s", elapsed)
	}

	// A caller deadline shorter than the fixed one stays in charge.
	short, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	runner.timeout = time.Minute
	if err := runner.VerifyVersion(short); CodeOf(err) != CodeTimeout {
		t.Fatalf("caller deadline: %v", err)
	}

	// A canceled caller is reported as canceled, and the cancellation is not
	// cached as a version failure.
	canceled, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	if err := runner.VerifyVersion(canceled); CodeOf(err) != CodeCanceled {
		t.Fatalf("canceled caller: %v", err)
	}
}

// TestUnavailableBinaryIsRefused covers the host-layout defects that are not a
// socket permission problem.
func TestUnavailableBinaryIsRefused(t *testing.T) {
	empty := &CLIRunner{timeout: commandTimeout}
	if err := empty.VerifyVersion(context.Background()); CodeOf(err) != CodeUnavailable {
		t.Fatalf("no executor: %v", err)
	}

	for _, stderr := range []string{
		"Error: error loading config file /etc/meshmux/headscale.yaml: no such file or directory",
		"Error: loading configuration: config file not found",
	} {
		fake := &fakeExec{replies: []fakeReply{{stderr: stderr, err: errors.New("exit status 1")}}}
		runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
		if err := runner.VerifyVersion(context.Background()); CodeOf(err) != CodeUnavailable {
			t.Fatalf("stderr %q: %v", stderr, CodeOf(err))
		}
	}
}

// TestEmptyListIsNotNull asserts an empty tailnet decodes as an empty slice, not
// as a zero time or a zero node. Headscale prints `null` for an empty list
// because the CLI marshals the nil protobuf slice directly.
func TestEmptyListIsNotNull(t *testing.T) {
	runner, _ := newTestRunner(t, fakeReply{stdout: "null"})
	nodes, err := runner.ListNodes(context.Background(), "")
	if err != nil {
		t.Fatalf("nodes: %v", err)
	}
	if nodes == nil || len(nodes) != 0 {
		t.Fatalf("nodes = %#v, want an empty slice", nodes)
	}
	runner, _ = newTestRunner(t, fakeReply{stdout: "null"})
	users, err := runner.ListUsers(context.Background())
	if err != nil {
		t.Fatalf("users: %v", err)
	}
	if users == nil || len(users) != 0 {
		t.Fatalf("users = %#v, want an empty slice", users)
	}
}

// TestTimestampShapeIsPinnedToThisRelease asserts the decoder expects the
// protobuf Timestamp shape of 0.29.5. A later Headscale serialises timestamps as
// RFC3339 strings; that output must fail as HEADSCALE_OUTPUT_INVALID instead of
// silently producing a zero expiry, and the handshake is what keeps such a
// binary from being used at all.
func TestTimestampShapeIsPinnedToThisRelease(t *testing.T) {
	doc := `[{"id":7,"given_name":"laptop-1","expiry":"2026-11-01T00:00:00Z"}]`
	runner, _ := newTestRunner(t, fakeReply{stdout: doc})
	if _, err := runner.ListNodes(context.Background(), ""); CodeOf(err) != CodeOutputInvalid {
		t.Fatalf("err = %v, want %s", err, CodeOutputInvalid)
	}

	// The unset-instant sentinel means "no expiry", not year 1.
	doc = `[{"id":7,"expiry":{"seconds":-62135596800}}]`
	runner, _ = newTestRunner(t, fakeReply{stdout: doc})
	nodes, err := runner.ListNodes(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	if !nodes[0].Expiry.IsZero() {
		t.Fatalf("expiry = %s, want the zero time", nodes[0].Expiry)
	}

	// A node that never expires simply omits the block.
	doc = `[{"id":7}]`
	runner, _ = newTestRunner(t, fakeReply{stdout: doc})
	nodes, err = runner.ListNodes(context.Background(), "")
	if err != nil || !nodes[0].Expiry.IsZero() {
		t.Fatalf("absent expiry: %v %s", err, nodes[0].Expiry)
	}

	// Out-of-range nanos are refused rather than normalised into a different
	// instant.
	doc = `[{"id":7,"expiry":{"seconds":1793491200,"nanos":1000000000}}]`
	runner, _ = newTestRunner(t, fakeReply{stdout: doc})
	if _, err := runner.ListNodes(context.Background(), ""); CodeOf(err) != CodeOutputInvalid {
		t.Fatalf("nanos overflow: %v", err)
	}
}

// TestCreateUserAlreadyExists asserts the idempotent-user case stays
// distinguishable, because provisioning the shared user must not fail a request
// when the user is already there.
func TestCreateUserAlreadyExists(t *testing.T) {
	fake := &fakeExec{replies: []fakeReply{
		{stdout: versionJSON(HeadscaleVersion)},
		{stderr: `Error: creating user: rpc error: code = AlreadyExists desc = user already exists`, err: errors.New("exit status 1")},
	}}
	runner := &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: fake.exec}
	if _, err := runner.CreateUser(context.Background(), "meshmux"); CodeOf(err) != CodeAlreadyExists {
		t.Fatalf("err = %v, want %s", err, CodeAlreadyExists)
	}
}

// TestBoundOutputIsTruncated checks the capture bound without a real process.
func TestBoundCapture(t *testing.T) {
	buffer := &boundedBuffer{max: 8}
	if n, err := buffer.Write([]byte("0123456789abcdef")); n != 16 || err != nil {
		t.Fatalf("Write = %d, %v", n, err)
	}
	if got := string(buffer.Bytes()); got != "01234567" || !buffer.truncated {
		t.Fatalf("capture = %q truncated=%t", got, buffer.truncated)
	}
}

// TestCommandEnvironmentIsScrubbed asserts the child cannot inherit a remote
// control address or credential from the Web service environment.
func TestCommandEnvironmentIsScrubbed(t *testing.T) {
	t.Setenv("HEADSCALE_CLI_ADDRESS", "203.0.113.9:50443")
	t.Setenv("HEADSCALE_CLI_API_KEY", "leaked-token")
	t.Setenv("HEADSCALE_CONFIG", "/tmp/elsewhere.yaml")
	for _, entry := range commandEnv() {
		if strings.Contains(entry, "203.0.113.9") || strings.Contains(entry, "leaked-token") || strings.Contains(entry, "/tmp/elsewhere.yaml") {
			t.Fatalf("child environment inherited %q", entry)
		}
	}
}

// TestNewCLIRunnerUsesFixedLayout pins the production paths so no edit can
// quietly point the adapter at a caller-chosen binary or configuration.
func TestNewCLIRunnerUsesFixedLayout(t *testing.T) {
	runner := NewCLIRunner()
	if runner.binary != "/usr/local/libexec/meshmux-headscale" || runner.config != "/etc/meshmux/headscale.yaml" {
		t.Fatalf("layout = %q, %q", runner.binary, runner.config)
	}
	if runner.timeout != 15*time.Second {
		t.Fatalf("timeout = %s", runner.timeout)
	}
	if runner.execute == nil {
		t.Fatal("production runner has no executor")
	}
}

// TestCodeOfIgnoresForeignErrors asserts a non-adapter error has no stable code,
// so a caller cannot mistake an unrelated failure for a Headscale refusal.
func TestCodeOfIgnoresForeignErrors(t *testing.T) {
	if got := CodeOf(errors.New("boom")); got != "" {
		t.Fatalf("CodeOf(foreign) = %q", got)
	}
	if got := CodeOf(nil); got != "" {
		t.Fatalf("CodeOf(nil) = %q", got)
	}
	wrapped := errors.Join(errors.New("context"), failure(CodeTimeout))
	if got := CodeOf(wrapped); got != CodeTimeout {
		t.Fatalf("CodeOf(joined) = %q", got)
	}
}

// TestPinnedVersionComesFromTheVersionsLeaf proves the adapter does not carry a
// second literal. It used to repeat the release to stay a leaf; the pin now has
// one definition in internal/cli/versions, which every layer may import, so a
// bump there changes the handshake here and the installer manifest together.
func TestPinnedVersionComesFromTheVersionsLeaf(t *testing.T) {
	if HeadscaleVersion != versions.HeadscaleVersion {
		t.Fatalf("adapter pin = %q, versions leaf = %q", HeadscaleVersion, versions.HeadscaleVersion)
	}
	if versions.HeadscaleVersion != "0.29.5" {
		t.Fatalf("versions leaf = %q; the argv table above was written for 0.29.5", versions.HeadscaleVersion)
	}
}
