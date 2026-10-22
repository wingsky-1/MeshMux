package headscale

// CLIRunner is the only production headscale adapter. Every call is one local
// process: a fixed executable, a fixed --config file, machine-readable output,
// no shell, a scrubbed environment and a hard deadline.
//
// Why argv shapes live in a table: an adapter that accepts a caller-chosen
// flag, subcommand or path is an arbitrary command runner in disguise, and the
// Hub already refuses that boundary for the Node Agent. Here the table is the
// complete vocabulary, so a missing shape is refused
// (HEADSCALE_ARGUMENT_INVALID) instead of probing whatever the installed binary
// happens to support.
//
// Three argv facts of Headscale 0.29.5 that this file encodes:
//   - `version` must be the first argument and must not carry --config. Any
//     other first argument makes the CLI load the server configuration before
//     the version command runs, so a broken config would hide the version and
//     the handshake would depend on the very host state it is meant to check.
//   - `nodes delete` prompts unless --force is set. A prompt would read the
//     service's stdin and hang until the deadline, so the Hub passes --force and
//     replaces the prompt with its own explicit, audited user action.
//   - `nodes approve-routes --routes=` is the documented way to remove every
//     approved route. The CLI has no separate clear subcommand, and an empty
//     value would not survive the ordinary flag-plus-value shape, so clearing is
//     a literal suffix of its own operation.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The fixed host layout. BinaryPath is the installer's staged Headscale copy
// and ConfigPath the Hub-generated server configuration; both are constants so
// no request, environment variable or caller input can redirect the adapter to
// another binary, configuration or address.
const (
	// BinaryPath is the fixed Headscale executable of a MeshMux Hub.
	BinaryPath = "/usr/local/libexec/meshmux-headscale"
	// ConfigPath is the fixed Headscale server configuration of a MeshMux Hub.
	// The CLI reads unix_socket from it, so the adapter always talks to the
	// local service and never to a remote control server.
	ConfigPath = "/etc/meshmux/headscale.yaml"

	// commandTimeout bounds one CLI call, including the process start. A
	// Headscale that does not answer in this window is reported as
	// HEADSCALE_TIMEOUT and its child is killed; the caller does not retry
	// inside the same request.
	commandTimeout = 15 * time.Second

	// maxStandardOutput bounds the machine-readable document this adapter will
	// decode. A node list of a few thousand entries fits; anything larger is
	// refused instead of buffered without limit.
	maxStandardOutput = 4 << 20
	// maxStandardError bounds the diagnostic capture. Stderr is only inspected
	// for classification markers and never surfaced to a caller.
	maxStandardError = 64 << 10
)

// operation is one entry of the fixed command vocabulary. It is a distinct
// type so a plain string cannot reach the table by accident.
type operation string

const (
	opVersion            operation = "version"
	opUsersList          operation = "users list"
	opUsersCreate        operation = "users create"
	opNodesList          operation = "nodes list"
	opNodesListByUser    operation = "nodes list --user"
	opNodesExpire        operation = "nodes expire"
	opNodesDelete        operation = "nodes delete"
	opNodesApproveRoutes operation = "nodes approve-routes"
	opNodesClearRoutes   operation = "nodes approve-routes --routes="
	opPreAuthKeysCreate  operation = "preauthkeys create"
	opPreAuthKeysExpire  operation = "preauthkeys expire"
)

// commandSpec is one fixed argv shape: prefix, then one flag per caller value
// (an empty flag means the value is a positional argument), then suffix.
// --config ConfigPath is prepended for every operation except version, and
// "-o json" is appended to every operation. The flags are literals in the
// table, never part of a caller value, so a value that looks like a flag is
// refused rather than reinterpreted.
type commandSpec struct {
	prefix  []string
	flagFor []string
	suffix  []string
}

// commandTable is the complete argv vocabulary. It deliberately has no
// preauthkeys list entry: that listing prints key material, and the Hub only
// needs the key it minted for one device. It also has no nodes list-routes
// entry: `nodes list` already reports approved, available and subnet routes for
// every node, and a per-node route listing would drop the node context the
// caller needs anyway.
var commandTable = map[operation]commandSpec{
	opVersion:            {prefix: []string{"version"}},
	opUsersList:          {prefix: []string{"users", "list"}},
	opUsersCreate:        {prefix: []string{"users", "create"}, flagFor: []string{""}},
	opNodesList:          {prefix: []string{"nodes", "list"}},
	opNodesListByUser:    {prefix: []string{"nodes", "list"}, flagFor: []string{"--user"}},
	opNodesExpire:        {prefix: []string{"nodes", "expire"}, flagFor: []string{"--identifier"}},
	opNodesDelete:        {prefix: []string{"nodes", "delete"}, flagFor: []string{"--identifier"}, suffix: []string{"--force"}},
	opNodesApproveRoutes: {prefix: []string{"nodes", "approve-routes"}, flagFor: []string{"--identifier", "--routes"}},
	opNodesClearRoutes:   {prefix: []string{"nodes", "approve-routes"}, flagFor: []string{"--identifier"}, suffix: []string{"--routes="}},
	opPreAuthKeysCreate:  {prefix: []string{"preauthkeys", "create"}, flagFor: []string{"--user", "--expiration"}},
	opPreAuthKeysExpire:  {prefix: []string{"preauthkeys", "expire"}, flagFor: []string{"--id"}},
}

// commandEnv is the exact environment of the child. It is not inherited: an
// inherited HEADSCALE_CLI_ADDRESS, HEADSCALE_CLI_API_KEY or HEADSCALE_CONFIG
// could point the CLI at a remote control server, which is a different trust
// boundary than the local unix socket this adapter is built around.
func commandEnv() []string {
	return []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"LC_ALL=C",
	}
}

// executor is the process boundary. The production value runs a real child;
// tests replace it to assert argv without spawning anything.
type executor func(ctx context.Context, name string, args []string) (stdout, stderr []byte, err error)

// CLIRunner implements Client over the pinned executable. The zero value is not
// usable; call NewCLIRunner. The path fields stay unexported so production code
// cannot point the adapter at a caller-chosen binary or configuration.
//
// A successful version handshake is cached for the lifetime of the value: a
// Headscale upgrade is followed by a restart of the Hub services (the installer
// and the upgrade path own that restart), so the cache cannot outlive a version
// change unnoticed. A failed handshake is never cached, so a repaired host
// recovers without restarting the Web process.
type CLIRunner struct {
	binary  string
	config  string
	timeout time.Duration
	execute executor

	versionMu sync.Mutex
	verified  bool
}

var _ Client = (*CLIRunner)(nil)

// NewCLIRunner returns the production adapter over the fixed Hub layout.
func NewCLIRunner() *CLIRunner {
	return &CLIRunner{binary: BinaryPath, config: ConfigPath, timeout: commandTimeout, execute: runCommand}
}

// VerifyVersion performs the version handshake once and returns its outcome. A
// caller that wants to fail early (for example a Web page that shows a broken
// Hub instead of a failed change) calls this before offering a mutation; the
// mutating methods call it themselves, so this is not a prerequisite for
// correctness.
func (c *CLIRunner) VerifyVersion(ctx context.Context) error {
	c.versionMu.Lock()
	defer c.versionMu.Unlock()
	if c.verified {
		return nil
	}
	if err := c.checkVersion(ctx); err != nil {
		return err
	}
	c.verified = true
	return nil
}

// checkVersion reads `version -o json` and requires exactly HeadscaleVersion.
// The release value is compared, not the commit or build time: the pinned
// release is what the argv table was written against.
func (c *CLIRunner) checkVersion(ctx context.Context) error {
	args, err := c.buildArgs(opVersion)
	if err != nil {
		return err
	}
	out, err := c.executeArgs(ctx, args)
	if err != nil {
		if CodeOf(err) == CodeOutputInvalid {
			// The binary answered without a readable version document, so it
			// cannot prove it is the pinned release.
			return failure(CodeVersionMismatch)
		}
		return err
	}
	var info struct {
		Version string `json:"version"`
		Dirty   bool   `json:"dirty"`
	}
	if err := decodeOutput(out, &info); err != nil {
		return failure(CodeVersionMismatch)
	}
	if info.Dirty || strings.TrimPrefix(info.Version, "v") != HeadscaleVersion {
		// The reported release is not the pinned one, so every flag this
		// adapter passes is unverified. Refuse the change instead of guessing.
		return failure(CodeVersionMismatch)
	}
	return nil
}

// run builds the fixed argv of op, completes the version handshake of every
// non-version operation and executes it. Argument validation happens before the
// handshake, so a refused value is never reported as a version problem.
func (c *CLIRunner) run(ctx context.Context, op operation, values ...string) ([]byte, error) {
	args, err := c.buildArgs(op, values...)
	if err != nil {
		return nil, err
	}
	if op != opVersion {
		if err := c.VerifyVersion(ctx); err != nil {
			return nil, err
		}
	}
	return c.executeArgs(ctx, args)
}

// buildArgs turns one operation and its validated values into the exact argv of
// the table. It never consults the environment, the caller or the installed
// binary.
func (c *CLIRunner) buildArgs(op operation, values ...string) ([]string, error) {
	spec, ok := commandTable[op]
	if !ok || len(values) != len(spec.flagFor) {
		return nil, failure(CodeArgumentInvalid)
	}
	args := make([]string, 0, len(spec.prefix)+2*len(values)+len(spec.suffix)+4)
	if op != opVersion {
		args = append(args, "--config", c.config)
	}
	args = append(args, spec.prefix...)
	for i, value := range values {
		if err := validateValue(value); err != nil {
			return nil, err
		}
		if spec.flagFor[i] != "" {
			args = append(args, spec.flagFor[i])
		}
		args = append(args, value)
	}
	args = append(args, spec.suffix...)
	args = append(args, "-o", "json")
	return args, nil
}

// executeArgs runs one already-built argv under the fixed deadline.
func (c *CLIRunner) executeArgs(ctx context.Context, args []string) ([]byte, error) {
	if c.execute == nil || c.binary == "" {
		return nil, failure(CodeUnavailable)
	}
	commandCtx, cancel := c.commandContext(ctx)
	defer cancel()
	stdout, stderr, err := c.execute(commandCtx, c.binary, args)
	if err != nil {
		return nil, classifyFailure(ctx, commandCtx, err, stdout, stderr)
	}
	if len(stdout) == 0 {
		return nil, failure(CodeOutputInvalid)
	}
	return stdout, nil
}

// commandContext applies the fixed deadline. A caller deadline that is already
// shorter is left in charge, so a request-scoped timeout is not stretched.
func (c *CLIRunner) commandContext(ctx context.Context) (context.Context, context.CancelFunc) {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = commandTimeout
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, timeout)
}

// userNamePattern is the accepted Headscale user name: one lowercase label,
// mirroring the mesh domain rule. The CLI therefore never receives a value that
// could be read as a flag or split into several arguments.
var userNamePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._-]{0,61}[a-z0-9])?$`)

// validMinutes bounds a key lifetime to [1m, 24h]. The Hub mints a 15-minute
// enrollment key; a window beyond a day would outlive any plausible operator
// action, and a sub-minute window is not expressible as a whole number of
// minutes.
func validMinutes(minutes int64) bool { return minutes >= 1 && minutes <= 24*60 }

// validateValue refuses anything that cannot travel as one literal argv value,
// whatever operation asked for it.
func validateValue(value string) error {
	if value == "" || strings.HasPrefix(value, "-") {
		return failure(CodeArgumentInvalid)
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 || value[i] == 0x7f {
			return failure(CodeArgumentInvalid)
		}
	}
	return nil
}

func validateID(id uint64) error {
	if id == 0 {
		return failure(CodeArgumentInvalid)
	}
	return nil
}

// validateRoutePrefix is the adapter's half of the route contract: three shapes
// are refused here rather than sent to Headscale, because each one would change
// what the whole tailnet routes.
//   - an unparseable value is not a prefix at all;
//   - a /0 prefix is an exit route (0.0.0.0/0 or ::/0), which would make this
//     node the default gateway for every peer. MeshMux approves LAN subnets, not
//     exit nodes;
//   - a prefix with host bits set (10.0.0.1/8) is not the network it claims to
//     be. Accepting it would approve a different range than the caller read.
//
// Canonicalisation of accepted prefixes is the domain's job (the mesh layer
// compares advertised, approved and configured routes); this function only
// refuses. A comma is refused implicitly: no prefix parses with one, and the
// joined value is a CSV list for the CLI's StringSlice flag.
func validateRoutePrefix(raw string) error {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return failure(CodeRouteInvalid)
	}
	if prefix.Bits() == 0 {
		return failure(CodeRouteInvalid)
	}
	if prefix != prefix.Masked() {
		return failure(CodeRouteInvalid)
	}
	return nil
}

// joinRoutePrefixes turns validated prefixes into the single comma-separated
// argv value Headscale's --routes flag expects. Duplicates are preserved: the
// domain decides whether the set it asked for is the set it wants, and silently
// rewriting the list here would hide a caller bug.
func joinRoutePrefixes(prefixes []string) (string, error) {
	if len(prefixes) == 0 {
		// An empty approval is not a route change. Clearing has its own
		// operation, so a caller that meant "remove everything" is told so
		// instead of silently sending an empty list.
		return "", failure(CodeArgumentInvalid)
	}
	joined := make([]string, 0, len(prefixes))
	for _, raw := range prefixes {
		if err := validateRoutePrefix(raw); err != nil {
			return "", err
		}
		joined = append(joined, raw)
	}
	return strings.Join(joined, ","), nil
}

// ListUsers returns every Headscale user. The result is unfiltered: the caller
// resolves the shared default user by name and does not rely on the ordering.
func (c *CLIRunner) ListUsers(ctx context.Context) ([]User, error) {
	out, err := c.run(ctx, opUsersList)
	if err != nil {
		return nil, err
	}
	var decoded []userJSON
	if err := decodeOutput(out, &decoded); err != nil {
		return nil, err
	}
	users := make([]User, 0, len(decoded))
	for _, u := range decoded {
		users = append(users, u.toUser())
	}
	return users, nil
}

// CreateUser creates one user. It is not idempotent: a repeated name is
// reported as HEADSCALE_ALREADY_EXISTS and the caller decides whether the
// existing user is the one it wanted.
func (c *CLIRunner) CreateUser(ctx context.Context, name string) (User, error) {
	if !userNamePattern.MatchString(name) {
		return User{}, failure(CodeArgumentInvalid)
	}
	out, err := c.run(ctx, opUsersCreate, name)
	if err != nil {
		return User{}, err
	}
	var decoded userJSON
	if err := decodeOutput(out, &decoded); err != nil {
		return User{}, err
	}
	return decoded.toUser(), nil
}

// ListNodes returns the nodes of one user, or of the whole tailnet when user is
// empty.
func (c *CLIRunner) ListNodes(ctx context.Context, user string) ([]Node, error) {
	var (
		out []byte
		err error
	)
	if user == "" {
		out, err = c.run(ctx, opNodesList)
	} else {
		if !userNamePattern.MatchString(user) {
			return nil, failure(CodeArgumentInvalid)
		}
		out, err = c.run(ctx, opNodesListByUser, user)
	}
	if err != nil {
		return nil, err
	}
	var decoded []nodeJSON
	if err := decodeOutput(out, &decoded); err != nil {
		return nil, err
	}
	nodes := make([]Node, 0, len(decoded))
	for _, n := range decoded {
		node, err := n.toNode()
		if err != nil {
			return nil, err
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// CreatePreAuthKey mints one non-reusable key for one user and returns its
// plaintext exactly once. The plaintext is a one-shot value: it is not stored in
// the returned PreAuthKey, and this package never logs it. A non-Reusable,
// non-Ephemeral key keeps the node after enrollment, which is what a MeshMux
// device needs.
func (c *CLIRunner) CreatePreAuthKey(ctx context.Context, req PreAuthKeyRequest) (PreAuthKey, string, error) {
	if err := validateID(req.UserID); err != nil {
		return PreAuthKey{}, "", err
	}
	minutes := int64(req.Validity / time.Minute)
	if req.Validity%time.Minute != 0 || !validMinutes(minutes) {
		return PreAuthKey{}, "", failure(CodeArgumentInvalid)
	}
	out, err := c.run(ctx, opPreAuthKeysCreate, strconv.FormatUint(req.UserID, 10), strconv.FormatInt(minutes, 10)+"m")
	if err != nil {
		return PreAuthKey{}, "", err
	}
	var decoded preAuthKeyJSON
	if err := decodeOutput(out, &decoded); err != nil {
		return PreAuthKey{}, "", err
	}
	key, err := decoded.toPreAuthKey()
	if err != nil {
		return PreAuthKey{}, "", err
	}
	if err := validateKeySecret(decoded.Key); err != nil {
		return PreAuthKey{}, "", err
	}
	return key, decoded.Key, nil
}

// ExpirePreAuthKey expires one key immediately, so a leaked or abandoned key
// stops working before its window closes.
func (c *CLIRunner) ExpirePreAuthKey(ctx context.Context, id uint64) error {
	if err := validateID(id); err != nil {
		return err
	}
	_, err := c.run(ctx, opPreAuthKeysExpire, strconv.FormatUint(id, 10))
	return err
}

// ExpireNode logs a node out immediately while keeping it in Headscale, which
// is the reversible half of a revocation.
func (c *CLIRunner) ExpireNode(ctx context.Context, id uint64) error {
	if err := validateID(id); err != nil {
		return err
	}
	_, err := c.run(ctx, opNodesExpire, strconv.FormatUint(id, 10))
	return err
}

// DeleteNode removes a node. --force is part of the fixed argv: the Hub's own
// confirmed, audited action replaces the CLI prompt. A node that is already gone
// is reported as HEADSCALE_NOT_FOUND so a retried removal can be treated as
// settled by the caller instead of as a new failure.
func (c *CLIRunner) DeleteNode(ctx context.Context, id uint64) error {
	if err := validateID(id); err != nil {
		return err
	}
	out, err := c.run(ctx, opNodesDelete, strconv.FormatUint(id, 10))
	if err != nil {
		return err
	}
	var decoded struct {
		Result string `json:"Result"`
	}
	if err := decodeOutput(out, &decoded); err != nil {
		return err
	}
	if decoded.Result != "Node deleted" {
		// Anything else means the confirmation path was not taken, which would
		// leave the node in place while the caller believes otherwise.
		return failure(CodeOutputInvalid)
	}
	return nil
}

// SetApprovedRoutes replaces the approved route list of one node. Headscale's
// SetApprovedRoutes is a set operation, so this is not additive: the caller
// passes the complete list it wants approved. An empty list is refused because
// clearing is ClearApprovedRoutes, and a caller that reached here with nothing
// has a bug the adapter should not hide.
func (c *CLIRunner) SetApprovedRoutes(ctx context.Context, id uint64, prefixes []string) (Node, error) {
	if err := validateID(id); err != nil {
		return Node{}, err
	}
	joined, err := joinRoutePrefixes(prefixes)
	if err != nil {
		return Node{}, err
	}
	out, err := c.run(ctx, opNodesApproveRoutes, strconv.FormatUint(id, 10), joined)
	if err != nil {
		return Node{}, err
	}
	return decodeNode(out)
}

// ClearApprovedRoutes withdraws every approved route of one node. The node stays
// registered and keeps advertising its routes, so this is the reversible half of
// a route change: nothing is deleted and re-approval restores routing.
func (c *CLIRunner) ClearApprovedRoutes(ctx context.Context, id uint64) (Node, error) {
	if err := validateID(id); err != nil {
		return Node{}, err
	}
	out, err := c.run(ctx, opNodesClearRoutes, strconv.FormatUint(id, 10))
	if err != nil {
		return Node{}, err
	}
	return decodeNode(out)
}

// decodeNode reads the single-node document Headscale prints after a route
// change. It reuses nodeJSON so the route fields have exactly one shape in this
// package, and it requires an id: a document without one is not the node the
// caller asked about, so it must not be reported as the new state.
func decodeNode(out []byte) (Node, error) {
	var decoded nodeJSON
	if err := decodeOutput(out, &decoded); err != nil {
		return Node{}, err
	}
	return decoded.toNode()
}

// userJSON is the narrow view of one Headscale user. Unknown fields, including
// provider metadata, are dropped by encoding/json.
type userJSON struct {
	ID          uint64 `json:"id"`
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Email       string `json:"email"`
}

func (u userJSON) toUser() User {
	return User(u)
}

// nodeJSON is the narrow view of one Headscale node. There is no field for
// pre_auth_key, machine_key, node_key or disco_key: the decoder cannot retain
// them even when the CLI prints them, so the Node DTO has no key material at
// all.
type nodeJSON struct {
	ID              uint64         `json:"id"`
	Name            string         `json:"name"`
	GivenName       string         `json:"given_name"`
	User            *userJSON      `json:"user"`
	IPAddresses     []string       `json:"ip_addresses"`
	ApprovedRoutes  []string       `json:"approved_routes"`
	AvailableRoutes []string       `json:"available_routes"`
	SubnetRoutes    []string       `json:"subnet_routes"`
	Online          bool           `json:"online"`
	Expiry          *timestampJSON `json:"expiry"`
}

func (n nodeJSON) toNode() (Node, error) {
	if n.ID == 0 {
		return Node{}, failure(CodeOutputInvalid)
	}
	expiry, err := parseTimestamp(n.Expiry)
	if err != nil {
		return Node{}, err
	}
	node := Node{
		ID:              n.ID,
		Name:            n.Name,
		GivenName:       n.GivenName,
		IPAddresses:     append([]string(nil), n.IPAddresses...),
		ApprovedRoutes:  append([]string(nil), n.ApprovedRoutes...),
		AvailableRoutes: append([]string(nil), n.AvailableRoutes...),
		SubnetRoutes:    append([]string(nil), n.SubnetRoutes...),
		Online:          n.Online,
		Expiry:          expiry,
	}
	if n.User != nil {
		node.UserID = n.User.ID
		node.UserName = n.User.Name
	}
	return node, nil
}

// preAuthKeyJSON is the narrow view of one created key. Key is read only to
// hand it to the caller once; it is not part of PreAuthKey.
type preAuthKeyJSON struct {
	Key        string         `json:"key"`
	ID         uint64         `json:"id"`
	User       *userJSON      `json:"user"`
	Reusable   bool           `json:"reusable"`
	Ephemeral  bool           `json:"ephemeral"`
	Expiration *timestampJSON `json:"expiration"`
	CreatedAt  *timestampJSON `json:"created_at"`
}

func (k preAuthKeyJSON) toPreAuthKey() (PreAuthKey, error) {
	if k.ID == 0 {
		return PreAuthKey{}, failure(CodeOutputInvalid)
	}
	expiration, err := parseTimestamp(k.Expiration)
	if err != nil {
		return PreAuthKey{}, err
	}
	createdAt, err := parseTimestamp(k.CreatedAt)
	if err != nil {
		return PreAuthKey{}, err
	}
	key := PreAuthKey{
		ID:         k.ID,
		Reusable:   k.Reusable,
		Ephemeral:  k.Ephemeral,
		Expiration: expiration,
		CreatedAt:  createdAt,
	}
	if k.User != nil {
		key.UserID = k.User.ID
	}
	return key, nil
}

// validateKeySecret checks the shape of the one plaintext value this adapter
// ever returns, without assuming a prefix: a later Headscale patch may change
// the encoding, and dropping a valid key would break enrollment. Whitespace and
// control characters are refused because such a value would be quoted or logged
// wrongly by any consumer.
func validateKeySecret(key string) error {
	if len(key) < 8 || len(key) > 512 {
		return failure(CodeOutputInvalid)
	}
	for i := 0; i < len(key); i++ {
		if key[i] <= 0x20 || key[i] >= 0x7f {
			return failure(CodeOutputInvalid)
		}
	}
	return nil
}

// timestampJSON is the protobuf Timestamp encoding of Headscale 0.29.5's
// `-o json` output. The CLI serialises the gRPC messages with encoding/json, so
// a timestamp is this object rather than an RFC3339 string (the camelCase and
// RFC3339 shape arrives in a later release, which the version handshake
// rejects). An expiry of {"seconds":-62135596800} is the protobuf "unset"
// instant, which is Go's zero time.
type timestampJSON struct {
	Seconds int64 `json:"seconds"`
	Nanos   int32 `json:"nanos"`
}

func parseTimestamp(raw *timestampJSON) (time.Time, error) {
	if raw == nil || (raw.Seconds == 0 && raw.Nanos == 0) {
		return time.Time{}, nil
	}
	if raw.Nanos < 0 || raw.Nanos >= int32(time.Second) {
		return time.Time{}, failure(CodeOutputInvalid)
	}
	parsed := time.Unix(raw.Seconds, int64(raw.Nanos)).UTC()
	if parsed.Equal(time.Time{}) {
		// The unset instant: report "no expiry" rather than year 1.
		return time.Time{}, nil
	}
	return parsed, nil
}

// decodeOutput applies the strict decode of one machine-readable document: one
// JSON value, bounded size. Unknown fields are discarded, which is what keeps
// key material out of the DTOs.
func decodeOutput(out []byte, target any) error {
	if len(out) == 0 || len(out) > maxStandardOutput {
		return failure(CodeOutputInvalid)
	}
	trimmed := bytes.TrimSpace(out)
	if len(trimmed) == 0 {
		return failure(CodeOutputInvalid)
	}
	if err := json.Unmarshal(trimmed, target); err != nil {
		return failure(CodeOutputInvalid)
	}
	return nil
}

// classifyFailure maps a process failure to one stable code. The markers below
// were read from the real Headscale 0.29.5 CLI; the version handshake is what
// makes that assumption safe, because another release never reaches this
// function. The captured text is inspected and discarded: no stderr byte is
// exposed to a caller, so a diagnostic can quote a socket path or key material
// without leaking it.
//
// Order matters, and the dial case is the reason. 0.29.5 reports an absent or
// unreachable unix socket as
//
//	connecting to headscale: connecting to <socket>: context deadline exceeded
//
// because its own gRPC dial deadline (5s) expires first. Matching the bare
// "context deadline exceeded" before that phrase would report a missing socket as
// HEADSCALE_TIMEOUT, which points the operator at the wrong repair.
func classifyFailure(ctx, commandCtx context.Context, err error, stdout, stderr []byte) error {
	if errors.Is(ctx.Err(), context.Canceled) {
		return failure(CodeCanceled)
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(commandCtx.Err(), context.DeadlineExceeded) {
		return failure(CodeTimeout)
	}
	var startErr *exec.Error
	if errors.As(err, &startErr) {
		// The pinned executable is missing or not executable, so no Headscale
		// answered at all. This is a host-layout defect, not a protocol error.
		return failure(CodeUnavailable)
	}
	diagnostic := strings.ToLower(string(stderr) + "\n" + string(stdout))
	switch {
	case strings.Contains(diagnostic, "unable to read/write to headscale socket"):
		// Headscale's own wording for a socket this process may not use
		// (unix_socket_permission is "0770" and the Web user is outside the
		// group).
		return failure(CodeSocketUnavailable)
	case strings.Contains(diagnostic, "socket") && strings.Contains(diagnostic, "permission denied"):
		return failure(CodeSocketUnavailable)
	case strings.Contains(diagnostic, "connecting to") && strings.Contains(diagnostic, "context deadline exceeded"):
		// The dial never completed: the socket is absent or not accepting. The
		// local service is down or misconfigured; another address is not an
		// option this adapter may take.
		return failure(CodeSocketUnavailable)
	case strings.Contains(diagnostic, "connect: connection refused"),
		strings.Contains(diagnostic, "connect: no such file or directory"):
		return failure(CodeSocketUnavailable)
	case strings.Contains(diagnostic, "error loading config"),
		strings.Contains(diagnostic, "loading configuration"):
		// The configuration is unreadable or invalid, so no service call was
		// attempted. The installer validates it; this is a host-layout defect.
		return failure(CodeUnavailable)
	case strings.Contains(diagnostic, "rpc error: code = deadlineexceeded"):
		// The dial succeeded and the RPC itself ran out of time: the service is
		// reachable but did not answer.
		return failure(CodeTimeout)
	case strings.Contains(diagnostic, "parsing route"):
		// Headscale's own wording when a route is not a prefix: "parsing
		// route: <value>: netip.ParsePrefix(...)". It is a caller mistake, not a
		// command failure, and it is mapped before the not-found branch so a
		// value that happens to contain "not found" still reports the route.
		return failure(CodeRouteInvalid)
	case strings.Contains(diagnostic, "notfound"),
		strings.Contains(diagnostic, "not found"),
		strings.Contains(diagnostic, "no longer exists"):
		// "node not found" for a lookup and "node no longer exists in
		// NodeStore" for an expiry are both 0.29.5's wording for an absent
		// node, verified against the real binary.
		return failure(CodeNotFound)
	case strings.Contains(diagnostic, "already exists"):
		return failure(CodeAlreadyExists)
	}
	return failure(CodeCommandFailed)
}

// boundedBuffer captures child output up to a fixed size. It always reports a
// full write so the child is never blocked or killed by a short write.
type boundedBuffer struct {
	buf       bytes.Buffer
	max       int
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if remaining := b.max - b.buf.Len(); remaining > 0 {
		if len(p) > remaining {
			b.buf.Write(p[:remaining])
			b.truncated = true
		} else {
			b.buf.Write(p)
		}
	} else {
		b.truncated = true
	}
	return len(p), nil
}

func (b *boundedBuffer) Bytes() []byte { return b.buf.Bytes() }

// runCommand is the production executor: exec.CommandContext with no shell, a
// scrubbed environment, no stdin and a bounded capture. WaitDelay guarantees a
// bounded wait even if the child leaves a grandchild holding the pipes.
func runCommand(ctx context.Context, name string, args []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv()
	cmd.Stdin = nil
	cmd.WaitDelay = 2 * time.Second

	stdout := &boundedBuffer{max: maxStandardOutput}
	stderr := &boundedBuffer{max: maxStandardError}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}
