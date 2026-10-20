package install

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// TestLocalLineSystemVM runs only in an ephemeral Debian 13 VM with real
// systemd that already hosts an installed Hub. It is the co-located Line
// lifecycle acceptance:
//
//   - phase "install": snapshot the Hub ledger, run the real in-guest Web
//     lifecycle (Web initialization, pending Line creation, pairing, local
//     Line install, Line transport, subscriber, Agent v2 convergence and
//     subscription download), then prove the Hub ledger, its pins and its
//     runtime program survived.
//   - phase "post-reboot": prove the Hub ledger and the local-Line ledger
//     both survive a real reboot and still describe the same host.
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

	localLineWebLifecycle(t)

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

const (
	// localLineVMAdminPassword is the disposable VM administrator password.
	// It is never printed and only exists inside this ephemeral guest.
	localLineVMAdminPassword = "local-line-vm-password-2026"
	// localLineVMPollInterval and localLineVMPollDeadline bound the Agent
	// convergence wait: the Agent polls every 30 seconds, so a short poll
	// with a hard deadline is enough and no long fixed sleep is used.
	localLineVMPollInterval = 5 * time.Second
	localLineVMPollDeadline = 10 * time.Minute
	// localLineVMSSHPort is the real SSH listener the Hub VM image boots with.
	localLineVMSSHPort = 22
)

var (
	localLineVMCSRFPattern    = regexp.MustCompile(`<input type="hidden" name="csrf" value="([A-Za-z0-9_-]+)"`)
	localLineVMNodeIDPattern  = regexp.MustCompile(`Node ID（不可变）</dt><dd><code>([0-9a-f]{32})</code>`)
	localLineVMPairingPattern = regexp.MustCompile(`一次性配对码</dt><dd><code>([A-Za-z0-9_-]{43})</code>`)
	localLineVMTokenPattern   = regexp.MustCompile(`<pre class="sub-secret">([A-Za-z0-9_-]{48})</pre>`)
)

// localLineWebLifecycle drives the real in-guest lifecycle through the
// installed Hub: Web setup and login over loopback TLS, a pending Line, the
// real installer pairing, the Line transport, one subscriber, Agent v2
// convergence, the subscription download and a repair.
//
// Every HTTP request dials 127.0.0.1:443 while keeping the public Host and TLS
// server name from the recorded Hub domains; the /etc/hosts mapping is written
// here so the installer's own preflight and Agent client use the same route.
func localLineWebLifecycle(t *testing.T) {
	t.Helper()
	hub, exists, err := ReadState("/")
	if err != nil || !exists || hub.Status != "installed" {
		localLineVMFatal(t, hub.OperationID, "web", "HUB_LEDGER_MISSING",
			"the Web lifecycle requires an installed Hub ledger (exists=%v err=%v)", exists, err)
	}
	origin := hubOriginFor(hub)
	subscriptionOrigin := "https://" + hub.Config.SubscriptionDomain
	if origin == "" || hub.Config.SubscriptionDomain == "" {
		localLineVMFatal(t, hub.OperationID, "web", "HUB_ORIGIN_MISSING",
			"the Hub ledger records no management or subscription origin")
	}
	localLineVMPrepareHosts(t, hub.Config)
	localLineVMTrustCaddyCA(t, hub.OperationID)
	admin := localLineVMAdminClient(t)

	localLineVMWebSetup(t, admin, origin)
	vlessPort := localLineVMFreePort(t)
	nodeID, pairingCode := localLineVMCreateLine(t, admin, origin, vlessPort)
	cfg := node.Config{
		HubURL:    origin,
		NodeID:    nodeID,
		Role:      node.RoleEdge,
		VLESSPort: vlessPort,
		SSHPort:   localLineVMSSHPort,
	}
	localLineVMInstallLine(t, cfg, pairingCode)
	localLineVMSaveLineTransport(t, admin, origin, nodeID, vlessPort)
	token := localLineVMCreateSubscriber(t, admin, origin, nodeID)
	localLineVMWaitConverged(t, admin, origin, subscriptionOrigin, nodeID, token)
	localLineVMRepair(t, cfg)
	localLineVMRequireServices(t, hub.OperationID)
}

// localLineVMPrepareHosts maps the recorded Hub domains to loopback. The VM is
// disposable and the Hub Caddy listener owns 443 on every interface, so the
// installer preflight, the Agent client and the download all resolve locally.
func localLineVMPrepareHosts(t *testing.T, cfg Config) {
	t.Helper()
	const hostsPath = "/etc/hosts"
	current, err := os.ReadFile(hostsPath)
	if err != nil {
		localLineVMFatal(t, "", "web", "HOSTS_UNAVAILABLE", "cannot read /etc/hosts: %v", err)
	}
	lines := string(current)
	var add strings.Builder
	for _, domain := range []string{cfg.ManagementDomain, cfg.SubscriptionDomain, cfg.HeadscaleDomain} {
		if domain == "" || strings.Contains(lines, " "+domain+"\n") || strings.Contains(lines, " "+domain+" ") {
			continue
		}
		fmt.Fprintf(&add, "127.0.0.1 %s # meshmux local-line VM\n", domain)
	}
	if add.Len() == 0 {
		return
	}
	if !strings.HasSuffix(lines, "\n") {
		lines += "\n"
	}
	if err := os.WriteFile(hostsPath, []byte(lines+add.String()), 0644); err != nil {
		localLineVMFatal(t, "", "web", "HOSTS_UNAVAILABLE", "cannot update /etc/hosts: %v", err)
	}
}

// localLineVMTrustCaddyCA trusts the Hub's internal Caddy CA in the VM system
// store. The disposable Hub VM is installed with internal TLS, so the same
// trust roots that production would get from ACME are exercised here.
func localLineVMTrustCaddyCA(t *testing.T, operationID string) {
	t.Helper()
	const caPath = "/var/lib/meshmux-caddy/caddy/pki/authorities/local/root.crt"
	const dest = "/usr/local/share/ca-certificates/meshmux-local-line-vm.crt"
	pemData, err := os.ReadFile(caPath)
	if err != nil || !strings.Contains(string(pemData), "BEGIN CERTIFICATE") {
		localLineVMFatal(t, operationID, "web", "CADDY_INTERNAL_CA_MISSING",
			"the Hub has no internal Caddy CA; this VM profile requires a Hub installed with internal TLS")
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0755); err != nil {
		localLineVMFatal(t, operationID, "web", "CADDY_CA_TRUST_FAILED", "cannot create the system CA directory: %v", err)
	}
	if err := os.WriteFile(dest, pemData, 0644); err != nil {
		localLineVMFatal(t, operationID, "web", "CADDY_CA_TRUST_FAILED", "cannot stage the Caddy CA: %v", err)
	}
	if out, err := (ExecRunner{}).Run(context.Background(), "update-ca-certificates"); err != nil {
		localLineVMFatal(t, operationID, "web", "CADDY_CA_TRUST_FAILED",
			"update-ca-certificates failed: %v (%s)", err, strings.TrimSpace(string(out)))
	}
}

// localLineVMAdminClient returns the browser-like client of the operator
// console: one cookie jar, no redirect following (so every 303 is asserted),
// and a dialer that always reaches the guest loopback on 443.
func localLineVMAdminClient(t *testing.T) *http.Client {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		localLineVMFatal(t, "", "web", "COOKIE_JAR_FAILED", "cannot create the console cookie jar: %v", err)
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, "127.0.0.1:443")
	}
	return &http.Client{
		Transport: transport,
		Jar:       jar,
		Timeout:   30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// localLineVMRequest performs one console request and returns the status, the
// bounded body and the operation identifier of the response.
func localLineVMRequest(t *testing.T, client *http.Client, method, target string, form url.Values, origin string) (int, []byte, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, target, body)
	if err != nil {
		localLineVMFatal(t, "", "web", "WEB_REQUEST_INVALID", "cannot build a console request: %v", err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)
	}
	resp, err := client.Do(req)
	if err != nil {
		localLineVMFatal(t, "", "web", "WEB_UNREACHABLE",
			"the Hub console is not reachable over loopback TLS: %v", err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		localLineVMFatal(t, resp.Header.Get("X-Operation-ID"), "web", "WEB_READ_FAILED", "cannot read the console response")
	}
	return resp.StatusCode, data, resp.Header.Get("X-Operation-ID")
}

// localLineVMFetchCSRF reads one authenticated or anonymous console page and
// returns its CSRF field.
func localLineVMFetchCSRF(t *testing.T, client *http.Client, target, origin, stage string) string {
	t.Helper()
	status, body, op := localLineVMRequest(t, client, http.MethodGet, target, nil, origin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, stage, "WEB_PAGE_FAILED", "GET %s returned status %d", localLineVMPageName(target), status)
	}
	match := localLineVMCSRFPattern.FindSubmatch(body)
	if match == nil {
		localLineVMFatal(t, op, stage, "WEB_CSRF_MISSING", "the console page carries no CSRF field")
	}
	return string(match[1])
}

// localLineVMWebSetup initializes the administrator when the Hub is fresh and
// logs in with the disposable password. A second run of the same phase logs in
// to the already initialized Hub instead of failing.
func localLineVMWebSetup(t *testing.T, client *http.Client, origin string) {
	t.Helper()
	status, body, op := localLineVMRequest(t, client, http.MethodGet, origin+"/setup", nil, origin)
	switch status {
	case http.StatusOK:
		csrf := localLineVMCSRF(body)
		bootstrap, err := os.ReadFile("/var/lib/meshmux/bootstrap.token")
		if err != nil {
			localLineVMFatal(t, op, "web", "BOOTSTRAP_UNAVAILABLE",
				"cannot read the one-time bootstrap credential file: %v", err)
		}
		status, _, op = localLineVMRequest(t, client, http.MethodPost, origin+"/setup", url.Values{
			"csrf":      {csrf},
			"bootstrap": {strings.TrimSpace(string(bootstrap))},
			"password":  {localLineVMAdminPassword},
		}, origin)
		if status != http.StatusSeeOther {
			localLineVMFatal(t, op, "web", "WEB_SETUP_FAILED",
				"the administrator initialization was rejected with status %d", status)
		}
	case http.StatusForbidden:
		// SETUP_CLOSED: the administrator already exists in this VM.
	default:
		localLineVMFatal(t, op, "web", "WEB_SETUP_FAILED", "GET /setup returned status %d", status)
	}
	csrf := localLineVMFetchCSRF(t, client, origin+"/login", origin, "web")
	status, _, op = localLineVMRequest(t, client, http.MethodPost, origin+"/login", url.Values{
		"csrf":     {csrf},
		"password": {localLineVMAdminPassword},
	}, origin)
	if status != http.StatusSeeOther {
		localLineVMFatal(t, op, "web", "WEB_LOGIN_FAILED", "the administrator login was rejected with status %d", status)
	}
	// A 200 here proves the session cookie jar really holds an authenticated
	// session; the node page is never served anonymously.
	status, _, op = localLineVMRequest(t, client, http.MethodGet, origin+"/nodes", nil, origin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, "web", "WEB_LOGIN_FAILED", "the authenticated node page returned status %d", status)
	}
}

// localLineVMCreateLine creates one pending edge Line through the real console
// form and returns its node ID and one-time pairing code. The code is never
// logged.
func localLineVMCreateLine(t *testing.T, client *http.Client, origin string, vlessPort int) (string, string) {
	t.Helper()
	csrf := localLineVMFetchCSRF(t, client, origin+"/nodes", origin, "web")
	status, body, op := localLineVMRequest(t, client, http.MethodPost, origin+"/nodes", url.Values{
		"csrf":         {csrf},
		"role":         {"edge"},
		"display_name": {"vm-local-line"},
		"vless_port":   {strconv.Itoa(vlessPort)},
		"ssh_port":     {strconv.Itoa(localLineVMSSHPort)},
	}, origin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, "web", "LINE_CREATE_FAILED", "the pending Line form returned status %d", status)
	}
	nodeMatch := localLineVMNodeIDPattern.FindSubmatch(body)
	pairMatch := localLineVMPairingPattern.FindSubmatch(body)
	if nodeMatch == nil || pairMatch == nil {
		localLineVMFatal(t, op, "web", "LINE_CREATE_FAILED",
			"the pending Line page carries no node ID or one-time pairing code")
	}
	return string(nodeMatch[1]), string(pairMatch[1])
}

// localLineVMInstallLine runs the real installer with the real pairing code.
func localLineVMInstallLine(t *testing.T, cfg node.Config, pairingCode string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer cancel()
	operationID, err := NewOperationID()
	if err != nil {
		localLineVMFatal(t, "", "preflight", "OPERATION_ID_FAILED", "cannot generate an operation ID: %v", err)
	}
	result, err := InstallNode(ctx, cfg, operationID, false, pairingCode, NodeApplyOptions{Root: "/", Runner: ExecRunner{}})
	if err != nil || result.Status != "installed" {
		localLineVMFatal(t, result.OperationID, result.Stage, result.ErrorCode,
			"the co-located Line install did not reach installed (status=%s err=%v)", result.Status, err)
	}
}

// localLineVMSaveLineTransport stores the Line transport through the real
// console form. The Hub generates the REALITY key pair; the test never sees it.
func localLineVMSaveLineTransport(t *testing.T, client *http.Client, origin, nodeID string, vlessPort int) {
	t.Helper()
	csrf := localLineVMFetchCSRF(t, client, origin+"/subscribers", origin, "web")
	status, _, op := localLineVMRequest(t, client, http.MethodPost, origin+"/lines", url.Values{
		"csrf":             {csrf},
		"node_id":          {nodeID},
		"display_name":     {"vm-local-line"},
		"sort_order":       {"0"},
		"server":           {strings.TrimPrefix(origin, "https://")},
		"port":             {strconv.Itoa(vlessPort)},
		"server_name":      {"www.example.invalid"},
		"handshake_server": {"www.example.invalid"},
		"handshake_port":   {"443"},
	}, origin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, "web", "LINE_TRANSPORT_FAILED", "the Line transport form returned status %d", status)
	}
}

// localLineVMCreateSubscriber creates one subscriber on the Line and returns
// the one-time subscription token. The token is never logged.
func localLineVMCreateSubscriber(t *testing.T, client *http.Client, origin, nodeID string) string {
	t.Helper()
	csrf := localLineVMFetchCSRF(t, client, origin+"/subscribers", origin, "web")
	status, body, op := localLineVMRequest(t, client, http.MethodPost, origin+"/subscribers", url.Values{
		"csrf":           {csrf},
		"display_name":   {"vm-subscriber"},
		"line_" + nodeID: {"1"},
	}, origin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, "web", "SUBSCRIBER_CREATE_FAILED", "the subscriber form returned status %d", status)
	}
	match := localLineVMTokenPattern.FindSubmatch(body)
	if match == nil {
		localLineVMFatal(t, op, "web", "SUBSCRIBER_CREATE_FAILED", "the subscriber page carries no one-time subscription token")
	}
	return string(match[1])
}

// localLineVMWaitConverged waits for the real Agent to apply the v2 candidate,
// then proves the published subscription matches the active candidate.
func localLineVMWaitConverged(t *testing.T, client *http.Client, origin, subscriptionOrigin, nodeID, token string) {
	t.Helper()
	deadline := time.Now().Add(localLineVMPollDeadline)
	var observed int64
	var digestMatch bool
	for {
		status, body, op := localLineVMRequest(t, client, http.MethodGet, origin+"/api/nodes", nil, origin)
		if status != http.StatusOK {
			localLineVMFatal(t, op, "agent", "AGENT_STATUS_FAILED", "the node API returned status %d", status)
		}
		var listed struct {
			Nodes []struct {
				ID                   string `json:"id"`
				Offline              bool   `json:"offline"`
				LatestConfigRevision int64  `json:"latest_config_revision"`
				LatestConfigSHA256   string `json:"latest_config_sha256"`
				ObservedRevision     int64  `json:"observed_config_revision"`
				ObservedConfigSHA256 string `json:"observed_config_sha256"`
			} `json:"nodes"`
		}
		if err := json.Unmarshal(body, &listed); err != nil {
			localLineVMFatal(t, op, "agent", "AGENT_STATUS_FAILED", "the node API response is not valid JSON")
		}
		for _, n := range listed.Nodes {
			if n.ID != nodeID {
				continue
			}
			observed = n.ObservedRevision
			digestMatch = n.ObservedConfigSHA256 != "" && n.ObservedConfigSHA256 == n.LatestConfigSHA256
			if !n.Offline && n.ObservedRevision >= 2 && n.ObservedRevision == n.LatestConfigRevision && digestMatch {
				localLineVMAssertSubscription(t, client, subscriptionOrigin, token)
				return
			}
		}
		if time.Now().After(deadline) {
			localLineVMFatal(t, "", "agent", "AGENT_CONVERGENCE_TIMEOUT",
				"the Agent did not confirm the v2 candidate within the deadline (observed revision=%d, digest match=%v)", observed, digestMatch)
		}
		time.Sleep(localLineVMPollInterval)
	}
}

// localLineVMAssertSubscription proves the download is served, that the active
// candidate is a v2 document with REALITY and users, and that every published
// UUID appears in the downloaded client configuration. Values are compared in
// memory only and never printed.
func localLineVMAssertSubscription(t *testing.T, client *http.Client, subscriptionOrigin, token string) {
	t.Helper()
	candidateBody, err := os.ReadFile(node.ActiveCandidatePath)
	if err != nil {
		localLineVMFatal(t, "", "agent", "ACTIVE_CANDIDATE_MISSING", "the Agent active candidate is not readable: %v", err)
	}
	var document node.CandidateDocument
	if err := json.Unmarshal(candidateBody, &document); err != nil {
		localLineVMFatal(t, "", "agent", "ACTIVE_CANDIDATE_INVALID", "the Agent active candidate is not valid JSON")
	}
	if document.Schema != node.CandidateSchemaV2 {
		localLineVMFatal(t, "", "agent", "ACTIVE_CANDIDATE_NOT_V2",
			"the Agent active candidate is not a v2 document (schema=%q)", document.Schema)
	}
	if document.Reality == nil {
		localLineVMFatal(t, "", "agent", "ACTIVE_CANDIDATE_NOT_V2", "the Agent active candidate carries no REALITY block")
	}
	if len(document.Users) == 0 {
		localLineVMFatal(t, "", "agent", "ACTIVE_CANDIDATE_NOT_V2", "the Agent active candidate carries no VLESS user")
	}
	status, body, op := localLineVMRequest(t, client, http.MethodGet,
		subscriptionOrigin+"/subscription/"+token+"/sing-box.json", nil, subscriptionOrigin)
	if status != http.StatusOK {
		localLineVMFatal(t, op, "subscription", "SUBSCRIPTION_DOWNLOAD_FAILED",
			"the subscription download returned status %d", status)
	}
	if !json.Valid(body) || len(body) == 0 {
		localLineVMFatal(t, op, "subscription", "SUBSCRIPTION_INVALID", "the subscription download is not a non-empty JSON document")
	}
	for _, user := range document.Users {
		if !strings.Contains(string(body), user.UUID) {
			localLineVMFatal(t, op, "subscription", "SUBSCRIPTION_USER_MISSING",
				"the downloaded client configuration does not carry every active candidate user")
		}
	}
}

// localLineVMRepair repairs the co-located Line and proves the identity and
// the active candidate are untouched.
func localLineVMRepair(t *testing.T, cfg node.Config) {
	t.Helper()
	identityBefore := mustReadVM(t, node.IdentityPath)
	candidateBefore := mustReadVM(t, node.ActiveCandidatePath)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	operationID, err := NewOperationID()
	if err != nil {
		localLineVMFatal(t, "", "preflight", "OPERATION_ID_FAILED", "cannot generate an operation ID: %v", err)
	}
	result, err := InstallNode(ctx, cfg, operationID, true, "", NodeApplyOptions{Root: "/", Runner: ExecRunner{}})
	if err != nil || result.Status != "installed" {
		localLineVMFatal(t, result.OperationID, result.Stage, result.ErrorCode,
			"the co-located Line repair did not reach installed (status=%s err=%v)", result.Status, err)
	}
	if string(identityBefore) != string(mustReadVM(t, node.IdentityPath)) {
		localLineVMFatal(t, result.OperationID, "verify", "REPAIR_ROTATED_IDENTITY",
			"the repair rotated the persisted Agent identity")
	}
	if string(candidateBefore) != string(mustReadVM(t, node.ActiveCandidatePath)) {
		localLineVMFatal(t, result.OperationID, "verify", "REPAIR_REPLACED_CANDIDATE",
			"the repair replaced the active v2 candidate")
	}
}

// localLineVMRequireServices proves the Hub services and the Line services are
// active after the whole lifecycle.
func localLineVMRequireServices(t *testing.T, operationID string) {
	t.Helper()
	runner := ExecRunner{}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	for _, unit := range []string{
		"meshmux-web.service", "meshmux-headscale.service", "meshmux-caddy.service",
		node.AgentUnit, node.SingBoxUnit,
	} {
		if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", unit); err != nil {
			localLineVMFatal(t, operationID, "verify", "SERVICE_INACTIVE", "unit %s is not active", unit)
		}
	}
}

// localLineVMFreePort reserves one currently free TCP port and releases it for
// the installer. The VM is disposable and no other process races for it.
func localLineVMFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "0.0.0.0:0")
	if err != nil {
		localLineVMFatal(t, "", "web", "FREE_PORT_UNAVAILABLE", "cannot reserve a free VLESS port: %v", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	return port
}

// localLineVMCSRF extracts the first CSRF field of one console page.
func localLineVMCSRF(body []byte) string {
	match := localLineVMCSRFPattern.FindSubmatch(body)
	if match == nil {
		return ""
	}
	return string(match[1])
}

// localLineVMPageName keeps fatal messages free of query strings and secrets.
func localLineVMPageName(target string) string {
	if parsed, err := url.Parse(target); err == nil {
		return parsed.Path
	}
	return "the console page"
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
