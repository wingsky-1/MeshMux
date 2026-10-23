package node

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/wingsky-1/MeshMux/internal/protocol"
)

const (
	agentPairPath      = "/api/agent/pair"
	agentMetadataPath  = "/api/agent/node"
	agentManifestPath  = "/api/agent/manifest"
	agentConfigPrefix  = "/api/agent/config/"
	agentHeartbeatPath = "/api/agent/heartbeat"
	agentTasksPath     = "/api/agent/tasks"
	agentResultPath    = "/api/agent/result"

	configSHA256Header = "X-MeshMux-Config-SHA256"
	maxErrorBody       = 4 << 10
	maxPairBody        = 4 << 10
	maxMetadataBody    = 4 << 10
	maxManifestBody    = 64 << 10
	// maxConfigBody bounds one candidate document. The v2 document carries
	// the per-Line VLESS users and the REALITY block, so the bound is sized
	// for the fixed maximum of 1024 users and stays bounded: a larger body
	// is rejected instead of being buffered.
	maxConfigBody         = 1 << 20
	maxHeartbeatBody      = 4 << 10
	maxTasksBody          = 64 << 10
	maxResultBody         = 4 << 10
	maxTasks              = 8
	defaultRequestTimeout = 20 * time.Second
)

var (
	stableErrorCode = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,63}$`)
	responseKey     = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,63}$`)
)

// ClientError is returned for validation, transport, protocol and Hub errors.
// Error deliberately includes only the stable code; callers may inspect
// StatusCode for HTTP failures without exposing response bodies or URLs.
type ClientError struct {
	Code       string
	StatusCode int
}

func (e *ClientError) Error() string {
	if e == nil {
		return ""
	}
	return e.Code
}

// ManifestBytes is the release manifest document exactly as the Hub served it.
// It stays opaque here: the update path owns the pin it verifies, so this
// package never parses, rewrites or caches a manifest body.
type ManifestBytes []byte

// Client is the outbound Hub management client. One Client may be reused for
// pairing, polling and reporting; a successful Pair updates its in-memory
// identity for every authenticated call that follows.
type Client struct {
	config   Config
	origin   *url.URL
	http     *http.Client
	mu       sync.RWMutex
	identity Identity
}

// NewClient validates the local contract and builds a client bound to one
// exact Hub origin. A nil httpClient is the production path: system roots,
// hostname verification, TLS 1.2 or newer, a finite 20-second total request
// timeout, proxy environment support and no redirects. Tests may inject a
// client with a trusted test root so real TLS verification remains active;
// errors are still reduced to stable codes.
func NewClient(config Config, identity Identity, httpClient *http.Client) (*Client, error) {
	if err := config.Validate(); err != nil {
		return nil, &ClientError{Code: "CONFIG_INVALID"}
	}
	emptyIdentity := identity == Identity{}
	if !emptyIdentity {
		if err := identity.ValidateFor(config); err != nil {
			return nil, &ClientError{Code: "IDENTITY_INVALID"}
		}
	}

	origin, err := url.Parse(config.HubURL)
	if err != nil || origin.Scheme != "https" || origin.Host == "" {
		return nil, &ClientError{Code: "HUB_URL_INVALID"}
	}

	if httpClient == nil {
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		httpClient = &http.Client{Transport: transport, Timeout: defaultRequestTimeout}
	} else {
		httpClient = cloneHTTPClient(httpClient)
		if httpClient.Timeout <= 0 {
			httpClient.Timeout = defaultRequestTimeout
		}
	}
	httpClient.CheckRedirect = rejectRedirect

	return &Client{
		config:   config,
		origin:   origin,
		http:     httpClient,
		identity: identity,
	}, nil
}

// Pair exchanges a one-time pairing code for the configured node identity.
// IdentityToken is not persisted by this package; the installer owns private
// durable storage after this method returns.
func (c *Client) Pair(ctx context.Context, pairingCode string) (Identity, error) {
	if c == nil {
		return Identity{}, &ClientError{Code: "CLIENT_UNAVAILABLE"}
	}
	if err := c.config.Validate(); err != nil {
		return Identity{}, &ClientError{Code: "CONFIG_INVALID"}
	}
	if !tokenPattern.MatchString(pairingCode) {
		return Identity{}, &ClientError{Code: "PAIRING_CODE_INVALID"}
	}
	if !validVersionString(c.config.AgentVersion) {
		return Identity{}, &ClientError{Code: "VERSION_INVALID"}
	}
	reqBody := protocol.PairingRequest{
		NodeID:        c.config.NodeID,
		Role:          string(c.config.Role),
		PairingCode:   pairingCode,
		AgentVersion:  c.config.AgentVersion,
		KernelVersion: protocol.SingBoxVersion,
	}
	if err := protocol.ValidatePairingRequest(reqBody); err != nil {
		if strings.HasPrefix(err.Error(), "VERSION_") {
			return Identity{}, &ClientError{Code: "VERSION_INVALID"}
		}
		return Identity{}, &ClientError{Code: "PAIRING_INVALID"}
	}

	response, err := c.doJSON(ctx, http.MethodPost, agentPairPath, "", reqBody, maxPairBody)
	if err != nil {
		return Identity{}, err
	}
	// Pairing is the one documented response that may grow with operation
	// metadata. Validate the fields this client consumes while tolerating
	// additional server-owned fields.
	_, err = decodeJSONObject(response.body)
	if err != nil {
		return Identity{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	var body map[string]json.RawMessage
	if err := decodeSingleJSON(response.body, &body); err != nil {
		return Identity{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	var nodeID, identityToken string
	if json.Unmarshal(body["node_id"], &nodeID) != nil || json.Unmarshal(body["identity_token"], &identityToken) != nil {
		return Identity{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	var operationID string
	if json.Unmarshal(body["operation_id"], &operationID) != nil || operationID == "" {
		return Identity{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	identity := Identity{NodeID: nodeID, IdentityToken: identityToken}
	if err := identity.ValidateFor(c.config); err != nil {
		return Identity{}, &ClientError{Code: "IDENTITY_INVALID", StatusCode: response.status}
	}

	c.mu.Lock()
	c.identity = identity
	c.mu.Unlock()
	return identity, nil
}

// Metadata returns the immutable node identity and listener binding.
func (c *Client) Metadata(ctx context.Context) (Metadata, error) {
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return Metadata{}, err
	}
	response, err := c.doJSON(ctx, http.MethodGet, agentMetadataPath, identity.IdentityToken, nil, maxMetadataBody)
	if err != nil {
		return Metadata{}, err
	}
	var metadata Metadata
	if err := decodeResponseObject(response.body, &metadata, "node_id", "role", "vless_port", "ssh_port"); err != nil {
		return Metadata{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	if err := metadata.ValidateFor(c.config); err != nil {
		return Metadata{}, &ClientError{Code: "METADATA_INVALID", StatusCode: response.status}
	}
	return metadata, nil
}

// Manifest fetches the read-only release manifest of this Hub build from the
// fixed agent path. The bytes are returned untouched: the caller (the update
// path) verifies them against its pinned manifest SHA-256 and never falls back
// to a cached newer release.
func (c *Client) Manifest(ctx context.Context) (ManifestBytes, error) {
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return nil, err
	}
	response, err := c.doJSON(ctx, http.MethodGet, agentManifestPath, identity.IdentityToken, nil, maxManifestBody)
	if err != nil {
		return nil, err
	}
	if len(response.body) == 0 {
		return nil, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	return ManifestBytes(response.body), nil
}

// Candidate fetches one exact immutable candidate from the fixed revision
// path. The body is hashed before strict decoding, then bound to Config and
// to the requested revision.
func (c *Client) Candidate(ctx context.Context, revision int64) (CandidateDocument, error) {
	if revision < 1 {
		return CandidateDocument{}, &ClientError{Code: "REVISION_INVALID"}
	}
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return CandidateDocument{}, err
	}
	path := agentConfigPrefix + strconv.FormatInt(revision, 10)
	response, err := c.doJSON(ctx, http.MethodGet, path, identity.IdentityToken, nil, maxConfigBody)
	if err != nil {
		return CandidateDocument{}, err
	}

	claimed := strings.ToLower(strings.TrimSpace(response.header.Get(configSHA256Header)))
	sum := sha256.Sum256(response.body)
	actual := hex.EncodeToString(sum[:])
	if !sha256Pattern.MatchString(claimed) || claimed != actual {
		return CandidateDocument{}, &ClientError{Code: "CANDIDATE_HASH_MISMATCH", StatusCode: response.status}
	}
	var candidate CandidateDocument
	if err := decodeSingleJSON(response.body, &candidate); err != nil {
		return CandidateDocument{}, &ClientError{Code: "CANDIDATE_INVALID", StatusCode: response.status}
	}
	if err := candidate.ValidateFor(c.config); err != nil {
		return CandidateDocument{}, &ClientError{Code: "ROLE_MISMATCH", StatusCode: response.status}
	}
	if candidate.Revision != revision {
		return CandidateDocument{}, &ClientError{Code: "CANDIDATE_REVISION_MISMATCH", StatusCode: response.status}
	}
	return candidate, nil
}

// Heartbeat reports only the fixed Agent and kernel versions. The node
// identity is carried exclusively in the Authorization header.
func (c *Client) Heartbeat(ctx context.Context, req protocol.HeartbeatRequest) error {
	if err := req.Validate(); err != nil {
		return &ClientError{Code: "HEARTBEAT_INVALID"}
	}
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return err
	}
	response, err := c.doJSON(ctx, http.MethodPost, agentHeartbeatPath, identity.IdentityToken, req, maxHeartbeatBody)
	if err != nil {
		return err
	}
	var body struct {
		Status      string `json:"status"`
		OperationID string `json:"operation_id"`
	}
	if err := decodeResponseObject(response.body, &body, "status", "operation_id"); err != nil ||
		body.Status != "paired" || body.OperationID == "" {
		return &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	return nil
}

// Tasks returns the reconnect-safe pending task set, validating every task
// against the frozen protocol and this node's identity.
func (c *Client) Tasks(ctx context.Context) ([]protocol.Task, error) {
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return nil, err
	}
	response, err := c.doJSON(ctx, http.MethodGet, agentTasksPath, identity.IdentityToken, nil, maxTasksBody)
	if err != nil {
		return nil, err
	}
	var body struct {
		Tasks       []json.RawMessage `json:"tasks"`
		OperationID string            `json:"operation_id"`
	}
	if err := decodeResponseObject(response.body, &body, "tasks", "operation_id"); err != nil ||
		body.Tasks == nil || len(body.Tasks) > maxTasks || body.OperationID == "" {
		return nil, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	tasks := make([]protocol.Task, 0, len(body.Tasks))
	for _, raw := range body.Tasks {
		var task protocol.Task
		if err := decodeSingleJSON(raw, &task); err != nil {
			return nil, &ClientError{Code: "TASK_INVALID", StatusCode: response.status}
		}
		if err := protocol.ValidateTask(task); err != nil {
			return nil, &ClientError{Code: "TASK_INVALID", StatusCode: response.status}
		}
		if task.NodeID != identity.NodeID {
			return nil, &ClientError{Code: "TASK_NODE_MISMATCH", StatusCode: response.status}
		}
		tasks = append(tasks, task)
	}
	return tasks, nil
}

// Report submits one explicit task result. Pairing, token material and free
// text response bodies never enter errors or logs.
func (c *Client) Report(ctx context.Context, res protocol.TaskResult) error {
	if err := protocol.ValidateTaskResult(res); err != nil {
		return &ClientError{Code: "RESULT_INVALID"}
	}
	identity, err := c.authenticatedIdentity()
	if err != nil {
		return err
	}
	response, err := c.doJSON(ctx, http.MethodPost, agentResultPath, identity.IdentityToken, res, maxResultBody)
	if err != nil {
		return err
	}
	var body struct {
		Status      string `json:"status"`
		OperationID string `json:"operation_id"`
	}
	if err := decodeResponseObject(response.body, &body, "status", "operation_id"); err != nil ||
		body.Status != "recorded" || body.OperationID == "" {
		return &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.status}
	}
	return nil
}

type jsonResponse struct {
	status int
	header http.Header
	body   []byte
}

func (c *Client) authenticatedIdentity() (Identity, error) {
	if c == nil {
		return Identity{}, &ClientError{Code: "CLIENT_UNAVAILABLE"}
	}
	c.mu.RLock()
	identity := c.identity
	c.mu.RUnlock()
	if identity == (Identity{}) {
		return Identity{}, &ClientError{Code: "IDENTITY_REQUIRED"}
	}
	if err := identity.ValidateFor(c.config); err != nil {
		return Identity{}, &ClientError{Code: "IDENTITY_INVALID"}
	}
	return identity, nil
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	path string,
	token string,
	requestBody any,
	limit int64,
) (jsonResponse, error) {
	if c == nil {
		return jsonResponse{}, &ClientError{Code: "CLIENT_UNAVAILABLE"}
	}
	if ctx == nil || method != http.MethodGet && method != http.MethodPost ||
		method == http.MethodGet && requestBody != nil ||
		method == http.MethodPost && requestBody == nil {
		return jsonResponse{}, &ClientError{Code: "REQUEST_INVALID"}
	}
	fixedPath := path == agentPairPath || path == agentMetadataPath ||
		path == agentManifestPath || path == agentHeartbeatPath || path == agentTasksPath ||
		path == agentResultPath ||
		strings.HasPrefix(path, agentConfigPrefix) && validRevisionPath(path)
	if !fixedPath {
		return jsonResponse{}, &ClientError{Code: "REQUEST_INVALID"}
	}
	requestURL := *c.origin
	requestURL.Path = path
	requestURL.RawPath = ""
	requestURL.RawQuery = ""
	requestURL.Fragment = ""

	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			return jsonResponse{}, &ClientError{Code: "REQUEST_INVALID"}
		}
		body = bytes.NewReader(encoded)
	}
	req, err := http.NewRequestWithContext(ctx, method, requestURL.String(), body)
	if err != nil {
		return jsonResponse{}, &ClientError{Code: "REQUEST_INVALID"}
	}
	if err := ctx.Err(); err != nil {
		return jsonResponse{}, &ClientError{Code: "REQUEST_CANCELLED"}
	}
	req.Header.Set("Accept", "application/json")
	if requestBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		if !tokenPattern.MatchString(token) {
			return jsonResponse{}, &ClientError{Code: "IDENTITY_INVALID"}
		}
		req.Header.Set("Authorization", "Bearer "+token)
	}

	response, err := c.http.Do(req)
	if err != nil {
		return jsonResponse{}, classifyTransportError(ctx, err)
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return jsonResponse{}, c.statusError(ctx, response)
	}
	if err := requireJSONContentType(response.Header); err != nil {
		return jsonResponse{}, &ClientError{Code: "SERVER_RESPONSE_INVALID", StatusCode: response.StatusCode}
	}
	bodyBytes, err := readLimited(response.Body, limit)
	if err != nil {
		code := "SERVER_RESPONSE_INVALID"
		if errors.Is(err, errBodyTooLarge) {
			code = "RESPONSE_TOO_LARGE"
		} else if transportErr := classifyTransportError(ctx, err); transportErr.Code != "NETWORK_ERROR" {
			return jsonResponse{}, transportErr
		}
		return jsonResponse{}, &ClientError{Code: code, StatusCode: response.StatusCode}
	}
	return jsonResponse{status: response.StatusCode, header: response.Header.Clone(), body: bodyBytes}, nil
}

var errBodyTooLarge = errors.New("response body too large")

func (c *Client) statusError(ctx context.Context, response *http.Response) error {
	status := response.StatusCode
	body, err := readLimited(response.Body, maxErrorBody)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			return &ClientError{Code: statusFallback(status), StatusCode: status}
		}
		if transportErr := classifyTransportError(ctx, err); transportErr.Code != "NETWORK_ERROR" {
			return transportErr
		}
		return &ClientError{Code: statusFallback(status), StatusCode: status}
	}
	if !jsonMediaType(response.Header.Get("Content-Type")) {
		return &ClientError{Code: statusFallback(status), StatusCode: status}
	}
	code := extractErrorCode(body)
	if !stableErrorCode.MatchString(code) {
		return &ClientError{Code: statusFallback(status), StatusCode: status}
	}
	return &ClientError{Code: code, StatusCode: status}
}

func extractErrorCode(body []byte) string {
	// Error envelopes include diagnostic fields. Extract only the stable code
	// after this single-document check. No other field is read or exposed.
	fields, err := decodeJSONObject(body)
	if err != nil {
		return ""
	}
	var code string
	if err := json.Unmarshal(fields["error_code"], &code); err != nil {
		return ""
	}
	return code
}

func statusFallback(status int) string {
	switch status {
	case http.StatusUnauthorized:
		return "AGENT_UNAUTHORIZED"
	case http.StatusForbidden:
		return "ACCESS_DENIED"
	case http.StatusGone:
		return "PAIRING_EXPIRED"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusNotFound:
		return "NOT_FOUND"
	default:
		if status >= 300 && status < 400 {
			return "REDIRECT_REJECTED"
		}
		if status >= 500 {
			return "HUB_UNAVAILABLE"
		}
		return "HUB_REQUEST_REJECTED"
	}
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func classifyTransportError(ctx context.Context, err error) *ClientError {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
			return &ClientError{Code: "REQUEST_TIMEOUT"}
		}
		if errors.Is(ctx.Err(), context.Canceled) || errors.Is(err, context.Canceled) {
			return &ClientError{Code: "REQUEST_CANCELLED"}
		}
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &ClientError{Code: "REQUEST_TIMEOUT"}
	}
	var unknownAuthority x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var certificateInvalid x509.CertificateInvalidError
	var systemRoots x509.SystemRootsError
	if errors.As(err, &unknownAuthority) || errors.As(err, &hostnameErr) ||
		errors.As(err, &certificateInvalid) || errors.As(err, &systemRoots) {
		return &ClientError{Code: "TLS_VERIFY_FAILED"}
	}
	return &ClientError{Code: "NETWORK_ERROR"}
}

func cloneHTTPClient(source *http.Client) *http.Client {
	cloned := *source
	if transport, ok := source.Transport.(*http.Transport); ok {
		transport = transport.Clone()
		if transport.TLSClientConfig == nil {
			transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
		} else {
			transport.TLSClientConfig = transport.TLSClientConfig.Clone()
			if transport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
				transport.TLSClientConfig.MinVersion = tls.VersionTLS12
			}
		}
		cloned.Transport = transport
	} else if source.Transport != nil {
		// Custom test round trippers remain injection-capable. Production
		// always takes the nil-client path above with a real TLS transport.
	}
	return &cloned
}

func requireJSONContentType(header http.Header) error {
	if !jsonMediaType(header.Get("Content-Type")) {
		return errors.New("response is not JSON")
	}
	return nil
}

func jsonMediaType(raw string) bool {
	if raw == "" {
		return false
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	return err == nil && mediaType == "application/json"
}

func readLimited(reader io.Reader, limit int64) ([]byte, error) {
	if limit < 1 {
		return nil, errBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, errBodyTooLarge
	}
	return body, nil
}

func decodeSingleJSON(data []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return nil
}

func decodeResponseObject(data []byte, dst any, fields ...string) error {
	obj, err := decodeJSONObject(data)
	if err != nil {
		return err
	}
	if len(obj) != len(fields) {
		return errors.New("unexpected field")
	}
	for _, field := range fields {
		if _, ok := obj[field]; !ok {
			return fmt.Errorf("missing field")
		}
	}
	return decodeSingleJSON(data, dst)
}

func decodeJSONObject(raw json.RawMessage) (map[string]json.RawMessage, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errors.New("expected object")
	}
	obj := make(map[string]json.RawMessage)
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, err
		}
		key, ok := tok.(string)
		if !ok {
			return nil, errors.New("invalid key")
		}
		if !responseKey.MatchString(key) {
			return nil, errors.New("invalid key")
		}
		if _, exists := obj[key]; exists {
			return nil, errors.New("duplicate field")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return nil, err
		}
		obj[key] = value
	}
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}
	return obj, nil
}

func validVersionString(s string) bool {
	if len(s) < 1 || len(s) > 64 || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func validRevisionPath(path string) bool {
	revision := strings.TrimPrefix(path, agentConfigPrefix)
	if revision == "" || revision[0] == '0' || len(revision) > 19 {
		return false
	}
	for _, c := range revision {
		if c < '0' || c > '9' {
			return false
		}
	}
	_, err := strconv.ParseInt(revision, 10, 64)
	return err == nil
}
