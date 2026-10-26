package node

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// OutLinkMethod is the pinned Shadowsocks method of the Line→Out double-hop.
// Under Ruling R7 the path is never bare VLESS on the public internet.
const OutLinkMethod = "2022-blake3-aes-128-gcm"

// OutEgressHTTP marks an egress whose dial body is an external HTTP proxy
// instead of a MeshMux Out node (Ruling R11). The type field is omitted on the
// SS/link-key shape, so every stored document keeps its exact bytes. The value
// is owned by the wire contract so the subscription selection cannot copy a
// second literal.
const OutEgressHTTP = protocol.OutEgressHTTP

// maxProxyCredentialBytes bounds one HTTP proxy username or password. Basic
// credentials are short operator strings, never documents.
const maxProxyCredentialBytes = 256

// outLinkKeyBytes is the raw length of one link key. The 128-gcm method
// requires exactly 16 bytes on the dial side: `sing-box check` refuses any
// other length with "bad key length, required 16". (Ruling R7 names 32 bytes,
// which the kernel's outbound gate rejects; the method pins the length.)
const outLinkKeyBytes = 16

// OutEgress is the Hub-issued dial body of one Line's "out" outbound: either
// the selected Out node's address/port plus the SS link key (Ruling R7), or an
// external HTTP proxy's address/port plus optional Basic credentials
// (Ruling R11). The two shapes never mix.
//
// The endpoint is the egress the binding names, never the Line itself:
// rendering the Line address here would silently turn the Out path into a Line
// egress, the leak the fail-closed block stub exists to prevent. The key,
// username and password are node secrets in the same class as the per-Line
// VLESS UUIDs and the REALITY private key: they travel only over the
// authenticated Hub<->Agent channel (inside the immutable candidate document)
// and are never written to a public response, a subscription artifact or a
// generic log line. The stored operator URL never carries userinfo; UI
// projections show only host:port.
//
// UUID is the void Task-2 shape (a VLESS client credential). Stored
// documents rendered before the SS switch keep decoding and rendering
// byte-identical VLESS bytes, so their pinned digests still verify; the void
// credential no longer authenticates anywhere because the Out side is
// SS-only. New issuances always carry Key. The two never mix.
type OutEgress struct {
	Server string `json:"server"`
	Port   int    `json:"port"`
	// Type is empty for the SS link shape and "http" for an external HTTP
	// proxy. It is omitted for the SS shape so stored bytes stay identical.
	Type     string `json:"type,omitempty"`
	Key      string `json:"key,omitempty"`
	UUID     string `json:"uuid,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
}

// NewOutLinkKey issues one random link key: 16 bytes, base64-std encoded. It
// never derives from anything guessable; every transport set mints fresh
// entropy and an address update preserves it.
func NewOutLinkKey() (string, error) {
	var raw [outLinkKeyBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", errors.New("OUT_LINK_KEY_FAILED: the link key could not be issued")
	}
	return base64.StdEncoding.EncodeToString(raw[:]), nil
}

// ValidateOutLinkKey checks the encoded shape of one link key: canonical
// base64-std decoding to exactly the method's 16 bytes.
func ValidateOutLinkKey(key string) error {
	const invalid = "OUT_EGRESS_INVALID: out link key must be 16 random bytes in base64-std"
	if len(key) == 0 || len(key) > 64 {
		return errors.New(invalid)
	}
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != outLinkKeyBytes || base64.StdEncoding.EncodeToString(raw) != key {
		return errors.New(invalid)
	}
	return nil
}

// ParseHTTPProxyURL validates one operator-supplied HTTP proxy URL and returns
// its canonical dial body. Exactly one http:// URL with a host and an explicit
// port is accepted; optional userinfo is split into the credential fields so
// the stored URL can never contain a secret. A path is rejected because an
// HTTP proxy URL is an endpoint, not a resource URL.
func ParseHTTPProxyURL(raw string) (OutEgress, error) {
	invalid := errors.New("HTTP_PROXY_INVALID: provide one http://host:port URL with optional credentials")
	if raw == "" || len(raw) > 512 || strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, " \t\r\n") {
		return OutEgress{}, invalid
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "http" || parsed.Opaque != "" ||
		parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.RawPath != "" || (parsed.Path != "" && parsed.Path != "/") {
		return OutEgress{}, invalid
	}
	portRaw := parsed.Port()
	if portRaw == "" || len(portRaw) > 5 {
		return OutEgress{}, invalid
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		return OutEgress{}, invalid
	}
	server := strings.ToLower(parsed.Hostname())
	if !validRealityHost(server) {
		return OutEgress{}, invalid
	}
	var username, password string
	if parsed.User != nil {
		username = parsed.User.Username()
		password, _ = parsed.User.Password()
		if username == "" {
			return OutEgress{}, invalid
		}
	}
	egress := OutEgress{Server: server, Port: port, Type: OutEgressHTTP, Username: username, Password: password}
	if err := egress.Validate(); err != nil {
		return OutEgress{}, err
	}
	return egress, nil
}

// ProxyURL returns the canonical stored form of an HTTP proxy egress:
// http://host:port. It never carries userinfo, so it is safe for a list
// projection. A non-HTTP egress has no proxy URL.
func (e OutEgress) ProxyURL() string {
	if e.Type != OutEgressHTTP {
		return ""
	}
	return "http://" + net.JoinHostPort(e.Server, strconv.Itoa(e.Port))
}

// Validate checks the egress shape: one IP address or lowercase DNS name, one
// bounded port, and exactly one credential shape — the SS link key (or the
// void VLESS UUID only for stored history), or an external HTTP proxy with
// optional Basic credentials. No key, UUID and HTTP type may mix.
func (e OutEgress) Validate() error {
	if !validRealityHost(e.Server) {
		return errors.New("OUT_EGRESS_INVALID: need one IP address or lowercase DNS name without scheme, path, port or credentials")
	}
	if e.Port < 1 || e.Port > 65535 {
		return errors.New("OUT_EGRESS_INVALID: out port must be 1-65535")
	}
	switch e.Type {
	case "":
		switch {
		case e.Username != "" || e.Password != "":
			return errors.New("OUT_EGRESS_INVALID: an SS out egress carries no proxy credentials")
		case e.Key != "" && e.UUID != "":
			return errors.New("OUT_EGRESS_INVALID: out credential must be either the link key or the legacy UUID, never both")
		case e.Key != "":
			return ValidateOutLinkKey(e.Key)
		case e.UUID != "":
			if !protocol.ValidUUIDv4(e.UUID) {
				return errors.New("OUT_EGRESS_INVALID: out credential must be a canonical lowercase UUIDv4")
			}
			return nil
		default:
			return errors.New("OUT_EGRESS_INVALID: out credential must be a Hub-issued link key")
		}
	case OutEgressHTTP:
		if e.Key != "" || e.UUID != "" {
			return errors.New("OUT_EGRESS_INVALID: an http out egress carries no link key or UUID")
		}
		if e.Username == "" && e.Password != "" {
			return errors.New("OUT_EGRESS_INVALID: an http password requires a username")
		}
		if err := validateProxyCredential(e.Username); err != nil {
			return err
		}
		return validateProxyCredential(e.Password)
	default:
		return errors.New("OUT_EGRESS_INVALID: out egress type must be empty or http")
	}
}

// validateProxyCredential bounds one HTTP Basic credential string. The value
// is optional; an empty value is legal (no auth or an empty password). Control
// characters and NUL are rejected because the value reaches a kernel document
// and a header.
func validateProxyCredential(value string) error {
	if len(value) > maxProxyCredentialBytes || !utf8.ValidString(value) {
		return errors.New("OUT_EGRESS_INVALID: http proxy credentials must be valid UTF-8 up to 256 bytes")
	}
	for _, r := range value {
		if r == 0 || r < 0x20 || r == 0x7f {
			return errors.New("OUT_EGRESS_INVALID: http proxy credentials must not contain control characters")
		}
	}
	return nil
}
