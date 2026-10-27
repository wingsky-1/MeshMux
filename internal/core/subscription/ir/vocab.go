// Package ir holds the kernel-neutral vocabulary and immutable value shapes
// shared by the subscription composer and the policy generators.
//
// The package lives under internal/subscription on purpose: the subscription
// IR is owned by that layer, so policy may import ir downward while
// subscription never imports policy. It is a leaf (standard library only), so
// it adds no dependency edge of its own.
//
// Everything here is data plus pure predicates. It performs no I/O and holds
// no clock, database or random source.
package ir

import (
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"unicode"

	"github.com/wingsky-1/MeshMux/internal/core/node/protocol"
)

// Action is the egress of one selected rule. Both the rule library and the
// composer store exactly these three values; an Out or mesh endpoint is never a
// per-rule action.
type Action string

const (
	ActionDirect Action = "direct"
	ActionProxy  Action = "proxy"
	ActionReject Action = "reject"
)

// MatcherKind is the single matcher family of one rule. The library stocks
// exactly these six; SSID stays a generator capability, never a library kind.
type MatcherKind string

const (
	MatcherDomain       MatcherKind = "domain"
	MatcherDomainSuffix MatcherKind = "domain_suffix"
	MatcherIPCIDR       MatcherKind = "ipcidr"
	MatcherGeoSite      MatcherKind = "geosite"
	MatcherGeoIP        MatcherKind = "geoip"
	MatcherRuleSet      MatcherKind = "ruleset"
)

// Geo rule-set tag spellings. A GeoSite or GeoIP matcher renders as the kernel
// rule-set tag "<kind>-<code>", so the composer, the policy generators, the
// pin check and the client-document adapter all name the same tag. The prefix
// is derived from the matcher kind instead of being retyped, so the two can
// never drift.
const (
	GeoSiteTagPrefix = string(MatcherGeoSite) + "-"
	GeoIPTagPrefix   = string(MatcherGeoIP) + "-"
)

// GeoSiteTag returns the rendered rule-set tag of one GeoSite code.
func GeoSiteTag(code string) string { return GeoSiteTagPrefix + code }

// GeoIPTag returns the rendered rule-set tag of one GeoIP code.
func GeoIPTag(code string) string { return GeoIPTagPrefix + code }

// SplitGeoTag reports whether tag is a rendered geo rule-set tag and returns
// its matcher kind plus the code part after the prefix. An empty code is not a
// tag. A version suffix (for example "cn@2026.10.21") stays part of the code:
// the caller decides what it accepts.
func SplitGeoTag(tag string) (MatcherKind, string, bool) {
	if code, ok := strings.CutPrefix(tag, GeoSiteTagPrefix); ok && code != "" {
		return MatcherGeoSite, code, true
	}
	if code, ok := strings.CutPrefix(tag, GeoIPTagPrefix); ok && code != "" {
		return MatcherGeoIP, code, true
	}
	return "", "", false
}

// TailnetIPv4Prefix and TailnetIPv6Prefix are the address ranges the managed
// Headscale instance hands to mesh devices. The mesh domain and the mesh
// exporter both read them from here, so a route check, the rendered Headscale
// prefixes and a device document cannot drift.
const (
	TailnetIPv4Prefix = "100.64.0.0/10"
	TailnetIPv6Prefix = "fd7a:115c:a1e0::/48"
)

// Mesh purpose values. The mesh domain owns the lifecycle semantics and the
// subscription package owns the renderable subset; both read the spellings from
// here so a purpose can never be spelled two ways across the boundary. The
// values are the stored ones and are never translated.
const (
	MeshPurposeProxyMesh    = "proxy_mesh"
	MeshPurposeMeshOnly     = "mesh_only"
	MeshPurposeSubnetRouter = "subnet_router"
)

// MeshView is the read-only, non-secret projection of one mesh device that a
// client policy may consume. It carries no credential, enrollment secret, auth
// key or Line private key. Subscription exposes it as MeshConfigModel; policy
// consumes this shape without importing the subscription package.
type MeshView struct {
	DeviceID        string
	DisplayName     string
	Hostname        string
	ControlURL      string
	TailnetPrefixes []string
	LineLabels      []string
}

// MaxRuleValues bounds one matcher value list. It is shared by the rule
// library row and the composer selection so both halves of the contract agree.
const MaxRuleValues = 64

// MaxMeshLabels bounds the proxy labels and tailnet prefixes a mesh view may
// carry, so a foreign caller cannot turn the read-only projection into an
// unbounded input.
const MaxMeshLabels = 32

// ValidLabel reports whether value is a printable 1-80 rune display label. It
// is the shared shape check of the display names both layers accept.
func ValidLabel(value string) bool {
	if value == "" || len([]rune(value)) > 80 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Validate checks the read-only mesh projection at the module boundary. It is
// the anti-corruption step for the one foreign structure policy consumes: an
// empty or malformed identity is refused, every prefix must be one canonical
// CIDR network and every label must be a bounded printable name. The order is
// preserved because the policy derives rule order from it.
func (m MeshView) Validate() error {
	if m.DeviceID != "" && !ValidID(m.DeviceID) {
		return errInvalidMeshView
	}
	if m.DisplayName != "" && !ValidLabel(m.DisplayName) {
		return errInvalidMeshView
	}
	if m.Hostname != "" && !validMeshHostname(m.Hostname) {
		return errInvalidMeshView
	}
	if len(m.TailnetPrefixes) > MaxMeshLabels || len(m.LineLabels) > MaxMeshLabels {
		return errInvalidMeshView
	}
	for _, raw := range m.TailnetPrefixes {
		if _, err := CanonicalPrefix(raw); err != nil {
			return errInvalidMeshView
		}
	}
	for _, label := range m.LineLabels {
		if !ValidLabel(label) {
			return errInvalidMeshView
		}
	}
	return nil
}

// validMeshHostname accepts one canonical lowercase DNS label of 1-63
// characters, the only hostname shape a mesh endpoint may carry.
func validMeshHostname(hostname string) bool {
	if len(hostname) == 0 || len(hostname) > 63 {
		return false
	}
	for i := 0; i < len(hostname); i++ {
		c := hostname[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && c != '-' {
			return false
		}
		if (i == 0 || i == len(hostname)-1) && !alnum {
			return false
		}
	}
	return true
}

// ValidID reports whether value is 32 lowercase hex characters. The spelling is
// the wire grammar's, so an identity this layer accepts is exactly what the
// node's candidate reader accepts.
func ValidID(value string) bool { return protocol.ValidID(value) }

// domainPattern is the canonical lowercase DNS name accepted by every matcher
// and display label that names a host.
var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)

// tagPattern is the lowercase identifier of a geo code or rule-set tag.
var tagPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

// ssidPattern is the normalized Wi-Fi name accepted by the generator-only SSID
// matcher.
var ssidPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9._+-]{0,30}[a-z0-9])?$`)

// pinVersionPattern accepts one immutable version label. The mutable denylist
// below rejects path-style channels that still match the character set.
var pinVersionPattern = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z._-]{0,31}$`)

// mutablePinVersions are the labels that mean "whatever is newest", which is
// exactly what a version lock may not accept.
var mutablePinVersions = map[string]bool{
	"latest": true, "head": true, "main": true, "master": true,
	"stable": true, "dev": true, "nightly": true,
}

// ValidDomain reports whether value is one canonical lowercase DNS name.
func ValidDomain(value string) bool { return domainPattern.MatchString(value) }

// ValidTag reports whether value is one lowercase geo or rule-set identifier.
func ValidTag(value string) bool { return tagPattern.MatchString(value) }

// ValidSSID reports whether value is one normalized Wi-Fi name.
func ValidSSID(value string) bool { return ssidPattern.MatchString(value) }

// NormalizeSSID lowercases a Wi-Fi name and removes whitespace. The caller
// still validates the result with ValidSSID.
func NormalizeSSID(raw string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return -1
		}
		return unicode.ToLower(r)
	}, raw)
}

// PinDetail validates the shape of one rule-set version lock and returns a
// human-readable reason when it is unusable, or "" when it is valid. It never
// performs I/O. Callers wrap the detail with their layer's stable code:
// policy uses RULESET_PIN_INVALID, the composer uses COMPOSE_RULESET_UNPINNED.
func PinDetail(source, version, digest string) string {
	if source == "" || len(source) > 512 || strings.TrimSpace(source) != source {
		return "the source must be one exact URL"
	}
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Hostname() == "" ||
		parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" ||
		parsed.Opaque != "" || strings.ContainsAny(source, " \t\r\n") {
		return "the source must be one exact public HTTPS URL without credentials, query or fragment"
	}
	// A literal network address is not a public ruleset host. This is not a
	// full SSRF defence (the Hub never accepts the URL from a request); it
	// keeps a deployment from pinning a loopback or private artifact by
	// mistake, which would make the "public, reproducible" claim false.
	if addr, addrErr := netip.ParseAddr(parsed.Hostname()); addrErr == nil {
		if !addr.IsGlobalUnicast() || addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
			addr.IsUnspecified() || addr.IsMulticast() || addr.Is4In6() {
			return "the source must not be a loopback, private or unspecified literal address"
		}
	}
	if host := parsed.Hostname(); host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return "the source must be a public ruleset host"
	}
	if !pinVersionPattern.MatchString(version) || mutablePinVersions[strings.ToLower(version)] {
		return "the version must be one immutable label, not a mutable channel"
	}
	// A path that names a mutable channel is the same defect spelled in the
	// URL: the file behind it changes without the pin changing.
	for _, segment := range strings.Split(parsed.Path, "/") {
		if mutablePinVersions[strings.ToLower(segment)] {
			return "the source must name one immutable artifact, not a mutable channel"
		}
	}
	if !protocol.ValidSHA256(digest) {
		return "the digest must be 64 lowercase hex characters"
	}
	return ""
}

// CanonicalPrefix parses one aligned CIDR network. It is shared by the mesh
// route rules and the device document so both refuse a host route the same way.
func CanonicalPrefix(raw string) (netip.Prefix, error) {
	prefix, err := netip.ParsePrefix(raw)
	if err != nil || prefix.Masked() != prefix {
		return netip.Prefix{}, errInvalidPrefix
	}
	return prefix, nil
}

// errInvalidPrefix is private so callers always phrase their own stable code.
var errInvalidPrefix = errorString("ir: not a canonical CIDR network")

// errInvalidMeshView is the anti-corruption refusal of one foreign mesh view.
var errInvalidMeshView = errorString("ir: the mesh view is not a canonical projection")

type errorString string

func (e errorString) Error() string { return string(e) }
