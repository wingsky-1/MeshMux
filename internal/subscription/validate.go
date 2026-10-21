package subscription

import (
	"errors"
	"net"
	"strconv"
	"strings"
	"unicode/utf8"
)

const maxDisplayNameRunes = 80

// NormalizeDisplayName trims surrounding whitespace and validates a display
// label of 1-80 printable runes. Callers that accept user input should use this
// before constructing a Subscriber or Line.
func NormalizeDisplayName(raw string) (string, error) {
	name := strings.TrimSpace(raw)
	if err := validateDisplayNameShape(name); err != nil {
		return "", err
	}
	return name, nil
}

// ValidateDisplayName requires an already normalized (trimmed) display label.
func ValidateDisplayName(name string) error {
	if strings.TrimSpace(name) != name {
		return errors.New("DISPLAY_NAME_INVALID: trim surrounding whitespace and use 1-80 printable characters")
	}
	return validateDisplayNameShape(name)
}

func validateDisplayNameShape(name string) error {
	if name == "" || !utf8.ValidString(name) || utf8.RuneCountInString(name) > maxDisplayNameRunes {
		return errors.New("DISPLAY_NAME_INVALID: use 1-80 printable characters")
	}
	for _, r := range name {
		if !strconv.IsPrint(r) {
			return errors.New("DISPLAY_NAME_INVALID: control and non-printable characters rejected")
		}
	}
	return nil
}

// validHost accepts one ASCII hostname or IP address. It rejects URL schemes,
// paths, query/fragment characters, embedded ports, credentials, bracketed
// IPv6, zone identifiers and trailing dots so the value is safe to place
// directly in a transport configuration.
func validHost(value string) bool {
	if value == "" || len(value) > 253 {
		return false
	}
	if net.ParseIP(value) != nil {
		return true
	}
	if strings.HasSuffix(value, ".") || numericDotted(value) {
		return false
	}
	for label := range strings.SplitSeq(value, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			switch {
			case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			case c == '-' && i > 0 && i < len(label)-1:
			default:
				return false
			}
		}
	}
	return true
}

// numericDotted prevents an invalid IPv4 spelling such as 999.1.1.1 from
// being reinterpreted as a DNS name.
func numericDotted(value string) bool {
	if !strings.Contains(value, ".") {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] != '.' && (value[i] < '0' || value[i] > '9') {
			return false
		}
	}
	return true
}
