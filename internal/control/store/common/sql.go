package common

// Shared SQL plumbing every store domain reads through.
//
// A row scanner is the smallest interface a scan needs, so a *sql.Row, a
// *sql.Rows and a test double are all accepted without a second abstraction.
// The helpers below are pure: they translate driver errors into the stable
// vocabulary the callers already speak.

import (
	"database/sql"
	"strings"
)

// RowScanner is the one scan surface the store's read helpers accept.
type RowScanner interface {
	Scan(...any) error
}

// RowQueryer is the one single-row query surface the store's read helpers accept.
type RowQueryer interface {
	QueryRow(query string, args ...any) *sql.Row
}

// Itoa is the one integer-to-text helper the operator messages use, so a bound
// is never re-typed as a literal at a call site.
func Itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [8]byte
	pos := len(buf)
	for n > 0 {
		pos--
		buf[pos] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[pos:])
}

// IsUniqueConstraint reports whether err is SQLite's unique-constraint refusal.
func IsUniqueConstraint(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
