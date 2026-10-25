package store

import "strings"

// Error-code handling on the web boundary.
//
// A refusal from a store or domain package is "CODE: detail" by convention. The
// code segment is compared against a constant - never against a message prefix -
// so a detail that happens to start with the same text cannot change behaviour.
// Nothing here validates a code: a caller either compares it to a constant or
// checks it against a registered set (see mesh_codes.go).

// codeDatabaseUnavailable marks an unusable database. It is the one store
// failure the pages report separately from an ordinary refusal.
const CodeDatabaseUnavailable = "DATABASE_UNAVAILABLE"

// errorCodeOf returns the code segment of err: the text before the first colon,
// or the whole message when there is none. A nil error has no code.
func ErrorCodeOf(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	if index := strings.IndexByte(message, ':'); index > 0 {
		message = message[:index]
	}
	return strings.TrimSpace(message)
}
