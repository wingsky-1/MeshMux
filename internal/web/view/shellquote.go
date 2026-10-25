package view

import "strings"

// ShellQuote renders one POSIX shell word. The command shown by Web remains
// copyable while local config values cannot break out into shell syntax.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
