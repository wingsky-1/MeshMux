package hubupgrade

// The one unit-shape parser shared by the dispatch boundary and the restore
// executor (#11d Task 4, spec §5.1/§5.7).
//
// The privileged dispatcher may only accept a request whose data_dir equals the
// one the running Web unit (including its drop-ins) was started with. That
// comparison is a fixed single-line ExecStart shape, not a shell parser: no
// continuations, no reset, no multiple starts and no relative executable. A
// shape that does not parse is refused with HUB_RESTORE_UNIT_SHAPE_INVALID.

import (
	"path/filepath"
	"strings"
)

const codeUnitShape = CodeRestoreUnitShapeInvalid

// safeExecArg reports whether an argv element needs no systemd quoting.
// Anything else is rendered inside double quotes with the escapes systemd
// understands.
func safeExecArg(arg string) bool {
	if arg == "" {
		return false
	}
	for _, r := range arg {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case strings.ContainsRune("_./:@=+-,", r):
		default:
			return false
		}
	}
	return true
}

// ParseWebExecStart returns the argv of exactly one simple ExecStart line in
// [Service]. systemd's basic quoting is supported; command lines, environment
// files, multiple lines and continuations are not.
func ParseWebExecStart(unit string) ([]string, error) {
	section := ""
	var values []string
	for _, raw := range strings.Split(unit, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Service" {
			continue
		}
		if strings.HasSuffix(line, `\`) {
			return nil, fail(codeUnitShape, "the web unit continues an ExecStart line")
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ExecStart" {
			continue
		}
		values = append(values, strings.TrimSpace(value))
	}
	if len(values) != 1 {
		return nil, fail(codeUnitShape, "the web unit does not carry exactly one ExecStart line")
	}
	if values[0] == "" {
		return nil, fail(codeUnitShape, "the web unit resets ExecStart without a command")
	}
	argv, err := splitExecArgs(values[0])
	if err != nil {
		return nil, err
	}
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return nil, fail(codeUnitShape, "the web unit ExecStart is not an absolute executable")
	}
	for _, arg := range argv {
		if strings.ContainsAny(arg, "\x00\n\r") {
			return nil, fail(codeUnitShape, "the web unit ExecStart carries a control byte")
		}
	}
	return argv, nil
}

// DataDirFromArgv extracts the single --data-dir value the dispatcher compares
// against the request. Both the split and the "=" forms are accepted because
// systemd does not normalise them; the value itself must be a clean absolute
// path.
func DataDirFromArgv(argv []string) (string, error) {
	value := ""
	found := false
	for i := 1; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--data-dir":
			if i+1 >= len(argv) {
				return "", fail(codeUnitShape, "the web unit names --data-dir without a value")
			}
			value, found = argv[i+1], true
			i++
		case strings.HasPrefix(arg, "--data-dir="):
			value, found = strings.TrimPrefix(arg, "--data-dir="), true
		default:
			continue
		}
		if !found || value == "" {
			return "", fail(codeUnitShape, "the web unit names an empty --data-dir")
		}
		if !cleanAbsolutePath(value) {
			return "", fail(codeUnitShape, "the web unit --data-dir is not a clean absolute path")
		}
	}
	if !found {
		return "", fail(codeUnitShape, "the web unit does not name --data-dir")
	}
	// A second occurrence would have overwritten value; detect it explicitly so
	// an appended drop-in cannot smuggle a second directory.
	count := 0
	for i := 1; i < len(argv); i++ {
		if argv[i] == "--data-dir" || strings.HasPrefix(argv[i], "--data-dir=") {
			count++
		}
	}
	if count != 1 {
		return "", fail(codeUnitShape, "the web unit names --data-dir more than once")
	}
	return value, nil
}

// splitExecArgs implements the systemd quoting subset this repository renders:
// whitespace separation, single quotes as literals, double quotes with
// backslash escapes, and backslash escapes outside quotes.
func splitExecArgs(value string) ([]string, error) {
	var args []string
	var current strings.Builder
	started := false
	inSingle, inDouble, escaped := false, false, false
	flush := func() {
		if started {
			args = append(args, current.String())
			current.Reset()
			started = false
		}
	}
	for _, r := range value {
		if escaped {
			current.WriteRune(r)
			started = true
			escaped = false
			continue
		}
		switch {
		case inSingle:
			if r == '\'' {
				inSingle = false
			} else {
				current.WriteRune(r)
			}
			started = true
		case inDouble:
			switch r {
			case '"':
				inDouble = false
			case '\\':
				escaped = true
			default:
				current.WriteRune(r)
			}
			started = true
		default:
			switch r {
			case ' ', '\t':
				flush()
			case '\\':
				escaped = true
				started = true
			case '\'':
				inSingle = true
				started = true
			case '"':
				inDouble = true
				started = true
			default:
				current.WriteRune(r)
				started = true
			}
		}
	}
	if escaped || inSingle || inDouble {
		return nil, fail(codeUnitShape, "the web unit ExecStart quoting is unbalanced")
	}
	flush()
	return args, nil
}

// RenderDataDirDropIn renders the one restore drop-in: the base unit is never
// edited; this file resets ExecStart and repeats the same argv with only the
// --data-dir value replaced (spec §5.7). The output is deliberately a full
// unit fragment, so an operator can inspect exactly what systemd will run.
func RenderDataDirDropIn(argv []string, dataDir string) (string, error) {
	if len(argv) == 0 || !filepath.IsAbs(argv[0]) {
		return "", fail(codeUnitShape, "the web unit has no absolute executable")
	}
	if !cleanAbsolutePath(dataDir) {
		return "", fail(codeUnitShape, "the restore data directory is not a clean absolute path")
	}
	if _, err := DataDirFromArgv(argv); err != nil {
		return "", err
	}
	replaced := make([]string, 0, len(argv))
	found := false
	for i := 0; i < len(argv); i++ {
		arg := argv[i]
		switch {
		case arg == "--data-dir":
			if i+1 >= len(argv) {
				return "", fail(codeUnitShape, "the web unit names --data-dir without a value")
			}
			replaced = append(replaced, arg, dataDir)
			i++
			found = true
		case strings.HasPrefix(arg, "--data-dir="):
			replaced = append(replaced, "--data-dir="+dataDir)
			found = true
		default:
			replaced = append(replaced, arg)
		}
	}
	if !found {
		return "", fail(codeUnitShape, "the web unit does not name --data-dir")
	}
	var line strings.Builder
	for i, arg := range replaced {
		if i > 0 {
			line.WriteByte(' ')
		}
		rendered, err := renderExecArg(arg)
		if err != nil {
			return "", err
		}
		line.WriteString(rendered)
	}
	var out strings.Builder
	out.WriteString("# MeshMux Hub restore (#11d): the base unit stays unchanged; only --data-dir moves.\n")
	out.WriteString("[Service]\n")
	out.WriteString("ExecStart=\n")
	out.WriteString("ExecStart=")
	out.WriteString(line.String())
	out.WriteString("\n")
	return out.String(), nil
}

// renderExecArg writes one systemd ExecStart argument. The safe set is rendered
// verbatim; everything else is double-quoted with backslash escaping, and "%"
// is doubled because systemd treats a single percent as a specifier.
func renderExecArg(arg string) (string, error) {
	if strings.ContainsAny(arg, "\x00\n\r") {
		return "", fail(codeUnitShape, "a web unit argument carries a control byte")
	}
	escaped := strings.ReplaceAll(arg, "%", "%%")
	if safeExecArg(arg) {
		return escaped, nil
	}
	escaped = strings.ReplaceAll(escaped, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return `"` + escaped + `"`, nil
}

// ApplyExecStartDropIn folds the ExecStart assignments of one root-owned drop-in
// onto the effective argv. An empty value resets; a second non-empty value is
// ambiguous for a simple service and is refused, exactly as the dispatcher
// already treats the effective Web unit.
func ApplyExecStartDropIn(current []string, unit string) ([]string, error) {
	section := ""
	for _, raw := range strings.Split(unit, "\n") {
		line := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSpace(line[1 : len(line)-1])
			continue
		}
		if section != "Service" {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(key) != "ExecStart" {
			continue
		}
		value = strings.TrimSpace(value)
		if value == "" {
			current = nil
			continue
		}
		if current != nil {
			return nil, fail(codeUnitShape, "the web drop-in adds a second effective ExecStart")
		}
		parsed, err := ParseWebExecStart("[Service]\nExecStart=" + value + "\n")
		if err != nil {
			return nil, err
		}
		current = parsed
	}
	return current, nil
}
