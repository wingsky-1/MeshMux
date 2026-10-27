package update

import (
	"os"
	"path/filepath"
)

// atomicWriteSpec is the caller-specific half of writeAtomicJSONResult: the
// private temp pattern, the stable failure code and the three failure details
// of one fixed record type. Keeping them per caller lets the shared flow stay
// identical while each record keeps its own error_code.
type atomicWriteSpec struct {
	tmpPattern    string
	failCode      string
	dirDetail     string
	writeDetail   string
	publishDetail string
}

// writeAtomicJSONResult publishes already-validated and encoded result bytes
// atomically with mode 0600. A crash leaves either the previous file or the
// complete new one, never a truncated record the Agent would have to guess
// about. The caller owns validate and json.Marshal; only the
// CreateTemp→Chmod→Write→Sync→Close→Rename flow is shared.
func writeAtomicJSONResult(path string, data []byte, spec atomicWriteSpec) error {
	file, err := os.CreateTemp(filepath.Dir(path), spec.tmpPattern)
	if err != nil {
		return fail(spec.failCode, spec.dirDetail)
	}
	temp := file.Name()
	defer func() {
		if temp != "" {
			_ = os.Remove(temp)
		}
	}()
	if err = file.Chmod(0600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return fail(spec.failCode, spec.writeDetail)
	}
	if err = os.Rename(temp, path); err != nil {
		return fail(spec.failCode, spec.publishDetail)
	}
	temp = ""
	return nil
}
