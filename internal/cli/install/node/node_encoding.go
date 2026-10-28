package node

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// Small wrappers keep the transaction's error messages stable while sharing
// the standard library encoding behavior.
func jsonMarshal(v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func jsonUnmarshal(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func sumBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
