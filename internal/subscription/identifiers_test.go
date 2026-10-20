package subscription

import (
	"strings"
	"testing"
)

func TestNewIDIsCanonicalAndUnique(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		id, err := NewID()
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateID(id); err != nil {
			t.Fatalf("NewID produced invalid ID: %v", err)
		}
		if id != strings.ToLower(id) {
			t.Fatalf("ID is not lowercase: %q", id)
		}
		if _, ok := seen[id]; ok {
			t.Fatalf("duplicate ID: %q", id)
		}
		seen[id] = struct{}{}
	}
}

func TestValidateIDRejectsNonCanonicalValues(t *testing.T) {
	valid := strings.Repeat("a", 32)
	if err := ValidateID(valid); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"",
		valid[:31],
		valid + "a",
		strings.ToUpper(valid),
		strings.Repeat("g", 32),
		" " + valid[1:],
		valid[:31] + "\n",
		"界" + valid[1:],
	} {
		if err := ValidateID(value); err == nil {
			t.Fatalf("invalid ID accepted: %q", value)
		}
	}
}

func TestNewUUIDIsCanonicalV4AndUnique(t *testing.T) {
	seen := make(map[string]struct{}, 128)
	for i := 0; i < 128; i++ {
		uuid, err := NewUUID()
		if err != nil {
			t.Fatal(err)
		}
		if err = ValidateUUID(uuid); err != nil {
			t.Fatalf("NewUUID produced invalid UUID: %v", err)
		}
		if uuid != strings.ToLower(uuid) || uuid[14] != '4' || !strings.ContainsRune("89ab", rune(uuid[19])) {
			t.Fatalf("UUID is not canonical v4: %q", uuid)
		}
		if _, ok := seen[uuid]; ok {
			t.Fatalf("duplicate UUID: %q", uuid)
		}
		seen[uuid] = struct{}{}
	}
}

func TestValidateUUIDRejectsMalformedOrWrongVersion(t *testing.T) {
	valid, err := NewUUID()
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{
		"",
		valid[:35],
		valid + "0",
		strings.ToUpper(valid),
		"{" + valid + "}",
		strings.ReplaceAll(valid, "-", ""),
		valid[:14] + "1" + valid[15:],
		valid[:19] + "c" + valid[20:],
		valid[:19] + "7" + valid[20:],
		valid[:19] + "g" + valid[20:],
		valid[:8] + "_" + valid[9:],
	} {
		if err := ValidateUUID(value); err == nil {
			t.Fatalf("invalid UUID accepted: %q", value)
		}
	}
}
