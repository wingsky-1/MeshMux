package common

import (
	"crypto/rand"
	"errors"
	"strings"
	"sync"
	"testing"
)

// failingEntropy makes crypto/rand fail without touching the real entropy
// source, proving the gate refuses instead of reusing a fixed scratch name.
type failingEntropy struct{}

func (failingEntropy) Read([]byte) (int, error) {
	return 0, errors.New("entropy unavailable")
}

func TestGateScratchNameRefusesEntropyFailure(t *testing.T) {
	previous := rand.Reader
	rand.Reader = failingEntropy{}
	t.Cleanup(func() { rand.Reader = previous })

	name, err := randomGateName()
	if err == nil || name != "" {
		t.Fatalf("randomGateName = %q, %v; want an empty name and an error", name, err)
	}
	if !strings.Contains(err.Error(), PublishGateCode) {
		t.Fatalf("error %q does not carry PUBLISH_GATE_FAILED", err)
	}

	v := &execPublishVerifier{dir: t.TempDir(), name: randomGateName}
	if _, cleanup, err := v.write(KernelSingBox, []byte(`{"log":{}}`)); err == nil {
		cleanup()
		t.Fatal("gate wrote a scratch file without entropy")
	} else if !strings.Contains(err.Error(), PublishGateCode) {
		t.Fatalf("write error %q does not carry PUBLISH_GATE_FAILED", err)
	}
}

func TestGateScratchNameIsUniqueUnderConcurrency(t *testing.T) {
	const runs = 128
	names := make(chan string, runs)
	var wg sync.WaitGroup
	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			name, err := randomGateName()
			if err != nil {
				t.Errorf("randomGateName: %v", err)
				return
			}
			names <- name
		}()
	}
	wg.Wait()
	close(names)

	seen := make(map[string]struct{}, runs)
	for name := range names {
		if name == "check" {
			t.Fatal("gate fell back to the fixed scratch name")
		}
		if _, duplicate := seen[name]; duplicate {
			t.Fatalf("concurrent gate runs shared scratch name %q", name)
		}
		seen[name] = struct{}{}
	}
	if len(seen) != runs {
		t.Fatalf("generated %d unique names, want %d", len(seen), runs)
	}
}
