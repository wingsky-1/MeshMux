package infra

import (
	"testing"
	"time"
)

// TestPairingLimiterWindowIsAnchoredAndNeverSlides pins the arithmetic the
// handler relies on, without an HTTP round trip: the window opens at its first
// attempt, refused attempts do not extend it, a success clears it, and a clock
// that moved backwards opens a new window instead of blocking for the skew.
func TestPairingLimiterWindowIsAnchoredAndNeverSlides(t *testing.T) {
	var rt Runtime
	base := time.Now()
	for i := range PairBudget {
		if ok, _ := rt.pairing.spend(base.Add(time.Duration(i) * time.Second)); !ok {
			t.Fatalf("attempt %d refused inside the budget", i+1)
		}
	}
	// A refused attempt reports the remainder of the window that already
	// started, not a fresh minute.
	ok, retry := rt.pairing.spend(base.Add(50 * time.Second))
	if ok {
		t.Fatal("attempt beyond the budget was admitted")
	}
	if want := 10 * time.Second; retry != want {
		t.Fatalf("retry = %v, want %v", retry, want)
	}
	// Still refused near the end of the window: a refusal never slid it.
	if ok, _ := rt.pairing.spend(base.Add(59 * time.Second)); ok {
		t.Fatal("a refusal extended the window")
	}
	// The window reopens exactly at its end.
	if ok, _ := rt.pairing.spend(base.Add(PairWindow)); !ok {
		t.Fatal("the window did not reopen at its end")
	}
	// A successful pairing clears it, so a fleet install is not throttled.
	rt.pairing.clear()
	for i := range PairBudget {
		if ok, _ := rt.pairing.spend(base.Add(PairWindow + time.Duration(i)*time.Second)); !ok {
			t.Fatalf("attempt %d after a successful pairing was refused", i+1)
		}
	}
	// A clock that moved backwards opens a new window rather than holding the
	// caller for the skew.
	if ok, _ := rt.pairing.spend(base.Add(-time.Hour)); !ok {
		t.Fatal("a backwards clock kept the old window")
	}
}
