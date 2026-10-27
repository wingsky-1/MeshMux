package infra

import (
	"sync"
	"time"
)

// The pairing budget bounds the unauthenticated pairing endpoint.
//
// /api/agent/pair is the one endpoint that spends a secret before any session
// exists, so a flood of well-formed requests makes the Hub hash a code and open
// a SQLite transaction for each attempt. The login budget cannot carry this:
// sharing auth_limit would let an anonymous flood exhaust the administrator's
// login budget, and it would put one contended row - on a pool that has a single
// connection - on the path of every pairing attempt.
//
// The budget is therefore a per-process counter with no database round trip of
// its own. It is not keyed by client address: the Hub cannot trust a forwarded
// address (Cloudflare/CDN/shared egress), and a per-address map would grow with
// attacker input. The window is anchored at its first attempt, so a refusal
// cannot slide it forward, and a successful pairing clears it - the same
// success-clears rule the login budget follows - so an operator pairing a fleet
// of nodes never locks themselves out, while the failures a flood produces still
// cost the full budget.
//
// The trade-off is the documented one for the login budget: a sustained attacker
// can refuse real pairing for one window. Because the window is a minute and a
// refusal states its remainder, the cost is bounded and visible. A restart
// resets the counter; a remote request cannot cause one.
const (
	// PairWindow is the length of one pairing budget window.
	PairWindow = time.Minute
	// PairBudget is how many pairing attempts one window admits.
	PairBudget = 20
)

// pairLimiter is the pairing budget's state. The zero value is a fresh window.
type pairLimiter struct {
	mu       sync.Mutex
	started  time.Time
	attempts int
}

// spend charges one attempt against the current window. The second result is how
// long the caller must wait when the attempt is refused. A window that has not
// started, has elapsed, or lies in the future (the clock moved backwards) is
// replaced rather than extended.
func (l *pairLimiter) spend(now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.started.IsZero() || now.Before(l.started) || now.Sub(l.started) >= PairWindow {
		l.started, l.attempts = now, 0
	}
	l.attempts++
	if l.attempts <= PairBudget {
		return true, 0
	}
	retry := l.started.Add(PairWindow).Sub(now)
	if retry <= 0 {
		retry = time.Second
	}
	return false, retry
}

// clear ends the current window. It is called only after a one-time code was
// actually spent, so a successful pairing is never charged: proof of a valid
// code is the pairing analogue of a proven password, and the proof cannot be
// replayed because the code is single-use.
func (l *pairLimiter) clear() {
	l.mu.Lock()
	l.started, l.attempts = time.Time{}, 0
	l.mu.Unlock()
}

// SpendPairing charges one pairing attempt and reports the wait when refused.
func (rt *Runtime) SpendPairing(now time.Time) (bool, time.Duration) {
	return rt.pairing.spend(now)
}

// ClearPairing ends the pairing window after a one-time code was spent.
func (rt *Runtime) ClearPairing() { rt.pairing.clear() }
