package handler

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// wrongCode returns a code-shaped secret that is never the real one, so a burst
// exercises the refusal path without touching any stored pairing row.
func wrongCode(code string) string {
	first := byte('A')
	if code[0] == 'A' {
		first = 'B'
	}
	return string(first) + code[1:]
}

// pairJSONBody posts one raw body to the pairing endpoint, for the checks that
// need a malformed request rather than a well-formed attempt.
func pairJSONBody(t *testing.T, app *Server, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", testOrigin+"/api/agent/pair", strings.NewReader(body))
	r.URL.Scheme, r.URL.Host = "", ""
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	app.Handler().ServeHTTP(w, r)
	return w
}

// TestPairingBudgetRefusesAFloodAndStatesTheWait pins the budget itself: the
// endpoint that spends a secret before any session exists admits a bounded
// number of attempts per window and then refuses with an actionable remainder.
func TestPairingBudgetRefusesAFloodAndStatesTheWait(t *testing.T) {
	app, _ := testApp(t)
	_, code := createPendingNode(t, app, "edge", "pair-flood", 8443, 2222)
	base := time.Now()
	app.now = func() time.Time { return base }
	bad := wrongCode(code)
	// A malformed body never reaches the store, so it is not charged: a real
	// agent with a broken local config is not locked out by its own retries.
	for range 5 {
		if w := pairJSONBody(t, app, `{}`); w.Code != 400 {
			t.Fatalf("malformed body status = %d, want 400", w.Code)
		}
	}
	for i := range pairBudget {
		w := pairJSON(t, app, strings.Repeat("a", 32), "edge", bad)
		if w.Code != 401 {
			t.Fatalf("attempt %d status = %d, want 401: %.200s", i+1, w.Code, w.Body.String())
		}
	}
	// The window is anchored at its first attempt, so the refusal reports the
	// whole remaining window instead of a constant.
	w := pairJSON(t, app, strings.Repeat("a", 32), "edge", bad)
	requireStatus(t, w, 429)
	if got := w.Header().Get("Retry-After"); got != strconv.Itoa(int(pairWindow/time.Second)) {
		t.Fatalf("Retry-After at the start of the window = %q, want %d", got, int(pairWindow/time.Second))
	}
	for _, want := range []string{"PAIRING_RATE_LIMITED", "配对预算为 " + strconv.Itoa(pairBudget) + " 次 / 分钟", "已配对身份、心跳与任务不受影响"} {
		if !strings.Contains(w.Body.String(), want) {
			t.Fatalf("refusal lost %q: %.300s", want, w.Body.String())
		}
	}
	// The window reopens without a sliding extension.
	app.now = func() time.Time { return base.Add(pairWindow) }
	if w := pairJSON(t, app, strings.Repeat("a", 32), "edge", bad); w.Code != 401 {
		t.Fatalf("attempt after the window status = %d, want 401: %.200s", w.Code, w.Body.String())
	}
}

// TestPairingFloodNeverContendsForTheSingleConnection is the reason the budget
// is process-local. The store runs on one connection (SetMaxOpenConns(1)), so a
// limiter that read or wrote SQLite would queue every flood attempt behind the
// connection the rest of the Hub needs. Holding that one connection open makes
// the difference deterministic: a budgeted refusal must still answer, because it
// touches no database at all.
func TestPairingFloodNeverContendsForTheSingleConnection(t *testing.T) {
	app, _ := testApp(t)
	node, code := createPendingNode(t, app, "edge", "pair-hold", 8443, 2222)
	base := time.Now()
	app.now = func() time.Time { return base }
	bad := wrongCode(code)
	for range pairBudget {
		requireStatus(t, pairJSON(t, app, strings.Repeat("a", 32), "edge", bad), 401)
	}

	// Hold the only connection for the duration of the burst. A limiter that
	// touched SQLite would block here forever; a budgeted refusal cannot.
	tx, err := app.store.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	rolledBack := false
	rollback := func() {
		if rolledBack {
			return
		}
		rolledBack = true
		if err := tx.Rollback(); err != nil {
			t.Errorf("release the held connection: %v", err)
		}
	}
	defer rollback()

	// A real code is refused too, and the refusal happens before the store is
	// reached: the flood cannot spend an operator's one-time code, and the code
	// is still usable once the window reopens.
	w := pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 429)

	var wg sync.WaitGroup
	results := make(chan *httptest.ResponseRecorder, 16)
	for range cap(results) {
		wg.Go(func() { results <- pairJSON(t, app, strings.Repeat("a", 32), "edge", bad) })
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("a refused pairing attempt blocked on the single database connection")
	}
	close(results)
	for refused := range results {
		if refused.Code != 429 || !strings.Contains(refused.Body.String(), "PAIRING_RATE_LIMITED") {
			t.Fatalf("concurrent refusal = %d %.200s", refused.Code, refused.Body.String())
		}
	}
	rollback()
	// With the connection free again the budget is the only thing refusing.
	app.now = func() time.Time { return base.Add(pairWindow) }
	requireStatus(t, pairJSON(t, app, node.ID, "edge", code), 200)
}

// TestPairingSuccessClearsTheBudget keeps the pairing budget from locking an
// operator out of a fleet install: proving a code is the pairing analogue of a
// proven password, and the proof is single-use so it cannot be replayed.
func TestPairingSuccessClearsTheBudget(t *testing.T) {
	app, _ := testApp(t)
	base := time.Now()
	app.now = func() time.Time { return base }
	for i := range 2 * pairBudget {
		node, code := createPendingNode(t, app, "edge", "fleet-"+strconv.Itoa(i), 8443, 2222)
		w := pairJSON(t, app, node.ID, "edge", code)
		if w.Code != 200 {
			t.Fatalf("pairing %d status = %d, want 200: %.200s", i+1, w.Code, w.Body.String())
		}
		clearNodeTasks(t, app, node.ID)
	}
}

// TestPairingRefusalIsNotACodeOracle merges the three "this code will not work"
// answers into one. A caller must not be able to learn from the response whether
// a guessed code ever existed, when it lapsed, or that it was already spent; the
// Hub log keeps the distinction for the operator, reachable through the
// operation_id the response carries.
func TestPairingRefusalIsNotACodeOracle(t *testing.T) {
	app, logs := testApp(t)
	consumedNode, consumedCode := createPendingNode(t, app, "edge", "oracle-consumed", 8443, 2222)
	requireStatus(t, pairJSON(t, app, consumedNode.ID, "edge", consumedCode), 200)
	clearNodeTasks(t, app, consumedNode.ID)
	expiredNode, expiredCode := createPendingNode(t, app, "edge", "oracle-expired", 8444, 2224)
	if _, err := app.store.DB.Exec(`UPDATE node_pairing SET expires=0 WHERE node_id=?`, expiredNode.ID); err != nil {
		t.Fatal(err)
	}

	type refusal struct {
		Status    int
		ErrorCode string `json:"error_code"`
		Stage     string `json:"stage"`
		Message   string `json:"message"`
		Next      string `json:"next_action"`
	}
	read := func(w *httptest.ResponseRecorder) refusal {
		t.Helper()
		var body refusal
		if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
			t.Fatalf("refusal is not the agent envelope: %v %.200s", err, w.Body.String())
		}
		body.Status = w.Code
		return body
	}
	unknown := read(pairJSON(t, app, strings.Repeat("a", 32), "edge", strings.Repeat("A", 43)))
	consumed := read(pairJSON(t, app, consumedNode.ID, "edge", consumedCode))
	expired := read(pairJSON(t, app, expiredNode.ID, "edge", expiredCode))
	if unknown != consumed || unknown != expired {
		t.Fatalf("refusals differ and leak the code's history: unknown=%+v consumed=%+v expired=%+v", unknown, consumed, expired)
	}
	if unknown.Status != 401 || unknown.ErrorCode != "PAIRING_INVALID" || unknown.Stage != "agent" {
		t.Fatalf("neutral refusal wrong: %+v", unknown)
	}
	// The operator still gets the reason, keyed by the same operation_id.
	for _, reason := range []string{"PAIRING_CONSUMED", "PAIRING_EXPIRED"} {
		if !strings.Contains(logs.String(), `"error_code":"`+reason+`"`) {
			t.Fatalf("log lost %s: %s", reason, logs.String())
		}
	}
}

// TestPairingRefusesAnUnavailableDatabaseAsItself keeps a Hub outage from being
// reported as a rejected code: the operator must not reissue a code that was
// never the problem.
func TestPairingRefusesAnUnavailableDatabaseAsItself(t *testing.T) {
	app, _ := testApp(t)
	node, code := createPendingNode(t, app, "edge", "pair-db", 8443, 2222)
	if err := app.store.DB.Close(); err != nil {
		t.Fatal(err)
	}
	w := pairJSON(t, app, node.ID, "edge", code)
	requireStatus(t, w, 503)
	if !strings.Contains(w.Body.String(), "DATABASE_UNAVAILABLE") {
		t.Fatalf("outage was reported as a code rejection: %.200s", w.Body.String())
	}
}

// TestPairingLimiterWindowIsAnchoredAndNeverSlides pins the arithmetic the
// handler relies on, without an HTTP round trip: the window opens at its first
// attempt, refused attempts do not extend it, a success clears it, and a clock
// that moved backwards opens a new window instead of blocking for the skew.
func TestPairingLimiterWindowIsAnchoredAndNeverSlides(t *testing.T) {
	var limiter pairLimiter
	base := time.Now()
	for i := range pairBudget {
		if ok, _ := limiter.spend(base.Add(time.Duration(i) * time.Second)); !ok {
			t.Fatalf("attempt %d refused inside the budget", i+1)
		}
	}
	// A refused attempt reports the remainder of the window that already
	// started, not a fresh minute.
	ok, retry := limiter.spend(base.Add(50 * time.Second))
	if ok {
		t.Fatal("attempt beyond the budget was admitted")
	}
	if want := 10 * time.Second; retry != want {
		t.Fatalf("retry = %v, want %v", retry, want)
	}
	// Still refused near the end of the window: a refusal never slid it.
	if ok, _ := limiter.spend(base.Add(59 * time.Second)); ok {
		t.Fatal("a refusal extended the window")
	}
	// The window reopens exactly at its end.
	if ok, _ := limiter.spend(base.Add(pairWindow)); !ok {
		t.Fatal("the window did not reopen at its end")
	}
	// A successful pairing clears it, so a fleet install is not throttled.
	limiter.clear()
	for i := range pairBudget {
		if ok, _ := limiter.spend(base.Add(pairWindow + time.Duration(i)*time.Second)); !ok {
			t.Fatalf("attempt %d after a successful pairing was refused", i+1)
		}
	}
	// A clock that moved backwards opens a new window rather than holding the
	// caller for the skew.
	if ok, _ := limiter.spend(base.Add(-time.Hour)); !ok {
		t.Fatal("a backwards clock kept the old window")
	}
}
