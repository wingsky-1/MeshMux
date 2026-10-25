package web

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/node"
)

// artifactSink is an http.ResponseWriter that keeps no body: it counts the bytes
// so a test can verify a large download without buffering it on the test side,
// which is exactly the property under test.
type artifactSink struct {
	header http.Header
	status int
	body   int64
}

func newArtifactSink() *artifactSink { return &artifactSink{header: http.Header{}} }

func (a *artifactSink) Header() http.Header { return a.header }

func (a *artifactSink) WriteHeader(status int) { a.status = status }

func (a *artifactSink) Write(p []byte) (int, error) {
	if a.status == 0 {
		a.status = http.StatusOK
	}
	a.body += int64(len(p))
	return len(p), nil
}

// artifactDownload performs one authenticated download through the real router
// and writes into sink, so no test-side buffer grows with the artifact.
func artifactDownload(t *testing.T, b *browser, sink http.ResponseWriter) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/nodes/cli", nil)
	r.RemoteAddr = "127.0.0.1:40000"
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.AddCookie(b.cookie)
	b.app.Handler().ServeHTTP(sink, r)
}

// writeArtifact writes size zero bytes and returns the path with their digest.
// The content is cheap to generate so the fixture does not dominate the
// measurement, and it is still a real digest for the streaming path to match.
func writeArtifact(t *testing.T, size int) (string, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "meshmux")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := io.CopyN(f, zeroReader{}, int64(size)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	hasher := sha256.New()
	if _, err := io.Copy(hasher, f); err != nil {
		t.Fatal(err)
	}
	return path, hex.EncodeToString(hasher.Sum(nil))
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func installTestArtifact(app *Server, path, digest string) {
	app.cfg.InstallArtifact = &InstallArtifact{
		Path: path, Version: node.CurrentAgentVersion(), Architecture: "amd64", SHA256: digest,
	}
}

// totalAlloc runs fn and reports how many bytes it allocated. TotalAlloc counts
// every allocation, so a buffered copy of an N-byte artifact cannot hide behind
// a GC: it has to allocate at least N bytes, while a chunked copy allocates one
// fixed buffer.
func totalAlloc(fn func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	fn()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestInstallArtifactDownloadStreamsInsteadOfBuffering pins the property that
// made the old handler unsafe for the Hub's memory budget: a download must not
// allocate the artifact. The bound is half the file, which the previous
// io.ReadAll implementation could never meet (it allocated the full size plus a
// growing slice copy), while a chunked copy sits far below it.
func TestInstallArtifactDownloadStreamsInsteadOfBuffering(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	const size = 16 << 20
	path, digest := writeArtifact(t, size)
	installTestArtifact(app, path, digest)

	sink := newArtifactSink()
	allocated := totalAlloc(func() { artifactDownload(t, b, sink) })

	if sink.status != http.StatusOK {
		t.Fatalf("status=%d body=%d", sink.status, sink.body)
	}
	if got := sink.header.Get("Content-Length"); got != strconv.Itoa(size) {
		t.Fatalf("Content-Length=%q want %d", got, size)
	}
	if sink.body != size {
		t.Fatalf("received %d bytes want %d", sink.body, size)
	}
	if sink.header.Get("Content-Disposition") != `attachment; filename="meshmux"` {
		t.Fatalf("Content-Disposition=%q", sink.header.Get("Content-Disposition"))
	}
	t.Logf("%d-byte download allocated %d bytes", size, allocated)
	if limit := uint64(size / 2); allocated > limit {
		t.Fatalf("a %d-byte download allocated %d bytes (limit %d): the body was buffered", size, allocated, limit)
	}
}

// TestConcurrentInstallArtifactDownloadsDoNotScaleWithFileSize is the
// concurrency half of the same property: four parallel downloads of an 8 MiB
// artifact must together allocate less than one copy of it. The old handler
// needed at least 4x8 MiB and could briefly hold twice that per request, so its
// resident set followed the number of clients; the streamed handler adds one
// 32 KiB buffer per download.
func TestConcurrentInstallArtifactDownloadsDoNotScaleWithFileSize(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	const size = 8 << 20
	path, digest := writeArtifact(t, size)
	installTestArtifact(app, path, digest)

	const clients = 4
	sinks := make([]*artifactSink, clients)
	for i := range sinks {
		sinks[i] = newArtifactSink()
	}
	var wg sync.WaitGroup
	allocated := totalAlloc(func() {
		for i := range sinks {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				artifactDownload(t, b, sinks[i])
			}(i)
		}
		wg.Wait()
	})

	for i, sink := range sinks {
		if sink.status != http.StatusOK || sink.body != size {
			t.Fatalf("download %d: status=%d body=%d", i, sink.status, sink.body)
		}
	}
	t.Logf("%d concurrent %d-byte downloads allocated %d bytes", clients, size, allocated)
	if limit := uint64(size); allocated > limit {
		t.Fatalf("%d concurrent %d-byte downloads allocated %d bytes (limit %d): memory follows the client count",
			clients, size, allocated, limit)
	}
}

// TestInstallArtifactDownloadRefusesAChangedArtifactBeforeTheBody keeps the
// refusal honest: the pinned digest is checked before a single byte or
// Content-Length is promised, so a changed file still answers 503 with a stable
// code instead of a truncated attachment.
func TestInstallArtifactDownloadRefusesAChangedArtifactBeforeTheBody(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	path, _ := writeArtifact(t, 4096)
	// A pinned digest that belongs to some other content, never to this file.
	installTestArtifact(app, path, strings.Repeat("a", 64))

	// A refusal happens before the body, so a recorder is safe here and lets the
	// test read the stable code.
	w := httptest.NewRecorder()
	artifactDownload(t, b, w)
	requireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), "INSTALL_ARTIFACT_CHANGED") {
		t.Fatalf("refusal lost its code: %.300s", w.Body.String())
	}
	if w.Header().Get("Content-Disposition") != "" || w.Header().Get("Content-Length") != "" {
		t.Fatalf("refusal promised a body: disposition=%q length=%q",
			w.Header().Get("Content-Disposition"), w.Header().Get("Content-Length"))
	}

	// The same holds when the file itself changed after its digest was pinned:
	// truncating it must be refused as a changed artifact, not served short.
	if err := os.Truncate(path, 1024); err != nil {
		t.Fatal(err)
	}
	w = httptest.NewRecorder()
	artifactDownload(t, b, w)
	requireStatus(t, w, http.StatusServiceUnavailable)
	if !strings.Contains(w.Body.String(), "INSTALL_ARTIFACT_CHANGED") {
		t.Fatalf("truncated artifact lost its code: %.300s", w.Body.String())
	}
}

// TestInstallArtifactDownloadRefusesAnOversizedArtifactWithoutReadingIt pins the
// 128 MiB bound on the path that streams: a sparse file over the limit is
// refused from Stat, never copied.
func TestInstallArtifactDownloadRefusesAnOversizedArtifactWithoutReadingIt(t *testing.T) {
	app, _ := testApp(t)
	b := &browser{app: app}
	initialize(t, b)
	loginAs(t, b, testPassword)

	path := filepath.Join(t.TempDir(), "meshmux")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Truncate(installArtifactMaxBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	installTestArtifact(app, path, strings.Repeat("0", 64))

	w := httptest.NewRecorder()
	artifactDownload(t, b, w)
	requireStatus(t, w, http.StatusServiceUnavailable)
	if w.Header().Get("Content-Disposition") != "" {
		t.Fatalf("oversized artifact was offered as an attachment")
	}
	if !strings.Contains(w.Body.String(), "INSTALL_ARTIFACT_INVALID") {
		t.Fatalf("oversized artifact lost its code: %.300s", w.Body.String())
	}
}

// TestCopyArtifactVerifiedReportsWhatWentWrong keeps the failure classes apart: a
// completed copy with the wrong digest is the abortable INSTALL_ARTIFACT_CHANGED,
// a short read is io.ErrUnexpectedEOF and a failed read keeps its own error, so
// the caller never reports a transport fault as a changed artifact.
func TestCopyArtifactVerifiedReportsWhatWentWrong(t *testing.T) {
	body := []byte("fixed-test-cli")
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	chunk := make([]byte, 4)

	if n, err := copyArtifactVerified(io.Discard, strings.NewReader(string(body)), int64(len(body)), digest, chunk); err != nil || n != int64(len(body)) {
		t.Fatalf("verified copy: n=%d err=%v", n, err)
	}
	if _, err := copyArtifactVerified(io.Discard, strings.NewReader(string(body)), int64(len(body)), strings.Repeat("0", 64), chunk); !errors.Is(err, errInstallArtifactChanged) {
		t.Fatalf("digest mismatch: err=%v", err)
	}
	// A reader that ends early must not be reported as a changed artifact.
	if _, err := copyArtifactVerified(io.Discard, strings.NewReader("fixed"), int64(len(body)), digest, chunk); !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("short read: err=%v", err)
	}
	sentinel := errors.New("READ_FAILED")
	if _, err := copyArtifactVerified(io.Discard, failingReader{sentinel}, int64(len(body)), digest, chunk); !errors.Is(err, sentinel) {
		t.Fatalf("read failure: err=%v", err)
	}
}

type failingReader struct{ err error }

func (f failingReader) Read([]byte) (int, error) { return 0, f.err }

// TestBoundaryLetsAnAbortReachNetHTTP pins the boundary's half of the streamed
// download: a handler that aborts a started response must not have a 500 body
// appended by the recovery wrapper, while an ordinary panic still becomes the
// stable INTERNAL_ERROR envelope.
func TestBoundaryLetsAnAbortReachNetHTTP(t *testing.T) {
	app, _ := testApp(t)
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodGet, testOrigin+"/api/nodes/cli", nil)
		r.URL.Scheme = ""
		r.URL.Host = ""
		return r
	}
	abort := app.boundary(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic(http.ErrAbortHandler)
	}))
	func() {
		defer func() {
			if recovered := recover(); recovered != http.ErrAbortHandler {
				t.Fatalf("abort was swallowed: recover()=%v", recovered)
			}
		}()
		abort.ServeHTTP(httptest.NewRecorder(), request())
	}()

	boom := app.boundary(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("unexpected")
	}))
	w := httptest.NewRecorder()
	boom.ServeHTTP(w, request())
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "INTERNAL_ERROR") {
		t.Fatalf("ordinary panic: status=%d body=%.200s", w.Code, w.Body.String())
	}
}
