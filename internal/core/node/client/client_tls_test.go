package client

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClientTLSUnknownCAAndHostnameMismatch(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, configMetadataForClientTest())
	}))
	defer server.Close()

	config := validConfig()
	config.HubURL = server.URL
	client, err := NewClient(config, validIdentity(config), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("unknown CA accepted")
	} else {
		requireClientError(t, err, "TLS_VERIFY_FAILED", 0)
	}

	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.ServerName = "other.example.invalid"
	injected := &http.Client{Transport: transport}
	client, err = NewClient(config, validIdentity(config), injected)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("trusted certificate for a different hostname accepted")
	} else {
		requireClientError(t, err, "TLS_VERIFY_FAILED", 0)
	}
}

func configMetadataForClientTest() Metadata {
	config := validConfig()
	metadata := config.Metadata()
	metadata.ConfigRevision = 1
	return metadata
}

func TestClientTLSMinimumVersion(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, configMetadataForClientTest())
	}))
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS11}
	server.StartTLS()
	defer server.Close()

	config := validConfig()
	config.HubURL = server.URL
	client, err := NewClient(config, validIdentity(config), nil)
	if err != nil {
		t.Fatal(err)
	}
	// The loopback test origin has a public root that does not trust this
	// fixture certificate. TLS version failure is still observable before
	// certificate validation on this deliberately TLS-1.1-only server.
	client.http.Transport.(*http.Transport).TLSClientConfig.InsecureSkipVerify = true //nolint:gosec -- isolate protocol-version assertion
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("TLS 1.1 server accepted")
	} else {
		requireClientError(t, err, "NETWORK_ERROR", 0)
	}
}

func TestClientInjectedHTTPClientRaisesTLSMinimum(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusOK, configMetadataForClientTest())
	}))
	defer server.Close()

	transport := server.Client().Transport.(*http.Transport).Clone()
	transport.TLSClientConfig = transport.TLSClientConfig.Clone()
	transport.TLSClientConfig.MinVersion = tls.VersionTLS10
	injected := &http.Client{Transport: transport}

	config := validConfig()
	config.HubURL = server.URL
	client, err := NewClient(config, validIdentity(config), injected)
	if err != nil {
		t.Fatal(err)
	}
	clonedTransport := client.http.Transport.(*http.Transport)
	if clonedTransport.TLSClientConfig.MinVersion < tls.VersionTLS12 {
		t.Fatalf("injected TLS minimum = %x, want >= TLS 1.2", clonedTransport.TLSClientConfig.MinVersion)
	}
	if transport.TLSClientConfig.MinVersion != tls.VersionTLS10 {
		t.Fatal("constructor mutated the caller's HTTP client")
	}
}

func TestClientSetsFiniteTimeoutWhenMissing(t *testing.T) {
	config := validConfig()
	for _, injected := range []*http.Client{nil, {}} {
		client, err := NewClient(config, validIdentity(config), injected)
		if err != nil {
			t.Fatal(err)
		}
		if client.http.Timeout <= 0 || client.http.Timeout > DefaultRequestTimeout {
			t.Fatalf("HTTP timeout = %s, want (0,%s]", client.http.Timeout, DefaultRequestTimeout)
		}
	}

	const short = 3 * time.Second
	client, err := NewClient(config, validIdentity(config), &http.Client{Timeout: short})
	if err != nil {
		t.Fatal(err)
	}
	if client.http.Timeout != short {
		t.Fatalf("short injected timeout = %s, want %s", client.http.Timeout, short)
	}
}

func TestClientStalledTLSResponsesTimeOut(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/config/1") {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
			_, _ = io.WriteString(w, `{"schema":`)
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
		// Block only on the test channel, never on the request context: once
		// the client deadline fires the server must still be stalled, so a
		// legitimately completed response can never win the race against the
		// timeout assertion below. The deferred close releases the handler.
		<-block
	}))
	defer server.Close()
	// Release stalled handlers before the server closes: httptest Server.Close
	// waits for active handlers, so closing the channel must come first in
	// LIFO order.
	defer close(block)

	config := validConfig()
	config.HubURL = server.URL
	client := newTestClient(t, &testHub{server: server, t: t}, config, validIdentity(config))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	started := time.Now()
	if _, err := client.Metadata(ctx); err == nil {
		t.Fatal("stalled response headers accepted")
	} else {
		requireClientError(t, err, "REQUEST_TIMEOUT", 0)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled headers were not bounded by the request deadline")
	}

	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started = time.Now()
	if _, err := client.Candidate(ctx, 1); err == nil {
		t.Fatal("stalled response body accepted")
	} else {
		requireClientError(t, err, "REQUEST_TIMEOUT", 0)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("stalled body was not bounded by the request deadline")
	}
}

func TestClientRequestTimeoutWithBackgroundContext(t *testing.T) {
	block := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block only on the test channel, never on the request context: once
		// the client deadline fires the server must still be stalled, so a
		// legitimately completed response can never win the race against the
		// timeout assertion below. The deferred close releases the handler.
		<-block
	}))
	defer server.Close()
	// Release stalled handlers before the server closes: httptest Server.Close
	// waits for active handlers, so closing the channel must come first in
	// LIFO order.
	defer close(block)

	config := validConfig()
	config.HubURL = server.URL
	client := newTestClient(t, &testHub{server: server, t: t}, config, validIdentity(config))
	client.http.Timeout = 100 * time.Millisecond

	started := time.Now()
	if _, err := client.Metadata(context.Background()); err == nil {
		t.Fatal("unbounded caller context bypassed the HTTP client timeout")
	} else {
		requireClientError(t, err, "REQUEST_TIMEOUT", 0)
	}
	if time.Since(started) > 2*time.Second {
		t.Fatal("zero-deadline request was not bounded by client timeout")
	}
}
