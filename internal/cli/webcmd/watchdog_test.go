package webcmd

// Tests for the #11d Task 7 watchdog (D2). The heartbeat is liveness only: it
// is sent while the database answers SELECT 1 and stops when it does not.

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func TestWatchdogHeartbeat(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "notify.sock")
	listener, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: socket, Net: "unixgram"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	var healthy atomic.Bool
	healthy.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Watchdog(ctx, socket, 10*time.Millisecond, func() bool { return healthy.Load() })
	}()

	if err := listener.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatalf("no heartbeat: %v", err)
	}
	if string(buffer[:n]) != "WATCHDOG=1\n" {
		t.Fatalf("heartbeat = %q", buffer[:n])
	}

	// Once the database readback fails, no further heartbeat may be sent.
	healthy.Store(false)
	if err := listener.SetReadDeadline(time.Now().Add(80 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	for {
		if _, _, err := listener.ReadFromUnix(buffer); err != nil {
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				break
			}
			t.Fatalf("read: %v", err)
		}
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Watchdog: %v", err)
	}
}

func TestWatchdogWithoutSocketIsANoOp(t *testing.T) {
	done := make(chan error, 1)
	go func() { done <- Watchdog(context.Background(), "", time.Second, func() bool { return true }) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("watchdog without a socket blocked")
	}
}

func TestWatchdogRefusesBadInterval(t *testing.T) {
	if err := Watchdog(context.Background(), filepath.Join(os.TempDir(), "x.sock"), 0, nil); err == nil {
		t.Fatal("zero interval was accepted")
	}
}
