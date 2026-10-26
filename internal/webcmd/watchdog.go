package webcmd

// The systemd watchdog of #11d Task 7 (D2).
//
// WatchdogSec=120 turns a wedged process into a restart: the unit must send
// WATCHDOG=1 to $NOTIFY_SOCKET at least every 120 seconds, otherwise systemd
// kills it. The heartbeat is sent only when the database still answers SELECT 1,
// so "the HTTP goroutine is scheduled" is not mistaken for "the service works".
// A failed readback stops the heartbeat; it never sends a false liveness signal.

import (
	"context"
	"errors"
	"net"
	"strings"
	"time"
)

// Watchdog sends WATCHDOG=1 every interval while healthy returns true. An empty
// socket is a no-op (the process was started outside systemd). The function
// returns when ctx ends; a send failure is returned so the caller can log it.
func Watchdog(ctx context.Context, socket string, interval time.Duration, healthy func() bool) error {
	if socket == "" {
		return nil
	}
	if interval <= 0 {
		return errors.New("WATCHDOG_INTERVAL_INVALID: the heartbeat interval is not positive")
	}
	// systemd encodes an abstract socket as @name; Go needs the NUL prefix.
	address := socket
	if strings.HasPrefix(address, "@") {
		address = "\x00" + strings.TrimPrefix(address, "@")
	}
	connection, err := net.DialUnix("unixgram", nil, &net.UnixAddr{Name: address, Net: "unixgram"})
	if err != nil {
		return errors.New("WATCHDOG_UNAVAILABLE: the notify socket could not be opened")
	}
	defer connection.Close()

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if healthy != nil && !healthy() {
				// Keep the connection but send nothing: systemd's own deadline
				// is the authority that restarts the unit.
				continue
			}
			if _, err := connection.Write([]byte("WATCHDOG=1\n")); err != nil {
				return errors.New("WATCHDOG_SEND_FAILED: the heartbeat could not be sent")
			}
		}
	}
}
