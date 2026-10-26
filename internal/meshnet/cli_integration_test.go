package meshnet

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"
)

// TestIntegrationAgainstRealCLI exercises the adapter against a genuine Headscale
// binary and a live local service. It is skipped unless both environment
// variables name an isolated fixture, because it creates a user and a pre-auth
// key in that instance and must never touch a production Hub:
//
//	MESHMUX_HEADSCALE_BIN=/tmp/isolated/headscale
//	MESHMUX_HEADSCALE_CONFIG=/tmp/isolated/config.yaml
//
// The unit tests assert argv and decoding against recorded documents; only this
// test proves the argv is accepted by the pinned release and that the wire shape
// decoded here is the one 0.29.5 actually prints.
func TestIntegrationAgainstRealCLI(t *testing.T) {
	binary := os.Getenv("MESHMUX_HEADSCALE_BIN")
	config := os.Getenv("MESHMUX_HEADSCALE_CONFIG")
	if binary == "" || config == "" {
		t.Skip("set MESHMUX_HEADSCALE_BIN and MESHMUX_HEADSCALE_CONFIG for an isolated Headscale instance")
	}
	runner := &CLIRunner{binary: binary, config: config, timeout: commandTimeout, execute: runCommand}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// The handshake must accept the pinned release and reject the pass-through
	// value the CLI prints for it.
	if err := runner.VerifyVersion(ctx); err != nil {
		t.Fatalf("version handshake: %v", err)
	}
	if HeadscaleVersion != "0.29.5" {
		t.Fatalf("integration test was written for 0.29.5, adapter pins %q", HeadscaleVersion)
	}

	user, err := runner.CreateUser(ctx, "meshmux-it")
	switch CodeOf(err) {
	case "":
		if user.ID == 0 || user.Name != "meshmux-it" {
			t.Fatalf("created user = %+v", user)
		}
	case CodeAlreadyExists:
		// A previous run left the user behind; the list below resolves it.
	default:
		t.Fatalf("create user: %v", err)
	}

	users, err := runner.ListUsers(ctx)
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	var found User
	for _, u := range users {
		if u.Name == "meshmux-it" {
			found = u
		}
	}
	if found.ID == 0 {
		t.Fatalf("created user is not listed: %+v", users)
	}

	// An empty tailnet decodes as an empty slice: 0.29.5 prints "null".
	nodes, err := runner.ListNodes(ctx, "meshmux-it")
	if err != nil {
		t.Fatalf("list nodes: %v", err)
	}
	if nodes == nil {
		t.Fatal("empty node list decoded as nil")
	}

	key, plaintext, err := runner.CreatePreAuthKey(ctx, PreAuthKeyRequest{UserID: found.ID, Validity: 15 * time.Minute})
	if err != nil {
		t.Fatalf("create pre-auth key: %v", err)
	}
	if !strings.HasPrefix(plaintext, "hskey-auth-") || len(plaintext) < 32 {
		t.Fatalf("plaintext key shape = %q", plaintext)
	}
	if key.ID == 0 || key.UserID != found.ID || key.Reusable || key.Ephemeral {
		t.Fatalf("key = %+v", key)
	}
	if key.Expiration.IsZero() || key.CreatedAt.IsZero() {
		t.Fatalf("key timestamps = %+v", key)
	}
	if got := key.Expiration.Sub(key.CreatedAt); got < 14*time.Minute || got > 16*time.Minute {
		t.Fatalf("key lifetime = %s, want about 15m", got)
	}

	// Expiring the key prints "{}" and must be a success.
	if err := runner.ExpirePreAuthKey(ctx, key.ID); err != nil {
		t.Fatalf("expire pre-auth key: %v", err)
	}

	// A node that does not exist is reported as not found, so a retried removal
	// can be settled instead of retried forever.
	if err := runner.DeleteNode(ctx, 424242); CodeOf(err) != CodeNotFound {
		t.Fatalf("delete absent node = %v, want %s", err, CodeNotFound)
	}
	if err := runner.ExpireNode(ctx, 424242); err == nil {
		t.Fatal("expiring an absent node must fail")
	}

	// Argument validation happens before any process is started, even with a
	// live service.
	if err := runner.ExpireNode(ctx, 0); CodeOf(err) != CodeArgumentInvalid {
		t.Fatalf("zero node id = %v", err)
	}
}
