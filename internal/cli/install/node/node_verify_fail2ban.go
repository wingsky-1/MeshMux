package node

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wingsky-1/MeshMux/internal/cli/install/core"
)

// Verify-tail Fail2ban jail readiness and readback: the selected jail must
// answer after start/reload and cover exactly this host's SSH listeners.

// fail2banReadyTimeout/Interval bound the wait for the daemon socket and
// our jail after (re)start. Tests shrink them; production uses the defaults.
var fail2banReadyTimeout = 30 * time.Second
var fail2banReadyInterval = time.Second

// waitFail2banJail blocks until the Line's own jail answers queries.
// `enable --now` and `reload` return before the daemon recreates its socket
// and loads the jail, so an immediate readback fails with exit 255 on fast
// hosts.
func waitFail2banJail(ctx context.Context, runner core.CommandRunner) error {
	return waitFail2banJailNamed(ctx, runner, core.NodeSSHJailName)
}

// waitFail2banJailNamed blocks until the named jail answers queries. A
// co-located Line reuses the Hub's jail instead of installing a second one
// for the same SSH listeners.
func waitFail2banJailNamed(ctx context.Context, runner core.CommandRunner, jail string) error {
	if jail == "" {
		jail = core.NodeSSHJailName
	}
	deadline := time.Now().Add(fail2banReadyTimeout)
	for {
		if _, err := runner.Run(ctx, "fail2ban-client", "status", jail); err == nil {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("FAIL2BAN_JAIL_UNAVAILABLE")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(fail2banReadyInterval):
		}
	}
}

// verifyNodeSSHJail reads the Line's own jail port set back from the running
// daemon.
func verifyNodeSSHJail(ctx context.Context, runner core.CommandRunner, ssh ...int) error {
	return verifyFail2banJailPorts(ctx, runner, core.NodeSSHJailName, ssh)
}

// verifyFail2banJailPorts reads a named jail's effective port set back from
// the running daemon. The jail name is explicit: a co-located Line verifies
// the Hub's jail instead of a second jail of its own.
//
// fail2ban 1.1.0 (Debian 13) removed `get <JAIL> port`; the jail port is
// read back through the nftables-multiport action instance, which also
// proves the daemon loaded the jail (an unknown jail errors out).
func verifyFail2banJailPorts(ctx context.Context, runner core.CommandRunner, jail string, ssh []int) error {
	if jail == "" {
		jail = core.NodeSSHJailName
	}
	portsOut, err := runner.Run(ctx, "fail2ban-client", "get", jail, "action", "nftables-multiport", "port")
	if err != nil {
		return fmt.Errorf("SSH_JAIL_QUERY_FAILED jail port readback: %v", err)
	}
	actionOut, err := runner.Run(ctx, "fail2ban-client", "get", jail, "action", "nftables-multiport", "actionstart")
	if err != nil {
		return fmt.Errorf("SSH_JAIL_QUERY_FAILED acl action readback: %v", err)
	}
	jailPorts, err := parseFail2banPorts(string(portsOut))
	if err != nil {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH jail ports unparsable: %v", err)
	}
	actionPorts, err := parseFail2banActionPorts(string(actionOut))
	if err != nil {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH acl action unparsable: %v", err)
	}
	want := sortedInts(ssh)
	if !core.EqualIntSets(jailPorts, want) || !core.EqualIntSets(actionPorts, want) {
		return fmt.Errorf("SSH_JAIL_PORT_MISMATCH jail=%v action=%v want=%v", jailPorts, actionPorts, want)
	}
	return nil
}

func parseFail2banPorts(output string) ([]int, error) {
	value := strings.TrimSpace(output)
	if output == value+"\n" {
		// A single CLI response line is expected, but a final newline alone
		// does not add a second value.
	} else if strings.ContainsAny(value, "\r\n") {
		return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
	}
	var ports []int
	for _, raw := range strings.Split(value, ",") {
		raw = strings.TrimSpace(raw)
		if strings.Contains(raw, ":") {
			return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
		}
		port, err := strconv.Atoi(raw)
		if err != nil || port < 1 || port > 65535 || core.ContainsPort(ports, port) {
			return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
		}
		ports = append(ports, port)
	}
	sort.Ints(ports)
	return ports, nil
}

// Real fail2ban 1.1.0 actionstart commands shell-escape the set braces
// (dport \{ ... \}), while older output used bare braces. Accept both so
// the readback works against the daemon instead of only the L1 fake.
var fail2banDportPattern = regexp.MustCompile(`dport\s+(?:\\?\{([^}]*)\}|([0-9]+))`)
var fail2banInteger = regexp.MustCompile(`\b[0-9]+\b`)

func parseFail2banActionPorts(output string) ([]int, error) {
	matches := fail2banDportPattern.FindAllStringSubmatch(output, -1)
	if len(matches) == 0 {
		return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
	}
	var ports []int
	for _, match := range matches {
		var body string
		if match[1] != "" {
			body = match[1]
		} else {
			body = match[2]
		}
		for _, raw := range fail2banInteger.FindAllString(body, -1) {
			port, err := strconv.Atoi(raw)
			if err != nil || port < 1 || port > 65535 || core.ContainsPort(ports, port) {
				return nil, errors.New("SSH_JAIL_PORT_MISMATCH")
			}
			ports = append(ports, port)
		}
	}
	sort.Ints(ports)
	return ports, nil
}
