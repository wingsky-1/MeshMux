package webcmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/wingsky-1/MeshMux/internal/web"
)

const (
	helperEnv = "MESHMUX_WEBCMD_HELPER"
	argsEnv   = "MESHMUX_WEBCMD_ARGS"
)

// TestRunHelperProcess executes Run in a child process so tests can observe
// the real process exit code without replacing os.Stdout/os.Stderr globally.
func TestRunHelperProcess(t *testing.T) {
	if os.Getenv(helperEnv) != "1" {
		return
	}
	var args []string
	if err := json.Unmarshal([]byte(os.Getenv(argsEnv)), &args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(97)
	}
	os.Exit(Run(args))
}

func runWebCommand(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	payload, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunHelperProcess$", "-test.v=false")
	cmd.Env = append(os.Environ(), helperEnv+"=1", argsEnv+"="+string(payload))
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err = cmd.Run()
	if err == nil {
		return 0, stdout.String(), stderr.String()
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("run child process: %v", err)
	}
	return exitErr.ExitCode(), stdout.String(), stderr.String()
}

func tempDataDir(t *testing.T) string {
	t.Helper()
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(parent, "state")
}

func TestRunRejectsFlagErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"unknown flag", []string{"--not-a-real-flag"}},
		{"missing flag value", []string{"--origin"}},
		{"positional argument", []string{
			"--origin", "https://console.example.invalid",
			"--data-dir", tempDataDir(t),
			"unexpected",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _, _ := runWebCommand(t, tc.args...)
			if code != 2 {
				t.Fatalf("Run(%v)=%d, want usage exit 2", tc.args, code)
			}
		})
	}
}

func TestRunRejectsInvalidStartupConfig(t *testing.T) {
	for _, tc := range []struct {
		name string
		args func(string) []string
	}{
		{"missing origin", func(dir string) []string {
			return []string{"--data-dir", dir}
		}},
		{"missing data dir", func(string) []string {
			return []string{"--origin", "https://console.example.invalid"}
		}},
		{"non HTTPS origin", func(dir string) []string {
			return []string{"--origin", "http://console.example.invalid", "--data-dir", dir}
		}},
		{"origin with path", func(dir string) []string {
			return []string{"--origin", "https://console.example.invalid/admin", "--data-dir", dir}
		}},
		{"development origin does not match listener", func(dir string) []string {
			return []string{
				"--listen", "127.0.0.1:9080",
				"--origin", "http://console.example.invalid",
				"--data-dir", dir,
				"--dev-http",
			}
		}},
		{"development HTTP with direct Caddy", func(dir string) []string {
			return []string{
				"--listen", "127.0.0.1:9080",
				"--origin", "http://127.0.0.1:9080",
				"--data-dir", dir,
				"--dev-http",
				"--direct-caddy",
			}
		}},
		{"non-loopback listener", func(dir string) []string {
			return []string{
				"--listen", "0.0.0.0:9080",
				"--origin", "https://console.example.invalid",
				"--data-dir", dir,
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, _ := runWebCommand(t, tc.args(tempDataDir(t))...)
			if code != 1 {
				t.Fatalf("Run()=%d, want startup failure exit 1; stdout=%s", code, stdout)
			}
			if !strings.Contains(stdout, `"error_code":"STARTUP_FAILED"`) {
				t.Fatalf("startup failure was not logged as STARTUP_FAILED: %s", stdout)
			}
		})
	}
}

func TestRunAcceptsSupportedModes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	// The occupied loopback port makes the accepted configuration fail at
	// net.Listen instead of starting a long-running service.
	wantStage := "LISTEN_FAILED"
	if os.Geteuid() == 0 {
		// web.Config.Validate rejects root before the listener is reached.
		wantStage = "STARTUP_FAILED"
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"HTTPS behind an additional proxy", []string{
			"--listen", addr,
			"--origin", "https://console.example.invalid",
			"--data-dir", tempDataDir(t),
		}},
		{"HTTPS directly behind Caddy", []string{
			"--listen", addr,
			"--origin", "https://console.example.invalid",
			"--data-dir", tempDataDir(t),
			"--direct-caddy",
		}},
		{"isolated development HTTP", []string{
			"--listen", addr,
			"--origin", "http://" + addr,
			"--data-dir", tempDataDir(t),
			"--dev-http",
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, stderr := runWebCommand(t, tc.args...)
			if code != 1 {
				t.Fatalf("Run(%v)=%d, want exit 1; stdout=%s stderr=%s", tc.args, code, stdout, stderr)
			}
			if !strings.Contains(stdout, `"error_code":"`+wantStage+`"`) {
				t.Fatalf("expected %s after accepted flags: stdout=%s stderr=%s", wantStage, stdout, stderr)
			}
		})
	}
}

func TestWebConfigValidationContract(t *testing.T) {
	base := web.Config{
		Listen:  "127.0.0.1:9080",
		Origin:  "https://console.example.invalid",
		DataDir: "state",
	}
	for _, tc := range []struct {
		name string
		cfg  web.Config
		uid  int
		want string
	}{
		{"public HTTPS origin", base, 1000, ""},
		{"development HTTP origin", web.Config{
			Listen: "127.0.0.1:9080", Origin: "http://127.0.0.1:9080", DataDir: "state", DevHTTP: true,
		}, 1000, ""},
		{"HTTPS required", web.Config{
			Listen: "127.0.0.1:9080", Origin: "http://console.example.invalid", DataDir: "state",
		}, 1000, "HTTPS_REQUIRED"},
		{"origin path", web.Config{
			Listen: "127.0.0.1:9080", Origin: "https://console.example.invalid/admin", DataDir: "state",
		}, 1000, "ORIGIN_INVALID"},
		{"non-loopback listener", web.Config{
			Listen: "0.0.0.0:9080", Origin: "https://console.example.invalid", DataDir: "state",
		}, 1000, "LISTEN_INVALID"},
		{"hostname listener", web.Config{
			Listen: "localhost:9080", Origin: "https://console.example.invalid", DataDir: "state",
		}, 1000, "LISTEN_INVALID"},
		{"development origin host mismatch", web.Config{
			Listen: "127.0.0.1:9080", Origin: "http://console.example.invalid", DataDir: "state", DevHTTP: true,
		}, 1000, "ORIGIN_INVALID"},
		{"development HTTP with direct proxy", web.Config{
			Listen: "127.0.0.1:9080", Origin: "http://127.0.0.1:9080", DataDir: "state", DevHTTP: true, DirectProxy: true,
		}, 1000, "ORIGIN_INVALID"},
		{"missing data dir", web.Config{
			Listen: "127.0.0.1:9080", Origin: "https://console.example.invalid",
		}, 1000, "DATA_DIR_REQUIRED"},
		{"missing origin", web.Config{
			Listen: "127.0.0.1:9080", DataDir: "state",
		}, 1000, "ORIGIN_INVALID"},
		{"root forbidden", base, 0, "ROOT_FORBIDDEN"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate(tc.uid)
			if tc.want == "" {
				if err != nil {
					t.Fatalf("Validate()=%v, want success", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Validate()=%v, want error containing %q", err, tc.want)
			}
		})
	}
}
