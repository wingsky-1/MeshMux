package webcmd

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

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

func TestRunSurfacesStableStartupCodes(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is refused before configuration validation")
	}
	for _, tc := range []struct {
		name     string
		args     func(string) []string
		wantCode string
	}{
		{"missing origin", func(dir string) []string {
			return []string{"--data-dir", dir}
		}, "ORIGIN_INVALID"},
		{"missing data dir", func(string) []string {
			return []string{"--origin", "https://console.example.invalid"}
		}, "DATA_DIR_REQUIRED"},
		{"non HTTPS origin", func(dir string) []string {
			return []string{"--origin", "http://console.example.invalid", "--data-dir", dir}
		}, "HTTPS_REQUIRED"},
		{"origin with path", func(dir string) []string {
			return []string{"--origin", "https://console.example.invalid/admin", "--data-dir", dir}
		}, "ORIGIN_INVALID"},
		{"development origin does not match listener", func(dir string) []string {
			return []string{
				"--listen", "127.0.0.1:9080",
				"--origin", "http://console.example.invalid",
				"--data-dir", dir,
				"--dev-http",
			}
		}, "ORIGIN_INVALID"},
		{"development HTTP with direct Caddy", func(dir string) []string {
			return []string{
				"--listen", "127.0.0.1:9080",
				"--origin", "http://127.0.0.1:9080",
				"--data-dir", dir,
				"--dev-http",
				"--direct-caddy",
			}
		}, "ORIGIN_INVALID"},
		{"non-loopback listener", func(dir string) []string {
			return []string{
				"--listen", "0.0.0.0:9080",
				"--origin", "https://console.example.invalid",
				"--data-dir", dir,
			}
		}, "LISTEN_INVALID"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, stdout, _ := runWebCommand(t, tc.args(tempDataDir(t))...)
			if code != 1 {
				t.Fatalf("Run()=%d, want startup failure exit 1; stdout=%s", code, stdout)
			}
			if !strings.Contains(stdout, `"error_code":"`+tc.wantCode+`"`) {
				t.Fatalf("startup refusal was not logged as %s: %s", tc.wantCode, stdout)
			}
			if strings.Contains(stdout, `"error_code":"STARTUP_FAILED"`) {
				t.Fatalf("stable code was collapsed into STARTUP_FAILED: %s", stdout)
			}
		})
	}
}

// TestRunSurfacesSchemaTooNewRecord is the operator-facing half of the DB gate:
// the old binary's refusal must keep its stable code and name the fixed backup
// record, instead of being flattened into an unexplained STARTUP_FAILED.
func TestRunSurfacesSchemaTooNewRecord(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root is refused before the store opens")
	}
	dir := tempDataDir(t)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dir, "meshmux.db")
	file, err := os.OpenFile(dbPath, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	// One above the schema this binary owns: 11 is a version the migration
	// chain can still upgrade from, so it would not exercise the gate.
	if _, err := db.Exec(`PRAGMA user_version=14`); err != nil {
		db.Close()
		t.Fatal(err)
	}
	db.Close()
	recordPath := filepath.Join(dir, "database-backup", "record.json")
	if err := os.MkdirAll(filepath.Dir(recordPath), 0700); err != nil {
		t.Fatal(err)
	}
	// Existence is the whole check for the old binary, so even an unreadable
	// future record must be named.
	if err := os.WriteFile(recordPath, []byte(`{"schema":99}`), 0600); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := runWebCommand(t,
		"--listen", "127.0.0.1:9080",
		"--origin", "https://console.example.invalid",
		"--data-dir", dir,
	)
	if code != 1 {
		t.Fatalf("Run()=%d, want startup failure exit 1; stdout=%s stderr=%s", code, stdout, stderr)
	}
	if !strings.Contains(stdout, `"error_code":"SCHEMA_TOO_NEW"`) {
		t.Fatalf("SCHEMA_TOO_NEW was not surfaced: %s", stdout)
	}
	if !strings.Contains(stdout, recordPath) {
		t.Fatalf("startup log does not name the backup record %q: %s", recordPath, stdout)
	}
	if !strings.Contains(stdout, `"detail"`) {
		t.Fatalf("SCHEMA_TOO_NEW detail was dropped: %s", stdout)
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
		wantStage = "ROOT_FORBIDDEN"
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
