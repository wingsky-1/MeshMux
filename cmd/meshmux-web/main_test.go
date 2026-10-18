package main

import (
	"flag"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Exercise the real service lifecycle in a child process. CI's normal user can
// run it; a root-only development container instead proves startup refusal.
func TestServiceProcess(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	listener.Close()
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	origin := "http://" + addr
	start := func() *exec.Cmd {
		cmd := exec.Command(os.Args[0], "-test.run=TestServiceHelperProcess")
		cmd.Env = append(os.Environ(), "MESHMUX_TEST_PROCESS=1", "MESHMUX_TEST_ADDR="+addr, "MESHMUX_TEST_DIR="+state)
		log, err := os.OpenFile(filepath.Join(dir, "service.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout = log
		cmd.Stderr = log
		if err = cmd.Start(); err != nil {
			log.Close()
			t.Fatal(err)
		}
		log.Close()
		return cmd
	}
	stop := func(cmd *exec.Cmd) {
		t.Helper()
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan error, 1)
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("unclean shutdown: %v", err)
			}
		case <-time.After(15 * time.Second):
			cmd.Process.Kill()
			t.Fatal("shutdown timeout")
		}
	}
	cmd := start()
	if os.Geteuid() == 0 {
		err := cmd.Wait()
		if err == nil {
			t.Fatal("root Web unexpectedly started")
		}
		b, _ := os.ReadFile(filepath.Join(dir, "service.log"))
		if !strings.Contains(string(b), "ROOT_FORBIDDEN") {
			t.Fatalf("wrong refusal: %s", b)
		}
		if _, err = os.Stat(state); !os.IsNotExist(err) {
			t.Fatal("root startup wrote state")
		}
		return
	}
	// Always clean up the child, including when an assertion fails.
	defer func() {
		if cmd != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar, Timeout: 2 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	wait := func() {
		t.Helper()
		for i := 0; i < 100; i++ {
			r, err := client.Get(origin + "/healthz")
			if err == nil {
				r.Body.Close()
				if r.StatusCode == 200 {
					return
				}
			}
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatal("service not ready")
	}
	request := func(method, path string, data url.Values, want int) string {
		t.Helper()
		req, _ := http.NewRequest(method, origin+path, strings.NewReader(data.Encode()))
		if method == "POST" {
			req.Header.Set("Origin", origin)
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != want {
			t.Fatalf("%s %s: %d want %d", method, path, resp.StatusCode, want)
		}
		return string(b)
	}
	csrf := func(body string) string {
		t.Helper()
		m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(body)
		if len(m) != 2 {
			t.Fatal("missing csrf")
		}
		return m[1]
	}
	wait()
	request("GET", "/api/status", nil, 401)
	token, err := os.ReadFile(filepath.Join(state, "bootstrap.token"))
	if err != nil {
		t.Fatal(err)
	}
	c := csrf(request("GET", "/setup", nil, 200))
	password := "process-test-password-only"
	request("POST", "/setup", url.Values{"csrf": {c}, "bootstrap": {strings.TrimSpace(string(token))}, "password": {password}}, 303)
	c = csrf(request("GET", "/login", nil, 200))
	request("POST", "/login", url.Values{"csrf": {c}, "password": {password}}, 303)
	request("GET", "/api/status", nil, 200)
	stop(cmd)
	cmd = start()
	wait()
	request("GET", "/api/status", nil, 200)
	c = csrf(request("GET", "/", nil, 200))
	request("POST", "/logout", url.Values{"csrf": {c}}, 303)
	request("GET", "/api/status", nil, 401)
	stop(cmd)
	cmd = nil
	b, _ := os.ReadFile(filepath.Join(dir, "service.log"))
	if strings.Contains(string(b), password) || strings.Contains(string(b), strings.TrimSpace(string(token))) {
		t.Fatal("secret in process log")
	}
}

func TestServiceHelperProcess(t *testing.T) {
	if os.Getenv("MESHMUX_TEST_PROCESS") != "1" {
		return
	}
	addr := os.Getenv("MESHMUX_TEST_ADDR")
	flag.CommandLine = flag.NewFlagSet("meshmux-web", flag.ExitOnError)
	os.Args = []string{"meshmux-web", "--listen", addr, "--origin", "http://" + addr, "--data-dir", os.Getenv("MESHMUX_TEST_DIR"), "--dev-http"}
	os.Exit(run())
}
