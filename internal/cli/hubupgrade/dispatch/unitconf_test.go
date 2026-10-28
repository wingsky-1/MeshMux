package dispatch

// Unit-shape tests of #11d Task 4 (spec §5.1, §5.7). The dispatcher trusts the
// Web only because the request data_dir equals the one fixed in the Web unit;
// the parser therefore accepts exactly one simple ExecStart line.

import (
	"strings"
	"testing"
)

func TestParseWebExecStart(t *testing.T) {
	unit := `[Unit]
Description=MeshMux Hub Web

[Service]
Type=simple
User=meshmux
ExecStart=/usr/local/libexec/meshmuxd __internal-web --listen 127.0.0.1:9080 --origin https://admin.example.org --data-dir /var/lib/meshmux

[Install]
WantedBy=multi-user.target
`
	argv, err := ParseWebExecStart(unit)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/usr/local/libexec/meshmuxd", "__internal-web", "--listen", "127.0.0.1:9080", "--origin", "https://admin.example.org", "--data-dir", "/var/lib/meshmux"}
	if strings.Join(argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %#v, want %#v", argv, want)
	}
	dataDir, err := DataDirFromArgv(argv)
	if err != nil || dataDir != "/var/lib/meshmux" {
		t.Fatalf("data dir = %q, %v", dataDir, err)
	}
}

func TestParseWebExecStartQuotesAndEquals(t *testing.T) {
	unit := "[Service]\nExecStart=\"/usr/local/libexec/meshmuxd\" __internal-web --origin=\"https://admin.example.org\" --data-dir=/var/lib/meshmux\n"
	argv, err := ParseWebExecStart(unit)
	if err != nil {
		t.Fatal(err)
	}
	if argv[2] != "--origin=https://admin.example.org" {
		t.Fatalf("quoted argument lost its bytes: %#v", argv)
	}
	if dataDir, err := DataDirFromArgv(argv); err != nil || dataDir != "/var/lib/meshmux" {
		t.Fatalf("--data-dir= form = %q, %v", dataDir, err)
	}
}

func TestParseWebExecStartRejectsAmbiguousShapes(t *testing.T) {
	cases := map[string]string{
		"missing":      "[Service]\nType=simple\n",
		"multiple":     "[Service]\nExecStart=/bin/a\nExecStart=/bin/b\n",
		"continuation": "[Service]\nExecStart=/bin/a \\\n --data-dir /var/lib/meshmux\n",
		"reset":        "[Service]\nExecStart=\nExecStart=/bin/a --data-dir /var/lib/meshmux\n",
		"relative":     "[Service]\nExecStart=meshmuxd __internal-web --data-dir /var/lib/meshmux\n",
		"unclosed":     "[Service]\nExecStart=/bin/a \"unclosed\n",
	}
	for name, unit := range cases {
		if _, err := ParseWebExecStart(unit); err == nil {
			t.Fatalf("%s: ambiguous unit shape was accepted", name)
		}
	}
}

// TestRenderDataDirDropIn pins the one restore unit write: the base unit is not
// edited, the drop-in resets ExecStart and repeats the same argv with only the
// data directory replaced. The fold is the same one the dispatcher applies.
func TestRenderDataDirDropIn(t *testing.T) {
	argv := []string{
		"/usr/local/libexec/meshmuxd", "__internal-web",
		"--listen", "127.0.0.1:9080",
		"--origin", "https://admin.example.org",
		"--subscription-origin", "https://sub.example.org",
		"--headscale-origin", "https://mesh.example.org",
		"--data-dir", "/var/lib/meshmux",
	}
	body, err := RenderDataDirDropIn(argv, "/var/lib/meshmux/restore-abcdef-1700000000")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"[Service]\nExecStart=\nExecStart=/usr/local/libexec/meshmuxd __internal-web ",
		"--data-dir /var/lib/meshmux/restore-abcdef-1700000000\n"} {
		if !strings.Contains(body, want) {
			t.Fatalf("drop-in missing %q:\n%s", want, body)
		}
	}
	if strings.Contains(body, "--data-dir /var/lib/meshmux\n") {
		t.Fatal("the drop-in still names the old data directory")
	}
	got, err := ApplyExecStartDropIn(argv, body)
	if err != nil {
		t.Fatal(err)
	}
	dataDir, err := DataDirFromArgv(got)
	if err != nil || dataDir != "/var/lib/meshmux/restore-abcdef-1700000000" {
		t.Fatalf("effective data dir = %q, %v", dataDir, err)
	}
	for i := range argv {
		if argv[i] == "--data-dir" {
			break
		}
		if got[i] != argv[i] {
			t.Fatalf("argv[%d] changed: %q != %q", i, got[i], argv[i])
		}
	}

	quoted := []string{"/bin/meshmuxd", "--origin", "https://admin.example.org/a b", "--data-dir=/var/lib/meshmux"}
	body, err = RenderDataDirDropIn(quoted, "/var/lib/meshmux/new")
	if err != nil {
		t.Fatal(err)
	}
	got, err = ApplyExecStartDropIn(quoted, body)
	if err != nil {
		t.Fatal(err)
	}
	if got[2] != "https://admin.example.org/a b" {
		t.Fatalf("quoted argument lost its bytes: %#v", got)
	}
	if dataDir, err := DataDirFromArgv(got); err != nil || dataDir != "/var/lib/meshmux/new" {
		t.Fatalf("--data-dir= form = %q, %v", dataDir, err)
	}
}

func TestRenderDataDirDropInRejectsForeignShapes(t *testing.T) {
	base := []string{"/bin/meshmuxd", "__internal-web", "--data-dir", "/var/lib/meshmux"}
	for name, tc := range map[string]struct {
		argv    []string
		dataDir string
	}{
		"no data dir":    {[]string{"/bin/meshmuxd", "__internal-web"}, "/var/lib/meshmux/new"},
		"relative":       {base, "relative"},
		"dirty":          {base, "/var/lib/meshmux/../new"},
		"control byte":   {[]string{"/bin/meshmuxd", "--data-dir", "/var/lib/meshmux\nevil"}, "/var/lib/meshmux/new"},
		"relative exec":  {[]string{"meshmuxd", "--data-dir", "/var/lib/meshmux"}, "/var/lib/meshmux/new"},
		"duplicate flag": {[]string{"/bin/meshmuxd", "--data-dir", "/var/lib/meshmux", "--data-dir", "/tmp/x"}, "/var/lib/meshmux/new"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := RenderDataDirDropIn(tc.argv, tc.dataDir); err == nil {
				t.Fatal("ambiguous drop-in shape was accepted")
			}
		})
	}
}

func TestDataDirFromArgvRejectsForeignShapes(t *testing.T) {
	cases := [][]string{
		{"/bin/meshmuxd", "__internal-web"},
		{"/bin/meshmuxd", "--data-dir", "/var/lib/meshmux", "--data-dir", "/tmp/x"},
		{"/bin/meshmuxd", "--data-dir", "relative"},
		{"/bin/meshmuxd", "--data-dir", "/var/lib/meshmux/../meshmux"},
		{"/bin/meshmuxd", "--data-dir"},
	}
	for _, argv := range cases {
		if _, err := DataDirFromArgv(argv); err == nil {
			t.Fatalf("argv %#v was accepted", argv)
		}
	}
}
