package hubupgrade

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
