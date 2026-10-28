package spec

import "testing"

func TestKernelReleasePins(t *testing.T) {
	for architecture, want := range map[string]KernelRelease{
		"amd64": {
			Version:       "1.14.3",
			SourceURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-amd64.tar.gz",
			ArchiveSHA256: "e2bdf179c15a3652955dc44867e33ca0965c9c9b91b34267dcc5a5d639a5feee",
			BinarySHA256:  "768d31fa7f68debc067bb4626539498a1e8751d36a7b99e1a54bee6a23815f93",
		},
		"arm64": {
			Version:       "1.14.3",
			SourceURL:     "https://github.com/SagerNet/sing-box/releases/download/v1.14.3/sing-box-1.14.3-linux-arm64.tar.gz",
			ArchiveSHA256: "29dae24d76bea3bc62d07dd3e60cfc12003de7debbd6b768df9be9c68360174e",
			BinarySHA256:  "299f9f6080d9c43504714ddddae6aa9b853d430ccfc816c456a73613b5455689",
		},
	} {
		got, ok := KernelReleaseFor(architecture)
		if !ok || got != want {
			t.Fatalf("%s release = %+v, %v", architecture, got, ok)
		}
	}
	if _, ok := KernelReleaseFor("386"); ok {
		t.Fatal("unsupported architecture received a release")
	}
}
