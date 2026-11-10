package sys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWirelessInterfaces(t *testing.T) {
	root := t.TempDir()
	for _, d := range []string{"lo", "enp0s31f6", "wlp0s20f3/wireless"} {
		if err := os.MkdirAll(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	old := netClass
	netClass = root
	defer func() { netClass = old }()
	got := wirelessInterfaces()
	if len(got) != 1 || got[0] != "wlp0s20f3" {
		t.Fatalf("got %v", got)
	}
}
