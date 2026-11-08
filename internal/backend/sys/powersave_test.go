package sys

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mdlayher/netlink"
)

func TestPowerSaveRequest(t *testing.T) {
	for _, on := range []bool{true, false} {
		msg, err := powerSaveRequest(28, 1, 4, on)
		if err != nil {
			t.Fatal(err)
		}
		if msg.Header.Command != nl80211CmdSetPowerSave || msg.Header.Version != 1 {
			t.Fatalf("header %+v", msg.Header)
		}
		ad, err := netlink.NewAttributeDecoder(msg.Data)
		if err != nil {
			t.Fatal(err)
		}
		got := map[uint16]uint32{}
		for ad.Next() {
			got[ad.Type()] = ad.Uint32()
		}
		want := uint32(0)
		if on {
			want = 1
		}
		if got[nl80211AttrIfindex] != 4 || got[nl80211AttrPSState] != want || len(got) != 2 {
			t.Fatalf("on=%v attributes %v", on, got)
		}
	}
}

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
