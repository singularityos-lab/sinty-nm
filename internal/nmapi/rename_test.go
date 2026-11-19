package nmapi

import (
	"testing"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

func TestRenamedLinkReplacesTheOldDevice(t *testing.T) {
	conn := privateBus(t)
	m, err := New(conn, Backends{Link: fakeLink{}, Wifi: &fakeWifi{}, DHCP: &fakeDHCP{wifi: &fakeWifi{}}, DNS: &recordDNS{}, RFKill: fakeRF{}, Conn: offlineConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	old := m.devByIface["wlan0"]
	if old == nil {
		t.Fatal("wlan0 missing at start")
	}

	m.onLinkEvent(core.LinkInfo{Index: 3, Name: "wlp1s0", Kind: core.KindWifi, Up: true, MAC: "02:00:00:00:00:01"}, true)

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.devByIface["wlan0"] != nil {
		t.Fatal("wlan0 still registered after the rename")
	}
	if _, ok := m.devByPath[old.path]; ok {
		t.Fatal("the old device path is still registered")
	}
	d := m.devByIface["wlp1s0"]
	if d == nil || d.index != 3 {
		t.Fatalf("wlp1s0 not registered with index 3: %+v", d)
	}
	n := 0
	for _, x := range m.devices {
		if x.index == 3 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("%d devices for ifindex 3, want 1", n)
	}
}
