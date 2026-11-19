package nmapi

import (
	"testing"
)

func TestPropertyChangesAfterTheBusClosesDoNotPanic(t *testing.T) {
	conn := privateBus(t)
	m, err := New(conn, Backends{Link: fakeLink{}, Wifi: &fakeWifi{}, DHCP: &fakeDHCP{wifi: &fakeWifi{}}, DNS: &recordDNS{}, RFKill: fakeRF{}, Conn: offlineConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	d := m.devByIface["wlan0"]
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	m.onRFKillEvent(true, false)
	d.setState(devStateDisconnected, devReasonNone)
	if v := m.rootProps.GetMust(RootIface, "WirelessEnabled"); v != false {
		t.Fatalf("WirelessEnabled = %v after a soft block, want false", v)
	}
}
