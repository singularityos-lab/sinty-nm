package nmapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

type offlineConn struct{}

func (offlineConn) Check(context.Context) (core.Connectivity, error) {
	return core.ConnNone, errors.New("offline")
}

type lateLink struct {
	fakeLink
	calls atomic.Int32
}

func (l *lateLink) IPv4(index int) (*core.Lease, error) {
	if index != 3 || l.calls.Add(1) < 3 {
		return &core.Lease{}, nil
	}
	return &core.Lease{IP: net.IPv4(192, 168, 1, 3).To4(), PrefixLen: 24, Gateway: net.IPv4(192, 168, 1, 1).To4()}, nil
}

func TestAdoptedWifiPublishesTheKernelIPv4(t *testing.T) {
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("# iwd\nnameserver 192.168.1.1\nnameserver fd00::53\nsearch lan\nnameserver 9.9.9.9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldResolv, oldDelay := resolvConf, observeDelay
	resolvConf, observeDelay = resolv, 5*time.Millisecond
	defer func() { resolvConf, observeDelay = oldResolv, oldDelay }()

	conn := privateBus(t)
	link := &lateLink{}
	m, err := New(conn, Backends{Link: link, Wifi: &fakeWifi{}, DHCP: &fakeDHCP{wifi: &fakeWifi{}}, DNS: fakeDNS{}, RFKill: fakeRF{}, Conn: offlineConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	dev := m.devByIface["wlan0"]
	m.onWifiEvent(core.WifiEvent{Device: "wlan0", State: core.WifiConnected, ConnectedSSID: []byte("Casa")})
	waitFor(t, "ip4 config published", func() bool {
		dev.mu.Lock()
		defer dev.mu.Unlock()
		return dev.ip4 != nullPath
	})
	if link.calls.Load() < 3 {
		t.Fatalf("published before the address existed: %d calls", link.calls.Load())
	}
	spec := dev.ip4obj.spec[ifaceIP4]
	data := spec["AddressData"].Value.([]map[string]dbus.Variant)
	if len(data) != 1 || data[0]["address"].Value() != "192.168.1.3" || data[0]["prefix"].Value() != uint32(24) {
		t.Fatalf("AddressData %v", data)
	}
	if spec["Gateway"].Value != "192.168.1.1" {
		t.Fatalf("Gateway %v", spec["Gateway"].Value)
	}
	ns := spec["Nameservers"].Value.([]uint32)
	if len(ns) != 2 {
		t.Fatalf("Nameservers %v", ns)
	}
	m.mu.Lock()
	var ac *ActiveConnection
	for _, a := range m.activeConns {
		ac = a
	}
	m.mu.Unlock()
	if ac == nil || ac.ip4 != dev.ip4 {
		t.Fatalf("active connection does not carry the config")
	}

	m.onWifiEvent(core.WifiEvent{Device: "wlan0", State: core.WifiDisconnected})
	dev.mu.Lock()
	gone := dev.ip4 == nullPath && dev.ip4obj == nil
	dev.mu.Unlock()
	if !gone {
		t.Fatal("ip4 config left behind after disconnect")
	}
}

func TestNameservers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r")
	_ = os.WriteFile(p, []byte("nameserver 1.1.1.1\nnameserver\nnameserver ::1\noptions edns0\n"), 0o644)
	got := nameservers(p)
	if len(got) != 1 || got[0].String() != "1.1.1.1" {
		t.Fatalf("%v", got)
	}
	if nameservers(filepath.Join(t.TempDir(), "missing")) != nil {
		t.Fatal("missing file")
	}
}
