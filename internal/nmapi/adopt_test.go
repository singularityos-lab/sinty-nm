package nmapi

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
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
	oldResolv, oldDir, oldDelay := resolvConf, resolvconfDir, observeDelay
	resolvConf, resolvconfDir, observeDelay = resolv, filepath.Join(dir, "none"), 5*time.Millisecond
	defer func() { resolvConf, resolvconfDir, observeDelay = oldResolv, oldDir, oldDelay }()

	conn := privateBus(t)
	link := &lateLink{}
	dns := &recordDNS{}
	m, err := New(conn, Backends{Link: link, Wifi: &fakeWifi{}, DHCP: &fakeDHCP{wifi: &fakeWifi{}}, DNS: dns, RFKill: fakeRF{}, Conn: offlineConn{}})
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
	dev.mu.Lock()
	spec := dev.ip4obj.spec[ifaceIP4]
	ip4 := dev.ip4
	dev.mu.Unlock()
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
	var carried dbus.ObjectPath
	for _, a := range m.activeConns {
		carried = a.ip4
	}
	m.mu.Unlock()
	if carried != ip4 {
		t.Fatalf("active connection does not carry the config")
	}
	e, ok := dns.entry("wlan0")
	if !ok || len(e.Nameservers) != 2 || len(e.Domains) != 1 || e.Domains[0] != "lan" {
		t.Fatalf("adopted DNS not registered: %+v %v", e, ok)
	}

	m.onWifiEvent(core.WifiEvent{Device: "wlan0", State: core.WifiDisconnected})
	dev.mu.Lock()
	gone := dev.ip4 == nullPath && dev.ip4obj == nil
	dev.mu.Unlock()
	if !gone {
		t.Fatal("ip4 config left behind after disconnect")
	}
	if _, ok := dns.entry("wlan0"); ok {
		t.Fatal("adopted DNS left behind after disconnect")
	}
}

type recordDNS struct {
	mu      sync.Mutex
	entries map[string]core.DNSEntry
}

func (r *recordDNS) Set(e core.DNSEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]core.DNSEntry)
	}
	r.entries[e.Iface] = e
	return nil
}

func (r *recordDNS) Revert(iface string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.entries, iface)
	return nil
}

func (r *recordDNS) entry(iface string) (core.DNSEntry, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[iface]
	return e, ok
}

func TestParseResolver(t *testing.T) {
	p := filepath.Join(t.TempDir(), "r")
	_ = os.WriteFile(p, []byte("nameserver 1.1.1.1\nnameserver\nnameserver ::1\noptions edns0\n"), 0o644)
	got, _, owned := parseResolver(p)
	if len(got) != 1 || got[0].String() != "1.1.1.1" || owned {
		t.Fatalf("%v %v", got, owned)
	}
	if got, _, _ := parseResolver(filepath.Join(t.TempDir(), "missing")); got != nil {
		t.Fatal("missing file")
	}
}

func TestAdoptedWifiLeasesWhenNoAddressAppears(t *testing.T) {
	dir := t.TempDir()
	oldResolv, oldDir, oldDelay := resolvConf, resolvconfDir, observeDelay
	resolvConf, resolvconfDir, observeDelay = filepath.Join(dir, "resolv.conf"), filepath.Join(dir, "none"), time.Millisecond
	defer func() { resolvConf, resolvconfDir, observeDelay = oldResolv, oldDir, oldDelay }()

	conn := privateBus(t)
	dns := &recordDNS{}
	dh := &fakeDHCP{wifi: &fakeWifi{}, dead: "Dead", failing: "Broken"}
	m, err := New(conn, Backends{Link: fakeLink{}, Wifi: &fakeWifi{}, DHCP: dh, DNS: dns, RFKill: fakeRF{}, Conn: offlineConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	if err := conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus.Properties"), dbus.WithMatchMember("PropertiesChanged"), dbus.WithMatchArg(0, ifaceActive)); err != nil {
		t.Fatal(err)
	}
	signals := make(chan *dbus.Signal, 16)
	conn.Signal(signals)
	dev := m.devByIface["wlan0"]
	m.onWifiEvent(core.WifiEvent{Device: "wlan0", State: core.WifiConnected, ConnectedSSID: []byte("Casa")})
	deadline := time.After(5 * time.Second)
	for published := false; !published; {
		select {
		case sig := <-signals:
			if changed, ok := sig.Body[1].(map[string]dbus.Variant); ok {
				if v, ok := changed["Ip4Config"]; ok && v.Value() != nullPath {
					published = true
				}
			}
		case <-deadline:
			t.Fatal("leased ip4 config never published on the active connection")
		}
	}
	data := dev.ip4obj.spec[ifaceIP4]["AddressData"].Value.([]map[string]dbus.Variant)
	if len(data) != 1 || data[0]["address"].Value() != "192.168.1.50" {
		t.Fatalf("AddressData %v", data)
	}
	if _, ok := dns.entry("wlan0"); !ok {
		t.Fatal("leased DNS not registered")
	}
}

type ownLink struct {
	fakeLink
}

func (ownLink) IPv4(index int) (*core.Lease, error) {
	if index != 3 {
		return &core.Lease{}, nil
	}
	return &core.Lease{IP: net.IPv4(192, 168, 1, 23).To4(), PrefixLen: 24, Gateway: net.IPv4(192, 168, 1, 1).To4()}, nil
}

func adoptWith(t *testing.T, dh *fakeDHCP) *recordDNS {
	t.Helper()
	dir := t.TempDir()
	resolv := filepath.Join(dir, "resolv.conf")
	if err := os.WriteFile(resolv, []byte("# managed by sinty-nm\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldResolv, oldDir, oldDelay := resolvConf, resolvconfDir, observeDelay
	resolvConf, resolvconfDir, observeDelay = resolv, filepath.Join(dir, "none"), time.Millisecond
	t.Cleanup(func() { resolvConf, resolvconfDir, observeDelay = oldResolv, oldDir, oldDelay })

	conn := privateBus(t)
	dns := &recordDNS{}
	m, err := New(conn, Backends{Link: ownLink{}, Wifi: &fakeWifi{}, DHCP: dh, DNS: dns, RFKill: fakeRF{}, Conn: offlineConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	m.onWifiEvent(core.WifiEvent{Device: "wlan0", State: core.WifiConnected, ConnectedSSID: []byte("Casa")})
	waitFor(t, "dns registered", func() bool {
		e, ok := dns.entry("wlan0")
		return ok && len(e.Nameservers) > 0
	})
	return dns
}

func TestAdoptedWifiKeepsTheResolversOfOurOwnLease(t *testing.T) {
	own := &core.Lease{IP: net.IPv4(192, 168, 1, 23).To4(), PrefixLen: 24, DNS: []net.IP{net.IPv4(192, 168, 1, 254)}, Domains: []string{"lan"}}
	dns := adoptWith(t, &fakeDHCP{wifi: &fakeWifi{}, dead: "Dead", failing: "Broken", bound: own})
	e, _ := dns.entry("wlan0")
	if len(e.Nameservers) != 1 || !e.Nameservers[0].Equal(net.IPv4(192, 168, 1, 254)) || len(e.Domains) != 1 {
		t.Fatalf("adopted entry %+v", e)
	}
}

func TestAdoptedWifiWithoutResolversLeasesInstead(t *testing.T) {
	dns := adoptWith(t, &fakeDHCP{wifi: &fakeWifi{}, dead: "Dead", failing: "Broken"})
	e, _ := dns.entry("wlan0")
	if len(e.Nameservers) != 1 || !e.Nameservers[0].Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("entry %+v", e)
	}
}
