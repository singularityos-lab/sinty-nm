package nmapi

import (
	"bufio"
	"context"
	"errors"
	"net"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

type fakeLink struct{}

func (fakeLink) DumpLinks() ([]core.LinkInfo, error) {
	return []core.LinkInfo{{Index: 3, Name: "wlan0", Kind: core.KindWifi, Up: true, MAC: "02:00:00:00:00:01"}}, nil
}
func (fakeLink) LinkByName(name string) (core.LinkInfo, error) {
	return core.LinkInfo{}, errors.New("no link")
}
func (fakeLink) SetUp(int, bool) error                                      { return nil }
func (fakeLink) AddAddr(int, net.IP, int) error                             { return nil }
func (fakeLink) FlushAddrs(int) error                                       { return nil }
func (fakeLink) AddRoute(int, core.RouteInfo) error                         { return nil }
func (fakeLink) DelRoute(int, core.RouteInfo) error                         { return nil }
func (fakeLink) SetMTU(int, int) error                                      { return nil }
func (fakeLink) Subscribe(context.Context, func(core.LinkInfo, bool)) error { return nil }

type fakeWifi struct {
	mu        sync.Mutex
	connected string
}

func (*fakeWifi) ListDevices() ([]core.WifiDevice, error)          { return nil, nil }
func (*fakeWifi) SetPowered(string, bool) error                    { return nil }
func (*fakeWifi) Scan(string) error                                { return nil }
func (*fakeWifi) OrderedNetworks(string) ([]core.ScannedAP, error) { return nil, nil }
func (w *fakeWifi) Connect(_ string, ssid []byte, _ core.SecretFunc) error {
	w.mu.Lock()
	w.connected = string(ssid)
	w.mu.Unlock()
	return nil
}
func (w *fakeWifi) Disconnect(string) error {
	w.mu.Lock()
	w.connected = ""
	w.mu.Unlock()
	return nil
}
func (*fakeWifi) Forget(string, []byte) error                           { return nil }
func (*fakeWifi) State(string) (core.WifiState, error)                  { return core.WifiDisconnected, nil }
func (*fakeWifi) Subscribe(context.Context, func(core.WifiEvent)) error { return nil }

type fakeDHCP struct {
	wifi    *fakeWifi
	dead    string
	failing string
}

func (d *fakeDHCP) Acquire(ctx context.Context, _ string, _ net.HardwareAddr) (*core.Lease, error) {
	d.wifi.mu.Lock()
	ssid := d.wifi.connected
	d.wifi.mu.Unlock()
	switch ssid {
	case d.dead:
		<-ctx.Done()
		return nil, ctx.Err()
	case d.failing:
		return nil, errors.New("no lease")
	}
	return &core.Lease{IP: net.IPv4(192, 168, 1, 50), PrefixLen: 24, Gateway: net.IPv4(192, 168, 1, 1)}, nil
}
func (*fakeDHCP) Release(string) error { return nil }

type fakeDNS struct{}

func (fakeDNS) Set(core.DNSEntry) error { return nil }
func (fakeDNS) Revert(string) error     { return nil }

type fakeRF struct{}

func (fakeRF) WifiSoftBlocked() (bool, error)                         { return false, nil }
func (fakeRF) WifiHardBlocked() (bool, error)                         { return false, nil }
func (fakeRF) SetWifiBlocked(bool) error                              { return nil }
func (fakeRF) Subscribe(context.Context, func(soft, hard bool)) error { return nil }

type fakeConn struct{}

func (fakeConn) Check(context.Context) (core.Connectivity, error) { return core.ConnFull, nil }

func privateBus(t *testing.T) *dbus.Conn {
	t.Helper()
	cmd := exec.Command("dbus-daemon", "--session", "--nofork", "--print-address")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Skip(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skip("dbus-daemon not available")
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	addr, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	conn, err := dbus.Connect(strings.TrimSpace(addr))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

func wifiProfile(m *Manager, ssid string) *SettingsConnection {
	settings := map[string]map[string]dbus.Variant{
		"connection":      {"id": dbus.MakeVariant(ssid), "type": dbus.MakeVariant("802-11-wireless"), "uuid": dbus.MakeVariant(newUUID())},
		"802-11-wireless": {"ssid": dbus.MakeVariant([]byte(ssid))},
		"ipv4":            {"method": dbus.MakeVariant("auto")},
	}
	sc := m.settings.newConnection(settings, "")
	m.settings.mu.Lock()
	m.settings.conns = append(m.settings.conns, sc)
	m.settings.mu.Unlock()
	if err := sc.export(); err != nil {
		panic(err)
	}
	return sc
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func activeIDs(m *Manager) []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []string
	for _, ac := range m.activeConns {
		out = append(out, ac.id)
	}
	return out
}

func setup(t *testing.T) (*Manager, *Device, *fakeWifi, *fakeDHCP) {
	conn := privateBus(t)
	w := &fakeWifi{}
	dh := &fakeDHCP{wifi: w, dead: "Dead", failing: "Broken"}
	m, err := New(conn, Backends{Link: fakeLink{}, Wifi: w, DHCP: dh, DNS: fakeDNS{}, RFKill: fakeRF{}, Conn: fakeConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	return m, m.devByIface["wlan0"], w, dh
}

func TestSwitchingWifiReplacesTheStuckConnection(t *testing.T) {
	m, dev, w, _ := setup(t)
	dead := wifiProfile(m, "Dead")
	good := wifiProfile(m, "Good")

	stuck, err := m.activate(dead, dev, nullPath)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "stuck in dhcp", func() bool { return dev.state == devStateIPConfig })

	next, err := m.activate(good, dev, nullPath)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "second network activated", func() bool { return next.state == acStateActivated })

	if ids := activeIDs(m); len(ids) != 1 || ids[0] != "Good" {
		t.Fatalf("active connections after switch: %v", ids)
	}
	if !stuck.gone || stuck.state != acStateDeactivated {
		t.Fatalf("first connection still alive: gone=%v state=%d", stuck.gone, stuck.state)
	}
	if dev.activeConn != next.path || dev.state != devStateActivated {
		t.Fatalf("device points at %s state %d", dev.activeConn, dev.state)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.connected != "Good" {
		t.Fatalf("radio associated with %q", w.connected)
	}
}

func TestDisconnectAndDeleteActiveWifi(t *testing.T) {
	m, dev, _, _ := setup(t)
	good := wifiProfile(m, "Good")
	ac, err := m.activate(good, dev, nullPath)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "activated", func() bool { return ac.state == acStateActivated })
	if derr := good.Delete(); derr != nil {
		t.Fatal(derr)
	}
	if ids := activeIDs(m); len(ids) != 0 {
		t.Fatalf("deleted profile still active: %v", ids)
	}
	if dev.activeConn != nullPath || dev.state != devStateDisconnected {
		t.Fatalf("device after delete: %s state %d", dev.activeConn, dev.state)
	}
	if m.settings.byPath(good.path) != nil {
		t.Fatal("profile still listed")
	}
}

func TestFailedActivationDoesNotStayActive(t *testing.T) {
	m, dev, _, _ := setup(t)
	broken := wifiProfile(m, "Broken")
	ac, err := m.activate(broken, dev, nullPath)
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "failure settled", func() bool { return ac.gone })
	if ids := activeIDs(m); len(ids) != 0 {
		t.Fatalf("failed connection still listed: %v", ids)
	}
	if dev.activeConn != nullPath {
		t.Fatalf("device still bound to %s", dev.activeConn)
	}
	if derr := dev.Disconnect(); derr != nil {
		t.Fatal(derr)
	}
}
