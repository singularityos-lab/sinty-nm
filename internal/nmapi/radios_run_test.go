package nmapi

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

type switchedWifi struct {
	fakeWifi
	mu    sync.Mutex
	set   []bool
	scans int
}

func (w *switchedWifi) SetPowered(_ string, on bool) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.set = append(w.set, on)
	return nil
}

func (w *switchedWifi) Scan(string) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.scans++
	return nil
}

func (w *switchedWifi) seen() ([]bool, int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]bool(nil), w.set...), w.scans
}

func bootRadios(t *testing.T, file string) (*Manager, *switchedWifi, dbus.BusObject) {
	conn := privateBus(t)
	w := &switchedWifi{}
	m, err := New(conn, Backends{Link: fakeLink{}, Wifi: w, DHCP: &fakeDHCP{wifi: &w.fakeWifi}, DNS: fakeDNS{}, RFKill: fakeRF{}, Conn: fakeConn{}, RadiosFile: file})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	return m, w, conn.Object(conn.Names()[0], "/org/freedesktop/NetworkManager")
}

func TestRadiosStayOffWhileTheDaemonRuns(t *testing.T) {
	file := filepath.Join(t.TempDir(), "radios.json")
	_, _, before := bootRadios(t, file)
	if err := before.SetProperty(RootIface+".WirelessEnabled", dbus.MakeVariant(false)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "choice saved", func() bool { return !loadRadios(file).Wireless })

	m, w, after := bootRadios(t, file)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = m.Run(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, "startup pass", func() bool {
		set, _ := w.seen()
		return len(set) > 1
	})
	m.devByIface["wlan0"].scanAndPopulate()
	set, scans := w.seen()
	for _, on := range set {
		if on {
			t.Fatalf("switched back on: %v", set)
		}
	}
	if scans != 0 {
		t.Fatalf("scanned %d times with the radio off", scans)
	}
	if v, err := after.GetProperty(RootIface + ".WirelessEnabled"); err != nil || v.Value() != false {
		t.Fatalf("shown as %v after a restart: %v", v, err)
	}

	if err := after.SetProperty(RootIface+".WirelessEnabled", dbus.MakeVariant(true)); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "switched on", func() bool { return loadRadios(file).Wireless })
	m.devByIface["wlan0"].scanAndPopulate()
	if _, scans := w.seen(); scans != 1 {
		t.Fatalf("scanned %d times with the radio on", scans)
	}
}
