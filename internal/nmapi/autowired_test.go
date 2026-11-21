package nmapi

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

type wiredLink struct{ fakeLink }

func (wiredLink) DumpLinks() ([]core.LinkInfo, error) {
	return []core.LinkInfo{{Index: 4, Name: "usb0", Kind: core.KindEthernet, Up: true, MAC: "02:00:00:00:00:02"}}, nil
}

type lateDHCP struct {
	mu       sync.Mutex
	failures int
	tries    int
}

func (d *lateDHCP) Acquire(context.Context, string, net.HardwareAddr) (*core.Lease, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.tries++
	if d.tries <= d.failures {
		return nil, errors.New("no offer")
	}
	return &core.Lease{IP: net.IPv4(172, 16, 42, 2), PrefixLen: 24}, nil
}
func (*lateDHCP) Release(string) error     { return nil }
func (*lateDHCP) Bound(string) *core.Lease { return nil }

func TestWiredLinkTakesALateLeaseAfterLinkLocal(t *testing.T) {
	old := wiredRetryDelay
	wiredRetryDelay = func(int) time.Duration { return 20 * time.Millisecond }
	t.Cleanup(func() { wiredRetryDelay = old })

	dh := &lateDHCP{failures: 2}
	link := &recordingLink{}
	m, err := New(privateBus(t), Backends{Link: link, Wifi: &fakeWifi{}, DHCP: dh, DNS: fakeDNS{}, RFKill: fakeRF{}, Conn: fakeConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	dev := m.devByIface["usb0"]
	dev.updateLink(core.LinkInfo{Index: 4, Name: "usb0", Kind: core.KindEthernet, Up: true, Carrier: true})

	waitFor(t, "the lease that arrives after two misses", func() bool {
		return link.last().Equal(net.IPv4(172, 16, 42, 2))
	})
	dh.mu.Lock()
	defer dh.mu.Unlock()
	if dh.tries != 3 {
		t.Fatalf("lease attempts: %d", dh.tries)
	}
}

func TestStaleCarrierReadKeepsANewerCarrierEvent(t *testing.T) {
	dh := &lateDHCP{}
	link := &recordingLink{}
	m, err := New(privateBus(t), Backends{Link: link, Wifi: &fakeWifi{}, DHCP: dh, DNS: fakeDNS{}, RFKill: fakeRF{}, Conn: fakeConn{}})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Export(); err != nil {
		t.Fatal(err)
	}
	dev := m.devByIface["usb0"]
	dev.mu.Lock()
	dev.carrier = true
	dev.mu.Unlock()
	m.manageWired(dev)
	waitFor(t, "wired link configured", func() bool {
		return link.last().Equal(net.IPv4(172, 16, 42, 2))
	})
}

type recordingLink struct {
	wiredLink
	mu    sync.Mutex
	addrs []net.IP
}

func (l *recordingLink) AddAddr(_ int, ip net.IP, _ int) error {
	l.mu.Lock()
	l.addrs = append(l.addrs, ip)
	l.mu.Unlock()
	return nil
}

func (l *recordingLink) last() net.IP {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.addrs) == 0 {
		return nil
	}
	return l.addrs[len(l.addrs)-1]
}

func (*recordingLink) LinkByName(name string) (core.LinkInfo, error) {
	return core.LinkInfo{Index: 4, Name: name, Kind: core.KindEthernet, Up: true}, nil
}
