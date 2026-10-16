package core

import (
	"net"
	"testing"
)

func TestLinkLocalLease(t *testing.T) {
	a, _ := net.ParseMAC("52:54:00:aa:00:01")
	b, _ := net.ParseMAC("52:54:00:aa:00:02")
	la, lb := LinkLocalLease(a), LinkLocalLease(b)
	if !la.IP.Equal(LinkLocalLease(a).IP) {
		t.Fatalf("not stable for the same MAC: %v", la.IP)
	}
	if la.IP.Equal(lb.IP) {
		t.Fatalf("two MACs share %v", la.IP)
	}
	for _, l := range []*Lease{la, lb} {
		ip := l.IP.To4()
		if ip == nil || ip[0] != 169 || ip[1] != 254 || ip[2] == 0 || ip[2] == 255 {
			t.Fatalf("outside the usable link-local range: %v", l.IP)
		}
		if l.PrefixLen != 16 || l.Gateway != nil || len(l.DNS) != 0 {
			t.Fatalf("unexpected lease shape: %+v", l)
		}
	}
	for i := 0; i < 4096; i++ {
		mac := net.HardwareAddr{0x52, 0x54, 0, byte(i >> 8), byte(i), 7}
		ip := LinkLocalLease(mac).IP.To4()
		if ip[2] == 0 || ip[2] == 255 {
			t.Fatalf("reserved subnet for %v: %v", mac, ip)
		}
	}
}
