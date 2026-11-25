package sys

import (
	"net"
	"strings"
	"testing"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

func TestRenderRefusesInjectedSearchDomains(t *testing.T) {
	m := &dnsManager{entries: map[string]core.DNSEntry{
		"eth0": {
			Iface:       "eth0",
			Nameservers: []net.IP{net.IPv4(192, 168, 1, 1)},
			Domains:     []string{"lan\x00", "evil\nnameserver 6.6.6.6", "corp.example.com."},
		},
	}}
	got := string(m.render())
	want := core.ResolvConfMarker + "\nnameserver 192.168.1.1\nsearch lan corp.example.com\n"
	if got != want {
		t.Fatalf("render:\n%q\nwant\n%q", got, want)
	}
	if strings.Contains(got, "6.6.6.6") {
		t.Fatal("injected nameserver reached resolv.conf")
	}
}
