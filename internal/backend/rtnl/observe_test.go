package rtnl

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	ss "github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"
)

func TestObserveIPv4(t *testing.T) {
	addrs := []ss.NetAddress{
		{Index: 1, Family: syscall.AF_INET, Prefix: 8, Scope: syscall.RT_SCOPE_HOST, Address: "127.0.0.1"},
		{Index: 4, Family: syscall.AF_INET6, Prefix: 64, Scope: syscall.RT_SCOPE_LINK, Address: "fe80::1"},
		{Index: 4, Family: syscall.AF_INET, Prefix: 24, Scope: syscall.RT_SCOPE_UNIVERSE, Address: "192.168.1.3"},
		{Index: 5, Family: syscall.AF_INET, Prefix: 32, Scope: syscall.RT_SCOPE_UNIVERSE, Address: "10.0.0.9"},
	}
	routes := []ss.NetRoute{
		{Oif: 4, Family: syscall.AF_INET, Prefix: 24, Table: mainTable, Destination: "192.168.1.0"},
		{Oif: 4, Family: syscall.AF_INET, Prefix: 0, Table: mainTable, Priority: 600, Gateway: "192.168.1.254"},
		{Oif: 4, Family: syscall.AF_INET, Prefix: 0, Table: mainTable, Priority: 304, Gateway: "192.168.1.1"},
		{Oif: 4, Family: syscall.AF_INET, Prefix: 0, Table: 255, Gateway: "192.168.1.9"},
		{Oif: 5, Family: syscall.AF_INET, Prefix: 0, Table: mainTable, Priority: 1, Gateway: "10.0.0.1"},
	}
	l := observeIPv4(addrs, routes, 4)
	if l.IP.String() != "192.168.1.3" || l.PrefixLen != 24 || l.Gateway.String() != "192.168.1.1" {
		t.Fatalf("got %v/%d via %v", l.IP, l.PrefixLen, l.Gateway)
	}
	none := observeIPv4(addrs, routes, 7)
	if none.IP != nil || none.Gateway != nil {
		t.Fatalf("unknown link %+v", none)
	}
}

func TestIPv4MatchesKernel(t *testing.T) {
	links, err := ss.NetLinks()
	if err != nil {
		t.Skip(err)
	}
	addrs, _ := ss.NetAddresses()
	b := &Backend{}
	for _, li := range links {
		l, err := b.IPv4(int(li.Index))
		if err != nil {
			t.Fatal(err)
		}
		if l.IP == nil {
			continue
		}
		found := false
		for _, a := range addrs {
			if a.Index == li.Index && a.Address == l.IP.String() && int(a.Prefix) == l.PrefixLen {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: %v/%d not among the kernel addresses", li.Name, l.IP, l.PrefixLen)
		}
	}
}

func TestIsGadgetFollowsTheParentDevice(t *testing.T) {
	root := t.TempDir()
	old := sysClassNet
	sysClassNet = filepath.Join(root, "class", "net")
	t.Cleanup(func() { sysClassNet = old })
	for name, parent := range map[string]string{"usb0": "udc/gadget.0", "eth0": "pci/0000:00:1f.6"} {
		dev := filepath.Join(root, "devices", parent)
		if err := os.MkdirAll(dev, 0o755); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(sysClassNet, name)
		if err := os.MkdirAll(link, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(dev, filepath.Join(link, "device")); err != nil {
			t.Fatal(err)
		}
	}
	if !isGadget("usb0") {
		t.Error("usb0 under a gadget is not reported as one")
	}
	if isGadget("eth0") || isGadget("lo") {
		t.Error("a non-gadget link is reported as a gadget")
	}
}
