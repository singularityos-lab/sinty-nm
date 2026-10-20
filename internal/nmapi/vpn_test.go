package nmapi

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
)

func dnsU32(s string) uint32 {
	return binary.LittleEndian.Uint32(net.ParseIP(s).To4())
}

func libnmWireGuard() map[string]map[string]dbus.Variant {
	return map[string]map[string]dbus.Variant{
		"connection": {
			"id":             dbus.MakeVariant("oneclick2"),
			"type":           dbus.MakeVariant("wireguard"),
			"interface-name": dbus.MakeVariant("oneclick2"),
		},
		"wireguard": {
			"private-key": dbus.MakeVariant("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="),
			"listen-port": dbus.MakeVariant(uint32(51820)),
			"peers": dbus.MakeVariant([]map[string]dbus.Variant{{
				"public-key":           dbus.MakeVariant("xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="),
				"endpoint":             dbus.MakeVariant("vpn.example.org:51820"),
				"allowed-ips":          dbus.MakeVariant([]string{"0.0.0.0/0", "10.8.0.0/24"}),
				"persistent-keepalive": dbus.MakeVariant(uint32(25)),
			}}),
		},
		"ipv4": {
			"method":       dbus.MakeVariant("manual"),
			"address-data": dbus.MakeVariant([]map[string]dbus.Variant{{"address": dbus.MakeVariant("10.8.0.2"), "prefix": dbus.MakeVariant(uint32(24))}}),
			"dns":          dbus.MakeVariant([]uint32{dnsU32("1.1.1.1"), dnsU32("9.9.9.9")}),
		},
	}
}

func checkProfile(t *testing.T, sc *SettingsConnection) {
	t.Helper()
	cfg := sc.wgConfig()
	if cfg.PrivateKey == "" || cfg.ListenPort != 51820 || len(cfg.Peers) != 1 {
		t.Fatalf("wg config: %+v", cfg)
	}
	p := cfg.Peers[0]
	if p.Endpoint != "vpn.example.org:51820" || p.Keepalive != 25 || len(p.AllowedIPs) != 2 || p.AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Fatalf("peer: %+v", p)
	}
	ip := sc.ipConfig("ipv4")
	if len(ip.addrs) != 1 || ip.addrs[0].String() != "10.8.0.2/24" {
		t.Fatalf("addrs: %v", ip.addrs)
	}
	if len(ip.dns) != 2 || !ip.dns[0].Equal(net.ParseIP("1.1.1.1")) || !ip.dns[1].Equal(net.ParseIP("9.9.9.9")) {
		t.Fatalf("dns: %v", ip.dns)
	}
	if sc.interfaceName() != "oneclick2" {
		t.Fatalf("iface: %s", sc.interfaceName())
	}
}

func TestWireGuardProfileSurvivesKeyfile(t *testing.T) {
	settings := libnmWireGuard()
	checkProfile(t, &SettingsConnection{settings: settings, id: "oneclick2"})
	path := filepath.Join(t.TempDir(), "oneclick2.nmconnection")
	if err := writeKeyfile(path, settings); err != nil {
		t.Fatal(err)
	}
	back, err := readKeyfile(path)
	if err != nil {
		t.Fatal(err)
	}
	checkProfile(t, &SettingsConnection{settings: back, id: "oneclick2"})
}

func TestHalvesSplitDefaultRoute(t *testing.T) {
	_, all, _ := net.ParseCIDR("0.0.0.0/0")
	h := halves(*all)
	if len(h) != 2 || h[0].String() != "0.0.0.0/1" || h[1].String() != "128.0.0.0/1" {
		t.Fatalf("halves: %v", h)
	}
	_, lan, _ := net.ParseCIDR("10.8.0.0/24")
	if l := halves(*lan); len(l) != 1 || l[0].String() != "10.8.0.0/24" {
		t.Fatalf("lan: %v", l)
	}
}

func TestInterfaceNameFromID(t *testing.T) {
	sc := &SettingsConnection{settings: map[string]map[string]dbus.Variant{"connection": {"type": dbus.MakeVariant("wireguard")}}, id: "My Office VPN (home)"}
	if n := sc.interfaceName(); n != "myofficevpnhome" {
		t.Fatalf("name %q", n)
	}
}
