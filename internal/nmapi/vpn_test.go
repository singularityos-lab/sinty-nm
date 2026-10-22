package nmapi

import (
	"encoding/binary"
	"net"
	"os"
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
			"id":             dbus.MakeVariant("office"),
			"type":           dbus.MakeVariant("wireguard"),
			"interface-name": dbus.MakeVariant("office"),
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
	if sc.interfaceName() != "office" {
		t.Fatalf("iface: %s", sc.interfaceName())
	}
}

func TestWireGuardProfileSurvivesKeyfile(t *testing.T) {
	settings := libnmWireGuard()
	checkProfile(t, &SettingsConnection{settings: settings, id: "office"})
	path := filepath.Join(t.TempDir(), "office.nmconnection")
	if err := writeKeyfile(path, settings); err != nil {
		t.Fatal(err)
	}
	back, err := readKeyfile(path)
	if err != nil {
		t.Fatal(err)
	}
	checkProfile(t, &SettingsConnection{settings: back, id: "office"})
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

func TestKeepSecretsOnUpdate(t *testing.T) {
	prev := map[string]map[string]dbus.Variant{
		"connection": {"id": dbus.MakeVariant("wg0")},
		"wireguard":  {"private-key": dbus.MakeVariant("secret")},
	}
	next := map[string]map[string]dbus.Variant{
		"connection": {"id": dbus.MakeVariant("wg0"), "autoconnect": dbus.MakeVariant(false)},
		"wireguard":  {"listen-port": dbus.MakeVariant(uint32(0))},
	}
	keepSecrets(next, prev)
	if got := variantString(next["wireguard"], "private-key"); got != "secret" {
		t.Fatalf("private-key not kept: %q", got)
	}
}

func TestLegacyKeyfileLists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "office.nmconnection")
	body := "[connection]\nid=office\ntype=wireguard\ninterface-name=office\n\n" +
		"[ipv4]\naddress-data=[map[address:\"10.8.0.8\" prefix:@u 32]]\ndns-data=[10.8.0.1]\ndns-search=[~]\nmethod=manual\nroute-data=[]\n\n" +
		"[wireguard]\npeers=[map[allowed-ips:[\"0.0.0.0/0\"] endpoint:\"203.0.113.7:51820\" public-key:\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\"]]\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	back, legacy, err := readKeyfileLegacy(path)
	if err != nil || !legacy {
		t.Fatalf("legacy %v err %v", legacy, err)
	}
	sc := &SettingsConnection{settings: back, id: "office"}
	ip := sc.ipConfig("ipv4")
	if len(ip.addrs) != 1 || ip.addrs[0].String() != "10.8.0.8/32" {
		t.Fatalf("addrs: %v", ip.addrs)
	}
	if len(ip.dns) != 1 || !ip.dns[0].Equal(net.ParseIP("10.8.0.1")) {
		t.Fatalf("dns: %v", ip.dns)
	}
	cfg := sc.wgConfig()
	if len(cfg.Peers) != 1 || cfg.Peers[0].Endpoint != "203.0.113.7:51820" || len(cfg.Peers[0].AllowedIPs) != 1 || cfg.Peers[0].AllowedIPs[0].String() != "0.0.0.0/0" {
		t.Fatalf("peers: %+v", cfg.Peers)
	}
	if err := writeKeyfile(path, back); err != nil {
		t.Fatal(err)
	}
	again, legacy, err := readKeyfileLegacy(path)
	if err != nil || legacy {
		t.Fatalf("rewritten legacy %v err %v", legacy, err)
	}
	if got := (&SettingsConnection{settings: again}).ipConfig("ipv4"); len(got.addrs) != 1 {
		t.Fatalf("rewritten addrs: %v", got.addrs)
	}
}
