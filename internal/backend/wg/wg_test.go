package wg

import (
	"errors"
	"net"
	"os"
	"strings"
	"testing"

	ss "github.com/singularityos-lab/libsingularity/src/system/core/go/sintysystem"
	"github.com/singularityos-lab/sinty-nm/internal/core"
)

const (
	keyA = "dwdtCnMYpX08FsFyUbJmRQ8ML4BJmFV4dH5OzxkEjmg="
	keyB = "XXdiHLHmLJB8JTBL4XrxxseidpQllzP43uhdKHH5zFQ="
	keyC = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo="
	keyD = "YFyEp8Qx2O2zOUmRkFmUuKZ1lHM7iQ3vU2b9bXJ3Kmw="
)

func cidrs(t *testing.T, list ...string) []net.IPNet {
	var out []net.IPNet
	for _, c := range list {
		_, n, err := net.ParseCIDR(c)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *n)
	}
	return out
}

func TestRender(t *testing.T) {
	cfg := core.WGConfig{
		PrivateKey: keyA,
		ListenPort: 51820,
		FwMark:     0x51,
		Peers: []core.WGPeer{
			{PublicKey: keyB, Endpoint: "vpn.example.org:51820", AllowedIPs: cidrs(t, "0.0.0.0/0", "::/0"), Keepalive: 25},
			{PublicKey: keyC, PresharedKey: keyA, AllowedIPs: cidrs(t, "10.9.0.0/16")},
		},
	}
	lookup := func(ep string) (string, error) {
		if ep != "vpn.example.org:51820" {
			t.Fatalf("resolve %q", ep)
		}
		return "[2001:db8::7]:51820", nil
	}
	got, err := render(cfg, lookup)
	if err != nil {
		t.Fatal(err)
	}
	want := "[Interface]\nPrivateKey = " + keyA + "\nListenPort = 51820\nFwMark = 81\n" +
		"[Peer]\nPublicKey = " + keyB + "\nEndpoint = [2001:db8::7]:51820\nPersistentKeepalive = 25\nAllowedIPs = 0.0.0.0/0, ::/0\n" +
		"[Peer]\nPublicKey = " + keyC + "\nPresharedKey = " + keyA + "\nAllowedIPs = 10.9.0.0/16\n"
	if got != want {
		t.Fatalf("got\n%s\nwant\n%s", got, want)
	}
	bare, _ := render(core.WGConfig{PrivateKey: keyA}, lookup)
	if bare != "[Interface]\nPrivateKey = "+keyA+"\n" {
		t.Fatalf("bare %q", bare)
	}
	_, err = render(core.WGConfig{PrivateKey: keyA, Peers: []core.WGPeer{{PublicKey: keyB, Endpoint: "x:1"}}},
		func(string) (string, error) { return "", errors.New("no such host") })
	if err == nil || !strings.Contains(err.Error(), "x:1") {
		t.Fatalf("resolve failure: %v", err)
	}
}

func TestResolve(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1:51820": "127.0.0.1:51820",
		"[fd00::1]:443":   "[fd00::1]:443",
		"localhost:1":     "127.0.0.1:1",
	} {
		got, err := resolve(in)
		if err != nil {
			t.Fatalf("%s: %v", in, err)
		}
		if in == "localhost:1" && got == "[::1]:1" {
			continue
		}
		if got != want {
			t.Fatalf("%s: got %s want %s", in, got, want)
		}
	}
}

func TestConfigureInPrivateNamespace(t *testing.T) {
	if os.Getenv("SINTY_NM_NETNS") != "1" {
		t.Skip("run under unshare -Urn with SINTY_NM_NETNS=1")
	}
	b, _ := New()
	cfg := core.WGConfig{
		PrivateKey: keyA,
		ListenPort: 51830,
		Peers:      []core.WGPeer{{PublicKey: keyC, Endpoint: "127.0.0.1:51831", AllowedIPs: cidrs(t, "10.140.0.0/16"), Keepalive: 5}},
	}
	if err := b.Configure("wgnm0", cfg); err != nil {
		t.Fatal(err)
	}
	dev, peers, err := ss.WgGet("wgnm0")
	if err != nil {
		t.Fatal(err)
	}
	if dev.ListenPort != 51830 || dev.PublicKey != keyB {
		t.Fatalf("device %+v", dev)
	}
	if len(peers) != 1 || peers[0].PublicKey != keyC || peers[0].Endpoint != "127.0.0.1:51831" || peers[0].AllowedIPs != "10.140.0.0/16" || peers[0].Keepalive != 5 {
		t.Fatalf("peers %+v", peers)
	}
	link, err := ss.NetLinkByName("wgnm0")
	if err != nil || link.Flags&1 == 0 {
		t.Fatalf("link %+v %v", link, err)
	}
	routes, _ := ss.NetRoutes()
	for _, r := range routes {
		if r.Destination == "10.140.0.0" {
			t.Fatalf("route added %+v", r)
		}
	}
	cfg.ListenPort = 0
	cfg.Peers = []core.WGPeer{{PublicKey: keyD, AllowedIPs: cidrs(t, "10.141.0.0/16")}}
	if err := b.Configure("wgnm0", cfg); err != nil {
		t.Fatal(err)
	}
	dev, peers, _ = ss.WgGet("wgnm0")
	if dev.ListenPort != 51830 || len(peers) != 1 || peers[0].PublicKey != keyD {
		t.Fatalf("after replace %+v %+v", dev, peers)
	}
	if err := b.Remove("wgnm0"); err != nil {
		t.Fatal(err)
	}
	if _, err := ss.NetLinkByName("wgnm0"); err == nil {
		t.Fatal("link still there")
	}
	bad := core.WGConfig{PrivateKey: "short"}
	if err := b.Configure("wgnm1", bad); err == nil {
		t.Fatal("bad key accepted")
	}
}
