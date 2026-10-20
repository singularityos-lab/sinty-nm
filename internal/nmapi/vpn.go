package nmapi

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

type ipSettings struct {
	addrs   []net.IPNet
	dns     []net.IP
	domains []string
}

type vpnRoute struct {
	index int
	route core.RouteInfo
}

func variantUint(g map[string]dbus.Variant, key string) int {
	if g == nil {
		return 0
	}
	v, ok := g[key]
	if !ok {
		return 0
	}
	switch n := v.Value().(type) {
	case uint32:
		return int(n)
	case int32:
		return int(n)
	case uint64:
		return int(n)
	case int64:
		return int(n)
	case string:
		i, _ := strconv.Atoi(n)
		return i
	}
	return 0
}

func variantStrings(v dbus.Variant) []string {
	switch val := v.Value().(type) {
	case []string:
		return val
	case string:
		var out []string
		for _, p := range strings.FieldsFunc(val, func(r rune) bool { return r == ',' || r == ';' || r == ' ' }) {
			out = append(out, p)
		}
		return out
	}
	return nil
}

func (sc *SettingsConnection) interfaceName() string {
	sc.mu.Lock()
	name := variantString(sc.settings["connection"], "interface-name")
	id := sc.id
	sc.mu.Unlock()
	if name != "" {
		return name
	}
	var b strings.Builder
	for _, r := range strings.ToLower(id) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	name = b.String()
	if name == "" {
		name = "wg0"
	}
	if len(name) > 15 {
		name = name[:15]
	}
	return name
}

func (sc *SettingsConnection) wgConfig() core.WGConfig {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	g := sc.settings["wireguard"]
	cfg := core.WGConfig{}
	if g == nil {
		return cfg
	}
	cfg.PrivateKey = variantString(g, "private-key")
	cfg.ListenPort = variantUint(g, "listen-port")
	cfg.FwMark = variantUint(g, "fwmark")
	v, ok := g["peers"]
	if !ok {
		return cfg
	}
	peers, _ := v.Value().([]map[string]dbus.Variant)
	for _, p := range peers {
		peer := core.WGPeer{
			PublicKey:    variantString(p, "public-key"),
			PresharedKey: variantString(p, "preshared-key"),
			Endpoint:     variantString(p, "endpoint"),
			Keepalive:    variantUint(p, "persistent-keepalive"),
		}
		if a, ok := p["allowed-ips"]; ok {
			for _, s := range variantStrings(a) {
				if !strings.Contains(s, "/") {
					if ip := net.ParseIP(s); ip != nil && ip.To4() != nil {
						s += "/32"
					} else {
						s += "/128"
					}
				}
				if _, n, err := net.ParseCIDR(strings.TrimSpace(s)); err == nil {
					peer.AllowedIPs = append(peer.AllowedIPs, *n)
				}
			}
		}
		cfg.Peers = append(cfg.Peers, peer)
	}
	return cfg
}

func (sc *SettingsConnection) wgMTU() int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return variantUint(sc.settings["wireguard"], "mtu")
}

func (sc *SettingsConnection) ipConfig(group string) ipSettings {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	g := sc.settings[group]
	out := ipSettings{}
	if g == nil {
		return out
	}
	if v, ok := g["address-data"]; ok {
		list, _ := v.Value().([]map[string]dbus.Variant)
		for _, a := range list {
			ip := net.ParseIP(variantString(a, "address"))
			prefix := variantUint(a, "prefix")
			if ip == nil {
				continue
			}
			bits := 128
			if ip.To4() != nil {
				ip = ip.To4()
				bits = 32
			}
			if prefix <= 0 || prefix > bits {
				prefix = bits
			}
			out.addrs = append(out.addrs, net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, bits)})
		}
	}
	if len(out.addrs) == 0 && group == "ipv4" {
		if v, ok := g["addresses"]; ok {
			list, _ := v.Value().([][]uint32)
			for _, a := range list {
				if len(a) < 2 {
					continue
				}
				ip := make(net.IP, 4)
				binary.LittleEndian.PutUint32(ip, a[0])
				prefix := int(a[1])
				if prefix <= 0 || prefix > 32 {
					prefix = 32
				}
				out.addrs = append(out.addrs, net.IPNet{IP: ip, Mask: net.CIDRMask(prefix, 32)})
			}
		}
	}
	if v, ok := g["dns-data"]; ok {
		for _, s := range variantStrings(v) {
			if ip := net.ParseIP(s); ip != nil {
				out.dns = append(out.dns, ip)
			}
		}
	}
	if len(out.dns) == 0 {
		if v, ok := g["dns"]; ok {
			switch d := v.Value().(type) {
			case []uint32:
				for _, n := range d {
					ip := make(net.IP, 4)
					binary.LittleEndian.PutUint32(ip, n)
					out.dns = append(out.dns, ip)
				}
			case [][]byte:
				for _, b := range d {
					if len(b) == 16 {
						out.dns = append(out.dns, net.IP(b))
					}
				}
			default:
				for _, s := range variantStrings(v) {
					if ip := net.ParseIP(s); ip != nil {
						out.dns = append(out.dns, ip)
					}
				}
			}
		}
	}
	if v, ok := g["dns-search"]; ok {
		out.domains = variantStrings(v)
	}
	return out
}

func (m *Manager) ensureWireGuardDevice(sc *SettingsConnection) (*Device, error) {
	name := sc.interfaceName()
	m.mu.Lock()
	d := m.devByIface[name]
	m.mu.Unlock()
	if d != nil {
		return d, nil
	}
	if err := m.b.WG.Configure(name, sc.wgConfig()); err != nil {
		return nil, err
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		m.mu.Lock()
		d = m.devByIface[name]
		m.mu.Unlock()
		if d != nil {
			return d, nil
		}
		if li, err := m.b.Link.LinkByName(name); err == nil {
			m.onLinkEvent(li, true)
			continue
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil, fmt.Errorf("wireguard interface %s did not appear", name)
}

func defaultGateway4(skip string) (string, net.IP) {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return "", nil
	}
	defer f.Close()
	best := -1
	var iface string
	var gw net.IP
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 8 || fields[0] == skip || fields[1] != "00000000" || fields[7] != "00000000" {
			continue
		}
		raw, err := hex.DecodeString(fields[2])
		if err != nil || len(raw) != 4 {
			continue
		}
		metric, _ := strconv.Atoi(fields[6])
		if best >= 0 && metric >= best {
			continue
		}
		best = metric
		iface = fields[0]
		gw = net.IPv4(raw[3], raw[2], raw[1], raw[0]).To4()
	}
	return iface, gw
}

func halves(n net.IPNet) []net.IPNet {
	ones, bits := n.Mask.Size()
	if ones != 0 {
		return []net.IPNet{n}
	}
	if bits == 32 {
		return []net.IPNet{
			{IP: net.IPv4(0, 0, 0, 0).To4(), Mask: net.CIDRMask(1, 32)},
			{IP: net.IPv4(128, 0, 0, 0).To4(), Mask: net.CIDRMask(1, 32)},
		}
	}
	return []net.IPNet{
		{IP: net.ParseIP("::"), Mask: net.CIDRMask(1, 128)},
		{IP: net.ParseIP("8000::"), Mask: net.CIDRMask(1, 128)},
	}
}

func (m *Manager) bringUpWireGuard(ac *ActiveConnection, sc *SettingsConnection, dev *Device) error {
	cfg := sc.wgConfig()
	if err := m.b.WG.Configure(dev.iface, cfg); err != nil {
		return err
	}
	if mtu := sc.wgMTU(); mtu > 0 {
		_ = m.b.Link.SetMTU(dev.index, mtu)
	}
	if err := m.b.Link.FlushAddrs(dev.index); err != nil {
		return fmt.Errorf("flush %s: %w", dev.iface, err)
	}
	v4 := sc.ipConfig("ipv4")
	v6 := sc.ipConfig("ipv6")
	for _, a := range append(append([]net.IPNet{}, v4.addrs...), v6.addrs...) {
		ones, _ := a.Mask.Size()
		if err := m.b.Link.AddAddr(dev.index, a.IP, ones); err != nil {
			return fmt.Errorf("address %s on %s: %w", a.String(), dev.iface, err)
		}
	}
	if err := m.b.Link.SetUp(dev.index, true); err != nil {
		return err
	}
	full := false
	for _, p := range cfg.Peers {
		for _, n := range p.AllowedIPs {
			if ones, bits := n.Mask.Size(); ones == 0 && bits == 32 {
				full = true
			}
			for _, h := range halves(n) {
				dst := h
				_ = m.b.Link.AddRoute(dev.index, core.RouteInfo{Dst: &dst, Metric: 50})
			}
		}
	}
	if full {
		gwIface, gw := defaultGateway4(dev.iface)
		if gw != nil {
			if li, err := m.b.Link.LinkByName(gwIface); err == nil {
				for _, p := range cfg.Peers {
					host, _, err := net.SplitHostPort(p.Endpoint)
					if err != nil {
						continue
					}
					ips, err := net.LookupIP(host)
					if err != nil {
						continue
					}
					for _, ip := range ips {
						if ip.To4() == nil {
							continue
						}
						dst := net.IPNet{IP: ip.To4(), Mask: net.CIDRMask(32, 32)}
						r := core.RouteInfo{Dst: &dst, Gw: gw, Metric: 5}
						if err := m.b.Link.AddRoute(li.Index, r); err == nil {
							ac.vpnRoutes = append(ac.vpnRoutes, vpnRoute{index: li.Index, route: r})
						}
					}
				}
			}
		}
	}
	dns := append(append([]net.IP{}, v4.dns...), v6.dns...)
	if len(dns) > 0 {
		domains := append(append([]string{}, v4.domains...), v6.domains...)
		_ = m.b.DNS.Set(core.DNSEntry{Iface: dev.iface, Nameservers: dns, Domains: domains, Priority: -50})
	}
	return nil
}

func (m *Manager) tearDownWireGuard(ac *ActiveConnection) {
	for _, r := range ac.vpnRoutes {
		_ = m.b.Link.DelRoute(r.index, r.route)
	}
	ac.vpnRoutes = nil
}
