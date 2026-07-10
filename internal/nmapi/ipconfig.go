package nmapi

import (
	"encoding/binary"
	"net"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// IPConfig is an org.freedesktop.NetworkManager.IP4Config or .IP6Config object built from
// an applied lease or static configuration.
type IPConfig struct {
	m     *Manager
	path  dbus.ObjectPath
	iface string
	props *prop.Properties
	spec  prop.Map
}

// newIP4Config builds and returns an IP4Config from an applied IPv4 lease.
func (m *Manager) newIP4Config(l *core.Lease) *IPConfig {
	ip := &IPConfig{m: m, path: m.ipGen.next(prefixIP4), iface: ifaceIP4}

	addr := ""
	if l.IP != nil {
		addr = l.IP.String()
	}
	gw := ""
	if l.Gateway != nil {
		gw = l.Gateway.String()
	}

	addressData := []map[string]dbus.Variant{}
	legacyAddrs := [][]uint32{}
	if l.IP != nil {
		addressData = append(addressData, map[string]dbus.Variant{
			"address": dbus.MakeVariant(addr),
			"prefix":  dbus.MakeVariant(uint32(l.PrefixLen)),
		})
		legacyAddrs = append(legacyAddrs, []uint32{ip4ToUint32(l.IP), uint32(l.PrefixLen), ip4ToUint32(l.Gateway)})
	}

	routeData := []map[string]dbus.Variant{}
	if l.Gateway != nil {
		routeData = append(routeData, map[string]dbus.Variant{
			"dest":     dbus.MakeVariant("0.0.0.0"),
			"prefix":   dbus.MakeVariant(uint32(0)),
			"next-hop": dbus.MakeVariant(gw),
			"metric":   dbus.MakeVariant(uint32(100)),
		})
	}

	nsLegacy := []uint32{}
	nsData := []string{}
	for _, d := range l.DNS {
		nsLegacy = append(nsLegacy, ip4ToUint32(d))
		nsData = append(nsData, d.String())
	}

	spec := prop.Map{
		ifaceIP4: {
			"Addresses":      {Value: legacyAddrs, Writable: false, Emit: prop.EmitTrue},
			"AddressData":    {Value: addressData, Writable: false, Emit: prop.EmitTrue},
			"Gateway":        {Value: gw, Writable: false, Emit: prop.EmitTrue},
			"Nameservers":    {Value: nsLegacy, Writable: false, Emit: prop.EmitTrue},
			"NameserverData": {Value: nsDataVariants(nsData), Writable: false, Emit: prop.EmitTrue},
			"Domains":        {Value: l.Domains, Writable: false, Emit: prop.EmitTrue},
			"RouteData":      {Value: routeData, Writable: false, Emit: prop.EmitTrue},
			"Routes":         {Value: [][]uint32{}, Writable: false, Emit: prop.EmitTrue},
		},
	}
	ip.spec = spec
	return ip
}

// ip6Addr is NM's legacy IP6Config address tuple, signature (ayuay).
type ip6Addr struct {
	Address []byte
	Prefix  uint32
	Gateway []byte
}

// newIP6ConfigEmpty builds a minimal, empty IP6Config (link-local only path). Full IPv6
// address reporting is a follow-up; clients that read it get correct empty defaults.
func (m *Manager) newIP6ConfigEmpty() *IPConfig {
	ip := &IPConfig{m: m, path: m.ipGen.next(prefixIP6), iface: ifaceIP6}
	ip.spec = prop.Map{
		ifaceIP6: {
			"Addresses":   {Value: []ip6Addr{}, Writable: false, Emit: prop.EmitTrue},
			"AddressData": {Value: []map[string]dbus.Variant{}, Writable: false, Emit: prop.EmitTrue},
			"Gateway":     {Value: "", Writable: false, Emit: prop.EmitTrue},
			"Nameservers": {Value: [][]byte{}, Writable: false, Emit: prop.EmitTrue},
			"Domains":     {Value: []string{}, Writable: false, Emit: prop.EmitTrue},
			"RouteData":   {Value: []map[string]dbus.Variant{}, Writable: false, Emit: prop.EmitTrue},
		},
	}
	return ip
}

// spec holds the property table until export runs.
func (ip *IPConfig) export() error {
	p, err := prop.Export(ip.m.conn, ip.path, ip.spec)
	if err != nil {
		return err
	}
	ip.props = p
	node := &introspect.Node{
		Name: string(ip.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{Name: ip.iface},
		},
	}
	return ip.m.conn.Export(introspect.NewIntrospectable(node), ip.path, "org.freedesktop.DBus.Introspectable")
}

// unexport removes the IPConfig object.
func (ip *IPConfig) unexport() {
	_ = ip.m.conn.Export(nil, ip.path, "org.freedesktop.DBus.Properties")
	_ = ip.m.conn.Export(nil, ip.path, "org.freedesktop.DBus.Introspectable")
}

// nsDataVariants wraps nameserver strings as NM's NameserverData aa{sv}.
func nsDataVariants(ns []string) []map[string]dbus.Variant {
	out := make([]map[string]dbus.Variant, 0, len(ns))
	for _, s := range ns {
		out = append(out, map[string]dbus.Variant{"address": dbus.MakeVariant(s)})
	}
	return out
}

// ip4ToUint32 packs an IPv4 address into the little-endian uint32 NM uses in its legacy
// au address arrays (the well-known "host byte order" NM quirk on LE machines).
func ip4ToUint32(ip net.IP) uint32 {
	if ip == nil {
		return 0
	}
	v4 := ip.To4()
	if v4 == nil {
		return 0
	}
	return binary.LittleEndian.Uint32(v4)
}
