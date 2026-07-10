package nmapi

import (
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// deviceStateReason is NM's (state, reason) tuple for the Device.StateReason property.
type deviceStateReason struct {
	State  uint32
	Reason uint32
}

// Device is one network interface, exposed as org.freedesktop.NetworkManager.Device plus
// the kind-specific sub-interface (.Wireless / .Wired / .WireGuard).
type Device struct {
	m     *Manager
	path  dbus.ObjectPath
	props *prop.Properties

	iface   string
	index   int
	kind    core.DeviceKind
	nmType  uint32
	mac     string
	managed bool

	mu         sync.Mutex
	aps        []*AccessPoint
	apByBSSID  map[string]*AccessPoint
	activeAP   dbus.ObjectPath
	activeConn dbus.ObjectPath
	ip4        dbus.ObjectPath
	ip6        dbus.ObjectPath
	dhcp4      dbus.ObjectPath
	ip4obj     *IPConfig
	state      uint32
}

// newDevice builds an unexported Device from a link.
func newDevice(m *Manager, li core.LinkInfo) *Device {
	d := &Device{
		m:          m,
		path:       m.devGen.next(prefixDevices),
		iface:      li.Name,
		index:      li.Index,
		kind:       li.Kind,
		nmType:     deviceTypeFor(li.Kind),
		mac:        li.MAC,
		managed:    li.Kind != core.KindLoopback,
		apByBSSID:  map[string]*AccessPoint{},
		activeAP:   nullPath,
		activeConn: nullPath,
		ip4:        nullPath,
		ip6:        nullPath,
		dhcp4:      nullPath,
		state:      devStateDisconnected,
	}
	if !d.managed {
		d.state = devStateUnmanaged
	}
	return d
}

// export publishes the device object, its property tables (one per interface), its
// methods, and its introspection node.
func (d *Device) export() error {
	spec := prop.Map{
		ifaceDevice: {
			"DeviceType":           {Value: d.nmType, Writable: false, Emit: prop.EmitConst},
			"Real":                 {Value: true, Writable: false, Emit: prop.EmitConst},
			"HwAddress":            {Value: d.mac, Writable: false, Emit: prop.EmitTrue},
			"Capabilities":         {Value: uint32(1), Writable: false, Emit: prop.EmitConst}, // NM_DEVICE_CAP_NM_SUPPORTED
			"Driver":               {Value: "", Writable: false, Emit: prop.EmitConst},
			"State":                {Value: d.state, Writable: false, Emit: prop.EmitTrue},
			"StateReason":          {Value: deviceStateReason{d.state, devReasonNone}, Writable: false, Emit: prop.EmitTrue},
			"Interface":            {Value: d.iface, Writable: false, Emit: prop.EmitTrue},
			"IpInterface":          {Value: d.iface, Writable: false, Emit: prop.EmitTrue},
			"Managed":              {Value: d.managed, Writable: true, Emit: prop.EmitTrue},
			"Autoconnect":          {Value: true, Writable: true, Emit: prop.EmitTrue},
			"AvailableConnections": {Value: d.availableConnections(), Writable: false, Emit: prop.EmitTrue},
			"ActiveConnection":     {Value: d.activeConn, Writable: false, Emit: prop.EmitTrue},
			"Ip4Config":            {Value: d.ip4, Writable: false, Emit: prop.EmitTrue},
			"Ip6Config":            {Value: d.ip6, Writable: false, Emit: prop.EmitTrue},
			"Dhcp4Config":          {Value: d.dhcp4, Writable: false, Emit: prop.EmitTrue},
		},
	}
	switch d.kind {
	case core.KindWifi:
		spec[ifaceWireless] = map[string]*prop.Prop{
			"HwAddress":            {Value: d.mac, Writable: false, Emit: prop.EmitTrue},
			"PermHwAddress":        {Value: d.mac, Writable: false, Emit: prop.EmitTrue},
			"Mode":                 {Value: wifiModeInfra, Writable: false, Emit: prop.EmitTrue},
			"Bitrate":              {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
			"AccessPoints":         {Value: []dbus.ObjectPath{}, Writable: false, Emit: prop.EmitTrue},
			"ActiveAccessPoint":    {Value: d.activeAP, Writable: false, Emit: prop.EmitTrue},
			"WirelessCapabilities": {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
		}
	case core.KindEthernet:
		spec[ifaceWired] = map[string]*prop.Prop{
			"HwAddress":     {Value: d.mac, Writable: false, Emit: prop.EmitTrue},
			"PermHwAddress": {Value: d.mac, Writable: false, Emit: prop.EmitTrue},
			"Speed":         {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
			"Carrier":       {Value: false, Writable: false, Emit: prop.EmitTrue},
		}
	case core.KindWireGuard:
		spec[ifaceWireguard] = map[string]*prop.Prop{
			"PublicKey":  {Value: []byte{}, Writable: false, Emit: prop.EmitTrue},
			"ListenPort": {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
			"FwMark":     {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
		}
	}

	p, err := prop.Export(d.m.conn, d.path, spec)
	if err != nil {
		return err
	}
	d.props = p

	if err := d.m.conn.Export(d, d.path, ifaceDevice); err != nil {
		return err
	}
	if sub := d.subIface(); sub != "" {
		if err := d.m.conn.Export(d, d.path, sub); err != nil {
			return err
		}
	}
	return d.m.conn.Export(introspect.NewIntrospectable(d.node()), d.path, "org.freedesktop.DBus.Introspectable")
}

// unexport removes the device object from the bus.
func (d *Device) unexport() {
	_ = d.m.conn.Export(nil, d.path, ifaceDevice)
	if sub := d.subIface(); sub != "" {
		_ = d.m.conn.Export(nil, d.path, sub)
	}
	_ = d.m.conn.Export(nil, d.path, "org.freedesktop.DBus.Properties")
	_ = d.m.conn.Export(nil, d.path, "org.freedesktop.DBus.Introspectable")
	d.mu.Lock()
	aps := append([]*AccessPoint(nil), d.aps...)
	d.mu.Unlock()
	for _, ap := range aps {
		ap.unexport()
	}
}

// subIface returns the kind-specific interface name, or "" for kinds with no sub-iface.
func (d *Device) subIface() string {
	switch d.kind {
	case core.KindWifi:
		return ifaceWireless
	case core.KindEthernet:
		return ifaceWired
	case core.KindWireGuard:
		return ifaceWireguard
	default:
		return ""
	}
}

// node is the device introspection data, including the sub-interface when present.
func (d *Device) node() *introspect.Node {
	ifaces := []introspect.Interface{
		introspect.IntrospectData,
		prop.IntrospectData,
		{
			Name: ifaceDevice,
			Methods: []introspect.Method{
				{Name: "Disconnect"},
			},
			Signals: []introspect.Signal{
				{Name: "StateChanged", Args: []introspect.Arg{{Name: "new_state", Type: "u"}, {Name: "old_state", Type: "u"}, {Name: "reason", Type: "u"}}},
			},
		},
	}
	switch d.kind {
	case core.KindWifi:
		ifaces = append(ifaces, introspect.Interface{
			Name: ifaceWireless,
			Methods: []introspect.Method{
				{Name: "GetAllAccessPoints", Args: []introspect.Arg{{Name: "access_points", Type: "ao", Direction: "out"}}},
				{Name: "RequestScan", Args: []introspect.Arg{{Name: "options", Type: "a{sv}", Direction: "in"}}},
			},
			Signals: []introspect.Signal{
				{Name: "AccessPointAdded", Args: []introspect.Arg{{Name: "access_point", Type: "o"}}},
				{Name: "AccessPointRemoved", Args: []introspect.Arg{{Name: "access_point", Type: "o"}}},
			},
		})
	case core.KindEthernet:
		ifaces = append(ifaces, introspect.Interface{Name: ifaceWired})
	case core.KindWireGuard:
		ifaces = append(ifaces, introspect.Interface{Name: ifaceWireguard})
	}
	return &introspect.Node{Name: string(d.path), Interfaces: ifaces}
}

// availableConnections returns the profiles that can activate on this device.
func (d *Device) availableConnections() []dbus.ObjectPath {
	if d.m.settings == nil {
		return []dbus.ObjectPath{}
	}
	return d.m.settings.availableFor(d)
}

// Disconnect deactivates whatever is active on this device.
func (d *Device) Disconnect() *dbus.Error {
	d.mu.Lock()
	acPath := d.activeConn
	d.mu.Unlock()
	if acPath == nullPath {
		if d.kind == core.KindWifi {
			_ = d.m.b.Wifi.Disconnect(d.iface)
		}
		return nil
	}
	d.m.mu.Lock()
	ac := d.m.activeConns[acPath]
	d.m.mu.Unlock()
	if ac != nil {
		d.m.deactivate(ac)
	}
	return nil
}

// GetAllAccessPoints returns the current AP object paths (wifi devices).
func (d *Device) GetAllAccessPoints() ([]dbus.ObjectPath, *dbus.Error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	out := make([]dbus.ObjectPath, 0, len(d.aps))
	for _, ap := range d.aps {
		out = append(out, ap.path)
	}
	return out, nil
}

// RequestScan triggers a wifi scan and refreshes the AP list.
func (d *Device) RequestScan(options map[string]dbus.Variant) *dbus.Error {
	if d.kind != core.KindWifi {
		return dbus.NewError("org.freedesktop.NetworkManager.Device.NotAllowed", []interface{}{"not a wifi device"})
	}
	go func() {
		_ = d.m.b.Wifi.Scan(d.iface)
		d.populateAPs()
	}()
	return nil
}

// setState updates the device State and StateReason and emits Device.StateChanged.
func (d *Device) setState(state, reason uint32) {
	d.mu.Lock()
	old := d.state
	if old == state {
		d.mu.Unlock()
		return
	}
	d.state = state
	d.mu.Unlock()
	if d.props != nil {
		d.props.SetMust(ifaceDevice, "State", state)
		d.props.SetMust(ifaceDevice, "StateReason", deviceStateReason{state, reason})
	}
	_ = d.m.conn.Emit(d.path, ifaceDevice+".StateChanged", state, old, reason)
}

// setActiveConnection updates the ActiveConnection property.
func (d *Device) setActiveConnection(p dbus.ObjectPath) {
	d.mu.Lock()
	d.activeConn = p
	d.mu.Unlock()
	if d.props != nil {
		d.props.SetMust(ifaceDevice, "ActiveConnection", p)
	}
}

// setIP4Config updates the Ip4Config and Dhcp4Config properties.
func (d *Device) setIP4Config(ip4, dhcp4 dbus.ObjectPath) {
	d.mu.Lock()
	d.ip4 = ip4
	d.dhcp4 = dhcp4
	d.mu.Unlock()
	if d.props != nil {
		d.props.SetMust(ifaceDevice, "Ip4Config", ip4)
		d.props.SetMust(ifaceDevice, "Dhcp4Config", dhcp4)
	}
}

// setActiveAP updates the wireless ActiveAccessPoint property.
func (d *Device) setActiveAP(p dbus.ObjectPath) {
	d.mu.Lock()
	d.activeAP = p
	d.mu.Unlock()
	if d.props != nil && d.kind == core.KindWifi {
		d.props.SetMust(ifaceWireless, "ActiveAccessPoint", p)
	}
}

// refreshAvailable recomputes and publishes AvailableConnections.
func (d *Device) refreshAvailable() {
	if d.props != nil {
		d.props.SetMust(ifaceDevice, "AvailableConnections", d.availableConnections())
	}
}

// updateLink applies changed link facts (carrier) to the device props.
func (d *Device) updateLink(li core.LinkInfo) {
	if d.props != nil && d.kind == core.KindEthernet {
		d.props.SetMust(ifaceWired, "Carrier", li.Carrier)
	}
}
