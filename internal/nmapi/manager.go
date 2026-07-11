package nmapi

import (
	"context"
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// Backends is the wiring seam: main plugs the concrete rtnl/iwd/dhcp/wg/sys
// implementations of the core interfaces here, and nmapi drives them.
type Backends struct {
	Link   core.LinkBackend
	Wifi   core.WifiBackend
	DHCP   core.DHCPClient
	WG     core.WGBackend
	DNS    core.DNSManager
	RFKill core.RFKill
	Conn   core.ConnChecker
}

// Manager is the root org.freedesktop.NetworkManager object plus the live registries of
// child objects (devices, active connections, settings). It owns the bus connection and
// serializes registry mutation under mu.
type Manager struct {
	conn *dbus.Conn
	b    Backends

	rootProps *prop.Properties
	settings  *Settings
	om        *objectManager

	devGen pathGen
	apGen  pathGen
	acGen  pathGen
	ipGen  pathGen

	mu          sync.Mutex
	devices     []*Device
	devByPath   map[dbus.ObjectPath]*Device
	devByIface  map[string]*Device
	activeConns map[dbus.ObjectPath]*ActiveConnection

	state        uint32
	connectivity core.Connectivity
	primary      dbus.ObjectPath

	ctx context.Context
}

// New builds the manager bound to conn with the given backends. It loads persisted
// connection profiles and discovers the current links so Export can publish a populated
// tree; live updates and scans start in Run.
func New(conn *dbus.Conn, b Backends) (*Manager, error) {
	m := &Manager{
		conn:         conn,
		b:            b,
		devByPath:    map[dbus.ObjectPath]*Device{},
		devByIface:   map[string]*Device{},
		activeConns:  map[dbus.ObjectPath]*ActiveConnection{},
		state:        StateDisconnected,
		connectivity: core.ConnUnknown,
		primary:      nullPath,
		ctx:          context.Background(),
	}
	m.om = newObjectManager(m)

	s, err := newSettings(m)
	if err != nil {
		return nil, err
	}
	m.settings = s

	links, err := b.Link.DumpLinks()
	if err != nil {
		return nil, err
	}
	for _, li := range links {
		m.addDeviceLocked(li)
	}
	return m, nil
}

// Export publishes the whole object tree: the root manager, the Settings store with its
// connections, and every discovered device with its sub-interfaces. Dynamic objects
// (access points, active connections, IP configs) export themselves as they are created.
// The well-known name is owned by main before Export runs.
func (m *Manager) Export() error {
	if err := m.om.export(); err != nil {
		return err
	}
	propsSpec := prop.Map{
		RootIface: {
			"Version":                 {Value: Version, Writable: false, Emit: prop.EmitConst},
			"State":                   {Value: m.state, Writable: false, Emit: prop.EmitTrue},
			"Connectivity":            {Value: uint32(m.connectivity), Writable: false, Emit: prop.EmitTrue},
			"Devices":                 {Value: m.managedPathsLocked(), Writable: false, Emit: prop.EmitTrue},
			"AllDevices":              {Value: m.allPathsLocked(), Writable: false, Emit: prop.EmitTrue},
			"ActiveConnections":       {Value: []dbus.ObjectPath{}, Writable: false, Emit: prop.EmitTrue},
			"PrimaryConnection":       {Value: m.primary, Writable: false, Emit: prop.EmitTrue},
			"NetworkingEnabled":       {Value: true, Writable: false, Emit: prop.EmitTrue},
			"WirelessEnabled":         {Value: true, Writable: true, Emit: prop.EmitTrue, Callback: m.onSetWirelessEnabled},
			"WirelessHardwareEnabled": {Value: true, Writable: false, Emit: prop.EmitTrue},
			"WwanEnabled":             {Value: true, Writable: true, Emit: prop.EmitTrue, Callback: m.onSetWwanEnabled},
			"WwanHardwareEnabled":     {Value: true, Writable: false, Emit: prop.EmitTrue},
		},
	}
	p, err := prop.Export(m.conn, RootPath, propsSpec)
	if err != nil {
		return err
	}
	m.rootProps = p
	m.om.add(RootPath, RootIface, p)

	mapping := map[string]string{"NMState": "state"}
	if err := m.conn.ExportWithMap(m, mapping, RootPath, RootIface); err != nil {
		return err
	}
	if err := m.conn.Export(introspect.NewIntrospectable(m.rootNode()), RootPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}

	if err := m.settings.export(); err != nil {
		return err
	}
	m.mu.Lock()
	devs := append([]*Device(nil), m.devices...)
	m.mu.Unlock()
	for _, d := range devs {
		if err := d.export(); err != nil {
			return err
		}
	}

	// Reflect the current radio hard-block on the hardware-enabled props.
	if hard, err := m.b.RFKill.WifiHardBlocked(); err == nil {
		m.rootProps.SetMust(RootIface, "WirelessHardwareEnabled", !hard)
	}
	return nil
}

// Run starts the backend event loops (link, wifi, rfkill), performs the initial access
// point population, and polls connectivity. It blocks until ctx is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	m.mu.Lock()
	m.ctx = ctx
	m.mu.Unlock()

	go func() {
		_ = m.b.Link.Subscribe(ctx, m.onLinkEvent)
	}()
	go func() {
		_ = m.b.Wifi.Subscribe(ctx, m.onWifiEvent)
	}()
	go func() {
		_ = m.b.RFKill.Subscribe(ctx, m.onRFKillEvent)
	}()

	m.mu.Lock()
	wifiDevs := make([]*Device, 0)
	for _, d := range m.devices {
		if d.kind == core.KindWifi {
			wifiDevs = append(wifiDevs, d)
		}
	}
	m.mu.Unlock()
	// Power each wifi radio up and kick an initial scan so the AP list is populated at
	// startup (GetOrderedNetworks only returns what a scan already found). Then keep
	// rescanning on a slow cadence so the list stays fresh while the desktop is open.
	for _, d := range wifiDevs {
		d.scanAndPopulate()
	}
	go m.rescanLoop(ctx, wifiDevs)

	m.pollConnectivity(ctx)
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			m.pollConnectivity(ctx)
		}
	}
}

// rescanLoop periodically re-scans every wifi device so the AP list reflects the current
// airspace without a client having to call RequestScan.
func (m *Manager) rescanLoop(ctx context.Context, wifiDevs []*Device) {
	ticker := time.NewTicker(20 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for _, d := range wifiDevs {
				d.scanAndPopulate()
			}
		}
	}
}

// rootNode is the introspection data for the root manager object.
func (m *Manager) rootNode() *introspect.Node {
	return &introspect.Node{
		Name: string(RootPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name: RootIface,
				Methods: []introspect.Method{
					{Name: "GetDevices", Args: []introspect.Arg{{Name: "devices", Type: "ao", Direction: "out"}}},
					{Name: "GetAllDevices", Args: []introspect.Arg{{Name: "devices", Type: "ao", Direction: "out"}}},
					{Name: "GetDeviceByIpIface", Args: []introspect.Arg{{Name: "iface", Type: "s", Direction: "in"}, {Name: "device", Type: "o", Direction: "out"}}},
					{Name: "ActivateConnection", Args: []introspect.Arg{{Name: "connection", Type: "o", Direction: "in"}, {Name: "device", Type: "o", Direction: "in"}, {Name: "specific_object", Type: "o", Direction: "in"}, {Name: "active_connection", Type: "o", Direction: "out"}}},
					{Name: "AddAndActivateConnection", Args: []introspect.Arg{{Name: "connection", Type: "a{sa{sv}}", Direction: "in"}, {Name: "device", Type: "o", Direction: "in"}, {Name: "specific_object", Type: "o", Direction: "in"}, {Name: "path", Type: "o", Direction: "out"}, {Name: "active_connection", Type: "o", Direction: "out"}}},
					{Name: "DeactivateConnection", Args: []introspect.Arg{{Name: "active_connection", Type: "o", Direction: "in"}}},
					{Name: "CheckConnectivity", Args: []introspect.Arg{{Name: "connectivity", Type: "u", Direction: "out"}}},
					{Name: "Enable", Args: []introspect.Arg{{Name: "enable", Type: "b", Direction: "in"}}},
					{Name: "GetPermissions", Args: []introspect.Arg{{Name: "permissions", Type: "a{ss}", Direction: "out"}}},
					{Name: "state", Args: []introspect.Arg{{Name: "state", Type: "u", Direction: "out"}}},
				},
				Signals: []introspect.Signal{
					{Name: "StateChanged", Args: []introspect.Arg{{Name: "state", Type: "u"}}},
					{Name: "DeviceAdded", Args: []introspect.Arg{{Name: "device_path", Type: "o"}}},
					{Name: "DeviceRemoved", Args: []introspect.Arg{{Name: "device_path", Type: "o"}}},
				},
			},
		},
	}
}

// GetDevices returns the managed device object paths.
func (m *Manager) GetDevices() ([]dbus.ObjectPath, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.managedPathsLocked(), nil
}

// GetAllDevices returns every known device, managed or not (NM distinguishes the two).
func (m *Manager) GetAllDevices() ([]dbus.ObjectPath, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.allPathsLocked(), nil
}

// GetDeviceByIpIface resolves a device by its IP interface name.
func (m *Manager) GetDeviceByIpIface(iface string) (dbus.ObjectPath, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if d, ok := m.devByIface[iface]; ok {
		return d.path, nil
	}
	return nullPath, dbus.NewError("org.freedesktop.NetworkManager.UnknownDevice", []interface{}{"no such device"})
}

// ActivateConnection activates a persisted profile on a device.
func (m *Manager) ActivateConnection(connection, device, specificObject dbus.ObjectPath) (dbus.ObjectPath, *dbus.Error) {
	sc := m.settings.byPath(connection)
	if sc == nil {
		return nullPath, dbus.NewError("org.freedesktop.NetworkManager.UnknownConnection", []interface{}{"no such connection"})
	}
	dev := m.resolveDevice(device, sc)
	if dev == nil {
		return nullPath, dbus.NewError("org.freedesktop.NetworkManager.UnknownDevice", []interface{}{"no suitable device"})
	}
	ac, err := m.activate(sc, dev, specificObject)
	if err != nil {
		return nullPath, dbus.MakeFailedError(err)
	}
	return ac.path, nil
}

// AddAndActivateConnection persists a new profile and immediately activates it.
func (m *Manager) AddAndActivateConnection(settings map[string]map[string]dbus.Variant, device, specificObject dbus.ObjectPath) (dbus.ObjectPath, dbus.ObjectPath, *dbus.Error) {
	sc, err := m.settings.add(settings)
	if err != nil {
		return nullPath, nullPath, dbus.MakeFailedError(err)
	}
	dev := m.resolveDevice(device, sc)
	if dev == nil {
		return sc.path, nullPath, dbus.NewError("org.freedesktop.NetworkManager.UnknownDevice", []interface{}{"no suitable device"})
	}
	ac, err := m.activate(sc, dev, specificObject)
	if err != nil {
		return sc.path, nullPath, dbus.MakeFailedError(err)
	}
	return sc.path, ac.path, nil
}

// DeactivateConnection tears down an active connection and drops it.
func (m *Manager) DeactivateConnection(activeConnection dbus.ObjectPath) *dbus.Error {
	m.mu.Lock()
	ac := m.activeConns[activeConnection]
	m.mu.Unlock()
	if ac == nil {
		return dbus.NewError("org.freedesktop.NetworkManager.ConnectionNotActive", []interface{}{"not active"})
	}
	m.deactivate(ac)
	return nil
}

// CheckConnectivity forces a connectivity probe and returns the fresh state.
func (m *Manager) CheckConnectivity() (uint32, *dbus.Error) {
	ctx := m.runCtx()
	m.pollConnectivity(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	return uint32(m.connectivity), nil
}

// Enable toggles networking on/off. We reflect it on NetworkingEnabled; the radio path is
// handled via WirelessEnabled.
func (m *Manager) Enable(enable bool) *dbus.Error {
	if m.rootProps != nil {
		m.rootProps.SetMust(RootIface, "NetworkingEnabled", enable)
	}
	return nil
}

// GetPermissions returns the PolicyKit-style permission map. We are permissive: every
// known permission is granted (single-user Sinty box).
func (m *Manager) GetPermissions() (map[string]string, *dbus.Error) {
	perms := map[string]string{
		"org.freedesktop.NetworkManager.enable-disable-network": "yes",
		"org.freedesktop.NetworkManager.enable-disable-wifi":    "yes",
		"org.freedesktop.NetworkManager.enable-disable-wwan":    "yes",
		"org.freedesktop.NetworkManager.network-control":        "yes",
		"org.freedesktop.NetworkManager.wifi.share.protected":   "yes",
		"org.freedesktop.NetworkManager.wifi.share.open":        "yes",
		"org.freedesktop.NetworkManager.settings.modify.system": "yes",
		"org.freedesktop.NetworkManager.settings.modify.own":    "yes",
	}
	return perms, nil
}

// NMState is exported on the bus as the lowercase "state" method (NM's legacy accessor).
func (m *Manager) NMState() (uint32, *dbus.Error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.state, nil
}

// onSetWirelessEnabled accepts the Set immediately and applies the radio change off the
// caller path: rfkill soft-block plus powering the wifi devices.
func (m *Manager) onSetWirelessEnabled(c *prop.Change) *dbus.Error {
	on, _ := c.Value.(bool)
	go func() {
		_ = m.b.RFKill.SetWifiBlocked(!on)
		m.mu.Lock()
		devs := append([]*Device(nil), m.devices...)
		m.mu.Unlock()
		for _, d := range devs {
			if d.kind == core.KindWifi {
				_ = m.b.Wifi.SetPowered(d.iface, on)
			}
		}
	}()
	return nil
}

// onSetWwanEnabled accepts the Set; we have no WWAN hardware backend, so it is a no-op
// beyond recording the flag.
func (m *Manager) onSetWwanEnabled(c *prop.Change) *dbus.Error {
	return nil
}

// addDeviceLocked creates and registers a Device from a link. mu must be held.
func (m *Manager) addDeviceLocked(li core.LinkInfo) *Device {
	if _, ok := m.devByIface[li.Name]; ok {
		return m.devByIface[li.Name]
	}
	d := newDevice(m, li)
	m.devices = append(m.devices, d)
	m.devByPath[d.path] = d
	m.devByIface[li.Name] = d
	return d
}

// managedPathsLocked returns object paths of managed devices. mu must be held.
func (m *Manager) managedPathsLocked() []dbus.ObjectPath {
	out := []dbus.ObjectPath{}
	for _, d := range m.devices {
		if d.managed {
			out = append(out, d.path)
		}
	}
	return out
}

// allPathsLocked returns object paths of every device. mu must be held.
func (m *Manager) allPathsLocked() []dbus.ObjectPath {
	out := []dbus.ObjectPath{}
	for _, d := range m.devices {
		out = append(out, d.path)
	}
	return out
}

// resolveDevice picks the device for an activation: the explicit path if given and known,
// otherwise the first managed device matching the profile's connection type.
func (m *Manager) resolveDevice(path dbus.ObjectPath, sc *SettingsConnection) *Device {
	m.mu.Lock()
	defer m.mu.Unlock()
	if path != "" && path != nullPath {
		return m.devByPath[path]
	}
	want := sc.connType()
	for _, d := range m.devices {
		if !d.managed {
			continue
		}
		if (want == "802-11-wireless" && d.kind == core.KindWifi) ||
			(want == "802-3-ethernet" && d.kind == core.KindEthernet) ||
			(want == "wireguard" && d.kind == core.KindWireGuard) {
			return d
		}
	}
	return nil
}

// runCtx returns the active Run context, or Background if Run has not started.
func (m *Manager) runCtx() context.Context {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ctx != nil {
		return m.ctx
	}
	return context.Background()
}

// pollConnectivity probes reachability and updates the Connectivity property and the
// derived global State.
func (m *Manager) pollConnectivity(ctx context.Context) {
	c, err := m.b.Conn.Check(ctx)
	if err != nil {
		return
	}
	m.mu.Lock()
	m.connectivity = c
	m.mu.Unlock()
	if m.rootProps != nil {
		m.rootProps.SetMust(RootIface, "Connectivity", uint32(c))
	}
	switch c {
	case core.ConnFull:
		m.setState(StateConnectedGlobal)
	case core.ConnLimited, core.ConnPortal:
		m.setState(StateConnectedSite)
	case core.ConnNone:
		m.setState(StateConnectedLocal)
	}
}

// setState updates the global State property and emits StateChanged.
func (m *Manager) setState(s uint32) {
	m.mu.Lock()
	if m.state == s {
		m.mu.Unlock()
		return
	}
	m.state = s
	m.mu.Unlock()
	if m.rootProps != nil {
		m.rootProps.SetMust(RootIface, "State", s)
	}
	_ = m.conn.Emit(RootPath, RootIface+".StateChanged", s)
}

// refreshRootLists recomputes and publishes Devices, AllDevices, and ActiveConnections.
func (m *Manager) refreshRootLists() {
	if m.rootProps == nil {
		return
	}
	m.mu.Lock()
	managed := m.managedPathsLocked()
	all := m.allPathsLocked()
	acs := make([]dbus.ObjectPath, 0, len(m.activeConns))
	for p := range m.activeConns {
		acs = append(acs, p)
	}
	primary := m.primary
	m.mu.Unlock()
	m.rootProps.SetMust(RootIface, "Devices", managed)
	m.rootProps.SetMust(RootIface, "AllDevices", all)
	m.rootProps.SetMust(RootIface, "ActiveConnections", acs)
	m.rootProps.SetMust(RootIface, "PrimaryConnection", primary)
}
