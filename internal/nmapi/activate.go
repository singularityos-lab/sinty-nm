package nmapi

import (
	"context"
	"fmt"
	"log"
	"net"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// onLinkEvent keeps the device registry in sync with kernel link add/remove events and
// republishes the root device lists. mu is taken only around the registry mutation.
func (m *Manager) onLinkEvent(li core.LinkInfo, up bool) {
	if !up {
		m.mu.Lock()
		d := m.devByIface[li.Name]
		if d != nil {
			kept := m.devices[:0]
			for _, x := range m.devices {
				if x != d {
					kept = append(kept, x)
				}
			}
			m.devices = kept
			delete(m.devByPath, d.path)
			delete(m.devByIface, li.Name)
		}
		m.mu.Unlock()
		if d != nil {
			d.unexport()
			_ = m.conn.Emit(RootPath, RootIface+".DeviceRemoved", d.path)
			m.refreshRootLists()
		}
		return
	}

	m.mu.Lock()
	d, existed := m.devByIface[li.Name]
	if !existed {
		d = m.addDeviceLocked(li)
	}
	m.mu.Unlock()
	if existed {
		d.updateLink(li)
		return
	}
	if err := d.export(); err != nil {
		return
	}
	_ = m.conn.Emit(RootPath, RootIface+".DeviceAdded", d.path)
	m.refreshRootLists()
	if d.kind == core.KindWifi {
		d.populateAPs()
	}
}

// onWifiEvent reflects backend wifi state transitions onto the device object and, on a
// completed association, refreshes the active access point and AP list.
func (m *Manager) onWifiEvent(ev core.WifiEvent) {
	m.mu.Lock()
	d := m.devByIface[ev.Device]
	m.mu.Unlock()
	if d == nil || d.kind != core.KindWifi {
		return
	}
	switch ev.State {
	case core.WifiConnected:
		d.setState(devStateActivated, devReasonNone)
		if len(ev.ConnectedSSID) > 0 {
			d.setActiveAP(d.apPathForSSID(ev.ConnectedSSID))
		}
		go d.populateAPs()
	case core.WifiConnecting:
		d.setState(devStateConfig, devReasonNone)
	case core.WifiDisconnecting:
		d.setState(devStateDeactivating, devReasonNone)
	case core.WifiDisconnected:
		d.setState(devStateDisconnected, devReasonNone)
		d.setActiveAP(nullPath)
	}
}

// onRFKillEvent mirrors the radio hard/soft block onto the root wireless-enabled flags.
// SetMust bypasses the writable callback, so this does not loop back into the radio path.
func (m *Manager) onRFKillEvent(soft, hard bool) {
	if m.rootProps == nil {
		return
	}
	m.rootProps.SetMust(RootIface, "WirelessHardwareEnabled", !hard)
	m.rootProps.SetMust(RootIface, "WirelessEnabled", !(soft || hard))
}

// activate creates and exports an ActiveConnection in the activating state, moves the
// device to prepare, and runs the actual bring-up asynchronously (NM returns the active
// connection path immediately, before association/DHCP complete).
func (m *Manager) activate(sc *SettingsConnection, dev *Device, specific dbus.ObjectPath) (*ActiveConnection, error) {
	ac := m.newActiveConnection(sc, dev, specific)
	m.mu.Lock()
	m.activeConns[ac.path] = ac
	m.mu.Unlock()
	if err := ac.export(); err != nil {
		m.mu.Lock()
		delete(m.activeConns, ac.path)
		m.mu.Unlock()
		return nil, err
	}
	dev.setActiveConnection(ac.path)
	dev.setState(devStatePrepare, devReasonUserRequested)
	m.refreshRootLists()
	go m.runActivation(ac, sc, dev)
	return ac, nil
}

// runActivation performs the bring-up and settles the final device/active-connection state.
func (m *Manager) runActivation(ac *ActiveConnection, sc *SettingsConnection, dev *Device) {
	ctx := m.runCtx()
	if err := m.bringUp(ctx, ac, sc, dev); err != nil {
		log.Printf("activation of %s on %s failed: %v", sc.id, dev.iface, err)
		dev.setState(devStateFailed, devReasonNone)
		ac.setState(acStateDeactivated, devReasonNone)
		return
	}
	ac.setState(acStateActivated, devReasonNone)
	dev.setState(devStateActivated, devReasonNone)
	m.mu.Lock()
	m.primary = ac.path
	m.mu.Unlock()
	m.refreshRootLists()
	m.pollConnectivity(ctx)
}

// bringUp drives the mechanism for a device kind: associate/link-up, then L3 (DHCP or the
// static/wireguard path).
func (m *Manager) bringUp(ctx context.Context, ac *ActiveConnection, sc *SettingsConnection, dev *Device) error {
	switch dev.kind {
	case core.KindWifi:
		dev.setState(devStateConfig, devReasonNone)
		secret := func([]byte) (string, error) { return sc.psk(), nil }
		if err := m.b.Wifi.Connect(dev.iface, sc.ssid(), secret); err != nil {
			return err
		}
		dev.setActiveAP(dev.apPathForSSID(sc.ssid()))
		if isStatic(sc.ipv4Method()) {
			return nil
		}
		return m.configureDHCP(ctx, ac, dev)
	case core.KindEthernet:
		if err := m.b.Link.SetUp(dev.index, true); err != nil {
			return err
		}
		if isStatic(sc.ipv4Method()) {
			return nil
		}
		return m.configureDHCP(ctx, ac, dev)
	case core.KindWireGuard:
		return m.b.WG.Configure(dev.iface, sc.wgConfig())
	default:
		return fmt.Errorf("unsupported device kind for %s", dev.iface)
	}
}

// configureDHCP acquires a lease and applies address, default route, and DNS, then
// publishes an IP4Config on the device and active connection.
func (m *Manager) configureDHCP(ctx context.Context, ac *ActiveConnection, dev *Device) error {
	dev.setState(devStateIPConfig, devReasonNone)
	mac, _ := net.ParseMAC(dev.mac)
	lease, err := m.b.DHCP.Acquire(ctx, dev.iface, mac)
	if err != nil {
		return err
	}
	if err := m.b.Link.AddAddr(dev.index, lease.IP, lease.PrefixLen); err != nil {
		return err
	}
	_ = m.b.Link.SetUp(dev.index, true)
	if lease.Gateway != nil {
		_ = m.b.Link.AddRoute(dev.index, core.RouteInfo{Gw: lease.Gateway, Metric: 100})
	}
	_ = m.b.DNS.Set(core.DNSEntry{Iface: dev.iface, Nameservers: lease.DNS, Domains: lease.Domains, Priority: 100})

	ip4 := m.newIP4Config(lease)
	if err := ip4.export(); err == nil {
		dev.ip4obj = ip4
		dev.setIP4Config(ip4.path, nullPath)
		ac.setIP4(ip4.path)
	}
	return nil
}

// deactivate tears down an active connection: disconnect/remove the mechanism, flush L3,
// revert DNS, drop the objects, and settle the device back to disconnected.
func (m *Manager) deactivate(ac *ActiveConnection) {
	dev := ac.device
	ac.setState(acStateDeactivating, devReasonUserRequested)
	if dev != nil {
		dev.setState(devStateDeactivating, devReasonUserRequested)
		switch dev.kind {
		case core.KindWifi:
			_ = m.b.Wifi.Disconnect(dev.iface)
		case core.KindWireGuard:
			_ = m.b.WG.Remove(dev.iface)
		}
		_ = m.b.Link.FlushAddrs(dev.index)
		_ = m.b.DNS.Revert(dev.iface)
		dev.setActiveConnection(nullPath)
		dev.setActiveAP(nullPath)
		if dev.ip4obj != nil {
			dev.ip4obj.unexport()
			dev.ip4obj = nil
		}
		dev.setIP4Config(nullPath, nullPath)
	}
	m.mu.Lock()
	delete(m.activeConns, ac.path)
	if m.primary == ac.path {
		m.primary = nullPath
	}
	m.mu.Unlock()
	ac.setState(acStateDeactivated, devReasonUserRequested)
	ac.unexport()
	if dev != nil {
		dev.setState(devStateDisconnected, devReasonUserRequested)
	}
	m.refreshRootLists()
}

// isStatic reports whether an ipv4 method skips the DHCP client.
func isStatic(method string) bool {
	return method == "manual" || method == "disabled"
}
