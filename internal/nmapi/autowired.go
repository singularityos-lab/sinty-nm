package nmapi

import (
	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// autoConnectWired brings an ethernet device online without an explicit client request,
// the way NetworkManager's default wired autoconnect does. sinty-nm otherwise only ever
// drives wifi (iwd auto-associates); a wired link is only activated when a client calls
// ActivateConnection, which nothing does on a desktop or headless boot. The result is that
// ethernet users (docks, desktops) and QEMU virtio-net get no address, no route and no DNS.
// When a managed ethernet device has carrier and no active connection, reuse an existing
// wired profile (or synthesize a DHCP "Wired connection 1") and activate it.
func (m *Manager) autoConnectWired(d *Device) {
	if d == nil || d.kind != core.KindEthernet || !d.managed {
		return
	}
	d.mu.Lock()
	skip := !d.carrier || d.activeConn != nullPath || d.autoWired
	if !skip {
		d.autoWired = true
	}
	d.mu.Unlock()
	if skip {
		return
	}

	sc := m.firstWiredProfile(d)
	if sc == nil {
		var err error
		sc, err = m.settings.add(map[string]map[string]dbus.Variant{
			"connection": {
				"id":   dbus.MakeVariant("Wired connection 1"),
				"type": dbus.MakeVariant("802-3-ethernet"),
			},
			"802-3-ethernet": {},
			"ipv4":           {"method": dbus.MakeVariant("auto")},
			"ipv6":           {"method": dbus.MakeVariant("auto")},
		})
		if err != nil {
			d.mu.Lock()
			d.autoWired = false
			d.mu.Unlock()
			return
		}
	}
	if _, err := m.activate(sc, d, nullPath); err != nil {
		d.mu.Lock()
		d.autoWired = false
		d.mu.Unlock()
	}
}

// manageWired brings a managed ethernet link administratively up so the kernel can sense
// carrier, then autoconnects. A NIC reports no carrier while it is admin-down (operstate
// DOWN, qdisc noop), so gating the bring-up on carrier deadlocks: nothing raises the link,
// so carrier never appears, so autoConnectWired never runs. Raising the link is what lets
// carrier assert; then either it is already present (link was up at enumeration) and the
// autoConnectWired call here proceeds, or the carrier-up transition arrives as a link event
// and updateLink autoconnects then. Called at startup and when a wired device appears.
func (m *Manager) manageWired(d *Device) {
	if d == nil || d.kind != core.KindEthernet || !d.managed {
		return
	}
	if err := m.b.Link.SetUp(d.index, true); err != nil {
		return
	}
	// Re-read the link after raising it: carrier is asserted by the driver as part of the
	// bring-up, so the value from the initial enumeration (link down) is stale. Reading it
	// here, rather than only waiting for the multicast link event, also closes the startup
	// race where SetUp fires before the event subscription is bound and the carrier-up
	// notification is missed. A slow-negotiating NIC that is not up yet still gets picked up
	// later by the carrier-up event in updateLink.
	if li, err := m.b.Link.LinkByName(d.iface); err == nil {
		d.mu.Lock()
		d.carrier = li.Carrier
		d.mu.Unlock()
	}
	m.autoConnectWired(d)
}

// firstWiredProfile returns an existing ethernet profile applicable to d, or nil.
func (m *Manager) firstWiredProfile(d *Device) *SettingsConnection {
	for _, p := range m.settings.availableFor(d) {
		if sc := m.settings.byPath(p); sc != nil {
			return sc
		}
	}
	return nil
}
