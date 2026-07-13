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

// firstWiredProfile returns an existing ethernet profile applicable to d, or nil.
func (m *Manager) firstWiredProfile(d *Device) *SettingsConnection {
	for _, p := range m.settings.availableFor(d) {
		if sc := m.settings.byPath(p); sc != nil {
			return sc
		}
	}
	return nil
}
