package nmapi

import (
	"bytes"

	"github.com/godbus/dbus/v5"
)

// scanAndPopulate powers the radio, triggers a backend scan, and refreshes the AP list.
// GetOrderedNetworks only returns what a completed scan found, so a scan must run first;
// SetPowered is a no-op when the radio is already up.
func (d *Device) scanAndPopulate() {
	_ = d.m.b.Wifi.SetPowered(d.iface, true)
	_ = d.m.b.Wifi.Scan(d.iface)
	d.populateAPs()
}

// populateAPs reads the backend's ordered network list for this wifi device and
// reconciles the AccessPoint object set: new APs are exported and announced, vanished
// ones are unexported, survivors are refreshed in place. The AccessPoints property is
// republished with the live ordered paths.
func (d *Device) populateAPs() {
	nets, err := d.m.b.Wifi.OrderedNetworks(d.iface)
	if err != nil {
		return
	}

	d.mu.Lock()
	old := d.apByBSSID
	newList := make([]*AccessPoint, 0, len(nets))
	newByBSSID := make(map[string]*AccessPoint, len(nets))
	var added []*AccessPoint
	seen := make(map[string]bool, len(nets))
	for _, n := range nets {
		seen[n.BSSID] = true
		if ap, ok := old[n.BSSID]; ok {
			ap.update(n)
			newByBSSID[n.BSSID] = ap
			newList = append(newList, ap)
			continue
		}
		ap := newAccessPoint(d.m, n)
		newByBSSID[n.BSSID] = ap
		newList = append(newList, ap)
		added = append(added, ap)
	}
	var removed []*AccessPoint
	for b, ap := range old {
		if !seen[b] {
			removed = append(removed, ap)
		}
	}
	d.aps = newList
	d.apByBSSID = newByBSSID
	paths := make([]dbus.ObjectPath, 0, len(newList))
	for _, ap := range newList {
		paths = append(paths, ap.path)
	}
	d.mu.Unlock()

	for _, ap := range added {
		if err := ap.export(); err == nil {
			_ = d.m.conn.Emit(d.path, ifaceWireless+".AccessPointAdded", ap.path)
		}
	}
	for _, ap := range removed {
		_ = d.m.conn.Emit(d.path, ifaceWireless+".AccessPointRemoved", ap.path)
		ap.unexport()
	}
	if d.props != nil {
		d.props.SetMust(ifaceWireless, "AccessPoints", paths)
	}
}

// apPathForSSID returns the object path of the AP advertising ssid, or nullPath.
func (d *Device) apPathForSSID(ssid []byte) dbus.ObjectPath {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, ap := range d.aps {
		if bytes.Equal(ap.ssid, ssid) {
			return ap.path
		}
	}
	return nullPath
}
