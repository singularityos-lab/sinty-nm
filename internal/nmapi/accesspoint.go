package nmapi

import (
	"sync"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// AccessPoint is one scanned wifi network, exposed as
// org.freedesktop.NetworkManager.AccessPoint. Values come straight from a core.ScannedAP.
type AccessPoint struct {
	m     *Manager
	path  dbus.ObjectPath
	props *prop.Properties

	bssid  string
	ssid   []byte
	handle string

	mu   sync.Mutex
	last core.ScannedAP
}

// newAccessPoint builds an unexported AccessPoint from a scan result.
func newAccessPoint(m *Manager, n core.ScannedAP) *AccessPoint {
	return &AccessPoint{
		m:      m,
		path:   m.apGen.next(prefixAP),
		bssid:  n.BSSID,
		ssid:   append([]byte(nil), n.SSID...),
		handle: n.Handle,
		last:   n,
	}
}

// export publishes the AP with its property table and introspection.
func (ap *AccessPoint) export() error {
	ap.mu.Lock()
	n := ap.last
	ap.mu.Unlock()
	flags, wpa, rsn := apSecFlags(n.Security)
	spec := prop.Map{
		ifaceAP: {
			"Ssid":       {Value: ap.ssid, Writable: false, Emit: prop.EmitTrue},
			"Strength":   {Value: n.Strength, Writable: false, Emit: prop.EmitTrue},
			"Flags":      {Value: flags, Writable: false, Emit: prop.EmitTrue},
			"WpaFlags":   {Value: wpa, Writable: false, Emit: prop.EmitTrue},
			"RsnFlags":   {Value: rsn, Writable: false, Emit: prop.EmitTrue},
			"Frequency":  {Value: n.Frequency, Writable: false, Emit: prop.EmitTrue},
			"HwAddress":  {Value: ap.bssid, Writable: false, Emit: prop.EmitConst},
			"Mode":       {Value: wifiModeInfra, Writable: false, Emit: prop.EmitConst},
			"MaxBitrate": {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
			"LastSeen":   {Value: int32(nowBoot()), Writable: false, Emit: prop.EmitTrue},
		},
	}
	p, err := prop.Export(ap.m.conn, ap.path, spec)
	if err != nil {
		return err
	}
	ap.props = p

	node := &introspect.Node{
		Name: string(ap.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{Name: ifaceAP},
		},
	}
	return ap.m.conn.Export(introspect.NewIntrospectable(node), ap.path, "org.freedesktop.DBus.Introspectable")
}

// unexport removes the AP object from the bus.
func (ap *AccessPoint) unexport() {
	_ = ap.m.conn.Export(nil, ap.path, "org.freedesktop.DBus.Properties")
	_ = ap.m.conn.Export(nil, ap.path, "org.freedesktop.DBus.Introspectable")
}

// update refreshes the volatile properties (strength, frequency, security, last-seen).
func (ap *AccessPoint) update(n core.ScannedAP) {
	ap.mu.Lock()
	ap.last = n
	ap.handle = n.Handle
	ap.mu.Unlock()
	if ap.props == nil {
		return
	}
	flags, wpa, rsn := apSecFlags(n.Security)
	ap.props.SetMust(ifaceAP, "Strength", n.Strength)
	ap.props.SetMust(ifaceAP, "Frequency", n.Frequency)
	ap.props.SetMust(ifaceAP, "Flags", flags)
	ap.props.SetMust(ifaceAP, "WpaFlags", wpa)
	ap.props.SetMust(ifaceAP, "RsnFlags", rsn)
	ap.props.SetMust(ifaceAP, "LastSeen", int32(nowBoot()))
}

// nowBoot returns a seconds stamp for LastSeen. NM reports seconds since boot; a
// monotonic-ish stamp is enough for clients that only compare freshness.
func nowBoot() int64 {
	return time.Now().Unix()
}
