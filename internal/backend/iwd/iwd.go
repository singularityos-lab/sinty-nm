package iwd

import "github.com/godbus/dbus/v5"

const Dest = "net.connman.iwd"

// Backend holds the system-bus connection to iwd.
type Backend struct {
	conn *dbus.Conn
}

func New(conn *dbus.Conn) *Backend { return &Backend{conn: conn} }

// Device is a Wi-Fi interface as iwd sees it, normalized for nmapi.
type Device struct {
	Path    dbus.ObjectPath // iwd device object, e.g. /net/connman/iwd/0/4
	Name    string          // wlp0s20f3
	Address string          // MAC
	Powered bool
}

// AP is a scanned network, normalized for nmapi AccessPoint.
type AP struct {
	SSID     string
	Strength int16
	Known    bool
	Path     dbus.ObjectPath // iwd Network object for Connect()
}

// TODO(M1): ListDevices via ObjectManager.GetManagedObjects, filtering
//           net.connman.iwd.Device, mapping Powered/Name/Address.
// TODO(M1): OrderedNetworks(dev) -> []AP via Station.GetOrderedNetworks.
// TODO(M2): Connect(ap) via Network.Connect (saved secret) or with a provided PSK;
//           surface iwd Station.State changes as NM device state transitions.
// TODO(M2): watch InterfaceAdded/Removed + PropertiesChanged to stay live.
