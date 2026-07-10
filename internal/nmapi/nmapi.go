package nmapi

import "github.com/godbus/dbus/v5"

const (
	// BusName is the well-known name NM owns; we own it on Sinty.
	BusName = "org.freedesktop.NetworkManager"
	// RootPath and RootIface are the manager object.
	RootPath  = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	RootIface = "org.freedesktop.NetworkManager"

	// Version is reported on the root Version property. libnm (nmcli, the desktop applet)
	// warns "versions do not match" unless this tracks the NM release whose API we speak,
	// so we report that release: the compatibility contract is the API, not our own tag.
	Version = "1.52.1"
)

// NM global State values (org.freedesktop.NetworkManager.State), matching NM's enum so
// clients interpret them correctly.
const (
	StateUnknown         uint32 = 0
	StateAsleep          uint32 = 10
	StateDisconnected    uint32 = 20
	StateDisconnecting   uint32 = 30
	StateConnecting      uint32 = 40
	StateConnectedLocal  uint32 = 50
	StateConnectedSite   uint32 = 60
	StateConnectedGlobal uint32 = 70
)
