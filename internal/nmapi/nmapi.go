package nmapi

import "github.com/godbus/dbus/v5"

const (
	// BusName is the well-known name NM owns; we own it on Sinty.
	BusName = "org.freedesktop.NetworkManager"
	// RootPath and RootIface are the manager object.
	RootPath  = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	RootIface = "org.freedesktop.NetworkManager"

	// Version is reported on the root Version property.
	Version = "sinty-nm 0.1 (NM-compatible)"
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
