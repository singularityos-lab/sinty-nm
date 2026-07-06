package nmapi

import (
	"fmt"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
)

// Object path prefixes for the NM tree. Every dynamic object gets a stable, numbered path
// under one of these, matching NM's layout so introspecting clients feel at home.
const (
	prefixDevices  = "/org/freedesktop/NetworkManager/Devices"
	prefixAP       = "/org/freedesktop/NetworkManager/AccessPoint"
	prefixActive   = "/org/freedesktop/NetworkManager/ActiveConnection"
	prefixIP4      = "/org/freedesktop/NetworkManager/IP4Config"
	prefixIP6      = "/org/freedesktop/NetworkManager/IP6Config"
	prefixSettings = "/org/freedesktop/NetworkManager/Settings"
)

// SettingsPath is the singleton Settings object path.
const SettingsPath = dbus.ObjectPath("/org/freedesktop/NetworkManager/Settings")

// pathGen hands out monotonically increasing numbered object paths under a prefix.
type pathGen struct{ n atomic.Uint64 }

// next returns the next "<prefix>/N" object path.
func (g *pathGen) next(prefix string) dbus.ObjectPath {
	return dbus.ObjectPath(fmt.Sprintf("%s/%d", prefix, g.n.Add(1)))
}

// nullPath is NM's convention for "no object" in an object-path property.
const nullPath = dbus.ObjectPath("/")
