package nmapi

import (
	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

const (
	// BusName is the well-known name NM owns; we own it on Sinty.
	BusName = "org.freedesktop.NetworkManager"
	// RootPath and RootIface are the manager object.
	RootPath  = dbus.ObjectPath("/org/freedesktop/NetworkManager")
	RootIface = "org.freedesktop.NetworkManager"
)

// NM global State values (org.freedesktop.NetworkManager.State), matching NM's enum so
// clients interpret them correctly.
const (
	StateUnknown       uint32 = 0
	StateAsleep        uint32 = 10
	StateDisconnected  uint32 = 20
	StateDisconnecting uint32 = 30
	StateConnecting    uint32 = 40
	StateConnectedLocal  uint32 = 50
	StateConnectedSite   uint32 = 60
	StateConnectedGlobal uint32 = 70
)

// Server holds the bus connection and the exported manager object.
type Server struct {
	conn  *dbus.Conn
	props *prop.Properties
}

// New builds the server bound to conn.
func New(conn *dbus.Conn) (*Server, error) {
	return &Server{conn: conn}, nil
}

// Export publishes the manager object with its properties, methods, and introspection.
// M1 serves it read-only with empty device/connection lists; backends (rtnl, iwd) fill
// Devices and drive StateChanged in later milestones.
func (s *Server) Export() error {
	propsSpec := map[string]map[string]*prop.Prop{
		RootIface: {
			"Version":                 {Value: "sinty-nm 0.1 (NM-compatible)", Writable: false, Emit: prop.EmitTrue},
			"State":                   {Value: StateDisconnected, Writable: false, Emit: prop.EmitTrue},
			"Connectivity":            {Value: uint32(1), Writable: false, Emit: prop.EmitTrue}, // 1 = NONE until we probe
			"Devices":                 {Value: []dbus.ObjectPath{}, Writable: false, Emit: prop.EmitTrue},
			"AllDevices":              {Value: []dbus.ObjectPath{}, Writable: false, Emit: prop.EmitTrue},
			"ActiveConnections":       {Value: []dbus.ObjectPath{}, Writable: false, Emit: prop.EmitTrue},
			"NetworkingEnabled":       {Value: true, Writable: false, Emit: prop.EmitTrue},
			"WirelessEnabled":         {Value: true, Writable: true, Emit: prop.EmitTrue},
			"WirelessHardwareEnabled": {Value: true, Writable: false, Emit: prop.EmitTrue},
		},
	}
	p, err := prop.Export(s.conn, RootPath, propsSpec)
	if err != nil {
		return err
	}
	s.props = p

	if err := s.conn.Export(s, RootPath, RootIface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(RootPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name: RootIface,
				Methods: []introspect.Method{
					{Name: "GetDevices", Args: []introspect.Arg{{Name: "devices", Type: "ao", Direction: "out"}}},
					{Name: "GetAllDevices", Args: []introspect.Arg{{Name: "devices", Type: "ao", Direction: "out"}}},
				},
			},
		},
	}
	return s.conn.Export(introspect.NewIntrospectable(node), RootPath, "org.freedesktop.DBus.Introspectable")
}

// GetDevices returns the managed device object paths. M1: empty until the rtnl+iwd
// backends register devices under .../Devices/N.
func (s *Server) GetDevices() ([]dbus.ObjectPath, *dbus.Error) {
	return []dbus.ObjectPath{}, nil
}

// GetAllDevices mirrors GetDevices for now (NM distinguishes managed vs all).
func (s *Server) GetAllDevices() ([]dbus.ObjectPath, *dbus.Error) {
	return []dbus.ObjectPath{}, nil
}
