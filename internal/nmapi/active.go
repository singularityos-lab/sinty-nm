package nmapi

import (
	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

// ActiveConnection is a connection currently applied to a device, exposed as
// org.freedesktop.NetworkManager.Connection.Active. It is created by the activation flow
// and torn down by DeactivateConnection.
type ActiveConnection struct {
	m     *Manager
	path  dbus.ObjectPath
	props *prop.Properties

	conn     dbus.ObjectPath
	specific dbus.ObjectPath
	uuid     string
	id       string
	typ      string
	device   *Device
	state    uint32
	isDflt   bool
	ip4      dbus.ObjectPath
	ip6      dbus.ObjectPath
}

// newActiveConnection builds an unexported ActiveConnection in the activating state.
func (m *Manager) newActiveConnection(sc *SettingsConnection, dev *Device, specific dbus.ObjectPath) *ActiveConnection {
	return &ActiveConnection{
		m:        m,
		path:     m.acGen.next(prefixActive),
		conn:     sc.path,
		specific: orNull(specific),
		uuid:     sc.uuid,
		id:       sc.id,
		typ:      sc.connType(),
		device:   dev,
		state:    acStateActivating,
		ip4:      nullPath,
		ip6:      nullPath,
	}
}

// export publishes the ActiveConnection object.
func (ac *ActiveConnection) export() error {
	spec := prop.Map{
		ifaceActive: {
			"Connection":     {Value: ac.conn, Writable: false, Emit: prop.EmitConst},
			"SpecificObject": {Value: ac.specific, Writable: false, Emit: prop.EmitTrue},
			"Id":             {Value: ac.id, Writable: false, Emit: prop.EmitTrue},
			"Uuid":           {Value: ac.uuid, Writable: false, Emit: prop.EmitConst},
			"Type":           {Value: ac.typ, Writable: false, Emit: prop.EmitConst},
			"Devices":        {Value: []dbus.ObjectPath{ac.device.path}, Writable: false, Emit: prop.EmitTrue},
			"State":          {Value: ac.state, Writable: false, Emit: prop.EmitTrue},
			"Default":        {Value: ac.isDflt, Writable: false, Emit: prop.EmitTrue},
			"Default6":       {Value: false, Writable: false, Emit: prop.EmitTrue},
			"Ip4Config":      {Value: ac.ip4, Writable: false, Emit: prop.EmitTrue},
			"Ip6Config":      {Value: ac.ip6, Writable: false, Emit: prop.EmitTrue},
			"Master":         {Value: nullPath, Writable: false, Emit: prop.EmitTrue},
			"Vpn":            {Value: ac.typ == "wireguard", Writable: false, Emit: prop.EmitConst},
		},
	}
	p, err := prop.Export(ac.m.conn, ac.path, spec)
	if err != nil {
		return err
	}
	ac.props = p

	node := &introspect.Node{
		Name: string(ac.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name: ifaceActive,
				Signals: []introspect.Signal{
					{Name: "StateChanged", Args: []introspect.Arg{{Name: "state", Type: "u"}, {Name: "reason", Type: "u"}}},
				},
			},
		},
	}
	return ac.m.conn.Export(introspect.NewIntrospectable(node), ac.path, "org.freedesktop.DBus.Introspectable")
}

// unexport removes the ActiveConnection object.
func (ac *ActiveConnection) unexport() {
	_ = ac.m.conn.Export(nil, ac.path, "org.freedesktop.DBus.Properties")
	_ = ac.m.conn.Export(nil, ac.path, "org.freedesktop.DBus.Introspectable")
}

// setState updates State and emits Connection.Active.StateChanged.
func (ac *ActiveConnection) setState(state, reason uint32) {
	ac.state = state
	if ac.props != nil {
		ac.props.SetMust(ifaceActive, "State", state)
	}
	_ = ac.m.conn.Emit(ac.path, ifaceActive+".StateChanged", state, reason)
}

// setIP4 publishes the Ip4Config path.
func (ac *ActiveConnection) setIP4(p dbus.ObjectPath) {
	ac.ip4 = p
	if ac.props != nil {
		ac.props.SetMust(ifaceActive, "Ip4Config", p)
	}
}

// orNull normalizes an empty object path to NM's "/" sentinel.
func orNull(p dbus.ObjectPath) dbus.ObjectPath {
	if p == "" {
		return nullPath
	}
	return p
}
