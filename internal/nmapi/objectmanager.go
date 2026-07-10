package nmapi

import (
	"sort"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"
)

// NM exposes org.freedesktop.DBus.ObjectManager at /org/freedesktop, and libnm
// (NMClient, so nmcli and every desktop) initializes exclusively through it: without
// GetManagedObjects the daemon is reported as "NetworkManager is not running" even
// while it owns the well-known name. objectManager mirrors our live object registry
// onto that interface.
const (
	omPath  = dbus.ObjectPath("/org/freedesktop")
	omIface = "org.freedesktop.DBus.ObjectManager"
)

// objectManager tracks every exported object and the property tables behind its
// interfaces, and serves GetManagedObjects from them.
type objectManager struct {
	m *Manager

	mu   sync.Mutex
	objs map[dbus.ObjectPath]map[string]*prop.Properties
}

func newObjectManager(m *Manager) *objectManager {
	return &objectManager{m: m, objs: map[dbus.ObjectPath]map[string]*prop.Properties{}}
}

// export publishes the ObjectManager object on the bus.
func (om *objectManager) export() error {
	if err := om.m.conn.Export(om, omPath, omIface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(omPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name: omIface,
				Methods: []introspect.Method{
					{Name: "GetManagedObjects", Args: []introspect.Arg{{Name: "objects", Type: "a{oa{sa{sv}}}", Direction: "out"}}},
				},
				Signals: []introspect.Signal{
					{Name: "InterfacesAdded", Args: []introspect.Arg{{Name: "object", Type: "o"}, {Name: "interfaces", Type: "a{sa{sv}}"}}},
					{Name: "InterfacesRemoved", Args: []introspect.Arg{{Name: "object", Type: "o"}, {Name: "interfaces", Type: "as"}}},
				},
			},
		},
	}
	return om.m.conn.Export(introspect.NewIntrospectable(node), omPath, "org.freedesktop.DBus.Introspectable")
}

// GetManagedObjects returns every object with the current values of all its
// interfaces' properties.
func (om *objectManager) GetManagedObjects() (map[dbus.ObjectPath]map[string]map[string]dbus.Variant, *dbus.Error) {
	om.mu.Lock()
	defer om.mu.Unlock()
	out := make(map[dbus.ObjectPath]map[string]map[string]dbus.Variant, len(om.objs))
	for path, ifaces := range om.objs {
		entry := make(map[string]map[string]dbus.Variant, len(ifaces))
		for iface, p := range ifaces {
			props, err := p.GetAll(iface)
			if err != nil {
				props = map[string]dbus.Variant{}
			}
			entry[iface] = props
		}
		out[path] = entry
	}
	return out, nil
}

// add registers an object's interface and announces it via InterfacesAdded.
func (om *objectManager) add(path dbus.ObjectPath, iface string, p *prop.Properties) {
	om.mu.Lock()
	if om.objs[path] == nil {
		om.objs[path] = map[string]*prop.Properties{}
	}
	om.objs[path][iface] = p
	om.mu.Unlock()

	props, err := p.GetAll(iface)
	if err != nil {
		props = map[string]dbus.Variant{}
	}
	payload := map[string]map[string]dbus.Variant{iface: props}
	_ = om.m.conn.Emit(omPath, omIface+".InterfacesAdded", path, payload)
}

// remove drops an object entirely and announces InterfacesRemoved for all its
// interfaces.
func (om *objectManager) remove(path dbus.ObjectPath) {
	om.mu.Lock()
	ifaces := om.objs[path]
	delete(om.objs, path)
	om.mu.Unlock()
	if len(ifaces) == 0 {
		return
	}
	names := make([]string, 0, len(ifaces))
	for n := range ifaces {
		names = append(names, n)
	}
	sort.Strings(names)
	_ = om.m.conn.Emit(omPath, omIface+".InterfacesRemoved", path, names)
}
