package nmapi

import (
	"encoding/json"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
)

const (
	profileAreaIface = "dev.sinty.ProfileArea1"
	vpnAreaPath      = dbus.ObjectPath("/dev/sinty/ProfileArea/vpn")
	vpnAreaKey       = "connection"
)

type vpnArea struct{ m *Manager }

type areaChoice struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

type areaOption struct {
	Key      string       `json:"key"`
	Label    string       `json:"label"`
	Subtitle string       `json:"subtitle"`
	Kind     string       `json:"kind"`
	Min      float64      `json:"min"`
	Max      float64      `json:"max"`
	ReadOnly bool         `json:"read-only"`
	Choices  []areaChoice `json:"choices"`
}

type areaInfo struct {
	ID      string       `json:"id"`
	Label   string       `json:"label"`
	Icon    string       `json:"icon"`
	Options []areaOption `json:"options"`
}

func isVPNType(t string) bool {
	return t == "vpn" || t == "wireguard"
}

func (sc *SettingsConnection) connID() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return variantString(sc.settings["connection"], "id")
}

func (m *Manager) vpnConnections() []*SettingsConnection {
	m.settings.mu.Lock()
	all := append([]*SettingsConnection(nil), m.settings.conns...)
	m.settings.mu.Unlock()
	var out []*SettingsConnection
	for _, sc := range all {
		if isVPNType(sc.connType()) {
			out = append(out, sc)
		}
	}
	return out
}

func (m *Manager) activeVPNs() []*ActiveConnection {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ActiveConnection
	for _, ac := range m.activeConns {
		if isVPNType(ac.typ) && !ac.gone {
			out = append(out, ac)
		}
	}
	return out
}

func (m *Manager) exportVPNArea() error {
	obj := &vpnArea{m}
	if err := m.conn.Export(obj, vpnAreaPath, profileAreaIface); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(vpnAreaPath),
		Interfaces: []introspect.Interface{introspect.IntrospectData, {
			Name:    profileAreaIface,
			Methods: introspect.Methods(obj),
			Signals: []introspect.Signal{{Name: "Changed", Args: []introspect.Arg{{Name: "keys", Type: "as"}}}},
		}},
	}
	return m.conn.Export(introspect.NewIntrospectable(node), vpnAreaPath, "org.freedesktop.DBus.Introspectable")
}

func (m *Manager) vpnAreaChanged(typ string) {
	if isVPNType(typ) && m.conn != nil {
		_ = m.conn.Emit(vpnAreaPath, profileAreaIface+".Changed", []string{vpnAreaKey})
	}
}

func (a *vpnArea) Describe() (string, *dbus.Error) {
	choices := []areaChoice{{"", "Off"}}
	for _, sc := range a.m.vpnConnections() {
		id := sc.connID()
		choices = append(choices, areaChoice{id, id})
	}
	info := areaInfo{ID: "vpn", Label: "VPN", Icon: "network-vpn-symbolic", Options: []areaOption{{
		Key: vpnAreaKey, Label: "VPN", Kind: "choice", Choices: choices,
	}}}
	data, err := json.Marshal(info)
	if err != nil {
		return "", dbus.MakeFailedError(err)
	}
	return string(data), nil
}

func (a *vpnArea) Snapshot(keys []string) (map[string]string, *dbus.Error) {
	out := map[string]string{}
	for _, k := range keys {
		if k != vpnAreaKey {
			continue
		}
		current := ""
		if active := a.m.activeVPNs(); len(active) > 0 {
			current = active[0].id
		}
		v, _ := json.Marshal(current)
		out[k] = string(v)
	}
	return out, nil
}

func (a *vpnArea) Apply(values map[string]string) *dbus.Error {
	raw, ok := values[vpnAreaKey]
	if !ok {
		return nil
	}
	var want string
	if err := json.Unmarshal([]byte(raw), &want); err != nil {
		return dbus.MakeFailedError(err)
	}
	on := false
	for _, ac := range a.m.activeVPNs() {
		if ac.id == want {
			on = true
			continue
		}
		a.m.deactivate(ac)
	}
	if want == "" || on {
		return nil
	}
	for _, sc := range a.m.vpnConnections() {
		if sc.connID() == want {
			_, err := a.m.ActivateConnection(sc.path, nullPath, nullPath)
			return err
		}
	}
	return dbus.NewError("org.freedesktop.NetworkManager.UnknownConnection", []interface{}{"no VPN named " + want})
}
