package nmapi

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/introspect"
	"github.com/godbus/dbus/v5/prop"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

// systemConnDir is where connection profiles are persisted, matching NM's location so a
// profile written by either daemon is found by the other.
const systemConnDir = "/etc/NetworkManager/system-connections"

// Settings is the org.freedesktop.NetworkManager.Settings singleton: the store of
// persisted connection profiles, each exported as a Settings.Connection child.
type Settings struct {
	m     *Manager
	props *prop.Properties

	connGen pathGen

	mu    sync.Mutex
	conns []*SettingsConnection
}

// SettingsConnection is one persisted profile, exported as
// org.freedesktop.NetworkManager.Settings.Connection. The canonical form is NM's
// a{sa{sv}} settings map; it is mirrored to an NM-style keyfile on disk.
type SettingsConnection struct {
	s     *Settings
	path  dbus.ObjectPath
	props *prop.Properties

	mu       sync.Mutex
	uuid     string
	id       string
	file     string
	settings map[string]map[string]dbus.Variant
}

// newSettings builds the store and loads every persisted profile from disk. Profiles are
// created in memory here; they (and the Settings object) reach the bus in export.
func newSettings(m *Manager) (*Settings, error) {
	s := &Settings{m: m}
	entries, err := os.ReadDir(systemConnDir)
	if err != nil {
		return s, nil // no profiles yet is not an error
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		full := filepath.Join(systemConnDir, e.Name())
		settings, err := readKeyfile(full)
		if err != nil {
			continue
		}
		s.conns = append(s.conns, s.newConnection(settings, full))
	}
	return s, nil
}

// newConnection wraps a settings map in a SettingsConnection, assigning it an object path
// and caching id/uuid. It does not touch the bus.
func (s *Settings) newConnection(settings map[string]map[string]dbus.Variant, file string) *SettingsConnection {
	sc := &SettingsConnection{
		s:        s,
		path:     s.connGen.next(prefixSettings),
		file:     file,
		settings: settings,
	}
	sc.uuid = variantString(settings["connection"], "uuid")
	sc.id = variantString(settings["connection"], "id")
	if sc.uuid == "" {
		sc.uuid = newUUID()
		setVariant(settings, "connection", "uuid", sc.uuid)
	}
	return sc
}

// export publishes the Settings object and each of its connections.
func (s *Settings) export() error {
	spec := prop.Map{
		ifaceSettings: {
			"Connections": {Value: s.connPathsLocked(), Writable: false, Emit: prop.EmitTrue},
			"Hostname":    {Value: hostname(), Writable: false, Emit: prop.EmitTrue},
			"CanModify":   {Value: true, Writable: false, Emit: prop.EmitConst},
		},
	}
	p, err := prop.Export(s.m.conn, SettingsPath, spec)
	if err != nil {
		return err
	}
	s.props = p
	s.m.om.add(SettingsPath, ifaceSettings, p)
	if err := s.m.conn.Export(s, SettingsPath, ifaceSettings); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(SettingsPath),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			prop.IntrospectData,
			{
				Name: ifaceSettings,
				Methods: []introspect.Method{
					{Name: "ListConnections", Args: []introspect.Arg{{Name: "connections", Type: "ao", Direction: "out"}}},
					{Name: "GetConnectionByUuid", Args: []introspect.Arg{{Name: "uuid", Type: "s", Direction: "in"}, {Name: "connection", Type: "o", Direction: "out"}}},
					{Name: "AddConnection", Args: []introspect.Arg{{Name: "connection", Type: "a{sa{sv}}", Direction: "in"}, {Name: "path", Type: "o", Direction: "out"}}},
					{Name: "ReloadConnections", Args: []introspect.Arg{{Name: "status", Type: "b", Direction: "out"}}},
				},
				Signals: []introspect.Signal{
					{Name: "NewConnection", Args: []introspect.Arg{{Name: "connection", Type: "o"}}},
					{Name: "ConnectionRemoved", Args: []introspect.Arg{{Name: "connection", Type: "o"}}},
				},
			},
		},
	}
	if err := s.m.conn.Export(introspect.NewIntrospectable(node), SettingsPath, "org.freedesktop.DBus.Introspectable"); err != nil {
		return err
	}
	s.mu.Lock()
	conns := append([]*SettingsConnection(nil), s.conns...)
	s.mu.Unlock()
	for _, sc := range conns {
		if err := sc.export(); err != nil {
			return err
		}
	}
	return nil
}

// ListConnections returns the object paths of all persisted profiles.
func (s *Settings) ListConnections() ([]dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connPathsLocked(), nil
}

// GetConnectionByUuid resolves a profile path by its UUID.
func (s *Settings) GetConnectionByUuid(uuid string) (dbus.ObjectPath, *dbus.Error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.conns {
		if sc.uuid == uuid {
			return sc.path, nil
		}
	}
	return nullPath, dbus.NewError("org.freedesktop.NetworkManager.Settings.InvalidConnection", []interface{}{"no such uuid"})
}

// AddConnection persists a new profile and exports it.
func (s *Settings) AddConnection(settings map[string]map[string]dbus.Variant) (dbus.ObjectPath, *dbus.Error) {
	sc, err := s.add(settings)
	if err != nil {
		return nullPath, dbus.MakeFailedError(err)
	}
	return sc.path, nil
}

// ReloadConnections re-reads profiles from disk. We already track them live, so this is a
// no-op that reports success.
func (s *Settings) ReloadConnections() (bool, *dbus.Error) {
	return true, nil
}

// add persists a profile map to a keyfile, wraps it, exports it, and announces it.
func (s *Settings) add(settings map[string]map[string]dbus.Variant) (*SettingsConnection, error) {
	if settings["connection"] == nil {
		return nil, fmt.Errorf("connection settings missing")
	}
	uuid := variantString(settings["connection"], "uuid")
	if uuid == "" {
		uuid = newUUID()
		setVariant(settings, "connection", "uuid", uuid)
	}
	id := variantString(settings["connection"], "id")
	if id == "" {
		id = uuid
	}
	file := filepath.Join(systemConnDir, sanitize(id)+".nmconnection")
	if err := writeKeyfile(file, settings); err != nil {
		return nil, err
	}
	sc := s.newConnection(settings, file)
	s.mu.Lock()
	s.conns = append(s.conns, sc)
	s.mu.Unlock()
	if err := sc.export(); err != nil {
		return nil, err
	}
	s.publishConnections()
	_ = s.m.conn.Emit(SettingsPath, ifaceSettings+".NewConnection", sc.path)
	return sc, nil
}

// remove drops a profile, deletes its keyfile, unexports it, and announces the removal.
func (s *Settings) remove(sc *SettingsConnection) {
	s.mu.Lock()
	out := s.conns[:0]
	for _, c := range s.conns {
		if c != sc {
			out = append(out, c)
		}
	}
	s.conns = out
	s.mu.Unlock()
	if sc.file != "" {
		_ = os.Remove(sc.file)
	}
	sc.unexport()
	s.publishConnections()
	_ = s.m.conn.Emit(SettingsPath, ifaceSettings+".ConnectionRemoved", sc.path)
}

// byPath resolves a profile by its object path.
func (s *Settings) byPath(p dbus.ObjectPath) *SettingsConnection {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sc := range s.conns {
		if sc.path == p {
			return sc
		}
	}
	return nil
}

// availableFor returns the profiles that can activate on a device, matched by type.
func (s *Settings) availableFor(d *Device) []dbus.ObjectPath {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := []dbus.ObjectPath{}
	for _, sc := range s.conns {
		if kindMatchesType(d.kind, sc.connType()) {
			out = append(out, sc.path)
		}
	}
	return out
}

// publishConnections republishes the Connections property.
func (s *Settings) publishConnections() {
	if s.props != nil {
		s.props.SetMust(ifaceSettings, "Connections", s.connPaths())
	}
	s.m.mu.Lock()
	devs := append([]*Device(nil), s.m.devices...)
	s.m.mu.Unlock()
	for _, d := range devs {
		d.refreshAvailable()
	}
}

func (s *Settings) connPaths() []dbus.ObjectPath {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connPathsLocked()
}

// connPathsLocked returns the profile object paths. mu must be held.
func (s *Settings) connPathsLocked() []dbus.ObjectPath {
	out := make([]dbus.ObjectPath, 0, len(s.conns))
	for _, sc := range s.conns {
		out = append(out, sc.path)
	}
	return out
}

// export publishes the profile object with its methods, its property table (libnm reads
// Unsaved/Flags/Filename through the object manager), and introspection.
func (sc *SettingsConnection) export() error {
	spec := prop.Map{
		ifaceConnection: {
			"Unsaved":  {Value: false, Writable: false, Emit: prop.EmitTrue},
			"Flags":    {Value: uint32(0), Writable: false, Emit: prop.EmitTrue},
			"Filename": {Value: sc.file, Writable: false, Emit: prop.EmitTrue},
		},
	}
	p, err := prop.Export(sc.s.m.conn, sc.path, spec)
	if err != nil {
		return err
	}
	sc.props = p
	sc.s.m.om.add(sc.path, ifaceConnection, p)
	if err := sc.s.m.conn.Export(sc, sc.path, ifaceConnection); err != nil {
		return err
	}
	node := &introspect.Node{
		Name: string(sc.path),
		Interfaces: []introspect.Interface{
			introspect.IntrospectData,
			{
				Name: ifaceConnection,
				Methods: []introspect.Method{
					{Name: "GetSettings", Args: []introspect.Arg{{Name: "settings", Type: "a{sa{sv}}", Direction: "out"}}},
					{Name: "Update", Args: []introspect.Arg{{Name: "properties", Type: "a{sa{sv}}", Direction: "in"}}},
					{Name: "Delete"},
					{Name: "GetSecrets", Args: []introspect.Arg{{Name: "setting_name", Type: "s", Direction: "in"}, {Name: "secrets", Type: "a{sa{sv}}", Direction: "out"}}},
				},
				Signals: []introspect.Signal{
					{Name: "Updated"},
					{Name: "Removed"},
				},
			},
		},
	}
	return sc.s.m.conn.Export(introspect.NewIntrospectable(node), sc.path, "org.freedesktop.DBus.Introspectable")
}

// unexport removes the profile object from the bus.
func (sc *SettingsConnection) unexport() {
	sc.s.m.om.remove(sc.path)
	_ = sc.s.m.conn.Export(nil, sc.path, ifaceConnection)
	_ = sc.s.m.conn.Export(nil, sc.path, "org.freedesktop.DBus.Properties")
	_ = sc.s.m.conn.Export(nil, sc.path, "org.freedesktop.DBus.Introspectable")
}

// GetSettings returns the profile with secret fields stripped (NM hands secrets out only
// through GetSecrets).
func (sc *SettingsConnection) GetSettings() (map[string]map[string]dbus.Variant, *dbus.Error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return cloneSettings(sc.settings, false), nil
}

// GetSecrets returns the requested setting group including its secret fields.
func (sc *SettingsConnection) GetSecrets(settingName string) (map[string]map[string]dbus.Variant, *dbus.Error) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	out := map[string]map[string]dbus.Variant{}
	if g, ok := sc.settings[settingName]; ok {
		out[settingName] = cloneGroup(g)
	}
	return out, nil
}

// Update replaces the profile settings and rewrites the keyfile.
func (sc *SettingsConnection) Update(settings map[string]map[string]dbus.Variant) *dbus.Error {
	sc.mu.Lock()
	sc.settings = settings
	sc.id = variantString(settings["connection"], "id")
	sc.uuid = variantString(settings["connection"], "uuid")
	file := sc.file
	sc.mu.Unlock()
	if err := writeKeyfile(file, settings); err != nil {
		return dbus.MakeFailedError(err)
	}
	_ = sc.s.m.conn.Emit(sc.path, ifaceConnection+".Updated")
	return nil
}

// Delete removes the profile and its keyfile.
func (sc *SettingsConnection) Delete() *dbus.Error {
	_ = sc.s.m.conn.Emit(sc.path, ifaceConnection+".Removed")
	sc.s.remove(sc)
	return nil
}

// connType returns the profile's connection type (e.g. 802-11-wireless).
func (sc *SettingsConnection) connType() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return variantString(sc.settings["connection"], "type")
}

// ssid returns the wifi SSID bytes, or nil for non-wifi profiles.
func (sc *SettingsConnection) ssid() []byte {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	g := sc.settings["802-11-wireless"]
	if g == nil {
		return nil
	}
	if v, ok := g["ssid"]; ok {
		if b, ok := v.Value().([]byte); ok {
			return b
		}
		if str, ok := v.Value().(string); ok {
			return []byte(str)
		}
	}
	return nil
}

// psk returns the pre-shared key from the wifi-security group, if any.
func (sc *SettingsConnection) psk() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return variantString(sc.settings["802-11-wireless-security"], "psk")
}

// ipv4Method returns the ipv4 method (auto, manual, disabled), defaulting to auto.
func (sc *SettingsConnection) ipv4Method() string {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	if mth := variantString(sc.settings["ipv4"], "method"); mth != "" {
		return mth
	}
	return "auto"
}

// wgConfig extracts a WireGuard configuration from the profile.
func (sc *SettingsConnection) wgConfig() core.WGConfig {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	g := sc.settings["wireguard"]
	cfg := core.WGConfig{}
	if g == nil {
		return cfg
	}
	cfg.PrivateKey = variantString(g, "private-key")
	return cfg
}

// kindMatchesType reports whether a device kind can carry a profile of connType.
func kindMatchesType(k core.DeviceKind, connType string) bool {
	switch connType {
	case "802-11-wireless":
		return k == core.KindWifi
	case "802-3-ethernet":
		return k == core.KindEthernet
	case "wireguard":
		return k == core.KindWireGuard
	}
	return false
}

// variantString reads a string-valued key from a settings group, tolerating absence.
func variantString(g map[string]dbus.Variant, key string) string {
	if g == nil {
		return ""
	}
	if v, ok := g[key]; ok {
		if s, ok := v.Value().(string); ok {
			return s
		}
		if b, ok := v.Value().([]byte); ok {
			return string(b)
		}
	}
	return ""
}

// setVariant assigns a group key, creating the group if needed.
func setVariant(settings map[string]map[string]dbus.Variant, group, key string, val interface{}) {
	if settings[group] == nil {
		settings[group] = map[string]dbus.Variant{}
	}
	settings[group][key] = dbus.MakeVariant(val)
}

// cloneSettings deep-copies a settings map. When withSecrets is false, known secret keys
// are dropped so GetSettings never leaks them.
func cloneSettings(in map[string]map[string]dbus.Variant, withSecrets bool) map[string]map[string]dbus.Variant {
	out := map[string]map[string]dbus.Variant{}
	for group, kv := range in {
		g := cloneGroup(kv)
		if !withSecrets && group == "802-11-wireless-security" {
			delete(g, "psk")
		}
		out[group] = g
	}
	return out
}

func cloneGroup(kv map[string]dbus.Variant) map[string]dbus.Variant {
	g := map[string]dbus.Variant{}
	for k, v := range kv {
		g[k] = v
	}
	return g
}

// sanitize turns a profile id into a safe filename stem.
func sanitize(id string) string {
	r := strings.NewReplacer("/", "_", " ", "_", "\\", "_")
	return r.Replace(id)
}

// hostname returns the kernel hostname for the Settings.Hostname property.
func hostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

// newUUID returns a random RFC 4122 v4 UUID string.
func newUUID() string {
	var b [16]byte
	_, _ = rand.Read(b[:])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// dbusGroupToKeyfile and keyfileToDbusGroup translate between NM's D-Bus setting names and
// the shorter keyfile group names (e.g. 802-11-wireless <-> wifi).
var dbusGroupToKeyfile = map[string]string{
	"connection":               "connection",
	"802-11-wireless":          "wifi",
	"802-11-wireless-security": "wifi-security",
	"802-3-ethernet":           "ethernet",
	"ipv4":                     "ipv4",
	"ipv6":                     "ipv6",
	"wireguard":                "wireguard",
}

func keyfileGroupToDbus(g string) string {
	for d, k := range dbusGroupToKeyfile {
		if k == g {
			return d
		}
	}
	return g
}

// writeKeyfile serializes a settings map to an NM-style keyfile at path (0600, atomic).
// ssid is written as its UTF-8 text; other values via their string form.
func writeKeyfile(path string, settings map[string]map[string]dbus.Variant) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	groups := make([]string, 0, len(settings))
	for g := range settings {
		groups = append(groups, g)
	}
	sort.Strings(groups)

	var sb strings.Builder
	for _, dg := range groups {
		kg := dbusGroupToKeyfile[dg]
		if kg == "" {
			kg = dg
		}
		fmt.Fprintf(&sb, "[%s]\n", kg)
		keys := make([]string, 0, len(settings[dg]))
		for k := range settings[dg] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			fmt.Fprintf(&sb, "%s=%s\n", k, keyfileValue(settings[dg][k]))
		}
		sb.WriteString("\n")
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(sb.String()), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// keyfileValue renders a variant to its keyfile string form.
func keyfileValue(v dbus.Variant) string {
	switch val := v.Value().(type) {
	case []byte:
		return string(val)
	case string:
		return val
	default:
		return fmt.Sprint(val)
	}
}

// readKeyfile parses an NM-style keyfile into a settings map. Group names are mapped back
// to their D-Bus form and the wifi ssid is restored to bytes.
func readKeyfile(path string) (map[string]map[string]dbus.Variant, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]dbus.Variant{}
	var group string
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			group = keyfileGroupToDbus(line[1 : len(line)-1])
			out[group] = map[string]dbus.Variant{}
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq < 0 || group == "" {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		if group == "802-11-wireless" && key == "ssid" {
			out[group][key] = dbus.MakeVariant([]byte(val))
			continue
		}
		out[group][key] = dbus.MakeVariant(val)
	}
	return out, nil
}
