package nmapi

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
)

var (
	netKindDir    = "/run/sinty-nm"
	domainNetwork = "/run/sinty-domaind/network"
)

const (
	KindNone   = "none"
	KindPublic = "public"
	KindHome   = "home"
	KindWork   = "work"
)

func classify(conn map[string]dbus.Variant, typ, uuid, domainUUID string) (string, bool) {
	kind := KindPublic
	switch zone := variantString(conn, "zone"); {
	case uuid != "" && uuid == domainUUID:
		kind = KindWork
	case zone == "home" || zone == "trusted":
		kind = KindHome
	}
	metered := typ == "gsm" || typ == "cdma" || typ == "bluetooth"
	if v, ok := conn["metered"]; ok {
		switch n := toInt(v.Value()); n {
		case 1, 3:
			metered = true
		case 2, 4:
			metered = false
		}
	}
	return kind, metered
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case int32:
		return int64(n)
	case int64:
		return n
	case uint32:
		return int64(n)
	case int:
		return int64(n)
	case string:
		i, _ := strconv.ParseInt(n, 10, 64)
		return i
	}
	return 0
}

func (m *Manager) publishNetworkKind() {
	m.mu.Lock()
	ac := m.activeConns[m.primary]
	var conn dbus.ObjectPath
	var typ, uuid string
	if ac != nil {
		conn, typ, uuid = ac.conn, ac.typ, ac.uuid
	}
	m.mu.Unlock()
	kind, metered := KindNone, false
	if ac != nil {
		var group map[string]dbus.Variant
		if m.settings != nil {
			if sc := m.settings.byPath(conn); sc != nil {
				sc.mu.Lock()
				group = cloneGroup(sc.settings["connection"])
				sc.mu.Unlock()
			}
		}
		domain, _ := os.ReadFile(domainNetwork)
		kind, metered = classify(group, typ, uuid, strings.TrimSpace(string(domain)))
	}
	writeNetworkKind(netKindDir, kind, metered)
}

func writeNetworkKind(dir, kind string, metered bool) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return
	}
	tmp := filepath.Join(dir, ".network-kind")
	if os.WriteFile(tmp, []byte(kind+"\n"), 0o644) == nil {
		os.Rename(tmp, filepath.Join(dir, "network-kind"))
	}
	if metered {
		os.WriteFile(filepath.Join(dir, "metered"), nil, 0o644)
	} else {
		os.Remove(filepath.Join(dir, "metered"))
	}
}
