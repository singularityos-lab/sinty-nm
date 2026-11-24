package nmapi

import (
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/godbus/dbus/v5"
	"github.com/singularityos-lab/libsingularity/src/system/core/go/netkind"
)

var (
	netKindDir    = netkind.Dir
	domainNetwork = "/run/sinty-domaind/network"
)

func classify(conn map[string]dbus.Variant, typ, uuid, domainUUID string) (netkind.Kind, bool) {
	kind := netkind.Public
	switch zone := variantString(conn, "zone"); {
	case uuid != "" && uuid == domainUUID:
		kind = netkind.Work
	case zone == "home" || zone == "trusted":
		kind = netkind.Home
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
	kind, metered := netkind.None, false
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
	if err := netkind.Write(netKindDir, kind, metered); err != nil {
		log.Printf("network kind: %v", err)
	}
}
