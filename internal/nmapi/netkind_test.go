package nmapi

import (
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/singularityos-lab/libsingularity/src/system/core/go/netkind"
)

func TestNetworksAreClassifiedFromTheirProfile(t *testing.T) {
	cases := []struct {
		name    string
		conn    map[string]dbus.Variant
		typ     string
		uuid    string
		domain  string
		kind    netkind.Kind
		metered bool
	}{
		{"unknown wifi", nil, "802-11-wireless", "a", "", netkind.Public, false},
		{"home zone", map[string]dbus.Variant{"zone": dbus.MakeVariant("home")}, "802-11-wireless", "a", "", netkind.Home, false},
		{"trusted zone", map[string]dbus.Variant{"zone": dbus.MakeVariant("trusted")}, "802-3-ethernet", "a", "", netkind.Home, false},
		{"domain network", map[string]dbus.Variant{"zone": dbus.MakeVariant("public")}, "802-3-ethernet", "d", "d", netkind.Work, false},
		{"mobile data", nil, "gsm", "a", "", netkind.Public, true},
		{"phone hotspot marked", map[string]dbus.Variant{"zone": dbus.MakeVariant("home"), "metered": dbus.MakeVariant(int32(1))}, "802-11-wireless", "a", "", netkind.Home, true},
		{"mobile marked unmetered", map[string]dbus.Variant{"metered": dbus.MakeVariant(int32(2))}, "gsm", "a", "", netkind.Public, false},
		{"empty domain never matches", nil, "802-3-ethernet", "", "", netkind.Public, false},
	}
	for _, c := range cases {
		kind, metered := classify(c.conn, c.typ, c.uuid, c.domain)
		if kind != c.kind || metered != c.metered {
			t.Errorf("%s: got %s metered=%v, want %s metered=%v", c.name, kind, metered, c.kind, c.metered)
		}
	}
}
