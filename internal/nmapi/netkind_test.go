package nmapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestNetworksAreClassifiedFromTheirProfile(t *testing.T) {
	cases := []struct {
		name    string
		conn    map[string]dbus.Variant
		typ     string
		uuid    string
		domain  string
		kind    string
		metered bool
	}{
		{"unknown wifi", nil, "802-11-wireless", "a", "", KindPublic, false},
		{"home zone", map[string]dbus.Variant{"zone": dbus.MakeVariant("home")}, "802-11-wireless", "a", "", KindHome, false},
		{"trusted zone", map[string]dbus.Variant{"zone": dbus.MakeVariant("trusted")}, "802-3-ethernet", "a", "", KindHome, false},
		{"domain network", map[string]dbus.Variant{"zone": dbus.MakeVariant("public")}, "802-3-ethernet", "d", "d", KindWork, false},
		{"mobile data", nil, "gsm", "a", "", KindPublic, true},
		{"phone hotspot marked", map[string]dbus.Variant{"zone": dbus.MakeVariant("home"), "metered": dbus.MakeVariant(int32(1))}, "802-11-wireless", "a", "", KindHome, true},
		{"mobile marked unmetered", map[string]dbus.Variant{"metered": dbus.MakeVariant(int32(2))}, "gsm", "a", "", KindPublic, false},
		{"empty domain never matches", nil, "802-3-ethernet", "", "", KindPublic, false},
	}
	for _, c := range cases {
		kind, metered := classify(c.conn, c.typ, c.uuid, c.domain)
		if kind != c.kind || metered != c.metered {
			t.Errorf("%s: got %s metered=%v, want %s metered=%v", c.name, kind, metered, c.kind, c.metered)
		}
	}
}

func TestTheKindIsWrittenWhereUpdatesReadIt(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "sinty-nm")
	writeNetworkKind(dir, KindHome, true)
	b, _ := os.ReadFile(filepath.Join(dir, "network-kind"))
	if string(b) != "home\n" {
		t.Fatalf("kind %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "metered")); err != nil {
		t.Fatal("metered flag missing")
	}
	writeNetworkKind(dir, KindPublic, false)
	b, _ = os.ReadFile(filepath.Join(dir, "network-kind"))
	if string(b) != "public\n" {
		t.Fatalf("kind %q", b)
	}
	if _, err := os.Stat(filepath.Join(dir, "metered")); !os.IsNotExist(err) {
		t.Fatal("metered flag left behind")
	}
}
