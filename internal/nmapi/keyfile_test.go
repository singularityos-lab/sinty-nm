package nmapi

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"
)

func roundTrip(t *testing.T, settings map[string]map[string]dbus.Variant) map[string]map[string]dbus.Variant {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.nmconnection")
	if err := writeKeyfile(path, settings); err != nil {
		t.Fatalf("writeKeyfile: %v", err)
	}
	got, err := readKeyfile(path)
	if err != nil {
		t.Fatalf("readKeyfile: %v", err)
	}
	return got
}

func TestKeyfileKeepsAHostileSSIDInItsField(t *testing.T) {
	ssid := []byte("x\n[ipv4]\ndns=6.6.6.6")
	got := roundTrip(t, map[string]map[string]dbus.Variant{
		"connection":      {"id": dbus.MakeVariant("cafe"), "type": dbus.MakeVariant("802-11-wireless")},
		"802-11-wireless": {"ssid": dbus.MakeVariant(ssid)},
	})
	if _, ok := got["ipv4"]; ok {
		t.Fatalf("the ssid created an ipv4 section: %v", got["ipv4"])
	}
	if b, _ := got["802-11-wireless"]["ssid"].Value().([]byte); !bytes.Equal(b, ssid) {
		t.Fatalf("ssid came back as %q, want %q", b, ssid)
	}
}

func TestKeyfileStringsSurviveExactly(t *testing.T) {
	for _, s := range []string{
		"plain",
		"",
		" leading and trailing ",
		"line\nbreak",
		"@b true",
		"[a b]",
		"tab\there",
		"back\\slash",
		"nul\x00byte",
		"\xff\xfe",
		"é ü 漢字",
	} {
		got := roundTrip(t, map[string]map[string]dbus.Variant{
			"connection": {"id": dbus.MakeVariant(s)},
		})
		if v, _ := got["connection"]["id"].Value().(string); v != s {
			t.Errorf("id %q came back as %q", s, v)
		}
	}
}

func TestKeyfileOldPlainFilesStillRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.nmconnection")
	if err := os.WriteFile(path, []byte("[connection]\nid=Home\\Net\n\n[wifi]\nssid=Home Net\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readKeyfile(path)
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := got["connection"]["id"].Value().(string); v != "Home\\Net" {
		t.Errorf("id %q", v)
	}
	if b, _ := got["802-11-wireless"]["ssid"].Value().([]byte); string(b) != "Home Net" {
		t.Errorf("ssid %q", b)
	}
}

func TestSettingsWithUnsafeNamesAreRefused(t *testing.T) {
	for _, s := range []map[string]map[string]dbus.Variant{
		{"connection": {"id\n[ipv4]\ndns": dbus.MakeVariant("x")}},
		{"connection]\n[ipv4": {"id": dbus.MakeVariant("x")}},
		{"connection": {"a=b": dbus.MakeVariant("x")}},
		{"": {"id": dbus.MakeVariant("x")}},
	} {
		if checkSettings(s) == nil {
			t.Errorf("accepted %v", s)
		}
	}
	ok := map[string]map[string]dbus.Variant{
		"802-11-wireless-security": {"key-mgmt": dbus.MakeVariant("wpa-psk")},
		"ipv4":                     {"address-data": dbus.MakeVariant("x"), "may_fail": dbus.MakeVariant(true)},
	}
	if err := checkSettings(ok); err != nil {
		t.Errorf("refused valid settings: %v", err)
	}
}

func FuzzKeyfileRoundTrip(f *testing.F) {
	f.Add("cafe", []byte("x\n[ipv4]\ndns=6.6.6.6"), "psk with space ")
	f.Add("", []byte{}, "@s \"x\"")
	f.Add("[a]", []byte{0xff, 0}, "\n")
	f.Fuzz(func(t *testing.T, id string, ssid []byte, psk string) {
		got := roundTrip(t, map[string]map[string]dbus.Variant{
			"connection":               {"id": dbus.MakeVariant(id)},
			"802-11-wireless":          {"ssid": dbus.MakeVariant(ssid)},
			"802-11-wireless-security": {"psk": dbus.MakeVariant(psk)},
		})
		if len(got) != 3 {
			t.Fatalf("%d sections came back: %v", len(got), got)
		}
		if v, _ := got["connection"]["id"].Value().(string); v != id {
			t.Fatalf("id %q came back as %q", id, v)
		}
		if v, _ := got["802-11-wireless-security"]["psk"].Value().(string); v != psk {
			t.Fatalf("psk %q came back as %q", psk, v)
		}
		if b, _ := got["802-11-wireless"]["ssid"].Value().([]byte); !bytes.Equal(b, ssid) {
			t.Fatalf("ssid %q came back as %q", ssid, b)
		}
	})
}
