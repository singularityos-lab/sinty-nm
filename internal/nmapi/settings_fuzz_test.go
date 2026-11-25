package nmapi

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

var fuzzGroups = []string{"connection", "802-11-wireless", "802-11-wireless-security", "ipv4", "ipv6", "wireguard", "vpn", "ethernet", "proxy"}

var fuzzKeys = []string{"id", "uuid", "type", "interface-name", "zone", "ssid", "psk", "method", "addresses", "address-data",
	"gateway", "dns", "dns-data", "dns-search", "ignore-auto-dns", "mtu", "private-key", "listen-port", "peers", "routes",
	"route-data", "data", "secrets", "key-mgmt", "autoconnect", "hidden", "mode", "seen-bssids"}

type fuzzReader struct {
	data []byte
	pos  int
}

func (r *fuzzReader) byte() byte {
	if r.pos >= len(r.data) {
		return 0
	}
	b := r.data[r.pos]
	r.pos++
	return b
}

func (r *fuzzReader) done() bool { return r.pos >= len(r.data) }

func (r *fuzzReader) bytes() []byte {
	n := int(r.byte() % 40)
	out := make([]byte, 0, n)
	for i := 0; i < n && !r.done(); i++ {
		out = append(out, r.byte())
	}
	return out
}

func (r *fuzzReader) str() string { return string(r.bytes()) }

func (r *fuzzReader) u32() uint32 {
	return uint32(r.byte()) | uint32(r.byte())<<8 | uint32(r.byte())<<16 | uint32(r.byte())<<24
}

func (r *fuzzReader) variant(depth int) dbus.Variant {
	switch k := r.byte() % 14; {
	case k == 0:
		return dbus.MakeVariant(r.str())
	case k == 1:
		return dbus.MakeVariant(r.bytes())
	case k == 2:
		return dbus.MakeVariant(r.u32())
	case k == 3:
		return dbus.MakeVariant(int32(r.u32()))
	case k == 4:
		return dbus.MakeVariant(r.byte()%2 == 0)
	case k == 5:
		n := int(r.byte() % 5)
		out := make([]string, n)
		for i := range out {
			out[i] = r.str()
		}
		return dbus.MakeVariant(out)
	case k == 6:
		n := int(r.byte() % 5)
		out := make([][]byte, n)
		for i := range out {
			out[i] = r.bytes()
		}
		return dbus.MakeVariant(out)
	case k == 7:
		n := int(r.byte() % 5)
		out := make([][]uint32, n)
		for i := range out {
			m := int(r.byte() % 4)
			out[i] = make([]uint32, m)
			for j := range out[i] {
				out[i][j] = r.u32()
			}
		}
		return dbus.MakeVariant(out)
	case k == 8:
		n := int(r.byte() % 5)
		out := make([]uint32, n)
		for i := range out {
			out[i] = r.u32()
		}
		return dbus.MakeVariant(out)
	case k == 9 && depth < 3:
		n := int(r.byte() % 4)
		out := make([]map[string]dbus.Variant, n)
		for i := range out {
			out[i] = r.group(depth + 1)
		}
		return dbus.MakeVariant(out)
	case k == 10 && depth < 3:
		return dbus.MakeVariant(r.group(depth + 1))
	case k == 11:
		n := int(r.byte() % 4)
		out := map[string]string{}
		for i := 0; i < n; i++ {
			out[r.str()] = r.str()
		}
		return dbus.MakeVariant(out)
	case k == 12 && depth < 3:
		return dbus.MakeVariant(r.variant(depth + 1))
	default:
		return dbus.MakeVariant(uint64(r.u32()) << 8)
	}
}

func (r *fuzzReader) key() string {
	if b := r.byte(); b%5 == 0 {
		return r.str()
	} else {
		return fuzzKeys[int(b)%len(fuzzKeys)]
	}
}

func (r *fuzzReader) group(depth int) map[string]dbus.Variant {
	n := int(r.byte() % 8)
	out := map[string]dbus.Variant{}
	for i := 0; i < n && !r.done(); i++ {
		out[r.key()] = r.variant(depth)
	}
	return out
}

func (r *fuzzReader) settings() map[string]map[string]dbus.Variant {
	n := int(r.byte()%6) + 1
	out := map[string]map[string]dbus.Variant{}
	for i := 0; i < n && !r.done(); i++ {
		name := fuzzGroups[int(r.byte())%len(fuzzGroups)]
		if r.byte()%7 == 0 {
			name = r.str()
		}
		out[name] = r.group(0)
	}
	return out
}

func FuzzSettingsFromTheBus(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte("\x03\x00\x02\x00\x01\x00\x05plain\x01\x03\x00\x02\x00\x06\x00\x04\x00\x08\x07"))
	f.Add([]byte{5, 3, 0, 7, 9, 0, 3, 1, 2, 3, 4, 2, 0, 4, 1, 10, 0, 7, 3, 2, 1, 2, 3, 4, 5, 6, 7, 8, 9})
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		r := &fuzzReader{data: data}
		settings := r.settings()
		update := r.settings()

		sc := &SettingsConnection{settings: settings}
		_ = sc.connType()
		_ = sc.ssid()
		_ = sc.psk()
		_ = sc.ipv4Method()
		_ = sc.interfaceName()
		_ = sc.connID()
		_ = sc.wgConfig()
		_ = sc.wgMTU()
		_ = sc.ipConfig("ipv4")
		_ = sc.ipConfig("ipv6")
		_, _, _ = sc.manualLease()
		sc.mergeDNS(&core.Lease{})
		_, _ = classify(settings["connection"], sc.connType(), variantString(settings["connection"], "uuid"), "")
		_ = variantUint(settings["ipv4"], "mtu")

		withSecrets := cloneSettings(settings, true)
		_ = cloneSettings(settings, false)
		keepSecrets(update, withSecrets)

		if settings["connection"] == nil || checkSettings(settings) != nil {
			return
		}
		path := filepath.Join(dir, "p.nmconnection")
		if err := writeKeyfile(path, settings); err != nil {
			return
		}
		back, err := readKeyfile(path)
		if err != nil {
			t.Fatalf("a keyfile written from accepted settings cannot be read back: %v", err)
		}
		again := &SettingsConnection{settings: back}
		_ = again.wgConfig()
		_ = again.ipConfig("ipv4")
		_, _, _ = again.manualLease()
	})
}

func FuzzLegacyValues(f *testing.F) {
	f.Add("")
	f.Add("[{'address': <'10.0.0.2'>, 'prefix': <uint32 24>}]")
	f.Add("{'a': <1>")
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = legacyMaps(s)
		_, _ = legacyPairs(s)
	})
}

func FuzzReadKeyfile(f *testing.F) {
	f.Add([]byte("[connection]\nid=x\nuuid=@a{bv} {}\n"))
	f.Add([]byte("[ipv4]\naddress-data=[map[address:\"10.0.0.2\" prefix:@u 24]]\n"))
	f.Add([]byte("[ipv4]\naddress-data=[map[a:\u0667]]\n"))
	f.Add([]byte("[wireguard]\nmtu=@u \u0661\n"))
	dir := f.TempDir()
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(dir, "in.nmconnection")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		settings, err := readKeyfile(path)
		if err != nil {
			return
		}
		sc := &SettingsConnection{settings: settings}
		_ = sc.wgConfig()
		_ = sc.ipConfig("ipv4")
		_, _, _ = sc.manualLease()
	})
}
