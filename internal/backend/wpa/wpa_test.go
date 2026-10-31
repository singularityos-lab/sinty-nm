package wpa

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

func TestParseScanResults(t *testing.T) {
	in := "bssid / frequency / signal level / flags / ssid\n" +
		"aa:aa:aa:aa:aa:01\t2412\t-70\t[WPA2-PSK-CCMP][ESS]\tcasa\n" +
		"aa:aa:aa:aa:aa:02\t5180\t-40\t[WPA2-PSK-CCMP][ESS]\tcasa\n" +
		"aa:aa:aa:aa:aa:03\t2437\t-50\t[ESS]\tbar\\x20caff\\xc3\\xa8\n" +
		"aa:aa:aa:aa:aa:04\t2437\t-30\t[ESS]\t\n" +
		"aa:aa:aa:aa:aa:05\t2462\t-90\t[WPA2-EAP-CCMP][ESS]\tlavoro\n"
	got := parseScanResults(in)
	if len(got) != 3 {
		t.Fatalf("got %d networks", len(got))
	}
	if string(got[0].SSID) != "casa" || got[0].BSSID != "aa:aa:aa:aa:aa:02" || got[0].Security != core.SecPSK {
		t.Fatalf("strongest: %+v", got[0])
	}
	if string(got[1].SSID) != "bar caffè" || got[1].Security != core.SecOpen {
		t.Fatalf("escaped: %q %v", got[1].SSID, got[1].Security)
	}
	if got[2].Security != core.SecEnterprise {
		t.Fatalf("enterprise: %+v", got[2])
	}
}

func TestParseStatus(t *testing.T) {
	state, ssid := parseStatus("bssid=aa\nssid=casa\nwpa_state=COMPLETED\nip_address=1\n")
	if state != core.WifiConnected || string(ssid) != "casa" {
		t.Fatalf("%v %q", state, ssid)
	}
	if state, _ := parseStatus("wpa_state=SCANNING\n"); state != core.WifiDisconnected {
		t.Fatalf("%v", state)
	}
}

func TestProfilesMatchIwdFiles(t *testing.T) {
	b := New()
	b.ProfileDir = t.TempDir()
	if err := os.WriteFile(filepath.Join(b.ProfileDir, "casa.psk"),
		[]byte("[Security]\nPreSharedKey=abc\nPassphrase=segreta\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if p := b.profile([]byte("casa")); p == nil || p.psk != "segreta" {
		t.Fatalf("%+v", p)
	}
	if err := b.saveProfile([]byte("caffè"), core.SecPSK, "parolalunga"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(b.ProfileDir, "=636166666ac3a8.psk")); err == nil {
		t.Fatal("wrong encoding accepted")
	}
	if p := b.profile([]byte("caffè")); p == nil || p.psk != "parolalunga" {
		t.Fatalf("%+v", p)
	}
	if err := b.Forget("", []byte("caffè")); err != nil {
		t.Fatal(err)
	}
	if b.profile([]byte("caffè")) != nil {
		t.Fatal("still known")
	}
}
