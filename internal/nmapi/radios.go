package nmapi

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"

	"github.com/singularityos-lab/sinty-nm/internal/core"
)

type radios struct {
	Wireless bool `json:"wireless"`
	Wwan     bool `json:"wwan"`
}

func loadRadios(path string) radios {
	r := radios{Wireless: true, Wwan: true}
	b, err := os.ReadFile(path)
	if err != nil {
		return r
	}
	if err := json.Unmarshal(b, &r); err != nil {
		log.Printf("radios: choice unreadable: %v", err)
		return radios{Wireless: true, Wwan: true}
	}
	return r
}

func saveRadios(path string, r radios) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path+".new", b, 0o600); err != nil {
		return err
	}
	return os.Rename(path+".new", path)
}

func (m *Manager) keepRadios(edit func(*radios)) {
	m.radiosMu.Lock()
	defer m.radiosMu.Unlock()
	edit(&m.radios)
	if m.b.RadiosFile == "" {
		return
	}
	if err := saveRadios(m.b.RadiosFile, m.radios); err != nil {
		log.Printf("radios: choice not saved: %v", err)
	}
}

func (m *Manager) restoreRadios() {
	m.radiosMu.Lock()
	r := m.radios
	m.radiosMu.Unlock()
	if !r.Wireless {
		if err := m.b.RFKill.SetWifiBlocked(true); err != nil {
			log.Printf("radios: wifi block: %v", err)
		}
		m.mu.Lock()
		devs := append([]*Device(nil), m.devices...)
		m.mu.Unlock()
		for _, d := range devs {
			if d.kind == core.KindWifi {
				_ = m.b.Wifi.SetPowered(d.iface, false)
			}
		}
	}
	if !r.Wwan {
		go func() {
			m.wwanMu.Lock()
			defer m.wwanMu.Unlock()
			m.applyWwan(false)
		}()
	}
}
