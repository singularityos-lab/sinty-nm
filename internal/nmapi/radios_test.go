package nmapi

import (
	"path/filepath"
	"testing"
)

func TestSwitchedOffRadiosSurviveARestart(t *testing.T) {
	file := filepath.Join(t.TempDir(), "state", "radios.json")
	if r := loadRadios(file); !r.Wireless || !r.Wwan {
		t.Fatalf("a first boot starts with %+v", r)
	}
	m := &Manager{b: Backends{RadiosFile: file}, radios: loadRadios(file)}
	m.keepRadios(func(r *radios) { r.Wwan = false })
	if r := loadRadios(file); !r.Wireless || r.Wwan {
		t.Fatalf("after a restart: %+v", r)
	}
}
