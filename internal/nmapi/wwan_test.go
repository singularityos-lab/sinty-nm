package nmapi

import (
	"errors"
	"testing"
)

type fakeWwan struct {
	err error
	set []bool
}

func (f *fakeWwan) SetPowered(on bool) error {
	f.set = append(f.set, on)
	return f.err
}

func TestAirplaneModeReachesTheModem(t *testing.T) {
	ok := &fakeWwan{}
	m := &Manager{b: Backends{Wwan: ok}}
	if m.applyWwan(false) || len(ok.set) != 1 || ok.set[0] {
		t.Fatalf("the modem was not switched off: %v", ok.set)
	}
	m.b.Wwan = &fakeWwan{err: errors.New("busy")}
	if !m.applyWwan(false) {
		t.Fatal("a refused switch off was reported as off")
	}
}
