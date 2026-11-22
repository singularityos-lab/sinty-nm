package mm

import (
	"errors"
	"testing"

	"github.com/godbus/dbus/v5"
)

func TestAMachineWithoutAModemIsNotAFailure(t *testing.T) {
	for _, name := range []string{"ServiceUnknown", "NameHasNoOwner", "UnknownObject"} {
		if err := ignoreMissing(dbus.Error{Name: "org.freedesktop.DBus.Error." + name}); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, err := range []error{dbus.Error{Name: "org.freedesktop.ModemManager1.Error.Core.Failed"}, errors.New("closed")} {
		if ignoreMissing(err) == nil {
			t.Errorf("%v was hidden", err)
		}
	}
}
