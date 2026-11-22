package mm

import (
	"context"
	"errors"
	"time"

	"github.com/godbus/dbus/v5"
)

const (
	busName      = "org.freedesktop.ModemManager1"
	modemPath    = dbus.ObjectPath("/org/freedesktop/ModemManager1/Modem/0")
	enableMethod = "org.freedesktop.ModemManager1.Modem.Enable"
	enableWait   = 40 * time.Second
)

type Backend struct {
	conn *dbus.Conn
}

func New(conn *dbus.Conn) *Backend {
	return &Backend{conn: conn}
}

func (b *Backend) SetPowered(on bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), enableWait)
	defer cancel()
	return ignoreMissing(b.conn.Object(busName, modemPath).CallWithContext(ctx, enableMethod, dbus.FlagNoAutoStart, on).Err)
}

func ignoreMissing(err error) error {
	var de dbus.Error
	if errors.As(err, &de) {
		switch de.Name {
		case "org.freedesktop.DBus.Error.ServiceUnknown",
			"org.freedesktop.DBus.Error.NameHasNoOwner",
			"org.freedesktop.DBus.Error.UnknownObject":
			return nil
		}
	}
	return err
}
