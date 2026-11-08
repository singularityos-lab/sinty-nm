package main

import (
	"context"
	"log"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/backend/sys"
)

const (
	powerName  = "dev.sinty.Power1"
	powerPath  = dbus.ObjectPath("/dev/sinty/Power1")
	powerIface = "dev.sinty.Power1"
)

func wirelessSave(v dbus.Variant) (bool, bool) {
	radio, ok := v.Value().(map[string]bool)
	if !ok {
		return false, false
	}
	save, ok := radio["wireless-save"]
	return save, ok
}

func followRadio(ctx context.Context, conn *dbus.Conn) {
	ch := make(chan *dbus.Signal, 8)
	if err := conn.AddMatchSignal(
		dbus.WithMatchObjectPath(powerPath),
		dbus.WithMatchInterface("org.freedesktop.DBus.Properties"),
		dbus.WithMatchMember("PropertiesChanged"),
		dbus.WithMatchArg(0, powerIface),
	); err != nil {
		log.Printf("radio policy unavailable: %v", err)
		return
	}
	_ = conn.AddMatchSignal(
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, powerName),
	)
	conn.Signal(ch)
	defer conn.RemoveSignal(ch)

	applied, known := false, false
	apply := func(save bool) {
		if known && save == applied {
			return
		}
		if err := sys.SetWifiPowerSave(save); err != nil {
			log.Printf("wifi power save %v: %v", save, err)
			return
		}
		applied, known = save, true
		log.Printf("wifi power save %v", save)
	}
	read := func() {
		if v, err := conn.Object(powerName, powerPath).GetProperty(powerIface + ".Radio"); err == nil {
			if save, ok := wirelessSave(v); ok {
				apply(save)
			}
		}
	}
	read()
	for {
		select {
		case <-ctx.Done():
			return
		case sig, ok := <-ch:
			if !ok {
				return
			}
			if sig.Name == "org.freedesktop.DBus.NameOwnerChanged" {
				if len(sig.Body) == 3 && sig.Body[0] == powerName && sig.Body[2] != "" {
					read()
				}
				continue
			}
			if sig.Path != powerPath || len(sig.Body) < 2 {
				continue
			}
			changed, ok := sig.Body[1].(map[string]dbus.Variant)
			if !ok {
				continue
			}
			if v, ok := changed["Radio"]; ok {
				if save, ok := wirelessSave(v); ok {
					apply(save)
				}
			}
		}
	}
}
