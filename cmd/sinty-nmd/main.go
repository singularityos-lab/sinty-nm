package main

import (
	"context"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/godbus/dbus/v5"

	"github.com/singularityos-lab/sinty-nm/internal/backend/dhcp"
	"github.com/singularityos-lab/sinty-nm/internal/backend/iwd"
	"github.com/singularityos-lab/sinty-nm/internal/backend/rtnl"
	"github.com/singularityos-lab/sinty-nm/internal/backend/sys"
	"github.com/singularityos-lab/sinty-nm/internal/backend/wg"
	"github.com/singularityos-lab/sinty-nm/internal/nmapi"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("sinty-nmd: ")

	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		log.Fatalf("system bus: %v", err)
	}
	defer conn.Close()

	// Claim the NetworkManager name. On Sinty, NM is absent, so this succeeds and the
	// whole userland (desktop, nmcli) transparently talks to us. On a host where NM is
	// already running, we refuse rather than fight for the name.
	reply, err := conn.RequestName(nmapi.BusName, dbus.NameFlagDoNotQueue)
	if err != nil {
		log.Fatalf("request name %s: %v", nmapi.BusName, err)
	}
	if reply != dbus.RequestNameReplyPrimaryOwner {
		log.Fatalf("%s already owned (real NetworkManager running?) - not starting", nmapi.BusName)
	}

	link, err := rtnl.New()
	if err != nil {
		log.Fatalf("rtnl backend: %v", err)
	}
	wifi, err := iwd.New(conn)
	if err != nil {
		log.Fatalf("iwd backend: %v", err)
	}
	wgb, err := wg.New()
	if err != nil {
		log.Fatalf("wireguard backend: %v", err)
	}
	rfk, err := sys.NewRFKill()
	if err != nil {
		log.Fatalf("rfkill backend: %v", err)
	}

	backends := nmapi.Backends{
		Link:   link,
		Wifi:   wifi,
		DHCP:   dhcp.New(),
		WG:     wgb,
		DNS:    sys.NewDNS(),
		RFKill: rfk,
		Conn:   sys.NewConnChecker(""),
	}

	mgr, err := nmapi.New(conn, backends)
	if err != nil {
		log.Fatalf("nmapi: %v", err)
	}
	if err := mgr.Export(); err != nil {
		log.Fatalf("export: %v", err)
	}
	log.Printf("owning %s; serving NetworkManager API", nmapi.BusName)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := mgr.Run(ctx); err != nil && ctx.Err() == nil {
		log.Fatalf("run: %v", err)
	}
	_ = os.Stdin
}
