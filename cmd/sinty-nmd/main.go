package main

import (
	"log"
	"os"

	"github.com/godbus/dbus/v5"
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

	srv, err := nmapi.New(conn)
	if err != nil {
		log.Fatalf("nmapi: %v", err)
	}
	if err := srv.Export(); err != nil {
		log.Fatalf("export: %v", err)
	}
	log.Printf("owning %s; serving NetworkManager API", nmapi.BusName)

	// Block forever; device/backend goroutines run under srv.
	select {}
	_ = os.Stdin
}
