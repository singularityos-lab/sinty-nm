# sinty-nm

A network manager for Sinty OS that speaks the NetworkManager D-Bus API. It owns
`org.freedesktop.NetworkManager` on the system bus and serves the same object tree, so
`nmcli`, applets, portals, and any libnm-based tool keep working against it unchanged.
Wi-Fi runs through iwd, L2/L3 through rtnetlink, IPv4 through a built-in DHCP client, and
VPN through WireGuard.

It drives iwd directly instead of shipping NetworkManager with its experimental iwd
backend, while staying wire-compatible with the NM ecosystem.

Packaging notes are in `packaging/`.

## Build

    go build ./cmd/sinty-nmd

Static binary for the image:

    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sinty-nmd ./cmd/sinty-nmd
