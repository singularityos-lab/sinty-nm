# Packaging sinty-nm on Sinty

sinty-nm owns the same bus name as NetworkManager, so nothing downstream changes.
Packaging just installs the daemon and makes sure the real NM is not also trying to own
`org.freedesktop.NetworkManager`.

## Files

- Binary: build static, install as `/usr/bin/sinty-nmd`.

      CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o sinty-nmd ./cmd/sinty-nmd

- D-Bus policy: `org.freedesktop.NetworkManager.conf` to `/usr/share/dbus-1/system.d/`
  (replaces NetworkManager's; without it the bus refuses the name).
- Unit: `sinty-nm.service` to `/usr/lib/systemd/system/`.

## Enable under sinit

sinit resolves enablement from `multi-user.target.wants`, so symlink there:

    ln -sf /usr/lib/systemd/system/sinty-nm.service \
       /usr/lib/systemd/system/multi-user.target.wants/sinty-nm.service

The unit is deliberately minimal (`Type=dbus`, no systemd sandboxing directives, which
break under sinit).

## Notes

- Do not ship NetworkManager alongside: two daemons cannot own the name. Drop the NM
  package (or remove its unit from every `*.target.wants`). iwd stays, it is the Wi-Fi
  backend driven over `net.connman.iwd`.
- sinty-nm writes `/etc/resolv.conf` directly, so it must be writable (a real file or a
  symlink onto a writable tmpfs), not a read-only rootfs path.
