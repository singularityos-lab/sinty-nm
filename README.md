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

## Use of Generative AI

Maintainers may use generative AI tools as assistants while working on sinty-nm. Non-trivial assisted commits disclose the tool, model, and scope of the work.

AI tools may assist with code comments, documentation, repetitive code, and issue triage. Maintainers make project decisions and review every assisted change before it is merged.

Use these trailers for non-trivial assisted commits:

```plain
Assisted-by: <tool>:<model-version>
AI-Scope: <what the tool generated and the prompt or a short prompt summary>
```

Single-line completions, renames, and formatting changes do not need trailers.

Coding agents must also follow [AGENTS.md](AGENTS.md) before changing files,
creating commits, or opening pull requests.
