# Contributing to sinty-nm

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-nm
cd sinty-nm
go build ./...
go test ./...
```

## Guidelines

- Keep changes additive and tested. sinty-nm owns the network stack, so a regression can drop connectivity;
  prefer small, verifiable commits over large rewrites.
- Match the surrounding style. Comments explain WHY, not WHAT.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

GPL-3.0-only.
