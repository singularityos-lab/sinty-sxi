# Contributing to sinty-sxi

Thanks for your interest in contributing!

## Quick Start

```bash
git clone https://github.com/singularityos-lab/sinty-sxi
cd sinty-sxi
go build ./...
go test ./...
```

## Guidelines

- Keep changes additive and tested. sinty-sxi decides which applications a
  system trusts; prefer small, verifiable commits over large rewrites.
- The wire decoder must keep accepting and rejecting exactly what the SXI v1
  corpus in `wire/testdata/v1` says. A change that moves a fixture result is a
  format change, not a fix.
- Match the surrounding style.
- By submitting a contribution you agree to the [CLA](CLA.md).

## License

BSD-2-Clause.
