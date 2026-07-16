# Contributing

Thanks for helping improve `microagency`.

This repository owns the MCP gateway: tool indexing, credential custody and
OAuth flows, the off-context reduce engines, and the audit chain. It does not
own VM internals — kernels, rootfs conversion, VM lifecycle, and supervisors
belong in [microagent](https://github.com/geoffbelknap/microagent).

## Development setup

Install Go (the version `go.mod` requires or newer). Then:

```bash
make build
```

`make build` compiles the wasm engines and minimizers and bundles them into
the binary, so `microagency up` works with nothing else to install. `make
install` does the same via `go install`.

## Checks

Run what CI runs before opening a PR:

```bash
go build ./...
go vet ./...
go test -short ./cmd/... ./internal/...
```

Each `engines/*` directory is a standalone Go module; CI runs their unit
tests too:

```bash
for d in engines/*/; do (cd "$d" && go test ./...); done
```

`make test` runs `go test ./...` for the main module. CI also runs the race
detector (`go test -race -short`) on push to main.

## Pull requests

- Keep changes narrowly scoped.
- Open normal PRs, not drafts.
- Do not widen this project into VM internals; those changes go to
  microagent.

## Security

Do not open public issues for security-sensitive reports. Follow
[`SECURITY.md`](SECURITY.md).
