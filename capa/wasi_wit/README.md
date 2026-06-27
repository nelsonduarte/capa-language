# Vendored WASI Preview 2 WIT (experimental `--wasi` mode)

This directory holds a minimal, vendored subset of the canonical
WASI Preview 2 (`0.2.0`) WIT interface definitions that Capa's
experimental `--wasi` component mode imports.

It is used only by `capa --wasm --component --wasi`. The default
`capa:host` path does not touch these files.

## Contents

| File | Upstream package | Source |
| --- | --- | --- |
| `deps/random/random.wit` | `wasi:random@0.2.0` | [`wasi-random` v0.2.0](https://github.com/WebAssembly/wasi-random/blob/v0.2.0/wit/random.wit) |
| `deps/clocks/clocks.wit` | `wasi:clocks@0.2.0` | [`wasi-clocks` v0.2.0](https://github.com/WebAssembly/wasi-clocks/blob/v0.2.0/wit) |

The definitions are trimmed to the functions Capa imports
(`get-random-u64`, `monotonic-clock.now`, `wall-clock.now`). The
`subscribe-*` functions of the upstream clocks interface (which pull
in `wasi:io/poll`) are intentionally omitted because Capa only reads
the clocks; this keeps the dependency surface to what `wasmtime`'s
`Linker.add_wasip2()` host provides.

## How it is consumed

`capa.cli._wrap_as_component`, in `--wasi` mode, writes the generated
program world to a temp dir and copies these files into the temp dir's
`deps/`, so `wasm-tools component embed` resolves the
`wasi:random` / `wasi:clocks` package references.

## Updating

These track WASI Preview 2 `0.2.0`. If the WASI release that
`wasmtime`'s `add_wasip2()` implements moves to a new minor, bump the
package versions here and the versioned import strings the Wasm
emitter writes (`wasi:random/random@0.2.0`,
`wasi:clocks/monotonic-clock@0.2.0`, `wasi:clocks/wall-clock@0.2.0`).
