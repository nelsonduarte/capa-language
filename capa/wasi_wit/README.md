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
| `deps/cli/environment.wit` | `wasi:cli@0.2.0` | [`wasi-cli` v0.2.0](https://github.com/WebAssembly/wasi-cli/blob/v0.2.0/wit/environment.wit) |

## License and provenance

These WIT files are vendored, unmodified in substance, from the
official WebAssembly interface repositories at tag `v0.2.0`:

- `deps/random/random.wit` from
  [`WebAssembly/wasi-random` v0.2.0](https://github.com/WebAssembly/wasi-random/blob/v0.2.0/wit/random.wit)
- `deps/clocks/clocks.wit` from
  [`WebAssembly/wasi-clocks` v0.2.0](https://github.com/WebAssembly/wasi-clocks/blob/v0.2.0/wit)
- `deps/cli/environment.wit` from
  [`WebAssembly/wasi-cli` v0.2.0](https://github.com/WebAssembly/wasi-cli/blob/v0.2.0/wit/environment.wit)

All three upstream repositories license their WIT under
**Apache-2.0 WITH LLVM-exception**. Each vendored `.wit` carries an
`SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception` header plus a
provenance line at the top of the file.

The Capa project itself is dual-licensed **MIT OR Apache-2.0**
(see `LICENSE-MIT` and `LICENSE-APACHE` at the repository root).
The vendored files are therefore compatible with Capa through the
Apache-2.0 arm of that dual license.

The definitions are trimmed to the functions Capa imports
(`get-random-u64`, `monotonic-clock.now`, `wall-clock.now`,
`environment.get-environment`, `environment.get-arguments`). The
`subscribe-*` functions of the upstream clocks interface (which pull
in `wasi:io/poll`) and the `initial-cwd` function of the upstream cli
environment interface are intentionally omitted because Capa only
reads the clocks and the env-set / argv; this keeps the dependency
surface to what `wasmtime`'s `Linker.add_wasip2()` host provides.

## How it is consumed

`capa.cli._wrap_as_component`, in `--wasi` mode, writes the generated
program world to a temp dir and copies these files into the temp dir's
`deps/`, so `wasm-tools component embed` resolves the
`wasi:random` / `wasi:clocks` / `wasi:cli` package references. A
program imports only the packages it actually uses; the unused deps
present in the temp dir are ignored by the embed.

## Updating

These track WASI Preview 2 `0.2.0`. If the WASI release that
`wasmtime`'s `add_wasip2()` implements moves to a new minor, bump the
package versions here and the versioned import strings the Wasm
emitter writes (`wasi:random/random@0.2.0`,
`wasi:clocks/monotonic-clock@0.2.0`, `wasi:clocks/wall-clock@0.2.0`,
`wasi:cli/environment@0.2.0`).
