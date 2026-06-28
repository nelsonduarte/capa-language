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
| `deps/filesystem/filesystem.wit` | `wasi:filesystem@0.2.0` | [`wasi-filesystem` v0.2.0](https://github.com/WebAssembly/wasi-filesystem/blob/v0.2.0/wit) |
| `deps/io/io.wit` | `wasi:io@0.2.0` | [`wasi-io` v0.2.0](https://github.com/WebAssembly/wasi-io/blob/v0.2.0/wit) |
| `deps/http/http.wit` | `wasi:http@0.2.0` | [`wasi-http` v0.2.0](https://github.com/WebAssembly/wasi-http/blob/v0.2.0/wit) |

## License and provenance

These WIT files are vendored, unmodified in substance, from the
official WebAssembly interface repositories at tag `v0.2.0`:

- `deps/random/random.wit` from
  [`WebAssembly/wasi-random` v0.2.0](https://github.com/WebAssembly/wasi-random/blob/v0.2.0/wit/random.wit)
- `deps/clocks/clocks.wit` from
  [`WebAssembly/wasi-clocks` v0.2.0](https://github.com/WebAssembly/wasi-clocks/blob/v0.2.0/wit)
- `deps/cli/environment.wit` from
  [`WebAssembly/wasi-cli` v0.2.0](https://github.com/WebAssembly/wasi-cli/blob/v0.2.0/wit/environment.wit)
- `deps/filesystem/filesystem.wit` from
  [`WebAssembly/wasi-filesystem` v0.2.0](https://github.com/WebAssembly/wasi-filesystem/blob/v0.2.0/wit)
- `deps/io/io.wit` from
  [`WebAssembly/wasi-io` v0.2.0](https://github.com/WebAssembly/wasi-io/blob/v0.2.0/wit)
- `deps/http/http.wit` from
  [`WebAssembly/wasi-http` v0.2.0](https://github.com/WebAssembly/wasi-http/blob/v0.2.0/wit)
  (`wit/types.wit` + `wit/handler.wit`)

All six upstream repositories license their WIT under
**Apache-2.0 WITH LLVM-exception**. Each vendored `.wit` carries an
`SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception` header plus a
provenance line at the top of the file.

The Capa project itself is dual-licensed **MIT OR Apache-2.0**
(see `LICENSE-MIT` and `LICENSE-APACHE` at the repository root).
The vendored files are therefore compatible with Capa through the
Apache-2.0 arm of that dual license.

The definitions are trimmed to the functions Capa imports
(`get-random-u64`, `monotonic-clock.now`, `wall-clock.now`,
`environment.get-environment`, `environment.get-arguments`,
`preopens.get-directories`, `descriptor.stat-at`,
`descriptor.create-directory-at`). The `subscribe-*` functions of the
upstream clocks interface (which pull in `wasi:io/poll`) and the
`initial-cwd` function of the upstream cli environment interface are
intentionally omitted because Capa only reads the clocks and the
env-set / argv; this keeps the dependency surface to what `wasmtime`'s
`Linker.add_wasip2()` host provides.

The `wasi:filesystem` migration now covers every Fs op: METADATA
(`exists` / `is_dir` via `descriptor.stat-at`, `mkdir` via
`descriptor.create-directory-at`, plus `preopens.get-directories`) AND
the stream-bearing `read` / `write` / `list_dir`
(`descriptor.open-at` + `wasi:io/streams` for read / write,
`descriptor.read-directory` enumeration for list_dir). The `wasi:io`
`input-stream` / `output-stream` / `error` / `pollable` resources are
therefore CALLED, not merely structural.

`wasi:http` (`deps/http/http.wit`) backs `Net.get` (Phase 1): the
outbound GET chain uses `wasi:http/outgoing-handler.handle` plus the
`wasi:http/types` resource chain (`outgoing-request` /
`future-incoming-response` / `incoming-response` / `incoming-body`),
reads the body via `wasi:io/streams.input-stream.blocking-read`, and
blocks synchronously via `wasi:io/poll.pollable.block`. The vendored
`http.wit` is the upstream `types.wit` + `handler.wit` unmodified in
substance; it `use`s `wasi:clocks` / `wasi:io` types, which are already
vendored next to it, so the package type-checks at embed time.
`wasmtime`'s `add_wasi_http()` (reached via the C-ABI, since the
high-level component API does not expose it) provides the full
interface at instantiation; the host links wasi:http ONLY when the
program uses `Net.get`.

## How it is consumed

`capa.cli._wrap_as_component`, in `--wasi` mode, writes the generated
program world to a temp dir and copies these files into the temp dir's
`deps/`, so `wasm-tools component embed` resolves the
`wasi:random` / `wasi:clocks` / `wasi:cli` / `wasi:filesystem` /
`wasi:io` / `wasi:http` package references. A program imports only the
packages it actually uses; the unused deps present in the temp dir are
ignored by the embed.

## Updating

These track WASI Preview 2 `0.2.0`. If the WASI release that
`wasmtime`'s `add_wasip2()` implements moves to a new minor, bump the
package versions here and the versioned import strings the Wasm
emitter writes (`wasi:random/random@0.2.0`,
`wasi:clocks/monotonic-clock@0.2.0`, `wasi:clocks/wall-clock@0.2.0`,
`wasi:cli/environment@0.2.0`, `wasi:filesystem/types@0.2.0`,
`wasi:io/streams@0.2.0`, `wasi:http/types@0.2.0`,
`wasi:http/outgoing-handler@0.2.0`).
