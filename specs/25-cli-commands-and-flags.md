# 25. CLI: all commands and flags

> **What this chapter covers.** The complete command-line reference of
> the reference compiler: every top-level flag and every subcommand,
> grouped by function, with what each DOES, what it PRODUCES, and
> which phase / backend it belongs to. It is the CLI surface; the deep
> content of each flag lives in its owning chapter: the phases in
> [18-compiler-pipeline.md](18-compiler-pipeline.md), the backends in
> [21-python-backend.md](21-python-backend.md) and
> [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md),
> runtime attenuation (WASI) in
> [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md),
> and the supply-chain artefacts in
> [29-capability-manifest.md](29-capability-manifest.md) and
> [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). The flag and subcommand surface was captured from
`python -m capa --help` and `python -m capa <sub> --help` at that
commit on 2026-09-11, `python -m capa` importing the checkout under
specification. The CLI lives in the [`capa/cli/`](../capa/cli/__init__.py)
package: the flag definitions in
[`capa/cli/_parser.py`](../capa/cli/_parser.py) (`build_parser`, line
141), the per-invocation driver in
[`capa/cli/__init__.py`](../capa/cli/__init__.py) (`main` at line 58,
`_main_dispatch` at line 93), the subcommand handlers in
[`capa/cli/subcommands.py`](../capa/cli/subcommands.py).

Depends on: [18-compiler-pipeline.md](18-compiler-pipeline.md).

---

## 1. The invocation model

There are TWO ways to invoke the compiler:

- **Flag mode** (default): `python -m capa [flags] [file]`. A single
  `.capa` file (or `--stdin`) run through the pipeline, with the flags
  acting as stop points (which phase runs, what is printed). This is
  [18-compiler-pipeline.md](18-compiler-pipeline.md)'s mode.
- **Subcommand mode**: `python -m capa <command> [args]`, with
  `command` in `init add install search test build run-aot migrate
  lsp repl`. Each subcommand has its own parser and its own semantics
  (project, dependencies, tests, AOT, tools).

**Subcommand dispatch happens BEFORE the top-level argparse**
([`capa/cli/__init__.py`](../capa/cli/__init__.py) lines 159 to 180):
if `sys.argv[1]` is one of the ten command names, the CLI routes to
the dedicated handler and never builds the flag parser. This is why,
for example, `capa test` accepts `--wasm` as its OWN flag (test
backend) without colliding with the top-level `--wasm`.

**The `--` separator.** In flag mode with `--run`, everything after
`--` is forwarded to the transpiled program, visible via
`env.args()`, and not interpreted by the CLI. The boundary "what the
compiler owns" is one definition (`_compiler_owned_args`), shared
with the floor gate, precisely so a `--help` destined for the program
does not switch that gate off. `run-aot` does the same split.

**The project floor gate.** Before any phase, `_main_dispatch`
resolves the project root (ancestor walk, `find_package_root`) and
enforces the compiler floor declared in the root `capa.toml`
(`enforce_root_floor`); a second layer re-derives the root from the
FILE (`_enforce_floor_for_file_root`). The dependency model and the
floor are documented in [`docs/packages.md`](../docs/packages.md).

**Exit codes** (from the `main` docstring, and observed):

| Code | Meaning |
|---|---|
| `0` | success (or a CI gate that passed: clean product, pure narrowing) |
| `1` | a POLICY refusal over an otherwise valid program: analysis error, `--fmt-check` complaint, a CI-gate violation (`--check-capabilities` / `--check-policies` / `--fail-on-widening`), a runtime abort under `--run` |
| `2` | a CONFIGURATION / argument problem: unreadable file, non-UTF-8, broken root `capa.toml`, invalid argument (for example a negative `--foreign-fuel`) |

The 1-versus-2 distinction is deliberate: 2 is configuration, 1 is a
policy refusal over a build that was otherwise fine.

---

## 2. Processing flags (the phases)

These flags choose how far along the pipeline to run and what to
print. They are the CLI face of the phase chain of
[18-compiler-pipeline.md](18-compiler-pipeline.md) section 8.

| Flag | What it does / produces |
|---|---|
| `file` (positional) | the `.capa` to process; optional (`nargs="?"`), since `--stdin` and `--capability-diff` do without it |
| `--stdin` | read the source from stdin instead of a file; `filename` becomes `<stdin>` |
| `--parse` | run lexer + parser and print the AST, then stop |
| `--check` | run lexer + parser + analyzer and print the summary `ok (N items, M expressions typed, K bindings)`, then stop; an analysis error exits 1 |
| `--transpile` | transpile to Python and print the generated code (without running) |
| `--run` | transpile and EXECUTE (call `main` with the instantiated capabilities); arguments after `--` reach the program via `env.args()` |
| `--watch` | re-run the program whenever it (or an imported module) changes on disk; implies `--run`; requires a `file`; Ctrl-C exits |
| `--ir` | use the CIR pipeline (AST -> CIR -> Python) instead of the legacy transpiler; same observable output on the covered subset; falls back to legacy when lowering raises `UnsupportedInIR` |
| `--fmt` | rewrite the file in canonical style (indentation at multiples of 4, trailing whitespace removed, blank runs collapsed, final newline); with `--stdin`, prints to stdout |
| `--fmt-check` | check whether the file is already canonical; exit 0 if yes, 1 if not; does NOT rewrite |
| `--doc` | emit a self-contained HTML documentation page from doc comments (`///`, `/** */`), capability signatures and attributes |

The default path (no processing flag) prints the lexer's token
stream; `--no-layout` omits the layout tokens (section 6 of
[03-lexis-and-layout.md](03-lexis-and-layout.md)).

Measured at `8e2c609`:

```
$ python -m capa --check hello.capa
hello.capa: ok (1 items, 3 expressions typed, 1 bindings)
$ printf 'fun main(s: Stdio)\n    s.println("x")\n' | python -m capa --check --stdin
<stdin>: ok (1 items, 3 expressions typed, 1 bindings)
$ python -m capa --fmt-check hello.capa ; echo "exit=$?"
exit=0
```

`--fmt` / `--fmt-check` operate on the raw source, BEFORE lexing, so
they work even on a file with syntax errors.

---

## 3. Backends and WASM

These flags select the Wasm backend and its output form. The Wasm
backend exists ONLY on the CIR path and has no fallback. Detail in
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md).

| Flag | What it does / produces |
|---|---|
| `--wasm` | compile via CIR to WebAssembly text (WAT); with `--transpile` prints the WAT, with `--run` assembles the WAT to binary (via `wasm-tools`) and runs it on a wasmtime host providing the capability interfaces |
| `--wit` | emit the WIT spec of the program's capability imports; an inspection of the surface the Wasm backend would generate; produces no executable output |
| `--prefer-wasm` | with `--run`: try the Wasm backend first and fall back to the Python pipeline only when CIR / Wasm emission rejects a construct; honoured automatically when `CAPA_PREFER_WASM=1` is in the environment; requires wasmtime-py and `wasm-tools` on PATH |
| `--output`, `-o OUTPUT` | with `--wasm`, write the assembled binary to the given path instead of executing; with `--component`, writes the Component Model wrapper |
| `--component` | with `--wasm`, wrap the core module in a Component Model component via `wasm-tools component new`; requires `wasm-tools` on PATH; the file embeds the WIT spec |

Measured, the WIT of a `Stdio`-only program:

```
$ python -m capa --wit hello.capa
package capa:host;

interface stdio {
  println: func(msg: string);
}

world program {
  import stdio;
  export main: func();
}
```

---

## 4. WASI and runtime attenuation

These flags configure the Wasm backend's runtime enforcement layer.
The CLI surface is here; the full derivation (static ceilings,
preopen enforcement, the SSRF analysis, foreign limits) is
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)'s
subject and is not repeated.

| Flag | What it does / produces | Detail in 23 |
|---|---|---|
| `--wasi` | EXPERIMENTAL; with `--wasm --component`, migrates the supported touch-points of `Random`/`Clock`/`Env`/`Fs`/`Net`/`Stdio` to the canonical WASI Preview 2 interfaces instead of `capa:host`; the rest stays on `capa:host` (hybrid) | sections 1-2 |
| `--preopen <dir>[:ro\|:rw]` | with `--wasi`, grants filesystem authority over `<dir>` as an operator-declared preopen (Level 2), unblocking DYNAMIC `Fs` paths; default `rw`; a single `--preopen` | section 5 |
| `--allow-host <host>[:get\|:post]` | with `--wasi`, grants network authority to reach `<host>` as an operator grant; REPEATABLE; `<host>` is normalized; `:get`/`:post` scope the method | section 6 |
| `--wasi-surface` | prints the argv-to-sink surface the compiler PROVES (which `env.args()` arguments reach an `Fs`/`Net`/`Env` sink, read or write); read-only, neither compiles nor runs | section 8 |
| `--wasm-memory-cap <pages>` | with `--wasm`, caps the emitted linear memory at N 64 KiB pages; deterministic trap ceiling; default 256 pages (16 MiB); `0` skips the cap | section 9 |
| `--foreign-fuel <N>` | with `--wasm --run`, caps an untrusted foreign component's CPU (fuel) per call; default 1e9; `0` skips | section 9 |
| `--foreign-memory-cap <MiB>` | with `--wasm --run`, caps the untrusted foreign's memory growth; default 256 MiB; `0` skips | section 9 |
| `--foreign-result-cap <MiB>` | with `--wasm --run`, caps the HOST-side buffer of a mediated result; default 256 MiB; `0` skips | section 9 |

A NEGATIVE value on any `--foreign-*` flag is rejected up front with
exit 2, so a typo does not silently disable the DoS protection (the
opt-out is an explicit `0`). `--preopen` / `--allow-host` are
recorded in the SBOM as operator-declared grants, distinct from the
derived surface.

Measured, the argv-to-sink surface of a program routing `env.args()`
into `Fs.read`:

```
$ python -m capa --wasi-surface sink.capa
sink.capa: WASI path-arg surface (compiler-derived, by-construction):
  argv[*] -> Fs.read (read-only)
```

The runs that prove the enforcement (`--preopen` denying traversal,
`--allow-host` refusing an ungranted host, the internal-IP SSRF
warning, the memory cap changing the `(memory ...)` declaration) are
MEASURED in [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md);
the `--foreign-*` runtime enforcement was not exercised there either
(it is pinned by the `tests/test_foreign_*` suites).

---

## 5. Supply chain: manifest, SBOM, policies, attestations

These flags emit the supply-chain artefacts. The CLI surface is here;
the content is [29-capability-manifest.md](29-capability-manifest.md)
and [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md).

| Flag | What it produces | Owner |
|---|---|---|
| `--manifest` | the per-program capability manifest JSON: per function, declared capabilities, attributes, signature, plus the user capability declarations and their implementors | 29 |
| `--manifest-digest` | the CANONICAL content-addressable manifest: the same, serialized byte-stable key-sorted, wrapped in a `content_integrity` envelope with a sha256 digest and an empty signature slot (the compiler holds no keys) | 29 |
| `--compose-sbom` | the composed SBOM of the whole PRODUCT: attributes functions to their owning package, walks the dependency DAG, rolls the capability surface up; an unanalysable dependency composes as the authority-UNKNOWN element dominating the join; requires a root `capa.toml` | 29 |
| `--check-capabilities` | CI GATE: composes the SBOM and checks each package against its `capa.toml` `[capabilities]` ceiling; exits NON-ZERO on violation; UNKNOWN fails closed unless `allow_unknown = true` | 29 |
| `--conformance-report` | the signable conformance report of `capa-policy.toml`: evaluates each organization policy over the composed graph, wrapped in the same `content_integrity` envelope | 29 |
| `--check-policies` | CI GATE: same evaluation, exits NON-ZERO on failure | 29 |
| `--capability-diff <old.json> <new.json>` | a signable AUTHORITY CHANGELOG between two capability artefacts: which capabilities each exported function (and the product) GAINED (widening) or LOST (narrowing); functions matched by the stable `(container, name)` identity, never by position; takes NO `.capa` file | 29 |
| `--fail-on-widening` | CI GATE for `--capability-diff`: exits NON-ZERO on any widening or an authority-UNKNOWN transition; pure narrowing / no change exits 0 | 29 |
| `--cyclonedx` | a CycloneDX 1.6 SBOM with the manifest embedded as `properties[]`; `SOURCE_DATE_EPOCH` fixes the timestamp for byte reproducibility | 30 |
| `--spdx` | an SPDX 2.3 SBOM with the manifest embedded as `annotations[]` | 30 |
| `--vex` | a VEX-only CycloneDX document from `@vex(cve, status, justification, detail)` attributes; per-function granularity | [`docs/provenance-signing.md`](../docs/provenance-signing.md) |
| `--provenance` | an SLSA Build L1 provenance attestation: an in-toto Statement v1 with an SLSA Provenance v1.0 predicate, subject = the SHA-256 of the source `.capa` | [`docs/provenance-signing.md`](../docs/provenance-signing.md) |

`--capability-diff` takes no `.capa`: it is handled before the
file/lex/analyze flow and operates on two JSON files. Over two
IDENTICAL artefacts it produces a zero-change changelog and exits 0
(measured: `summary {widenings: 0, narrowings: 0,
authority_unknown_regression: false}`).

All these emitters share the canonical serialization and the
`content_integrity` envelope (the compiler never signs; it records
the digest for an external signer).

---

## 6. Other flags

| Flag | What it does |
|---|---|
| `--version` | prints `capa <version>` and stops |
| `--no-color` | disables ANSI colours in output (the caret diagnostics) |
| `--no-layout` | omits the layout tokens `NEWLINE`/`INDENT`/`DEDENT`/`EOF` in the token dump |

Measured: `python -m capa --version` prints `capa 1.32.0`. Colour is
only applied when `sys.stdout.isatty()` and `--no-color` is absent.

---

## 7. Subcommands

Each subcommand has its own `ArgumentParser` and is routed by
`_main_dispatch` before the top-level parser
([`capa/cli/__init__.py`](../capa/cli/__init__.py) lines 159 to 180;
handlers in [`capa/cli/subcommands.py`](../capa/cli/subcommands.py)).
`init add install search test build run-aot migrate` use argparse
(and answer `<sub> --help`); `lsp` and `repl` do NOT (section 7.9).
The usage blocks below were captured from `<sub> --help` at
`8e2c609`.

### 7.1 `init`

Scaffolds a minimal Capa project (`main.capa` + `README.md` +
`.gitignore` + `.capa-version`).

```
usage: capa init [-h] [name]
```

`name` defaults to the current directory, which must be empty.

### 7.2 `add`

Declares a dependency in `capa.toml` and (by default) installs it
into `vendor/`.

```
usage: capa add [-h] [--git URL] [--tag TAG | --rev SHA | --branch NAME]
                [--verify-key FINGERPRINT] [--dev] [--force] [--no-install]
                name
```

| Option | What it does |
|---|---|
| `name` (positional) | dependency name (used as `vendor/<name>`) |
| `--git URL` | git URL; omitting it resolves the name via the public registry index |
| `--tag TAG` / `--rev SHA` / `--branch NAME` | the pin (mutually exclusive) |
| `--verify-key FINGERPRINT` | 40-char GPG fingerprint the tag/commit must be signed by |
| `--dev` | declare under `[dev-dependencies]` (installed only when this project is the root) |
| `--force` | overwrite an existing `[dependencies.<name>]` block |
| `--no-install` | edit `capa.toml` only; do not fetch |

### 7.3 `install`

Resolves the `capa.toml` dependencies into `vendor/` and writes
`capa.lock`.

```
usage: capa install [-h] [--update] [directory]
```

`--update` accepts a fresh upstream commit when `capa.lock` pins a
different SHA for the same git URL + tag; the default refusal exists
so a force-pushed tag does not silently enter the build.

### 7.4 `search`

Searches the registry by name and description.

```
usage: capa search [-h] [query]
```

With no `query`, lists the whole registry; with no results, prints to
stderr and exits 1.

### 7.5 `test`

Runs the project's tests (`tests/test_*.capa` under the root, sorted
order), each as `capa --run`.

```
usage: capa test [-h] [--wasm | --both]
```

`--wasm` runs every test on the Wasm backend; `--both` runs every
test on BOTH backends and diffs their stdout (matching output and
exit 0 on both is required to pass; a DIVERGED test shows the unified
diff). The result contract: a test passes when the process exits 0;
`main`'s return value is ignored, so a Capa program exits 0 exactly
when `main` runs to the end and 1 when it aborts (a deliberate
`panic("...")`, or a runtime error escaping `main`). `--wasm` /
`--both` require the Wasm toolchain.

### 7.6 `build`

Ahead-of-time compiles a Capa program to a portable AOT artefact
(Cranelift-compiled, no recompile on run).

```
usage: capa build [-h] [--release] [-o OUTPUT] [--wasm-memory-cap <pages>]
                  file
```

Requires the Wasm toolchain. `build`'s `--wasm-memory-cap` is
validated against `1..65536`; `<= 0` opts out of the bound, above the
maximum is refused with exit 2.

### 7.7 `run-aot`

Runs an AOT artefact built by `capa build --release`.

```
usage: capa run-aot [-h] file
```

It splits on `--` like flag mode (post-separator arguments reach the
program via `env.args()`), and deserializes the `.cwasm` against the
host engine (wasmtime refuses cross-engine instantiation).

### 7.8 `migrate`

Reports Python-to-Capa gradual-hardening progress for a `.capa` file.

```
usage: capa migrate [-h] [--json] file
```

Lexes + links (multi-file) + analyzes; analysis errors exit 1. With
`--json` prints the report as JSON, else human-readable text.

### 7.9 `lsp` and `repl`

`lsp` and `repl` do NOT go through argparse. The dispatch calls
`serve()` / `repl_serve()` directly
([`capa/cli/__init__.py`](../capa/cli/__init__.py) lines 175 to 180):

- `lsp` -> `from capa.lsp_server import serve; return serve()` (the
  language server on stdin/stdout).
- `repl` -> `from capa.repl import serve as repl_serve; return
  repl_serve()` (the interactive REPL).

Because they build no parser, `capa lsp --help` and
`capa repl --help` do NOT print argparse-style help: the `--help` is
passed to the server / REPL itself.

## 8. Notes

- **Scope of the measurements.** The pasted outputs are from minimal
  programs (`hello.capa`, `sink.capa`) and two manifest JSONs, run at
  `8e2c609` from a scratch folder. The flag list of section 9 of the
  Portuguese set was re-captured from `--help` at this commit: no
  flag or subcommand was added, removed or renamed.
- **MEASURED versus JUDGEMENT.** MEASURED: the `--help` surfaces (top
  level and the eight argparse subcommands), and the outputs of
  `--version` / `--check` / `--stdin` / `--fmt-check` / `--wit` /
  `--wasi-surface` / `--capability-diff`. JUDGEMENT: the exit-code
  table reads the `main` docstring plus observed behaviour, not an
  exhaustive enumeration of every error path; flag combinations not
  documented in each flag's help follow the driver's stop order
  (first stop wins; for example `--manifest --transpile` stops at the
  manifest emitter), which is a reading of
  [`capa/cli/__init__.py`](../capa/cli/__init__.py), not a test of
  every flag pair.
- **NOT VERIFIED by execution here.** `--watch` (the re-run loop);
  the `--foreign-*` runtime enforcement (see
  [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md));
  `build` / `run-aot` / `add` / `install` / `search` network and
  disk behaviour (their `--help` surfaces were captured; the
  composition gates were exercised on a real product tree in
  [29-capability-manifest.md](29-capability-manifest.md)); `lsp` /
  `repl` (read from the dispatch code; not run interactively).

---

## Links

- [18-compiler-pipeline.md](18-compiler-pipeline.md): the phases the
  processing flags reveal.
- [21-python-backend.md](21-python-backend.md) and
  [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the two backends behind `--transpile` / `--run` / `--ir` /
  `--wasm` / `--wit` / `--component` / `--output`.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  the detail of `--wasi`, `--preopen`, `--allow-host`,
  `--wasi-surface`, `--wasm-memory-cap` and the `--foreign-*` flags.
- [29-capability-manifest.md](29-capability-manifest.md) and
  [30-sbom-cyclonedx-spdx.md](30-sbom-cyclonedx-spdx.md): the
  supply-chain artefacts of section 5.
- [`docs/packages.md`](../docs/packages.md): the dependency model and
  the floor behind `init` / `add` / `install` / `search`.
