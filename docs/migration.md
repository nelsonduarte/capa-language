# Migrating from Python to Capa, one function at a time

This document walks through moving an existing Python program into Capa
incrementally, narrowing the capability surface as you go. The result is
a Capa program with the same behaviour as the Python original but with a
per-function authority manifest that an SBOM consumer can audit.

The paired files in [`examples/`](../examples/) are the running example:

| File | Role |
|---|---|
| `migrate_logfetcher_naive.py` | Original Python (~35 lines, touches Fs + Env + Net). Unchanged across all three steps. |
| `migrate_logfetcher_step1_unsafe.capa` | One Capa entry point that delegates everything back to the Python file via `py_import` / `py_invoke`. |
| `migrate_logfetcher_step2_mixed.capa` | One function moved into typed Capa (`save_response`, `Fs`-only); the rest still delegates. |
| `migrate_logfetcher_step3_typed.capa` | Every function carries an explicit capability signature; `Unsafe` is gone. |

The Python file itself never changes. Only the `.capa` file changes.

## Why migrate at all

Capa programs declare their authority in function signatures: a function
that opens a network socket has `Net` as a parameter; a function that
reads a file has `Fs`; a function that does neither has neither. The
compiler emits a manifest that an SBOM consumer (CycloneDX, SPDX, VEX,
SLSA provenance) can read at per-function granularity.

The Python equivalent does not exist. `pip freeze` lists packages, not
functions; a static analyser is heuristic and the granularity is the
import boundary at best.

If you have a Python program whose authority surface you want to make
auditable, the cheapest path is to keep the Python file intact, build a
thin Capa shell around it that does nothing but delegate, and then move
the program into typed Capa function by function. At each step the
manifest gets more honest and the `Unsafe` capability shrinks.

## The pattern: three stages

### Stage 1: all `Unsafe`, behaviour preserved

Write a Capa file with one function that imports the original Python
module and calls its entry point. Everything happens via `py_import` and
`py_invoke`, which together require the `Unsafe` capability.

```capa
fun main(stdio: Stdio, u: Unsafe)
    bootstrap_path(u)
    let mod = py_import(u, "migrate_logfetcher_naive")
    stdio.println("step1: delegating to migrate_logfetcher_naive.main() via py_invoke")
    py_invoke(u, mod.main, [])
```

What `capa --manifest` says about this stage:

```
bootstrap_path -> [Unsafe]
main           -> [Stdio, Unsafe]
```

The `Unsafe` is the audit signal. An SBOM consumer reading this manifest
sees: *this program escapes Capa's analysis; I cannot make claims about
its true authority surface*. That is honest reporting of the
not-yet-migrated state, which is the point.

### Stage 2: move one function at a time

Pick the function whose Capa equivalent is simplest. The first easy win
is usually a function that needs only one built-in capability and does
not need to read structured data back from Python. In the running
example, `save_response(path, content)` is that function: it takes two
strings and writes one file, mapping cleanly to `Fs.write`.

```capa
fun save_response(fs: Fs, path: String, content: String) -> Result<Unit, IoError>
    return fs.write(path, content)
```

The rest of `main` still calls back into the Python module for the
fetch + parse + env-read work; only the actual file write is now in
typed Capa. The Python file is unchanged.

What the manifest now says:

```
bootstrap_path -> [Unsafe]
save_response  -> [Fs]                  <- new, typed, no Unsafe
main           -> [Stdio, Fs, Unsafe]    <- Fs is now visible
```

The win is `Fs` becoming explicit in `main`'s signature. The SBOM
consumer can now see that the file-write authority is exercised by a
typed function, not buried inside an `Unsafe` block.

### Stage 3: fully typed, `Unsafe` gone

Move every remaining function into typed Capa. By the time the last
`py_invoke` is gone, the Python file is unreferenced and can be deleted.

```capa
fun main(stdio: Stdio, fs: Fs, env: Env, net: Net)
    match load_config(fs, "config.json")
        ...
```

What the manifest says:

```
config_field   -> []                          pure
load_config    -> [Fs]
get_api_key    -> [Env]
build_url      -> []                          pure
fetch_status   -> [Net]
save_response  -> [Fs]
main           -> [Stdio, Fs, Env, Net]       no Unsafe
```

The supply-chain audit story is now load-bearing: the SBOM is a true
per-function authority bound, not a single `Unsafe` blob.

## Bridging tricks for the middle stage

The awkward part of the middle stage is moving values back and forth
across the Capa-Python boundary. A few patterns make this tractable.

### `py_invoke` returns `Unknown`, Capa accepts it anywhere

A `py_invoke` call returns `Unknown` at the type-system level. Capa lets
`Unknown` stand wherever a concrete type is expected, so you can pass
the result of `py_invoke` to a typed Capa function without an explicit
cast. This is how step 2 passes a Python-side response string into
`save_response`.

The trade-off is honest: passing `Unknown` everywhere is unsafe in the
type sense (no actual check happens until runtime). It works for the
middle stage but you should still aim to move every function into
typed Capa before declaring victory.

### Field access on Python dicts via `builtins.dict.get`

If a Python function returns a dict and you need a single field from
Capa, you can pull it via `py_invoke` against `builtins.dict.get`:

```capa
let py_builtins = py_import(u, "builtins")
let base = py_invoke(u, py_builtins.dict.get, [cfg, "base_url"])
```

This stays `Unknown` and works for the transitional stage. By step 3
you replace it with `JsonValue` field navigation
(`cfg.as_object()?.get("base_url")?.as_string()?`).

### Result and Option chaining in fully-typed Capa

Step 3's `config_field` shows the explicit-match style: pattern match
on `Option`, return `Err` with a descriptive message on `None`. The `?`
operator is also available for Result and Option chaining if you
prefer the terser form.

## When to stop

The migration is complete when:

- the Python file is not imported anywhere from your Capa code
- no function declares `Unsafe` (except the legitimate cases where you
  genuinely need to call out to a Python library Capa has no built-in
  for)
- every function's `declared_capabilities` in the manifest matches what
  the function actually needs, and nothing more

You can stop sooner if a function genuinely needs a Python library Capa
does not cover. Leave that function with `Unsafe`; the rest of the
program still benefits from typing. The `Unsafe` is then a precise
audit signal pointing at the one place that needs human review.

## Honest limits

- **Capa's built-in capability surface is narrow.** `Net.get`, `Fs.read`,
  `Fs.write`, `Env.get`, `Clock.now_secs`, `Random.float_unit`, plus a
  handful of methods on each. If your Python uses, say, `requests` with
  custom headers, gRPC, or sqlite3, you stay on the `Unsafe` side of
  the boundary for that function. The migration story bottoms out at
  what Capa's standard library covers.
- **Performance.** Capa transpiles to Python. Runtime overhead is
  1.00x to 1.45x against hand-Python on benchmarked workloads
  ([`benchmarks/`](../benchmarks/README.md)). Acceptable for most
  application code, but native-backend tracks (Cranelift, LLVM,
  Wasm-CM) are not yet here.
- **No incremental compilation.** Each `capa --run` re-lexes / re-parses
  / re-analyses / re-transpiles the whole program. For files in this
  size class it is invisible; for large projects it would matter.
- **The Python file is not safer because of the migration.** It is
  still Python; it still has ambient authority. The Capa side is the
  audit surface. Once the migration is complete, you delete the Python
  file.

## Reproduction

The three Capa files in this walkthrough all compile and emit honest
manifests:

```bash
# Each stage compiles
capa --check examples/migrate_logfetcher_step1_unsafe.capa
capa --check examples/migrate_logfetcher_step2_mixed.capa
capa --check examples/migrate_logfetcher_step3_typed.capa

# The manifest progression: Unsafe shrinks, real capabilities appear
capa --manifest examples/migrate_logfetcher_step1_unsafe.capa | jq '.functions[] | {name, declared_capabilities}'
capa --manifest examples/migrate_logfetcher_step2_mixed.capa | jq '.functions[] | {name, declared_capabilities}'
capa --manifest examples/migrate_logfetcher_step3_typed.capa | jq '.functions[] | {name, declared_capabilities}'
```

Running any of the three actually fetches data and writes a file, so you
need a `config.json` next to where you run it and a `LOGS_API_KEY` env
var set. The full setup is in
[`migrate_logfetcher_naive.py`](../examples/migrate_logfetcher_naive.py)'s
docstring.
