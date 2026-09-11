# 22. Backend: Wasm Component Model

> **What this chapter covers.** Capa's second backend: how a Capa
> program becomes a WebAssembly module (WAT, then binary) and,
> optionally, a Component Model component, and how the runtime host
> loads and executes it. It describes the emitter
> (`capa/ir/_emit_wasm/`), WIT generation (`capa/ir/_emit_wit.py`,
> `capa/wasi_wit/`), the encoding of values / strings / structs /
> closures in linear memory, the `capa-manifest` custom section that
> travels inside the artefact, and the two hosts
> (`capa/runtime/_wasm_host.py` for the core module,
> `capa/runtime/_wasm_component_host.py` for the component). Unlike
> the Python backend ([21-python-backend.md](21-python-backend.md)),
> this backend departs ONLY from the IR (there is no legacy path) and
> has no fallback. Runtime attenuation over WASI imports (preopens,
> `--allow-host`, ceilings) is
> [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)'s
> subject; the backend-parity promise is
> [24-backend-parity.md](24-backend-parity.md)'s.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification. External toolchain used in the measurements:
`wasm-tools 1.249.0` (on `PATH`) and `wasmtime` (wasmtime-py) 46.0.1
(importable); both are requirements of the Wasm backend.

Depends on: [18-compiler-pipeline.md](18-compiler-pipeline.md),
[21-python-backend.md](21-python-backend.md).

---

## 1. What the Wasm backend is

The Wasm backend turns the IR (CIR) into a WebAssembly module. The
product has two forms, chosen by flag:

- **Core module** (`--wasm`, without `--component`). A classic Wasm
  module whose effects enter through host function imports
  (`capa:host/<cap>`). It is loaded by the `WasmHost`
  ([`capa/runtime/_wasm_host.py`](../capa/runtime/_wasm_host.py)),
  which speaks the core import protocol (raw pointers and canonical
  ABI return areas).
- **Component Model component** (`--wasm --component`). The core
  module is wrapped in a component that declares the capability
  interfaces as typed WIT imports. It is loaded by the
  `WasmComponentHost`
  ([`capa/runtime/_wasm_component_host.py`](../capa/runtime/_wasm_component_host.py)),
  which speaks the high-level Component Model protocol (lifted WIT
  values: strings, lists, records).

The trust-model difference against the Python backend (section 1 of
[21-python-backend.md](21-python-backend.md)): here the guest runs in
a Wasm sandbox and **only reaches an effect if the host gives it the
corresponding import**. Confinement does not depend on the integrity
of a shared interpreter; it depends on the import set the host
satisfies. The central point: capability methods are per-name imports
mirroring the WIT interface, and a capability "value" that is not
handle-bearing carries no runtime information at all (section 8).

This backend exists ONLY on the CIR path and **has no fallback**: an
IR coverage gap fails loudly instead of silently changing shape
([`capa/cli/_execute.py`](../capa/cli/_execute.py); see
[18-compiler-pipeline.md](18-compiler-pipeline.md) section 6).

The minimal program (`hello.capa`):

```capa
fun double(n: Int) -> Int
    return n * 2

fun main(stdio: Stdio)
    stdio.println("double(21) = ${double(21)}")
```

runs on both backends with identical output:

```
$ python -m capa --run hello.capa
double(21) = 42
$ python -m capa --run --wasm hello.capa
double(21) = 42
```

## 2. How the CLI drives Wasm emission

Source: [`capa/cli/_execute.py`](../capa/cli/_execute.py)
(`run_execute` at line 35). The flags that drive this backend:
`--wasm --wit --prefer-wasm --component --output`. The pipeline is
AST -> CIR -> WAT -> binary -> (wasmtime | file | component), and its
failures are loud, with no fallback to Python.

The end-to-end convenience functions live in
[`capa/ir/__init__.py`](../capa/ir/__init__.py):

- `compile_wat` (line 206): AST -> CIR -> WAT (text). It lowers,
  injects the built-in JSON parser when the program touches
  `parse_json`/`to_json`, monomorphises the generics (the Wasm backend
  cannot encode type variables), normalizes `Char` to `String`, and
  calls `emit_wat`. It also builds the manifest JSON (section 10) from
  the ORIGINAL AST.
- `compile_wasm` (line 403): AST -> CIR -> WAT -> binary. It calls
  `compile_wat` and runs `wasm-tools parse` to assemble the WAT into
  `.wasm` bytes. An assembly error raises a `RuntimeError` carrying
  `wasm-tools`' stderr and the WAT it refused.
- `compile_wit` (line 379): AST -> CIR -> WIT (section 9).

The artefact per flag:

- `--wasm --transpile` prints the WAT.
- `--wasm --output <f>` writes the binary; with `--component`, it
  wraps first via `_wrap_as_component`
  ([`capa/cli/_execute.py`](../capa/cli/_execute.py) line 624).
- `--wasm --run` assembles and executes; `--component --run` wraps and
  dispatches to the component host.
- `--wit` prints the WIT document and stops; it does not run the Wasm
  emitter.

The component wrap (`_wrap_as_component`) is the canonical two-step
`wasm-tools` flow: `wasm-tools component embed --world program <wit>
<core>` stamps the WIT world into the core module as a custom section,
then `wasm-tools component new` promotes that module to a component.
Both require `wasm-tools` on `PATH`.

`--prefer-wasm` ([`capa/cli/_execute.py`](../capa/cli/_execute.py)
line 133) is distinct: it asks a normal `--run` (without `--wasm`) to
use the Wasm pipeline when the toolchain is available (wasmtime
importable and `wasm-tools` on `PATH`); an assembly failure falls back
to the Python backend, but only BEFORE execution starts (once
execution has begun, failures are loud, so that something that should
fail closed is never re-executed with full authority). Which
capabilities exist on which backend is
[24-backend-parity.md](24-backend-parity.md)'s subject.

## 3. The emitter: `capa/ir/_emit_wasm/`

The package has **26 `.py` files** (`__init__.py` plus 25 emitter
modules) and a `_wasi/` subpackage of **6 `.py` files**. The 25
emitter modules: `_caps _closures _discovery _dispatch _encoding
_equality _foreign _grisu _json _layout _lists _locals _maps _match
_net _option _random _runtime _set_algebra _sets _strings _structs
_traits _tuples _values`; the `_wasi/` subpackage: `__init__
_constants _core _env _fs _net`.

The central design point: the emitter is the `WasmEmitter` class
([`capa/ir/_emit_wasm/__init__.py`](../capa/ir/_emit_wasm/__init__.py)
line 178), composed of **one mixin per concern**. The class's base
list is the backend's map (lines 178 to 203):

| Mixin | File | What it emits |
|---|---|---|
| `_RuntimeHelpersMixin` | `_runtime.py` | shared helpers (`$alloc`, `$itoa`, safe arithmetic) |
| `_GrisuEmissionMixin` | `_grisu.py` | Grisu2 / Dragon4 float-to-string |
| `_MatchEmissionMixin` | `_match.py` | `match`, variant tags, payload unwrap |
| `_StringEmissionMixin` | `_strings.py` | literals, concatenation, comparison, interning |
| `_MapEmissionMixin` / `_ListEmissionMixin` / `_SetEmissionMixin` / `_SetAlgebraMixin` | `_maps.py` `_lists.py` `_sets.py` `_set_algebra.py` | collections and their operations |
| `_ClosureEmissionMixin` | `_closures.py` | closures + HOFs (section 7) |
| `_CapDispatchMixin` | `_caps.py` | capability method calls (section 8) |
| `_JsonEmissionMixin` / `_OptionEmissionMixin` / `_TupleEmissionMixin` | `_json.py` `_option.py` `_tuples.py` | JsonValue, Option/Result, tuples |
| `_TraitEmissionMixin` | `_traits.py` | trait dispatch (type-id header + `call $<mangled>`) |
| `_EncodingMixin` | `_encoding.py` | pack/unpack of values in the i64 slot (section 5) |
| `_InstrDispatchMixin` | `_dispatch.py` | IR instruction dispatch to the right emitter |
| `_ForeignCallEmissionMixin` | `_foreign.py` | `capa:foreign/<comp>` imports (sandboxed FFI) |
| `_StructEmissionMixin` | `_structs.py` | `MakeStruct`, `FieldAccess` (section 6) |
| `_ValueEmissionMixin` | `_values.py` | pushing an IR `Value` onto the stack |
| `_LocalsCollectionMixin` | `_locals.py` | collecting each function's `(local ...)` |
| `_DiscoveryMixin` | `_discovery.py` | first pass: used caps, strings, rejections |
| `_EqualityMixin` | `_equality.py` | structural equality |
| `_RandomEmissionMixin` | `_random.py` | guest-side Random |
| `_WasiEmissionMixin` | `_wasi/` | WASI Preview 2 imports (opt-in `--wasi`, section 9) |

The dependency-free foundation is `_layout.py`: it owns the
size/alignment conventions of every value in linear memory and the
helpers that translate a Capa type string into a byte size or a
load/store opcode; every other submodule imports it freely.

The emission entry is `WasmEmitter.emit(module)` (line 418). The
sequence: pre-register `Option`/`Result`/`JsonValue`; compute struct
and sum layouts (`compute_struct_layout`, `compute_sum_layout` in
`_layout.py`); the first discovery pass (`_discover`,
`_discover_lambdas`, `_discover_foreign_calls`) collecting the used
capabilities and the strings; write the `(module` header with imports
and memory; emit each function; and append the manifest custom
section.

## 4. The frame of the emitted WAT module

Every module has the same frame. For `hello.capa` of section 1
(`python -m capa --wasm --transpile hello.capa`, trimmed):

```
(module
  (import "capa:host/stdio" "println" (func $Stdio_println (param i32) (param i32)))
  (memory (export "memory") 1 256)
  (data (i32.const 0) "true")
  (data (i32.const 5) "false")
  (data (i32.const 11) "double(21) = ")
  (global $heap_top (mut i32) (i32.const 32))
  (func $alloc (export "alloc") (param $size i32) (result i32)
    ...)
  (func $itoa (param $n i64) (result i32 i32) ...)
  (func $double (export "double") (param $n i64) (result i64)
    ...)
  (func $main (export "main")
    ...
    call $Stdio_println)
  (global $__capa_main_cap_types i32 (i32.const 0))
  (export "capa:main-cap-types=" (global $__capa_main_cap_types))
  (@custom "capa-manifest" "{\22capa_manifest_version\22:1,...}")
)
```

The pieces, in order:

1. **Capability imports.** One import per discovered (capability,
   method) pair, named `capa:host/<cap>` (lowercase WIT interface)
   with the method in kebab-case (`now_secs` -> `now-secs`) so that
   `wasm-tools component embed` can link the core module to the WIT.
   The local binding `$<Cap>_<method>` stays snake_case (internal).
   `panic` is a separate import (`capa:host/panic`), outside the
   capability system.
2. **Memory and data segment.** `(memory (export "memory") <initial>
   <cap>)`. The `initial` pages cover the whole static data segment;
   `<cap>` is the page ceiling (default `MEMORY_CAP_DEFAULT_PAGES` =
   256 pages = 16 MiB; override with `--wasm-memory-cap`). Each
   interned string literal is a `(data (i32.const <offset>)
   "<escaped>")`.
3. **The heap and the helpers.** `(global $heap_top ...)` marks the
   heap start, 8-aligned right after the data segment. `$alloc` is a
   bump allocator: align, advance `$heap_top`, `memory.grow` with
   `unreachable` on failure. It is only emitted when the program needs
   a heap (structs, sums, collections, ...).
4. **The functions.** Each top-level Capa function becomes a
   `(func $<name> (export "<name>") ...)`. Impl methods become
   top-level functions with the mangled name `<TypeName>_<method>`.
5. **`main`'s cap binding.** `_emit_main_cap_binding` records, as an
   export name (`capa:main-cap-types=...`), WHICH capability type each
   handle slot of `main` is entitled to. It is an export (module
   structure), not the debug `name` section, precisely to survive a
   `wasm-tools strip --all` (section 11).
6. **The manifest custom section** (section 10).

The concatenation of `"double(21) = "` with the integer happens in
memory: `$double` returns i64, `$itoa` converts it to an (ptr, len)
pair, an `$alloc` reserves the total buffer and two `memory.copy`
paste the static prefix and the digits before `call $Stdio_println`
receives the final (ptr, len) (visible in the full WAT body of
`$main`).

## 5. Value encoding

The base type mapping (`_emit_wasm/__init__.py` docstring and
`_layout.py`):

| Capa type | Wasm representation |
|---|---|
| `Int` | `i64` (signed 64-bit) |
| `Bool` | `i32` (0 or 1; Wasm has no native bool) |
| `Float` | `f64` |
| `Unit` | no result (the function omits the `(result ...)` clause) |
| `String` | (ptr i32, len i32) pair; 8 bytes in memory |
| `Char` | normalized to `String` before emission (`compile_wat`, section 2) |
| Struct / Sum / List / Map / Set / tuple / trait | i32 pointer to a heap record |

A **string** is a (ptr, len) pair. A literal is interned in the data
segment (`_intern_string`), which returns `(offset,
length_in_bytes)`; the same string dedups to the same offset. After
the data segment is written, the high-water mark freezes
(`_strings_frozen`), and a genuinely new string seen after that is
refused loudly instead of receiving an offset with no backing
`(data ...)` (defence in depth). This is why `emit()` pre-interns
(`"true"`/`"false"`, the `IoError` `": "` separator, the special Float
literals, String consts, the fixed `unwrap` messages) BEFORE emitting
the bodies.

When a value must fit a **uniform i64 payload slot** (a variant's data
slot, a Map value, a List element, a tuple component, a struct field),
the `_EncodingMixin` (`_encoding.py`) provides two encodings:

- **String in an i64 slot.** Packed as `(ptr | (len << 32))`; the
  read-back splits into `${name}_ptr` / `${name}_len`.
- **Pointer-shaped value in an i64 slot.** The raw i32 pointer
  extended to i64 (`i64.extend_i32_u`). The `_is_pointer_shape_ty`
  predicate decides what is pointer-shaped: a head in
  `_struct_layouts` or `_sum_layouts`, a trait type,
  `List`/`Map`/`Set`, or a non-unit tuple.

## 6. Structs in memory

A struct is a heap record referenced by an i32 pointer. The layout is
computed by `compute_struct_layout` (`_layout.py`): fields in
declaration order with natural alignment, total size rounded to 8. A
struct that implements a multi-impl trait reserves an 8-byte type-id
header at offset 0 (the type-id itself at offset 4, so the dispatcher
reads it from the same uniform offset for struct and sum), and the
fields start after it; the header does not appear in `fields`, so
field iteration never sees it.

For

```capa
type Point {
    x: Int,
    y: Int
}

fun main(stdio: Stdio)
    let p = Point { x: 3, y: 4 }
    stdio.println("sum=${p.x + p.y}")
```

the construction (`MakeStruct`) allocates 16 bytes and writes the two
i64 fields at offsets 0 and 8; the pointer lands in `$p`, and
`FieldAccess` is an `i64.load offset=<n>`:

```
$ python -m capa --wasm --transpile struct.capa
...
    call $alloc
    local.set $_ir_t0
    local.get $_ir_t0
    i64.const 3
    i64.store offset=0
    local.get $_ir_t0
    i64.const 4
    i64.store offset=8
    ...
    local.set $p
    local.get $p
    i64.load offset=0
    ...
```

Parity confirmed (`--run` versus `--run --wasm` both print `sum=7`).
Sum types carry a variant tag at offset 0 and the payload after it
(`compute_sum_layout`, `_layout.py`).

Generic functions are monomorphised before emission
(`capa/ir/_monomorphise/`), and every type token in a clone's name is
sanitised for the WAT identifier charset by `_sanitise_type_token`
([`capa/ir/_monomorphise/_typestr.py`](../capa/ir/_monomorphise/_typestr.py)
line 140): angle brackets, commas, parentheses AND typestate brackets
are rewritten (`[` becomes `_St_`), so a generic instantiated at a
state-qualified typestate emits a valid identifier. Measured: for
`fun idt<T>(consume x: T) -> T` applied to a value of static type
`Sock[Open]`, the clone is `$idt__Sock_St_Open`, the module
assembles, and the program prints `done` identically on both
backends.

## 7. Closures

Closure conversion belongs to the `_ClosureEmissionMixin`
(`_closures.py`). A closure lowers to a packed i64 value
`(fn_idx << 32) | env_ptr`: the high 32 bits are the function-table
index, the low 32 the pointer to the environment record (the
captures). Invocation unpacks and dispatches via `call_indirect`
against the signature's `(type $sig_N)`.

For

```capa
fun main(stdio: Stdio)
    let base = 10
    let add = fun (a: Int) -> Int => a + base
    stdio.println("${add(5)}")
```

the emitter produces the signature type, the function table, the
`elem` populating it, the lifted lambda, and the `call_indirect`:

```
$ python -m capa --wasm --transpile clo2.capa
...
  (type $sig_0 (func (param i32) (param i64) (result i64)))
  (table $fnref 1 1 funcref)
  (elem (i32.const 0) $lambda_0)
  (func $lambda_0 (type $sig_0) (param $env i32) (param $a i64) (result i64)
    ...
    call_indirect (type $sig_0)
```

The lambda ABI is `(env_ptr, args...) -> result`: the first parameter
is always the environment pointer. A top-level function passed as a
`Fun(...)` value (for example `xs.map(double_int)`) gets a tiny thunk
with the same ABI that ignores `env_ptr` and delegates to the named
function (`_fn_ref_thunks`). Parity confirmed (`--run` versus
`--run --wasm` both print `15`).

## 8. Capabilities on Wasm: erased or handle-bearing

The 10 built-in capabilities split, on Wasm, into two classes
([`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py)):

- **Handle-bearing** (`HANDLE_BEARING_CAPS`, line 79): `Fs, Net, Db,
  Proc, Env, Clock`. Each lowers to a REAL i32 handle into the host's
  per-instance cap table, so a restricted capability keeps its
  restriction across function boundaries. A handle occupies a Wasm
  slot everywhere a value can live: params, locals, struct fields,
  closure environments, call args, return values, and `main`'s
  exported signature.
- **Erased** (`ERASED_CAPS`, line 101): `Stdio, Random, Unsafe,
  Serve`. They push no Wasm value, having no attenuation surface to
  carry. (`Unsafe` and `Serve` are also Python-only, below.)

Every built-in capability MUST be in exactly one of the two sets; a
test (`TestCapabilityRegistry` in
[`tests/test_cap_handles.py`](../tests/test_cap_handles.py)) fails if
a new name lands in `BUILTIN_CAPS` without that decision recorded.

`main` with one handle-bearing capability (`Fs`) and one erased
(`Stdio`): the `Fs` becomes a `(param $fs i32)` in `main`'s signature,
the `Stdio` does not appear, and the export `capa:main-cap-types=fs`
records the slot's type:

```
$ python -m capa --wasm --transpile fsmain.capa | grep -n 'func \$main\|capa:main-cap-types'
  (func $main (export "main") (param $fs i32)
  (export "capa:main-cap-types=fs" (global $__capa_main_cap_types))
```

The host-side handle representation is the table in
[`capa/runtime/_cap_handles.py`](../capa/runtime/_cap_handles.py).
This is the exact difference against the Python backend, where a
capability is a first-class object whose restriction travels with the
value (sections 5 and 6 of
[21-python-backend.md](21-python-backend.md)). The handle table and
runtime attenuation detail is
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)'s.

**Python-only capabilities.** `PYTHON_ONLY_CAPS`
(`_capa_types.py` line 58) is `{Unsafe, Serve}`, a PERMANENT posture,
not a backlog item: `Unsafe` grants FFI/pointer primitives with no
sandboxed Wasm equivalent; `Serve` needs `wasi:sockets` to bind a
listening socket, a world neither vendored in `capa/wasi_wit` nor
reachable from the wasmtime-py bindings the hosts are built on. Two
independent paths reject (the `--wasm` emitter and `--wit` generation,
which never runs the emitter), sharing the same reachability sweep.

A `main(serve: Serve)` is refused by both:

```
$ python -m capa --wasm --transpile serve2.capa
capa: --wasm: the Serve capability is intentionally not supported on the Wasm backend (binding a listening socket needs wasi:sockets, which is neither vendored in capa/wasi_wit nor reachable from the wasmtime-py bindings the Wasm hosts are built on, so a guest can never be handed an inbound connection). Use the Python backend for these functions, or refactor to remove the Serve parameter.
  - main(serve: Serve)
$ python -m capa --wit serve2.capa
capa: --wit: the Serve capability is intentionally not supported on the Wasm backend (...). There is no WIT to emit for it: a WIT document describes a Wasm component, and this program cannot be one.
  - main(serve: Serve)
```

## 9. WIT generation

Source: [`capa/ir/_emit_wit.py`](../capa/ir/_emit_wit.py). The
`emit_wit` function (line 909) walks the CIR module, discovers the
reachable capabilities, and emits a WIT document declaring one
`interface` per touched capability plus a `world` importing each. The
`_WIT_SIGNATURES` table (line 44) maps (capability, method) to a WIT
signature; it is the contract that the Wasm emitter AND the host
bridge BOTH follow (adding a method here without supporting both sides
fails at instantiation, so the table is the single source of truth).
The WIT is generated per program, not as a canonical
`capa-stdlib.wit`, precisely because the capability set a program
touches IS the manifest Capa's story builds on.

For `hello.capa`:

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

`export main` mirrors `main`'s signature: handle-bearing capabilities
become `u32` parameters labelled `cap<N>-<kind>`, so the Component
Model world advertises the same parameter shape as the core module
(otherwise `wasm-tools component new` refuses on a core-vs-component
mismatch), and `main`'s return type becomes the result clause (`Int`
-> `s64`, `Float` -> `f64`, `Bool` -> `bool`, `String` -> `string`,
`Unit`/absent -> none). A `main` returning a composite raises
`MainReturnTypeUnsupported`, checked by `check_main_return_type`
([`capa/ir/__init__.py`](../capa/ir/__init__.py) line 347) BEFORE
`compile_wasm`, so the error surfaces as a clean Capa diagnostic
instead of a cryptic `wasm-tools` dump.

The `Fs` `main` of section 8 advertises the labelled slot:

```
$ python -m capa --wit fsmain.capa | grep 'export main'
  export main: func(cap0-fs: u32);
```

If the program uses `panic`, it gets its own
`interface panic { panic: func(msg: string); }` and the
`import panic;` in the world, kept in lockstep with the core module's
`capa:host/panic` import.

**Vendored WASI (`capa/wasi_wit/`).** A `README.md` and a `deps/`
folder with a minimal subset of the official WASI Preview 2 WIT
(`cli/`, `clocks/`, `filesystem/`, `http/`, `io/`, `random/`). In the
experimental opt-in `--wasi` mode, the migrated Random / Clock / Env
touch-points import canonical `wasi:random` / `wasi:clocks` /
`wasi:cli` interfaces instead of the `capa:host` ones
(`_emit_wit._emit_wit_wasi`; `_WasiEmissionMixin` in
`_emit_wasm/_wasi/`), and `_wrap_as_component` copies `deps/` next to
the generated world so the `embed` resolves offline. The WASI mode,
preopens and authority ceilings are
[23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)'s
subject.

## 10. The `capa-manifest` custom section

The capability manifest travels INSIDE the Wasm artefact as a custom
section named `capa-manifest`. Format v1: `{capa_manifest_version,
capa_version, functions: [{name, declared_capabilities}]}`, built by
`_build_wasm_capa_manifest_json`
([`capa/ir/__init__.py`](../capa/ir/__init__.py) line 298) from the
SAME `build_manifest` the rest of the supply-chain story uses, and
from the original AST (before any `--wasi` substitution), with compact
separators. Runtimes ignore custom sections by definition, so this is
purely an audit aid; `wasm-tools objdump` and any Wasm parser expose
it.

The section appears at the end of the module (visible in section 4's
WAT). The reader `read_wasm_manifest`
([`capa/ir/__init__.py`](../capa/ir/__init__.py) line 455) is a tiny
custom-section parser that needs neither `wasmtime` nor `wasm-tools`:

```
$ python -m capa --wasm --output hello.core.wasm hello.capa
capa: --wasm: wrote core module (1311 bytes) to hello.core.wasm
$ python -c "from capa.ir import read_wasm_manifest; \
    print(read_wasm_manifest(open('hello.core.wasm','rb').read()))"
{'capa_manifest_version': 1, 'capa_version': '1.32.0', 'functions':
[{'name': 'double', 'declared_capabilities': []}, {'name': 'main',
'declared_capabilities': ['Stdio']}]}
$ wasm-tools objdump hello.core.wasm | grep custom
  custom "capa-manifest"  ...  160 bytes | 1 count
  custom "name"           ...  513 bytes | 1 count
```

## 11. The runtime hosts

There are two, one per artefact form:

- **`WasmHost`** ([`capa/runtime/_wasm_host.py`](../capa/runtime/_wasm_host.py))
  loads a CORE module (`--wasm --run` without `--component`): it
  speaks the core import protocol (raw pointers, canonical ABI return
  areas).
- **`WasmComponentHost`**
  ([`capa/runtime/_wasm_component_host.py`](../capa/runtime/_wasm_component_host.py))
  loads a COMPONENT (`--wasm --component --run`): it uses
  `wasmtime.component.Component` and a high-level linker where each
  capability method is a Python function receiving lifted WIT values
  and returning the same shape, with no manual pointer work.

The two share semantics: a `capa --wasm --output` artefact is core and
loads via `WasmHost`; a `capa --wasm --component --output` artefact is
a component and loads via `WasmComponentHost`.

`main` dispatch in the component host (`run_main`): instantiate the
component, inspect the exported `main`'s type, read the
`cap<N>-<kind>` label of each parameter slot (the only place a slot
gains authority), and pass the corresponding root handle to each.
There is no fallback: a label this toolchain did not emit means the
component predates the binding, and guessing is the defect this
replaced (a pure `main` with no cap params keeps the trivial zero-arg
dispatch). This is why the binding is recorded as an export (section
4), not as the debug `name` section: it survives
`wasm-tools strip --all`.

The component assembles, writes and runs:

```
$ python -m capa --wasm --component --output hello.comp.wasm hello.capa
capa: --wasm: wrote component (2222 bytes) to hello.comp.wasm
$ python -m capa --run --wasm --component hello.capa
double(21) = 42
```

## 12. Notes

- Scope of the measurements. The pasted outputs are from minimal
  programs (`hello.capa`, `struct.capa`, `clo2.capa`, `fsmain.capa`,
  `serve2.capa`, `tsret.capa`), run at `8e2c609` with
  `wasm-tools 1.249.0` and wasmtime-py 46.0.1 on one Windows machine.
- Trust model (JUDGEMENT informed by reading). "The guest runs in a
  sandbox and only reaches an effect if the host gives it the import"
  is the design reading (the `capa:host/*` imports, the two hosts,
  the handle table). The CONCRETE WASI confinement (preopens,
  ceilings) is
  [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)'s
  subject; this chapter describes the emission structure, it does not
  measure adversarial confinement strength.
- NOT VERIFIED here. Output equality between backends was measured by
  running the minimal programs above, not by an exhaustive corpus
  comparison; the parity promise and its scope are
  [24-backend-parity.md](24-backend-parity.md)'s. The `--wasi` mode
  (WASI Preview 2 imports, preopens) is referenced at its boundary
  but was not exercised here.

---

## Links

- [21-python-backend.md](21-python-backend.md): the other backend,
  where capabilities are first-class objects instead of i32 handles.
- [18-compiler-pipeline.md](18-compiler-pipeline.md): where the Wasm
  emitter (phase 5b) and the CIR path (the only path to Wasm) sit.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  the WASI import boundary, preopens, `--allow-host`, authority
  ceilings and the runtime handle table.
- [24-backend-parity.md](24-backend-parity.md): the
  ideally-byte-identical output promise and its exact scope.
- [25-cli-commands-and-flags.md](25-cli-commands-and-flags.md): the
  full reference of `--wasm`, `--wit`, `--component`, `--output`,
  `--prefer-wasm` and the WASI flags.
- [11-builtin-capabilities.md](11-builtin-capabilities.md) and
  [12-attenuation.md](12-attenuation.md): the capability and
  attenuation model the i32 handles implement.
