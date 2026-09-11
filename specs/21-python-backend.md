# 21. Backend: the Python transpiler

> **What this chapter covers.** The Python backend: how a Capa program
> becomes Python code and how capabilities are MATERIALIZED at runtime
> (what a capability value actually is in the emitted Python, and how
> authority travels by argument instead of environment). There are two
> Python emission paths, both introduced in
> [18-compiler-pipeline.md](18-compiler-pipeline.md): the legacy
> transpiler (AST -> Python, `capa/transpiler/`) and the CIR path
> (`--ir`, AST -> IR -> Python, `capa/ir/_emit_python.py`). This
> chapter describes how each emits Python, where they differ, and the
> support runtime (`capa/runtime/`) the emitted code imports.

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every transcript re-run at that commit on
2026-09-11, `python -m capa` importing the checkout under
specification; all `file:line` citations are against this commit.

Depends on: [18-compiler-pipeline.md](18-compiler-pipeline.md).

---

## 1. What the Python backend is

The Python backend transpiles a Capa program to a STRING of Python
3.10+ code and either runs that string on the interpreter (`--run`) or
prints it (`--transpile`). There is no bytecode compilation step of
its own: the target is Python source, executed by the host
interpreter. This has a trust-model consequence this chapter does not
hide: on the Python backend **the host runtime is trusted**.
Capabilities are Python objects that interpose the effects, and the
confinement guarantee is as strong as the integrity of the interpreter
and the support runtime (`capa/runtime/`). The narrower runtime
confinement, by WASI imports, belongs to the Wasm backend
([23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md)).
What the Python backend guarantees by construction is not external
interposition; it is that authority only enters through the signature:
a function that did not receive the capability has no way to obtain
it, because the emitted Python exposes no global that holds one
(section 4).

## 2. The two Python emission paths

There are two Python code-generation paths, chosen by flag
([`capa/cli/_run_python.py`](../capa/cli/_run_python.py)):

- **Legacy transpiler (default).** The `Transpiler` class
  ([`capa/transpiler/__init__.py`](../capa/transpiler/__init__.py),
  `transpile` method at line 271) walks the AST after analysis and
  emits Python line by line through an `Emitter` that manages
  indentation (line 110). This is the path of `--transpile` and
  `--run` without `--ir`. `Transpiler` composes four mixins: `_items`
  (top-level declarations plus the `main` bootstrap), `_statements`,
  `_expressions` and `_methods` (per-type dispatch for
  `String`/`Map`/`Set` method calls).
- **CIR path (`--ir`, opt-in).** `compile_program(module, ...)`
  ([`capa/ir/__init__.py`](../capa/ir/__init__.py) line 131) lowers
  the AST to the IR and emits Python from it with `PythonEmitter`
  ([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py)). If the
  `Lowerer` meets a construct the IR does not cover, it raises
  `UnsupportedInIR` and the CLI falls back to the legacy transpiler
  with a one-line stderr notice.

The design point: **the two paths produce identical observable
behaviour** for the subset the IR covers; only the shape of the
intermediate Python differs. The CIR path exists because the Wasm
backend departs ONLY from the IR
([22-wasm-component-model-backend.md](22-wasm-component-model-backend.md));
the IR Python emitter keeps the CIR path exercised for the Python
target too.

For the minimal program `cap.capa`:

```capa
fun banner(stdio: Stdio, name: String)
    stdio.println("hello, ${name}")

fun main(stdio: Stdio)
    banner(stdio, "Capa")
```

the legacy path flattens the interpolation with `str(...)` and `+`:

```
$ python -m capa --transpile cap.capa
...
def banner(stdio, name):
    stdio.println(('hello, ' + str(name)))

def main(stdio):
    banner(stdio, 'Capa')

if __name__ == "__main__":
    main(Stdio())
```

the CIR path lowers to a form with explicit temporaries (`_ir_t0`) and
uses an f-string:

```
$ python -m capa --ir --transpile cap.capa
...
def banner(stdio, name):
    _ir_t0 = f'hello, {name}'
    stdio.println(_ir_t0)

def main(stdio):
    banner(stdio, 'Capa')

if __name__ == "__main__":
    main(Stdio())
```

The two paths run with identical output:

```
$ python -m capa --run cap.capa
hello, Capa
$ python -m capa --run --ir cap.capa
hello, Capa
```

## 3. The prelude and the bootstrap: the emitted file's skeleton

Every emitted Python file has the same frame: a **prelude** (runtime
imports), the function bodies, and a `main` **bootstrap**. The two
paths share exactly these two pieces, which is why the behaviour is
identical.

**The prelude.** It is the `_PRELUDE` constant of the legacy
transpiler ([`capa/transpiler/__init__.py`](../capa/transpiler/__init__.py)
line 72). It imports from the support runtime, by name (an explicit
list, measured as `from capa.runtime import (...)` in the output
above): the sum types (`Ok, Err, Result, Some, None_, Option`), the
**ten capability classes** (`Stdio, Fs, Env, Clock, Random, Net, Proc,
Db, Serve, Unsafe`), the collection types (`CapaList, CapaRange,
CapaSet`), the converters (`parse_int, parse_float, to_float,
to_int`), `panic`, `declassify`, the interop boundary (`py_import,
py_invoke`), the JSON codec and the safe-arithmetic helpers
(`_capa_iadd, _capa_isub, _capa_imul, _capa_idiv, _capa_shl,
_capa_shr`, plus the boundary helpers `_capa_list_get,
_capa_substring, ...`). The CIR path reuses the SAME `_PRELUDE`
constant instead of duplicating the import list, so the two paths stay
in lockstep over runtime API changes
([`capa/ir/__init__.py`](../capa/ir/__init__.py) lines 146 to 159).

**The `?` helper (the structural difference between the paths).** The
legacy transpiler always splices, right after the prelude, the
`_TRY_HELPER` block: the `_CapaTryEarlyReturn`, `_capa_try` and
`_capa_wrap` definitions that support the `?` operator in expression
position ([`capa/transpiler/__init__.py`](../capa/transpiler/__init__.py)
line 320). The CIR path deliberately **omits** this block: the
lowering expands `?` inline via a `TryUnwrap` node, so the exception
path is never reached. This is the most visible structural difference
between the two paths in the emitted file:

```
$ python -m capa --transpile cap.capa | grep -c "_capa_try"
1
$ python -m capa --ir --transpile cap.capa | grep -c "_capa_try"
0
```

## 4. The `main` bootstrap: authority instantiated, never ambient

The bootstrap is the `if __name__ == "__main__":` block that starts
the program. This is where capability materialization becomes visible:
each capability parameter of `main` is resolved to the
**instantiation of the corresponding capability class**, and the
instances are passed by argument in the call to `main`.

On the legacy path, `_emit_main_bootstrap`
([`capa/transpiler/_items.py`](../capa/transpiler/_items.py) line 214)
iterates `main`'s parameters, resolves each by its type name
(`_capability_for_param`, line 231) and emits `CapName()`. On the CIR
path, `_emit_main_bootstrap`
([`capa/ir/__init__.py`](../capa/ir/__init__.py) line 508) does the
same from `p.ty` (the type name the IR parameter carries), mirroring
the legacy path.

For a `main` with two capabilities:

```capa
fun main(fs: Fs, stdio: Stdio)
    let narrowed = fs.restrict_to("data")
    stdio.println("ok")
```

the bootstrap instantiates BOTH and passes them by argument:

```
$ python -m capa --transpile atten2.capa
...
def main(fs, stdio):
    narrowed = fs.restrict_to('data')
    stdio.println('ok')

if __name__ == "__main__":
    main(Fs(), Stdio())
```

This is the central point of the authority model materialized in the
emitted Python. The only way for a function to obtain a capability is
to RECEIVE it. The `Fs()`, `Stdio()` instances are created ONCE, in
the bootstrap, and propagated from there by explicit argument. There
is no global capability object, neither in the emitted file nor in the
imported runtime: importing `capa.runtime` grants no authority
([`capa/runtime/__init__.py`](../capa/runtime/__init__.py) line 29:
a program that imports the runtime "does not gain capacities by a
simple import"). A function without the parameter has no way to reach
the authority: the same discipline the analyzer refuses statically
before the program runs (see
[10-capability-model.md](10-capability-model.md)).

## 5. What a capability value actually is in the emitted Python

A capability materializes as an **instance of a Python class** defined
in [`capa/runtime/_capabilities.py`](../capa/runtime/_capabilities.py).
Each class interposes the effect: the methods Capa exposes are Python
methods that do the real IO. Measured anchors:

- `Stdio` (line 180): `println(text)` writes to `sys.stdout` and
  flushes; `read_line()` reads from `sys.stdin` and returns
  `Result[str, IoError]`. A Capa call `stdio.println(...)` transpiles
  to the same-named method call on the instance (measured in section
  2's output).
- `Fs` (line 209): carries its own authority. An instance holds `None`
  (unrestricted authority, what `main` receives) or a `frozenset` of
  allowed prefixes; the path check is path-aware (`os.path.realpath`
  plus `Path.is_relative_to`), with post-open TOCTOU hardening in
  `read`/`write` (`_fs_guard`).
- `Unsafe` (line 1897): deliberately WITHOUT methods. Its only role is
  to be the proof of authority the static checker requires for
  `py_import`/`py_invoke`; the materialization is an empty instance
  passed by argument.

A capability construct used as a VALUE emits the class instantiation;
on the CIR path this is the emitter's `cap_const` case
([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py) line 698).
There is no special capability representation at the emitted-Python
boundary: a capability is a first-class Python object whose
restriction state TRAVELS with the value (section 6).

Architecture note (what is NOT part of the Python backend). The
module [`capa/runtime/_cap_handles.py`](../capa/runtime/_cap_handles.py)
is not part of the Python backend's materialization. It is the Wasm
host's i32 handle table (its docstring: the Wasm backend "has no
native value representation for capabilities", so cap values on Wasm
become i32 handles into a host-side table). On the Python backend
capabilities are first-class objects and need no table; this is
precisely why a restricted capability stays sound across a function
boundary on Python, while Wasm needed the handle table. The runtime
modules `_wasm_component_host.py`, `_wasm_host.py`, `_foreign.py` and
`_aot.py` belong, respectively, to the Wasm hosts, the foreign
boundary and AOT, covered in
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)
and [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md).

## 6. Attenuation materialized: authority travels with the value

Attenuation (`restrict_to` and siblings,
[12-attenuation.md](12-attenuation.md)) materializes as a method
returning a **new, more restricted instance**, never mutating the
origin. `Fs.restrict_to`
([`capa/runtime/_capabilities.py`](../capa/runtime/_capabilities.py)
line 265) returns `Fs(_allowed_prefixes=existing | {canon})`: the
restriction is ADDED to the set and a path is only allowed if it falls
within ALL prefixes, so attenuation is monotone by construction.
Because the restricted instance is an ordinary Python value, the
restriction travels with it into any function it is passed to.

The restriction transpiles to a plain method call, with no special
treatment:

```
$ python -m capa --transpile atten2.capa | grep restrict_to
    narrowed = fs.restrict_to('data')
```

The `narrowed` value is an `Fs` instance with the `data` prefix in its
set; passed to another function, it carries the restriction along.

## 7. Method dispatch and calls

A capability method call (`stdio.println(...)`,
`fs.restrict_to(...)`) transpiles to the same-named attribute call on
the instance: the interposition is in the runtime, not in the emitter.
The legacy transpiler's `_methods` mixin handles per-type dispatch
only for the BUILT-IN `String`/`Map`/`Set` methods, not for
capabilities, whose methods resolve naturally as attributes of the
runtime object.

In arithmetic, both paths route `Int`/`Int` operands through the
runtime's safety helpers (`_capa_iadd`, `_capa_isub`, `_capa_imul`,
`_capa_idiv`, `_capa_shl`, `_capa_shr`) so the Python backend fails
loudly on the SAME input where the Wasm backend traps (overflow,
division by zero, `MIN/-1`); `Float`/`String`/`Bool` operands stay on
the plain Python operator
([`capa/ir/_emit_python.py`](../capa/ir/_emit_python.py) lines 63 to
73; the legacy path has the same rewrite in
`capa/transpiler/_expressions.py`). This is why `_capa_imul` appears
in the `double` example of
[18-compiler-pipeline.md](18-compiler-pipeline.md) section 6.

## 8. The support runtime (`capa/runtime/`)

`capa/runtime/` has 18 `.py` files at this commit: `__init__ _aot
_cap_handles _capabilities _convert _foreign _fs_guard _ifc _json
_list _panic _pyinterop _result _safety _set _trace
_wasm_component_host _wasm_host`. The public API is what
`__init__.py` re-exports and names in `__all__`; the submodule split
is internal organization.

The modules the **emitted Python** imports (via `_PRELUDE`) and
depends on at runtime:

- `_capabilities.py` (1909 lines): the ten capability classes and
  `IoError`. The heart of the materialization.
- `_result.py`: `Ok`, `Err`, `Result`, `Some`, `None_`, `Option`.
- `_convert.py`: `parse_int`, `parse_float`, `to_int`, `to_float`.
- `_ifc.py`: `declassify` (the IFC declassification operation, a
  runtime no-op with only static meaning; see
  [16-ifc-analyzer-and-tiers.md](16-ifc-analyzer-and-tiers.md)).
- `_json.py`, `_list.py`, `_set.py`: the JSON types,
  `CapaList`/`CapaRange`, `CapaSet`.
- `_safety.py`: the safe-arithmetic helpers of section 7.
- `_pyinterop.py`: `py_import`, `py_invoke`, both gated on `Unsafe`.
- `_panic.py`: `panic`.
- `_fs_guard.py`: the `Fs` TOCTOU hardening (imported by
  `_capabilities`).

The modules `_cap_handles.py`, `_wasm_component_host.py`,
`_wasm_host.py`, `_foreign.py`, `_aot.py` and `_trace.py` serve the
Wasm hosts, the foreign boundary, AOT and traceback rewriting, not the
emitted Python of a simple program (section 5).

## 9. The CIR path at the Python boundary

`PythonEmitter` walks a lowered CIR module and emits Python close to
what the legacy path produces, so the runtime behaviour is identical
for the subset the IR covers. The IR emitter itself is minimal and
does NOT reintroduce the prelude or the `?` helper; it is
`compile_program` ([`capa/ir/__init__.py`](../capa/ir/__init__.py)
line 131) that prepends the legacy `_PRELUDE` and appends the `main`
bootstrap, so the result is a directly executable program (sections 3
and 4). If the IR does not cover the program, `UnsupportedInIR` makes
the CLI fall back to the legacy path (section 2).

The IR's coverage includes closures: a program with a lambda compiles
through the CIR path WITHOUT falling back (measured: no fallback
breadcrumb on stderr, the emitted Python has `_ir_lambda0` and no
`_capa_try`):

```capa
fun main(stdio: Stdio)
    let add = fun (a: Int, b: Int) -> Int => a + b
    stdio.println("${add(2, 3)}")
```

```
$ python -m capa --ir --transpile clo.capa
...
def main(stdio):
    def _ir_lambda0(a, b):
        _ir_t1 = _capa_iadd(a, b)
        return _ir_t1
    add = _ir_lambda0
    _ir_t2 = add(2, 3)
    _ir_t3 = f'{_ir_t2}'
    stdio.println(_ir_t3)
$ python -m capa --run clo.capa
5
$ python -m capa --run --ir clo.capa
5
```

## 10. Notes

- Scope of the measurements. The pasted outputs are from three minimal
  programs (`cap.capa`, `atten2.capa`, `clo.capa`), run at `8e2c609`
  on the Python backend through both paths (legacy and CIR).
- Trust model (JUDGEMENT informed by reading). "On the Python backend
  the host runtime is trusted" is the model reading: capabilities are
  Python objects that interpose the effects and run in the same
  interpreter as the program, with no external sandbox. WASI-import
  confinement belongs to the Wasm backend.
- NOT VERIFIED. No exhaustive byte-by-byte comparison between the
  Python emitted by the two paths was made over a large program
  corpus; the equality ASSERTED is observable behaviour (same output
  when run), measured on the three programs above, not textual
  equality of the generated Python (which differs by construction:
  `_ir_t*` temporaries, f-strings, absence of the `?` helper). The
  precise IR coverage set (exactly which constructs raise
  `UnsupportedInIR`) is not measured here.

---

## Links

- [18-compiler-pipeline.md](18-compiler-pipeline.md): where the two
  codegen paths and the Python emitter sit in the phase chain.
- [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the other emitter, and the handle table (`_cap_handles.py`) the
  Python backend does not need.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  runtime confinement by WASI imports, narrower than the trusted host
  of the Python backend.
- [24-backend-parity.md](24-backend-parity.md): the
  ideally-byte-identical output promise and its scope.
- [10-capability-model.md](10-capability-model.md) and
  [12-attenuation.md](12-attenuation.md): the static model this
  chapter's runtime materialization implements.
