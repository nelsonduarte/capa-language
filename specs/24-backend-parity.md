# 24. Backend parity and its exact scope

> **What this chapter covers.** The promise of ideally byte-identical
> output on Capa's TWO production backends (the default Python
> transpiler, `--run`, of [21-python-backend.md](21-python-backend.md);
> and the Wasm Component Model backend, `--run --wasm`, of
> [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)),
> and the promise's exact scope: the capabilities that exist only on
> the Python backend (`Serve`, `Unsafe`;
> `capa/ir/_python_only_caps.py`) and the measured host-level
> differences (the recursion ceiling, the text of runtime-failure
> diagnostics). The verification method is running the SAME program on
> both backends and comparing the result byte for byte. The promise is
> about the two PRODUCTION backends; the `--ir` path (CIR -> Python)
> is EXPERIMENTAL and outside it (section 7).

**Version documented.** `main` at commit `8e2c609` (`capa 1.32.0` plus
unreleased commits). Every measurement in this chapter was re-run at
that commit on 2026-09-11, `python -m capa` importing the checkout
under specification, with `wasm-tools 1.249.0` (on `PATH`) and
wasmtime-py 46.0.1 (importable), on one Windows machine.

Depends on: [21-python-backend.md](21-python-backend.md),
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md).

---

## 1. The promise and its exact scope

Capa has TWO production backends. The same source program, unchanged,
runs on the Python transpiler (`--run`) and on the Wasm Component
Model backend (`--run --wasm`), and the design promise is that the
OBSERVABLE RESULT is ideally byte-identical between the two. The value
of the promise is double: a program developed and tested on the Python
backend (fast to iterate) runs in the sandboxed Wasm artefact (the
distribution target) with no semantic surprises; and, conversely, a
program audited as a Wasm artefact behaves the same when run on
Python.

The word "ideally" is deliberate and this chapter takes it seriously.
The promise is not a theorem: it is an engineering discipline whose
scope is measured and disclosed. Its boundaries fall in two classes:

- **Python-only capabilities** (section 4). Two of the ten built-in
  capabilities (`Serve`, `Unsafe`) do not exist on the Wasm backend,
  for PERMANENT platform reasons. A program touching them is refused
  loudly at Wasm emission; it runs only on the Python backend. This is
  not an output divergence, it is an up-front refusal to generate
  Wasm.
- **Host-level differences** (sections 5 and 6). Both backends run on
  a host, and two host properties differ: the recursion ceiling
  (section 5) and the text of the runtime-failure diagnostic (section
  6). Both measured differences are fail-loud on their failing side:
  neither produces output past its stop point.

The scope of the promise is the PYTHON backend (legacy path, `--run`)
versus the WASM backend (`--run --wasm`). The `--ir` path (CIR ->
Python) is a second, EXPERIMENTAL Python emission path and is outside
this promise (section 7). Where a library operation's result is
defined by a user-supplied function, the promise extends only as far
as that function's contract: `sorted_by` requires the comparator to be
a total order, and [`docs/stdlib.md`](../docs/stdlib.md) states that a
comparator that is not a total order has undefined results (the same
reasoning as C's `qsort`); `sorted()`/`min()`/`max()` exist precisely
so the compiler supplies a total order (section 8).

## 2. What "identical" means and how it is verified

The promise is about the program's OUTPUT (what it writes to stdout),
not about the shape of the intermediate code (which differs by
construction: Python source on one backend, WAT assembled to binary on
the other) nor about the text of runtime FAILURE diagnostics (which
reflect the host runtime, section 6). The verification method is
single and non-negotiable: run the same `.capa` on both backends and
compare the result with `cmp`.

The minimal program `hello.capa`:

```capa
fun double(n: Int) -> Int
    return n * 2

fun main(stdio: Stdio)
    stdio.println("double(21) = ${double(21)}")
```

```
$ python -m capa --run hello.capa > a.out
$ python -m capa --run --wasm hello.capa > b.out
$ cmp a.out b.out && echo "byte-identical"
byte-identical
```

Throughout this chapter, "IDENTICAL" means `cmp -s` true AND the same
exit code on both backends. This is the publishable evidence of the
discipline: not the claim that the backends are equal, but the
transcript of running them.

## 3. The byte-equality corpus

SCOPE of the measurement: **15 programs**, at `8e2c609`,
`wasm-tools 1.249.0`, wasmtime-py 46.0.1, compared with `cmp -s`
between `--run` and `--run --wasm`. Eleven are canonical repository
examples (`examples/*.capa`), four are minimal programs built for this
chapter. ALL 15 produced byte-identical output and the same exit code
on both backends.

| Program | Features exercised | Result |
|---|---|---|
| `examples/hello.capa` | println, function call, `Int` | IDENTICAL (rc=0) |
| `examples/basics.capa` | `Float`, arithmetic, formatting | IDENTICAL (rc=0) |
| `examples/patterns.capa` | tuple match, nesting, String literals, `Option` | IDENTICAL (rc=0) |
| `examples/json.capa` | `parse_json`/`to_json`, `JsonValue`, `Map`, `for` | IDENTICAL (rc=0) |
| `examples/generics.capa` | generics, monomorphisation, `Option` | IDENTICAL (rc=0) |
| `examples/closures.capa` | closures, HOFs, tuples of `Fun` | IDENTICAL (rc=0) |
| `examples/grades.capa` | structs, lists, iteration, formatting | IDENTICAL (rc=0) |
| `examples/tasks.capa` | sum types, match, lists | IDENTICAL (rc=0) |
| `examples/stdlib_list.capa` | `map`/`filter`/`fold`/`contains`, indexing | IDENTICAL (rc=0) |
| `examples/stdlib_string.capa` | `String` methods | IDENTICAL (rc=0) |
| `examples/stdlib_map_set.capa` | `Map`/`Set` and operations | IDENTICAL (rc=0) |
| `arith.capa` | `Int`/`Float`, `%`, comparison, `and` | IDENTICAL (rc=0) |
| `strings.capa` | interpolation, concat, `length`/`to_upper` | IDENTICAL (rc=0) |
| `structs.capa` | struct construction, `FieldAccess` | IDENTICAL (rc=0) |
| `closures_min.capa` | lambda capture, `Fun` as parameter | IDENTICAL (rc=0) |

`arith.capa` (the mixed-arithmetic column, demonstrating parity over
`Int`, `Float` and booleans):

```capa
fun main(stdio: Stdio)
    let a = 17
    let b = 5
    stdio.println("sum=${a + b} diff=${a - b} prod=${a * b} quot=${a / b} rem=${a % b}")
    let f = 3.5
    let g = 2.0
    stdio.println("fadd=${f + g} fmul=${f * g}")
    let both = (a > b) and (f < g)
    stdio.println("cmp=${a > b} and=${both}")
```

```
$ python -m capa --run arith.capa
sum=22 diff=12 prod=85 quot=3 rem=2
fadd=5.5 fmul=7.0
cmp=true and=false
$ python -m capa --run --wasm arith.capa
sum=22 diff=12 prod=85 quot=3 rem=2
fadd=5.5 fmul=7.0
cmp=true and=false
```

The equality is of OBSERVABLE output over this corpus of 15 programs.
It is not a universal parity proof (section 9): it is the measured
evidence, with its scope declared beside it.

## 4. Python-only capabilities: `Serve` and `Unsafe`

Two of the ten built-in capabilities do not exist on the Wasm backend.
The source of truth is `PYTHON_ONLY_CAPS`
([`capa/ir/_capa_types.py`](../capa/ir/_capa_types.py) line 58), the
frozenset `{Unsafe, Serve}`. The set is a PERMANENT platform stance,
not a backlog item, and the code says so explicitly:

- **`Unsafe`** grants raw pointer / FFI / memory-map primitives with
  no sandboxed Wasm equivalent. It is the exit hatch for
  `py_import`/`py_invoke` (section 5 of
  [21-python-backend.md](21-python-backend.md)).
- **`Serve`** (INBOUND connection authority) must bind a listening
  socket, which requires `wasi:sockets`, a world neither vendored in
  `capa/wasi_wit` nor reachable from the wasmtime-py bindings the Wasm
  hosts are built on. A guest can never be handed an inbound
  connection, so there is no Wasm to generate.

The exact text of each reason lives once in
`PYTHON_ONLY_CAP_REASONS`
([`capa/ir/_python_only_caps.py`](../capa/ir/_python_only_caps.py)
line 39), so the explanation is identical on every refusing path.

**Two independent paths refuse.** The reachability sweep lives once
(`find_rejection`, `_python_only_caps.py` line 161) and is called from
two independently reachable places: the Wasm emitter's discovery pass
(`_reject_python_only_cap_signatures`,
[`capa/ir/_emit_wasm/_discovery.py`](../capa/ir/_emit_wasm/_discovery.py)
line 566) and WIT generation
([`capa/ir/_emit_wit.py`](../capa/ir/_emit_wit.py)), which NEVER runs
the emitter (reachable via `capa --wit` alone). The sweep is recursive
through struct fields and variant payloads, so a parameter of a type
that merely CONTAINS the capability (`type Wrapper { u: Unsafe }`) is
caught too (`find_offending_sites`, line 96).

A `main(serve: Serve)` passes analysis (the Python backend accepts it)
but is refused on both Wasm paths, with the same text:

```
$ python -m capa --check serveonly.capa
serveonly.capa: ok (1 items, 4 expressions typed, 1 bindings)
$ python -m capa --run --wasm serveonly.capa
capa: --wasm: the Serve capability is intentionally not supported on the Wasm backend (binding a listening socket needs wasi:sockets, which is neither vendored in capa/wasi_wit nor reachable from the wasmtime-py bindings the Wasm hosts are built on, so a guest can never be handed an inbound connection). Use the Python backend for these functions, or refactor to remove the Serve parameter.
  - main(serve: Serve)
$ python -m capa --wit serveonly.capa
capa: --wit: the Serve capability is intentionally not supported ... There is no WIT to emit for it: a WIT document describes a Wasm component, and this program cannot be one.
  - main(serve: Serve)
```

`Unsafe` is refused the same way:

```
$ python -m capa --run --wasm unsafe.capa
capa: --wasm: the Unsafe capability is intentionally not supported on the Wasm backend (it grants raw pointer / FFI / memory-map primitives that have no sandboxed Wasm equivalent). Use the Python backend for these functions, or refactor to remove the Unsafe parameter.
  - main(u: Unsafe)
```

**Classification note (why they are in `ERASED_CAPS`).** In the Wasm
lowering map (section 8 of
[22-wasm-component-model-backend.md](22-wasm-component-model-backend.md)),
`Serve` and `Unsafe` sit in `ERASED_CAPS` (`_capa_types.py` line 101),
not in `HANDLE_BEARING_CAPS`. The code comment explains that "erased"
is the SAFEST classification for a refused cap: if the refusal ever
developed a hole, an erased cap pushes no value and the module fails
to link against an import nobody defined (loud), whereas a
handle-bearing cap would occupy an i32 slot with no entry in the
host's handle map. The refusal in depth is itself
honest-by-construction.

## 5. Host difference 1: the recursion ceiling (fail-loud, distinct ceilings)

The two backends have DIFFERENT recursion-depth ceilings. There is a
depth band in which the SAME program runs and produces output on the
Wasm backend but fails loudly on the Python backend. Both backends
fail LOUD at their ceilings (neither returns a silent wrong answer);
what differs is the boundary between running and failing.

Measured with the program

```capa
fun down(n: Int) -> Int
    if n <= 0
        return 0
    return 1 + down(n - 1)

fun main(stdio: Stdio)
    stdio.println("depth=${down(N)}")
```

varying `N`:

| Depth `N` | Python backend (`--run`) | Wasm backend (`--run --wasm`) |
|---|---|---|
| 950 | `depth=950` (rc=0) | `depth=950` (rc=0) |
| 1000 | fails loud (rc=1) | `depth=1000` (rc=0) |
| 20000 | fails loud (rc=1) | `depth=20000` (rc=0) |
| 60000 | fails loud (rc=1) | fails loud (rc=1) |

The Python backend fails between `N=950` (runs) and `N=1000` (fails)
with `RecursionError: maximum recursion depth exceeded`; the Wasm
backend runs up to at least `N=20000` and fails by `N=60000` with
`wasm trap: call stack exhausted`. Both break points are HOST ceilings
(the Python interpreter's recursion limit in one case, the stack size
wasmtime configures in the other), not language guarantees: neither
backend promises a recursion depth. What is honest to state: a
deep-recursion program in the roughly 1000-to-20000 band produces
output on Wasm and fails loud on Python. It is a real difference of
outcome (one backend produces output, the other fails), fail-loud on
the failing side.

SCOPE: measured on one machine at `8e2c609`, with the installed
interpreter recursion default and wasmtime stack default. The exact
numeric ceilings are host-configuration-sensitive
(`sys.setrecursionlimit`, wasmtime stack size) and are not a language
constant; what is asserted is the EXISTENCE of the divergence band and
its fail-loud character, not a universal number.

## 6. Host difference 2: the text of the runtime-failure diagnostic

When a program fails at runtime from the SAME cause on both backends
(`Int` overflow, division by zero), the program's OUTPUT up to the
failure point is identical and both backends fail loud at the same
point, but the TEXT of the failure diagnostic differs, because each
backend renders it through its host runtime. This does not contradict
the promise: the promise is about the program's output (stdout), and
that is identical; the failure diagnostic belongs to the host.

For `divzero.capa` (prints `before`, then divides by zero):

```capa
fun main(stdio: Stdio)
    let a = 10
    let b = 0
    stdio.println("before")
    stdio.println("${a / b}")
    stdio.println("after")
```

stdout is byte-identical on both backends (just `before`), and both
fail with rc=1:

```
$ python -m capa --run divzero.capa 2>/dev/null; echo "rc=$?"
before
rc=1
$ python -m capa --run --wasm divzero.capa 2>/dev/null; echo "rc=$?"
before
rc=1
```

What differs is the stderr diagnostic. The Python backend raises the
support runtime's exception
(`ZeroDivisionError: Int division by zero`, followed by a Capa
traceback naming the source line); the Wasm backend traps inside the
sandbox and wasmtime reports `wasm trap: integer divide by zero`. The
same pattern holds for `Int` overflow
(`9223372036854775807 + 1`, measured in
[05-base-and-composite-types.md](05-base-and-composite-types.md)
section 2): identical stdout, `OverflowError: ...` versus
`wasm trap: wasm 'unreachable' instruction executed`. The parity the
language promises is FAILING ON THE SAME INPUT (both refuse `MIN/-1`,
overflow, division by zero rather than giving divergent answers); the
exact failure text is the host's and is not part of the promise.

## 7. The `--ir` path is OUTSIDE the production promise

There is a third Python emission path, `--ir` (CIR -> Python,
`capa/ir/_emit_python.py`), described in section 2 of
[21-python-backend.md](21-python-backend.md). It EXISTS, but it is
EXPERIMENTAL and NOT part of the production parity promise. The
production promise is between the legacy Python transpiler (`--run`,
without `--ir`) and the Wasm backend (`--run --wasm`). When the
lowering meets a construct the IR does not cover, it raises
`UnsupportedInIR` and the CLI falls back to the legacy transpiler with
a stderr notice; that mechanism is a property of the experimental
path, not a production parity failure. The distinction is crisp:
`--run` (legacy) and `--run --wasm` are the promise's two backends;
`--ir` is an experimental path of the Python backend, outside it.
(The stdlib characterization corpus nonetheless exercises all THREE
paths; section 8.)

## 8. The ordering surface and the nets that hold parity

The container/string method surface of
[05-base-and-composite-types.md](05-base-and-composite-types.md)
section 10.1 (`List.pop / sorted / min / max`, `Map.remove / filter`,
`String.lines / split_once / find_index`) ran byte-identically on the
THREE execution paths (`--run`, `--run --ir`, `--run --wasm`),
verified with `cmp` over a program exercising all nine (transcript in
chapter 05); the repository's own characterization corpus
([`tests/stdlib_characterization/`](../tests/stdlib_characterization/)
with `TestThreeBackendAgreement` over its `_AGREEING` set in
[`tests/test_stdlib_characterization.py`](../tests/test_stdlib_characterization.py))
enforces the same equality in CI. The compiler-supplied `Float` order
(`sorted`/`min`/`max`) is TOTAL, `NaN` last, measured identical on the
three paths:

```
$ python -m capa --run nan_total.capa    # [2.0, nan, 3.0, 1.0, 4.0]
sorted=1.0|2.0|3.0|4.0|nan|
```

A non-ordered element rejection (`List<Bool>.sorted()`) carries the
same error text on the Python and Wasm paths (measured in chapter 05;
pinned by `TestCompilerOrderedRejectParity` in
[`tests/test_ir_wasm_parity.py`](../tests/test_ir_wasm_parity.py)).

With `sorted_by` the comparator is the user's, and the ordering
contract is the comparator being a total order;
[`docs/stdlib.md`](../docs/stdlib.md) states that a comparator that is
not a total order has undefined results. `sorted()` exists precisely
so that the compiler supplies the total order.

Two further nets hold this surface (read from the tests, suite green
in CI at this commit):

- **Every built-in method must compile ALONE on the Wasm backend**
  (`TestScratchLocalIsolationSweep`,
  [`tests/ir_wasm/test_wasm_sweeps.py`](../tests/ir_wasm/test_wasm_sweeps.py)):
  closes the masking class where a method's scratch locals were only
  declared under a sibling method's flag and every corpus program
  called the sibling first.
- **The ordering corpus includes negative integers** (before this,
  flipping the Wasm `Int` comparator to unsigned survived the whole
  suite).

## 9. Notes

- Scope of the measurements. Byte equality is measured over **15
  programs** (11 from `examples/`, 4 minimal ones built here) at
  `8e2c609`, comparing `--run` with `--run --wasm` via `cmp -s`. All
  15 were byte-identical with equal exit codes. The host differences
  of sections 5 and 6 were each reproduced by execution at the same
  commit.
- MEASURED versus JUDGEMENT. It is JUDGEMENT (a design reading) that
  section 6 "does not contradict the promise because the diagnostic
  belongs to the host"; the basis is that stdout is MEASURED identical
  and the differing text is the host runtime's (Python exception
  versus wasmtime trap).
- NOT VERIFIED. (1) Byte parity is NOT exhaustive: it is measured on
  the 15-program corpus of section 3 plus the stdlib characterization
  corpus's agreeing set, not over a universe of programs; the equality
  claim is about those corpora and does not generalize beyond them.
  (2) The exact recursion-ceiling numbers (section 5) are
  host-sensitive and were not measured on another machine or with
  other stack/recursion limits. (3) The `--wasi` mode was not
  exercised in this chapter. (4) No adversarial search for further
  divergences beyond these corpora was performed here; the honest
  claim is "none found in the tested corpus", not "none exist".

---

## Links

- [21-python-backend.md](21-python-backend.md): the default backend
  (`--run`) and the experimental `--ir` path outside this promise.
- [22-wasm-component-model-backend.md](22-wasm-component-model-backend.md):
  the Wasm backend, the handle-bearing/erased split, and the
  monomorphisation naming that keeps state-qualified generics
  assembling.
- [23-wasi-and-runtime-attenuation.md](23-wasi-and-runtime-attenuation.md):
  the `--wasi` mode, preopens and ceilings, not exercised here.
- [11-builtin-capabilities.md](11-builtin-capabilities.md): the 10
  built-in capabilities, of which `Serve` and `Unsafe` are the two
  Python-only ones.
- [05-base-and-composite-types.md](05-base-and-composite-types.md):
  the nine-method transcript and the checked-arithmetic parity this
  chapter's section 6 leans on.
