# Capa benchmarks

A small suite that compares the Python emitted by `capa
--transpile` against an idiomatic hand-Python implementation
of the same workload. The headline number this suite exists to
produce is the **runtime overhead** of Capa's capability
discipline: how much slower is a Capa program than the Python
program a human would have written by hand?

> The CRA-driven case for capability-typed source is the
> *integrity* argument (the SBOM honestly describes what the
> code does). A thesis chapter on that argument can't dodge the
> performance question. These benchmarks exist so that question
> has a numbers-backed answer rather than a hand-wave.

## How to run

```bash
python benchmarks/runner.py
```

Flags:

- `--iterations N` (default 10): inner loop count per trial.
- `--repeat M` (default 5): number of trials per workload.
- `--markdown`: emit a Markdown table instead of plain text.

The runner transpiles each `.capa` file in-process, writes the
generated Python next to the source as `*.bench.py` (gitignored),
imports it as a module, and times the relevant function with
`timeit.repeat`. The hand-Python baseline is imported from the
matching `*_baseline.py` module and timed the same way.

## Workloads

The suite picks three workloads chosen to expose different parts
of the Capa runtime cost:

| Workload | Shape | What it stresses |
|---|---|---|
| `fib(25)` | Pure compute, recursive | Function-call overhead. No List, no String methods, no Result boxing. |
| `scope_analyser (1000)` | Build + transform `List<Struct>` of 1000 items | `CapaList.push`, `for` over a CapaList, dataclass construction. Same shape as [`examples/cve_eslint_scope.capa`](../examples/cve_eslint_scope.capa). |
| `ua_parse (1000)` | Substring match + struct ctor on 1000 strings | Capa's `String.contains` vs Python's `in`, plus `match` over enum variants. Same shape as [`examples/cve_ua_parser_js.capa`](../examples/cve_ua_parser_js.capa). |

Each workload has a matching `_baseline.py` that implements the
same algorithm in idiomatic Python (dataclasses, native lists,
`in` for substring, `enumerate` for indexing). The pair is
intentionally tight; the goal is "Capa vs the Python a competent
developer would have written", not "Capa vs the most-optimised
Python possible".

## Headline results

Measured on Windows 11, CPython 3.14, `--iterations 30 --repeat 7`.
The numbers below are typical of three back-to-back runs;
individual runs vary by 5-10% but the **ratios are stable**.

| Workload | Description | Capa (ms) | Python (ms) | Overhead |
|---|---|---:|---:|---:|
| `fib(25)` | pure compute (recursive function call) | ~7.3 | ~7.4 | **1.00x** |
| `scope_analyser (1000)` | list-heavy (build + transform List<Struct>) | ~0.67 | ~0.57 | **1.20x** |
| `ua_parse (1000)` | string-heavy (substring match + struct ctor) | ~0.60 | ~0.42 | **1.45x** |

### What the numbers say

- **Pure compute is free.** `fib(25)` runs at parity with hand
  Python. The transpiler emits a plain Python function with no
  decorator (no `?` operator means no `_capa_wrap`), so the
  function-call cost is exactly Python's. This is the headline
  fact for any reader who worries that "capability discipline
  must cost something at runtime": no, the discipline is a
  static property of the type system; the runtime has nothing
  to do at function-call boundaries that Python wasn't already
  doing.

- **List operations cost ~20%.** `scope_analyser` builds and
  walks a `List<Struct>` of 1000 elements. Capa's `CapaList`
  wraps a Python list and exposes `.push`, `.length`,
  `.first`, `.last`, `.get` as method calls; the Python
  baseline uses native `.append` and `len()`. The 1.2x ratio
  is the cost of one extra method-lookup per list operation.
  Closing the gap is mechanical (special-case `CapaList` in the
  transpiler for code paths that statically know the type)
  but has not been done because 1.2x has been comfortably
  inside everyone's budget so far.

- **String + struct construction costs ~45%.** `ua_parse`
  combines substring matching with `match` over an enum
  variant and dataclass construction. The 1.45x ratio comes
  mostly from the dataclass `__init__` path (Capa's user
  structs are emitted as `@dataclass`, hand Python here uses
  the same) and the `match`-over-enum lowering. Substring
  matching itself goes through Python's `in` operator on both
  sides; that part is at parity.

The overall picture for the thesis: **single-digit overhead
percentages on the pure compute path, low-double-digit on
list-heavy paths, mid-double-digit on workloads that combine
list + string + struct construction**. Nothing pathological;
nothing close to "an order of magnitude". A reader asking "is
Capa practical at the source-level?" gets a numerical answer
with the same shape as "yes".

### What is *not* measured

This suite measures **runtime overhead** of the transpiled
program. The following are excluded by design:

- **Compile time.** The Capa pipeline (lex + parse + analyze +
  transpile) is run once per workload before the timing loop.
  It is not in the measured number. Compile time is a separate
  question, addressed in the `--check` and `--transpile` flag
  performance which is fast enough not to require a benchmark
  yet.

- **Python startup.** Both the Capa and baseline measurements
  run inside the same Python process via `exec()` of the
  transpiled output. Process startup is excluded so the
  comparison is about the work, not about CPython's
  interpreter coming online.

- **Capability call overhead.** None of the three workloads
  uses `Fs`, `Net`, `Env`, `Db`, or any other I/O capability
  on the hot path. Measuring those would mostly measure
  Python's stdlib I/O, not Capa.

- **JIT / specialisation.** CPython has no JIT (yet); these
  numbers are interpreter-direct.

## Reproducing

```bash
# Run with the default settings.
python benchmarks/runner.py

# Larger sample for less variance.
python benchmarks/runner.py --iterations 30 --repeat 7

# Markdown for pasting into a paper.
python benchmarks/runner.py --iterations 30 --repeat 7 --markdown
```

The numbers in this README were captured by the second of those
three commands; reproduction on a comparable machine should
land in the same range.
