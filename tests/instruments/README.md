# The measuring instruments

Tests that compare the compiler with a RULE rather than with another
backend, so they keep their meaning when a backend is removed. They run
under `python -m unittest discover tests` like every other test module.

## What is here, one place per rule

| module | the one thing it owns |
|---|---|
| `_provenance` | build identity: the whole-package hash of `capa`, computed by every child process over the tree it imported from and recomputed by the parent; a child whose line differs voids its rows |
| `_outcome` | the OUTCOME type (`CORRECT`, `WRONG:<key>`, `REFUSED`, `TIMEOUT`, `BROKEN`, `VOID`) and the normaliser that makes a key from an observation (exit class and LF stdout, nothing else) |
| `_runner` | how a program runs on a leg: one bounded child per leg, a per-program watchdog (fixed floor `PROGRAM_BOUND_S`), the command-line legs, the route-agreement check |
| `_register` | the known-outcome register: the member identity (file name plus program hash), the diff classes, the shrink-only ratchet |
| `absolute/` | instrument (a): the clause table `R1`..`R14`, the generator whose builders are the clauses, the hand-written anchors, the corpora and the controls, the grammar completeness pin, the evaluator self-test |
| `analysis_execution/` | instrument (b): the twin builder, its guards, the verdict, the public cases |
| `release_differential` | instrument (d): the check half and the two-layer manifest half, run by the release procedure |
| `ratchet` | the command the CI step runs |

The strict condition-position family lives with the other implicit-flow
enumerations in `tests/implicit_flow/_generated.py`; its gate is
`test_strict_positions`.

## The register

`tests/instrument_register.json` holds every outcome the suite knows is
not `CORRECT` today, keyed `<instrument>|<file>#<program hash>|<leg>`
with a one-line reason and the programme step expected to close it. The
gate diffs each run against it:

- `FIXED`: a registered member now reads `CORRECT`. Delete the entry (and,
  for a stdlib program, promote it to `_AGREEING`).
- `CHANGED`: a different wrong answer. Re-measure; never re-pin silently.
- `NEW`: an unregistered wrong answer. A new defect: fix it, or register it
  with its reason in the same change.
- `REGRESSION`: a member stopped running (`REFUSED` / `TIMEOUT` / `BROKEN`
  / `VOID`) without being registered as exactly that. Never a fix.
- `STALE` / `REGENERATED`: the registered program is gone, or its text
  changed. A regenerated program cannot inherit an entry.

The register may only shrink. `scripts/instrument_ratchet.sh` compares it,
entry by entry, with the register of the base of the pushed range; an
added or re-described entry fails unless the entry declares itself a
`REVEAL` (a `BROKEN` member that became `WRONG` once its gap closed, naming
the outcome it came from) or a `REGENERATED` member (same file, leg and
outcome under a new hash, naming the entry it replaces). The first landing
is a bootstrap and says so.

A stdlib characterization entry pins the vector of EVERY leg (the
`vectors` field; the outcome is their key, and the loader checks it) and
points, through `pins`, at the hand-written structural assertions a key
cannot express. `tests/test_stdlib_characterization.py` derives its
known-divergent list from these entries.

## The controls

Five programs assert the harness itself before any register is read: a
deliberate infinite loop must read `TIMEOUT`, a type error `REFUSED`, a
wrong expectation `WRONG`, an overflow expecting an abort `CORRECT`, and a
guard carrying a call `BROKEN` on the IR leg only (the one shape the CIR
Python emitter refuses today; when that gap closes the control must be
replaced or retired with its class). Two fixture children (`fixtures/`)
prove that a child lying about its hash or importing from another tree
voids its rows. The evaluator self-test plants twenty one-clause errors in
the evaluator and requires each to fail a hand-written anchor.

## Where the legs run

- The `test` matrix (no Wasm toolchain): the check and IR legs over the
  corpora, anchors and controls, a 20-program sample of `capa --ir --run`
  for route agreement, the Python legs of the twins, the condition-position
  family, and the ratchet step on one leg.
- The `wasi` job: the Wasm leg and `--wasm --run` sample, and the Wasm leg
  of the twins. Both classes are named in `tests/test_wasm_harness_present.py`,
  so a skip there is a loud failure.

Measured on the development machine (win32, sequential): the check and IR
legs over 309 programs take about 10 s, the Wasm leg about 13 s, the route
sample about 6 s, the twins about 3 s per backend set. The bound is a
fixed floor of `PROGRAM_BOUND_S` seconds per (program, leg); the slowest
program measured 0.07 s unloaded and 0.32 s under load; a hang costs about
the bound plus a child restart per hanging (program, leg).

## What the instruments see, and do not

Instrument (a) sees a wrong EVALUATION rule inside its grammar on any
executor, and only that: not `Float` (its printed form is unstated),
typestate, generics beyond the header's helpers, closures over mutable
state, strings beyond length and interpolation, capabilities other than
`Stdio`, or modules. A new AST node class fails the completeness pin; a new
rule clause lands with an anchor and an evaluator mutant.

Instrument (b) sees an explicit flow of a literal-key `Env` source to a
sink with an executable observable (stdout, stderr, a written file, an
abort message) on the backends it runs. It does not see implicit flows
(the condition-position family does, by `--check` alone), other label
sources, capability use, or a flag raised for a reason unrelated to the
case. The route-agreement check sees a command-line route that produces a
different result from the in-process leg; it cannot see a route swap
between two executors that agree.

Instrument (d) sees a diagnostic or a manifest fact the previous build
produced on its corpus and the candidate does not; it cannot see a defect
already in the previous build, nor a deletion that changes no diagnostic
on its corpus, which is why its corpus carries programs that produce
diagnostics.

A private configuration (loaded by `_private` when present) extends the
grammar, the cases, the positions, the legs and the register with shapes
that are not public yet, and keeps a list of the audit rows none of the
instruments see, placed against the programme steps whose regressions
would land there. The public tree is complete and green without it.

## Adding a member

Add the construct to the grammar (a kind with the clauses it exercises),
an anchor whose expectation is written by hand from the clause, and an
evaluator mutant the anchor catches; or a case file whose first line
declares the verdict it expects; or a position in the condition table.
Run the gate: a `NEW` row is either a defect to fix or an entry to add
with its reason, in the same change.
