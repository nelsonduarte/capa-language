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
| `release_differential` | instrument (d): the check half and the two-layer manifest half, run by hand between two builds, never by test discovery or CI |
| `ratchet` | the shrink-only check of the register, as a command; the CI step runs it through `scripts/instrument_ratchet.sh` |

The clause table of `absolute/_rule.py` is the code form of the
language's evaluation-order rule,
[`specs/09-expressions-and-control.md`](../../specs/09-expressions-and-control.md)
section 9: operands and arguments are evaluated in written order,
exactly once, with short-circuit, only the chosen branch or arm, a
lambda body per call, a `while` condition per iteration and a `for`
iterable once. The oracle compares every execution path it runs with
that rule, not with another backend.

## Running them

```bash
python -m unittest discover tests                      # the whole suite, instruments included
python -m unittest discover -s tests/instruments -t .  # the instruments alone
python -m unittest tests.instruments.test_selfcheck -v # one module
```

The instruments alone are 116 tests; on the development machine
(win32, with the Wasm toolchain installed, so no leg skipped) they took
108 s.

The strict condition-position family lives with the other implicit-flow
enumerations in `tests/implicit_flow/_generated.py`; its gate is
`test_strict_positions`. `_positions` is the one place that adds a
private extension's positions and writes the programs, for that gate
and for the seeded corpus of `release_differential`.

## The register

`tests/instrument_register.json` holds every outcome the suite knows is
not `CORRECT` today, keyed `<instrument>|<file>#<program hash>|<leg>`
with a one-line reason and the programme step expected to close it. The
gate diffs each run against it:

- `FIXED`: a registered member now reads `CORRECT`. Delete the entry (and,
  for a stdlib program, promote it to `_AGREEING`).
- `CHANGED`: a different wrong answer. Re-measure; never re-pin silently.
- `NEW`: an unregistered wrong answer: a defect the register does not
  know. An entry added for it turns this test green but fails the
  ratchet below; the register has no declared way to take in a new
  defect.
- `REGRESSION`: a member stopped running (`REFUSED` / `TIMEOUT` / `BROKEN`
  / `VOID`) without being registered as exactly that. Never a fix.
- `STALE` / `REGENERATED`: the registered program is gone, or its text
  changed. A regenerated program cannot inherit an entry.

An entry's fields are `outcome`, `reason` and `closes_in`; a stdlib
entry adds `vectors` (the observation of every leg) and `pins`. Loading
the file refuses an entry whose outcome is not one of the outcome
types, an entry that registers `CORRECT`, and a stdlib entry whose
outcome is not the key of its vectors.

The register may only shrink. `scripts/instrument_ratchet.sh` compares it,
entry by entry, with the register of the base of the pushed range (the
`before` sha of a push, the base sha of a pull request); an added or
re-described entry fails unless the entry declares itself a `REVEAL` or
a `REGENERATED` member. The first landing is a bootstrap and says so.
So the ways an entry changes are:

- **Remove** it when the gate reports `FIXED`, or when its program is
  gone (`STALE`). The ratchet always accepts a removal; if the member is
  still wrong, the next run reports it `NEW`.
- **Reveal**: a `BROKEN` member whose gap closed and that now reads
  `WRONG`. Keep the key, set the new outcome, and add
  `"accepted_as": "REVEAL"` with `"from_outcome"` equal to the base
  outcome.
- **Regenerate**: the same file, leg and outcome under a new program
  hash. Replace the entry by one under the new key with
  `"accepted_as": "REGENERATED"` and `"from_member"` naming the base key.
- Any other added entry, and any other change of outcome, fails the
  ratchet.

Run it by hand against a base register file, or against a commit the
way CI does:

```bash
python -m tests.instruments.ratchet --base <base register file, or NONE> --candidate tests/instrument_register.json
scripts/instrument_ratchet.sh <base commit sha>
```

Measured on this register (19 entries): against itself, `GREEN
added=0 re-described=0 removed=0 accepted=0`, exit 0; against `NONE`,
`BOOTSTRAP: no base register; the candidate (19 entries) is the first`,
exit 0; with one entry removed, `GREEN ... removed=1`, exit 0; with a
planted added entry, `RED added=1`, exit 1; with one outcome changed
and no declaration, `RED ... re-described=1`, exit 1; with the same
change declared as a `REVEAL` of a `BROKEN` entry, `GREEN ...
accepted=1`, exit 0.

The CI step runs `scripts/instrument_ratchet.sh` as a command, so the
script must be committed with the executable bit.
`tests/test_workflow_scripts_executable.py` guards that for every path
a workflow step runs as a command; what it reads in a step is specified
only by its probe table, `READER_PROBES`.

The words of an instrument (a) entry are checked too. `absolute/_reasons`
holds the one table of reasons: each row gives the exact text, its
`closes_in`, the legs and outcome type it may describe, the program-body
shapes it claims (read from the parsed body, the shared header stripped)
and the observation it claims on the leg. `test_absolute` checks every
public entry against its row on each run; `test_reasons` pins the walker
on anchors whose shapes are known by hand and shows each clause of the
check biting.

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
voids its rows. The evaluator self-test plants one-clause errors in the
evaluator (``absolute/_evaluator_mutants.MUTANTS``, nineteen in the public
configuration) and requires each to fail a hand-written anchor.

## Where the legs run

- The `test` matrix (no Wasm toolchain): the check and IR legs over the
  corpora, anchors and controls, the route sample of `capa --ir --run`
  (every anchor program plus the first ten of each generated corpus: 69
  programs, about 0.3 s each on the development machine), the Python legs
  of the twins, the condition-position family, and the ratchet step on one
  leg.
- The `wasi` job: the Wasm leg and `--wasm --run` sample, and the Wasm leg
  of the twins. Both classes are named in `tests/test_wasm_harness_present.py`,
  so a skip there is a loud failure.

Measured on the development machine (win32, sequential): the check and IR
legs over 309 programs take about 10 s, the Wasm leg about 13 s, each
route sample about 21 s, the twins about 3 s per backend set; the whole
`test_absolute` module (both leg classes) about 77 s. The bound is a
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

## Running the release differential

Instrument (d) is a command, not a test module. It takes two trees (the
previous build and the candidate, each a repository checkout or
archive) and the corpus directories whose `*.capa` files it runs; it
adds the strict condition-position family as its seeded negative
corpus unless `--no-seeded` is given:

```bash
python -m tests.instruments.release_differential <base tree> <candidate tree> <corpus dir>... [--work <dir>] [--no-seeded]
```

It prints one summary line and up to 40 moved items, and exits 1 when
anything moved. Its output names files and diagnostics. No CI job and
no script in this repository runs it today; running it between the
last release and a candidate is a manual step.

The child process that measures a tree imports `tests/instruments` and
`tests/implicit_flow` from that tree, so both trees must contain them.
A tree without them reads `VOID` on every row and the verdict is `RED`
for that reason alone. Measured on the development machine, with five
`examples/` programs as the corpus plus the seeded family (26
programs):

| base tree | result |
|---|---|
| the candidate itself | `files=31 rc_moves=0 lost_diagnostics=0 gained_diagnostics=0 manifest_facts=0 authority_changes=0 verdict=GREEN`, exit 0, 17 s |
| an archive of `v1.32.0` as released | `rc_moves=31`, every base row `VOID`, exit 1 |
| the same archive with the candidate's `tests/instruments` and `tests/implicit_flow` copied in | `rc_moves=0 lost_diagnostics=0 gained_diagnostics=0`, `manifest_facts=18` (one manifest field that 1.32.0 does not write), exit 1 |

## Adding a member

Add the construct to the grammar (a kind with the clauses it exercises),
an anchor whose expectation is written by hand from the clause, and an
evaluator mutant the anchor catches; or a case file whose first line
declares the verdict it expects; or a position in the condition table.
Run the gate. A `NEW` row is a defect the register does not know: an
entry added for it fails the ratchet (see "The register").
