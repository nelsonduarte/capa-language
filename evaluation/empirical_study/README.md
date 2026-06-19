# Capability-recall study (Phases 1a + 1b)

This harness measures how well three different treatments recover
per-function capability facts from a corpus of real-world-shaped Python
libraries, and scores each treatment against an auditable ground truth.

It is the quantitative core of the NLnet empirical study. It runs over
**two corpus roots**:

- **Phase 1a**: the 20-pair corpus in [`../sbom_diff/`](../sbom_diff/),
  whose authority is reached by `direct` calls or a local `via-helper`.
- **Phase 1b**: the 5-pair corpus in
  [`dispatch_pairs/`](dispatch_pairs/), whose authority is reached
  through **dynamic dispatch or data** -- the call target is selected
  at runtime by a callable looked up in a table, a name computed from
  input, or a tag read from deserialized data. This is the indirection
  a pattern heuristic cannot see and that interprocedural dataflow
  resolves only at the easy (constant-table) end.

Phase 1c (see *Pending* below) adds CodeQL as a literal dataflow layer.

## Unit of recall

One fact = a pair `(python_function, capability)`. A treatment "recovers"
a fact if it attributes that capability to that function. Capabilities
are Capa's axes: `Fs`, `Net`, `Clock`, `Env`, `Random`, `Proc`, `Stdio`.

The ground truth lives in [`ground_truth.csv`](ground_truth.csv) with a
`how` column recording how each function reaches the capability:

| `how` | meaning | corpus |
|---|---|---|
| `direct` | the sink API call is lexically inside the function body | 1a + 1b handlers |
| `via-helper` | the function reaches the sink only by calling another **local** function that holds it | 1a (`log_forwarder`, `session_token`) |
| `via-dispatch` | the sink is selected at runtime through a **callable** (a function value looked up in a table / list, or a method resolved by a computed name) | 1b (`command_registry`, `event_bus`, `reflect_dispatch`, `middleware_chain`) |
| `via-data` | the sink is selected through a **data tag** read from (de)serialized input that keys a handler table | 1b (`tagged_factory`) |

### How the ground truth was derived and validated

The ground truth is the honesty surface of the whole study, so it was
built semi-automatically and then **read by hand against every
`naive.py`**:

1. **`direct` facts** come from the Semgrep good-faith ruleset
   ([`rules/capability_rules.yaml`](rules/capability_rules.yaml)):
   each sink hit is attributed to its lexically-enclosing function.
2. **`via-helper` facts** come from an intra-file call-graph analysis
   of `naive.py` (`ast`): a function that reaches a capability **only**
   by calling a local helper that holds the sink.
3. Both were **cross-checked against the Capa manifest** of the
   `capa.capa` side (`declared_capabilities` = sink on the function;
   `transitively_reachable_capabilities` = reachable through the call
   graph) to anchor the axis set per pair.
4. **`via-dispatch` / `via-data` facts** (Phase 1b) are the authority a
   `naive.py` dispatcher reaches **transitively** when it invokes the
   handler that the runtime callable / data tag selects. Each was read
   by hand: the handler genuinely exercises the capability (a real
   `open` / `urlopen` / `os.environ.get`), and the dispatcher reaches
   it ONLY through the runtime-selected call (no sink is lexically in
   the dispatcher's body). The fact is attributed to the dispatcher
   because calling it can exercise that authority; the handler's own
   `direct` fact is recorded separately. On the Capa side these are
   cross-checked against the manifest: the handler / factory functions
   carry the capability in their signature, and the dispatcher
   functions (`dispatch`, `emit`, `run_action`, `run_pipeline`) report
   `transitively_reachable_capabilities = []` **and**
   `provably_excluded_capabilities = []` -- Capa declines to vouch the
   dispatcher is capability-free, which is the honest record that its
   authority depends on what was registered into the table it receives.
5. Every fact was then confirmed by reading the corresponding
   `naive.py` by hand. Divergences between the prose READMEs / the Capa
   side and what the Python code actually does are recorded under
   *Known divergences* below; the ground truth follows the **Python
   code that is being scored**, not the prose.

The 7 pure pairs (`colorama`, `csv_parser`, `humanize`, `pathspec`,
`slugify`, `tabulate`, `textwrap`) contribute **zero** facts by design:
no function in them exercises any capability. They are kept in the run so
the distribution count over all 25 pairs is honest.

## The three treatments

### T1 dependency / PURL SBOM (package granularity)
The corpus is **stdlib-only**: no `requirements.txt`, no installed
third-party packages. A real PyPI SBOM emitted by **Syft / cdxgen would
therefore be empty** (those tools scan package manifests and installed
dist-info, of which there are none here). To give T1 the most generous
possible reading, we use the **module-level imports** of each `naive.py`,
intersected with a capability-bearing-module allowlist, as the T1 proxy.
This is strictly more than Syft would report, and it is still
**package-granular**: it can say "this file imports `os`", never "this
function uses `Fs`". Per-function recall for T1 is therefore **0 by
construction**. That zero is a statement about **granularity**, not a
detection failure: T1 simply answers a coarser question.

> Syft was not run because a stdlib-only single-file corpus produces an
> empty Syft component list by definition; the import proxy is the
> charitable upper bound. The Phase-1b dispatch pairs are also
> stdlib-only, so the same import-proxy reading applies to them; a
> literal Syft run becomes meaningful only once the corpus grows pairs
> with real PyPI dependencies.

### T2 good-faith pattern heuristic (Semgrep)
The ruleset in [`rules/capability_rules.yaml`](rules/capability_rules.yaml)
is the **best reasonable line-level pattern set** a competent reviewer
would write (it even covers `os.path.exists` / `getmtime` probes that a
thin ruleset would miss). Each sink hit is attributed to its
lexically-enclosing function. **This is the honest line-level reading:**
it captures every `direct` fact but cannot see a capability reached only
through a helper call (`via-helper`), a runtime-selected callable
(`via-dispatch`), or a data tag (`via-data`).

### T3 Capa by construction
The per-function manifest from `python -m capa --manifest`. Capa
attributes every capability a function can reach (declared +
transitively reachable) by construction. Because Capa's type system
forbids reaching a capability that is not on a function's signature, axis
coverage from the manifest is a faithful, non-inflated reading of what
the Capa SBOM asserts.

## Honesty statement (read this before reading the numbers)

- **On direct calls, the pattern heuristic ties Capa.** Capa does **not**
  win on the easy cases. For every `direct` fact, T2 and T3 both score.
- **The T2 gap is entirely in indirection.** Every fact T2 misses is a
  `via-helper`, `via-dispatch`, or `via-data` fact (see
  [`false_negatives.csv`](false_negatives.csv)). T2 never misses a
  direct fact.
- **The gap is not uniform, and we say so.** The 2 `via-helper` misses
  are dataflow-resolvable: an interprocedural tool (CodeQL) follows the
  local call edge. The 10 `via-dispatch` / `via-data` misses (Phase 1b)
  are where the target is chosen at runtime; here only the type-carried
  capability is expected to recover the fact, except at the
  constant-table end (`command_registry`) which dataflow can still
  enumerate. The per-pair CodeQL expectation is recorded in each
  Phase-1b README and confirmed in Phase 1c.
- **The gap versus T1 is granularity, not detection.** T1 recovers 0
  per-function facts because a dependency SBOM is package-granular, not
  because it "fails to detect" anything. Comparing T1 to T2/T3 is a
  per-function-vs-per-package comparison, and we say so explicitly.
- No straw man: the T2 ruleset is deliberately strong so that any miss is
  structural, not a thin-ruleset artefact; and the Phase-1b dispatchers
  genuinely exercise the authority (the handlers do real I/O), so the
  `via-dispatch` / `via-data` facts are not invented.

## Known divergences (recorded, not papered over)

- **`disk_cache`**: the `capa.capa` side declares `cache_set: Fs + Clock`
  and the pair README repeats that, but `naive.py`'s `cache_set` only
  writes the file (`Fs`); it makes **no** clock read. The ground truth
  follows the Python code (`cache_set` -> `Fs` only). This is a Capa-side
  over-declaration relative to the scored Python, not a study bug; it is
  noted here for the audit trail.

## Outputs

Running the harness writes three CSVs next to it:

- [`per_pair.csv`](per_pair.csv) - one row per pair: ground-truth count
  and T1 / T2 / T3 recall (count and percent).
- [`aggregate.csv`](aggregate.csv) - totals and recall percentage per
  treatment.
- [`false_negatives.csv`](false_negatives.csv) - every fact T2 misses,
  with its `how` cause, the conservative class-level
  `dataflow_would_resolve` flag (`via-helper` yes; `via-dispatch` /
  `via-data` no), and a `t2b_codeql` column for the **literal** CodeQL
  verdict (`pending` until Phase 1c runs it). The finer per-pair CodeQL
  expectation lives in each Phase-1b pair's README, since a constant
  function table is points-to-resolvable while a computed name or a
  deserialized tag is not.

[`summary.md`](summary.md) is the human-readable writeup of one run.

## Reproducing

The harness uses **two interpreters on purpose**:

- The **compiler venv** (`.venv`) runs this script and `python -m capa`
  for T3.
- A **dedicated, isolated semgrep venv** runs T2. Semgrep's install
  downgrades several shared dependencies, so it must never be installed
  into the compiler venv. The isolated venv is git-ignored and recreated
  on demand:

```sh
# from the repo root, one-time setup of the isolated semgrep venv:
python -m venv evaluation/empirical_study/.semgrep-venv
evaluation/empirical_study/.semgrep-venv/Scripts/python -m pip install semgrep==1.167.0

# run the study (uses the compiler venv for capa, the isolated venv for semgrep):
.venv/Scripts/python evaluation/empirical_study/run_study.py
```

`run_study.py` locates the isolated semgrep binary itself
(`.semgrep-venv/Scripts/semgrep` on Windows, `.semgrep-venv/bin/semgrep`
on POSIX) and shells out to it; it never imports semgrep.

The harness is deterministic: every list is sorted, and semgrep and capa
are pure functions of their input files.

### Tests

```sh
.venv/Scripts/python -m pytest evaluation/empirical_study/test_run_study.py -q
```

The unit tests cover the pure pieces (ground-truth integrity, AST
attribution, T1 extraction, scoring arithmetic, false-negative
classification) and run with **no** semgrep or capa subprocess, so they
pass in CI without the isolated venv.

## The Phase-1b dispatch corpus

[`dispatch_pairs/`](dispatch_pairs/) holds 5 pairs covering the
indirection spectrum, from dataflow-resolvable to opaque. Each pair has
a `naive.py` whose dispatcher GENUINELY reaches the authority (the
handlers do real `open` / `urlopen` / `os.environ.get`), a faithful
`.capa` transliteration that keeps the SAME dispatch mechanism, and a
README with provenance, ground-truth, and a per-pair CodeQL expectation.

| Pair | Pattern | `how` | Provenance | CodeQL expectation (Phase 1c) |
|---|---|---|---|---|
| [`command_registry`](dispatch_pairs/command_registry/) | constant `{name: handler}` dict, runtime key | via-dispatch | CLI subcommand / URL routers | likely **resolves** (constant table) |
| [`event_bus`](dispatch_pairs/event_bus/) | callbacks in a list, registered at runtime, invoked in a loop | via-dispatch | signals, `pluggy`, webhooks, observer | likely **loses** (mutable list) |
| [`reflect_dispatch`](dispatch_pairs/reflect_dispatch/) | `getattr(self, "handle_" + name)` | via-dispatch | xmlrpc / `cmd.Cmd` / JSON-RPC / visitors | **loses** (computed name) |
| [`tagged_factory`](dispatch_pairs/tagged_factory/) | handler chosen by a tag in deserialized data | via-data | JSON-RPC method, pickle / YAML tags | **loses** (external data) |
| [`middleware_chain`](dispatch_pairs/middleware_chain/) | pipeline of stages assembled at runtime | via-dispatch | WSGI / ASGI middleware, data pipelines | **split** (literal vs config-assembled) |

`reflect_dispatch` records the one honest structural difference: Capa
has **no reflection** (no `getattr`), so the faithful equivalent keeps
the defining property -- a call target selected by a runtime-computed
name -- by indexing a `Map<String, Fun>` with the same computed string,
closed-world over the registered table instead of open-world over every
attribute. That absence is itself the security property.

## Status and pending phases

| Phase | Scope | Status |
|---|---|---|
| **1a** | recall over the 20-pair `sbom_diff` corpus (direct + via-helper) | **done** |
| **1b** | add 5 pairs with **genuine dispatch / data indirection** (sink chosen via a callable, a computed name, or a data tag) | **done** ([`dispatch_pairs/`](dispatch_pairs/)) |
| 1c | add **CodeQL** as a dataflow layer (T2b) to confirm it resolves `via-helper` and the constant-table dispatch but not the computed-name / deserialized-tag facts | pending (the `t2b_codeql` slot is wired) |

**Where the corpus now stands:** the 20 Phase-1a pairs make the
**granularity** point over T1 (per-function vs per-package) and show
parity-plus-structure versus T2 on direct calls. The 5 Phase-1b pairs
add the indirection that defeats a pattern heuristic outright (T2 falls
to 75 %) and, at the opaque end, is expected to defeat interprocedural
dataflow too -- which Phase 1c will confirm with a literal CodeQL run.
The spectrum is deliberately visible: `command_registry` is the easy
(dataflow-resolvable) end and is reported as such, not hidden.
