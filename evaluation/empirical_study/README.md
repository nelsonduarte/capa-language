# Capability-recall study (Phase 1a)

This harness measures how well three different treatments recover
per-function capability facts from a corpus of real-world-shaped Python
libraries, and scores each treatment against an auditable ground truth.

It is the quantitative core of the NLnet empirical study. **Phase 1a**
runs over the **existing 20-pair corpus** in
[`../sbom_diff/`](../sbom_diff/). Phases 1b and 1c (see *Pending* below)
extend the corpus and the toolset where this corpus cannot reach.

## Unit of recall

One fact = a pair `(python_function, capability)`. A treatment "recovers"
a fact if it attributes that capability to that function. Capabilities
are Capa's axes: `Fs`, `Net`, `Clock`, `Env`, `Random`, `Proc`, `Stdio`.

The ground truth lives in [`ground_truth.csv`](ground_truth.csv) with a
`how` column recording how each function reaches the capability:

| `how` | meaning |
|---|---|
| `direct` | the sink API call is lexically inside the function body |
| `via-helper` | the function reaches the sink only by calling another **local** function that holds it |
| `via-dispatch` | the sink is selected at runtime through a callable (not in this corpus) |
| `via-data` | the sink is selected through a data table / registry (not in this corpus) |

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
4. Every fact was then confirmed by reading the corresponding
   `naive.py` by hand. Divergences between the prose READMEs / the Capa
   side and what the Python code actually does are recorded under
   *Known divergences* below; the ground truth follows the **Python
   code that is being scored**, not the prose.

The 7 pure pairs (`colorama`, `csv_parser`, `humanize`, `pathspec`,
`slugify`, `tabulate`, `textwrap`) contribute **zero** facts by design:
no function in them exercises any capability. They are kept in the run so
the distribution count over all 20 pairs is honest.

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
> charitable upper bound. Phase 1b, which adds pairs with real PyPI
> dependencies, is where a literal Syft run becomes meaningful.

### T2 good-faith pattern heuristic (Semgrep)
The ruleset in [`rules/capability_rules.yaml`](rules/capability_rules.yaml)
is the **best reasonable line-level pattern set** a competent reviewer
would write (it even covers `os.path.exists` / `getmtime` probes that a
thin ruleset would miss). Each sink hit is attributed to its
lexically-enclosing function. **This is the honest line-level reading:**
it captures every `direct` fact but cannot see a capability reached only
through a helper call.

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
  `via-helper` fact (see [`false_negatives.csv`](false_negatives.csv)).
- **The gap versus T1 is granularity, not detection.** T1 recovers 0
  per-function facts because a dependency SBOM is package-granular, not
  because it "fails to detect" anything. Comparing T1 to T2/T3 is a
  per-function-vs-per-package comparison, and we say so explicitly.
- No straw man: the T2 ruleset is deliberately strong so that any miss is
  structural, not a thin-ruleset artefact.

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
  with its `how` cause and whether an interprocedural **dataflow** tool
  (e.g. CodeQL) would resolve it. `via-helper` is dataflow-resolvable;
  `via-dispatch` / `via-data` are not (they need the type system).

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

## Status and pending phases

| Phase | Scope | Status |
|---|---|---|
| **1a** | recall over the existing 20-pair corpus | **done** (this directory) |
| 1b | add pairs with **genuine dispatch / data indirection** (sink chosen via a callable or a data table) where Capa wins even against interprocedural dataflow | pending |
| 1c | add **CodeQL** as a dataflow layer (T2b) to show it resolves `via-helper` but not `via-dispatch` / `via-data` | pending |

**Why 1b and 1c matter:** the existing 20 pairs are overwhelmingly
`direct`-call. The only two indirect facts are `via-helper`, which a
dataflow tool would resolve. So on **this corpus alone** the strong
honest claim is the **granularity** gap over T1 (per-function vs
per-package) and the parity-plus-structure story versus T2; the
"Capa beats even dataflow" claim needs the dispatch/data pairs that 1b
adds.
