# Capability-recall study (Phases 1a + 1b + 1c)

This harness measures, for **four** different treatments, two distinct
things about per-function capability facts over a corpus of
real-world-shaped Python libraries: whether the treatment **positively
attributes** a capability to the function that exercises it (Q1), and
whether, under **closed-world SBOM semantics**, it **false-clears** a
function that does (Q2). Each treatment is scored against an auditable
ground truth by the **same criterion** within each question.

It is the quantitative core of the NLnet empirical study. It runs over
**two corpus roots**:

- **Phase 1a**: the 20-pair corpus in [`../sbom_diff/`](../sbom_diff/),
  whose authority is reached by `direct` calls or a local `via-helper`.
- **Phase 1b**: the 5-pair corpus in
  [`dispatch_pairs/`](dispatch_pairs/), whose authority is reached
  through **dynamic dispatch or data** -- the call target is selected
  at runtime by a callable looked up in a table, a name computed from
  input, or a tag read from deserialized data. This is the indirection
  a pattern heuristic cannot see and that interprocedural dataflow loses
  across the whole spectrum, including the supposedly-easy constant
  table (measured in Phase 1c).

**Phase 1c** adds **CodeQL** as a literal interprocedural-dataflow layer
(**T2b**), run in good faith and measured over all 25 pairs. The result
is below; the headline is that CodeQL **ties Capa on Q1** (it follows
via-helper edges Semgrep misses) but **false-clears the ten dispatcher
facts on Q2**, including the constant dict the Phase-1b note had guessed
it would resolve.

## Two questions, one criterion each

One fact = a pair `(python_function, capability)`. Capabilities are
Capa's axes: `Fs`, `Net`, `Clock`, `Env`, `Random`, `Proc`, `Stdio`.

The study asks **two separate questions** and scores **all four
treatments by the same criterion within each**. They are reported in
separate columns and are never collapsed, because a treatment can do
well on one and badly on the other.

- **Q1 - positive-attribution recall.** Does the treatment attribute
  capability `C` to the **named** function `F` that exercises it?
  Identical criterion for all four: `C` appears in the treatment's
  output **for `F`** (not merely somewhere in the pair). This is a
  **modest** measure. On it Capa does **not** beat the best dataflow
  tool - it **ties** it (CodeQL and Capa both 38/48): Capa is **sound,
  not omniscient**, and like CodeQL it declines to say which handler a
  dispatcher will run, so it does not positively attribute a handler's
  authority to the dispatcher.

- **Q2 - false-clearance under closed-world SBOM semantics.** This is
  the **headline** and the real argument for Capa. Under the semantics
  of an SBOM (a **closed list**: what is not listed for a function is
  implicitly **excluded**), a treatment commits a **false-clearance**
  for a true fact `(F, C)` if it gives the consumer **no way to know `F`
  can exercise `C`**. The operational definition per treatment:
  - **T1**: no per-function granularity -> cannot distinguish functions
    -> false-clears **every** per-function fact.
  - **T2**: `C` is cleared for `F` if `C` is **absent** from the
    detections for `F` (absence = implicit exclusion under the
    closed-world reading) -> false-clears exactly the facts it misses.
  - **T2b**: identical to T2. CodeQL's native output is a set of
    positive `(function, capability)` facts with **no explicit-exclusion
    field**, so absence is the only signal it gives, read closed-world as
    exclusion -> false-clears exactly the facts it misses.
  - **T3**: Capa's manifest gives each `(F, C)` **three** states:
    *reachable* (attributed), *provably-excluded* (sound, proved in
    Agda), or *not-determined*. Capa false-clears `(F, C)` **only if `C`
    is in `F`'s `provably_excluded_capabilities` while `F` truly
    exercises `C`** - which never happens, because provably-excluded is
    sound (used ⊆ declared; used ∩ provably-excluded = ∅). For the
    dispatchers `provably_excluded = []`, so no axis is cleared:
    **zero** false-clearances. The harness **computes** this from the
    real manifest rather than asserting it.

**The result, in one line:** Capa's advantage is **not** attributing
more (Q1, where it ties the best dataflow tool exactly) - it is **never
clearing a function incorrectly** under closed-world semantics, because
it distinguishes *provably excluded* from *not determined*.

**On the format asymmetry (a fair-scoring objection).** It is reasonable
to ask whether giving Capa a `provably_excluded` field but scoring T2 /
T2b by absence is a scoring bias. It is not. A consumer who **ignored**
`provably_excluded` and read Capa's `reachable = []` closed-world -
exactly the only reading Semgrep's and CodeQL's output admit (absence =
exclusion) - would **also** false-clear all ten dispatchers. The
separation is not that the metric applies a softer rule to Capa; it is
that Capa **offers** a *sound* exclusion channel (`provably_excluded`,
with the explicit *provably-excluded* vs *not-determined* distinction) a
consumer can rely on, while both real tools' native output has only
positive detections and no sound way to answer the exclusion question at
all. The per-treatment difference in the operational rule above is a
consequence of the different output formats, not a thumb on the scale.

**Why a sound tool would have to over-approximate (and degrade).** A
dataflow analysis is tuned for **precision** and accepts
**false-negatives** to avoid noise - the right trade for bug-finding,
the wrong one for an SBOM, where the false-negative under-reports
authority. To be *sound* about runtime dispatch a tool would have to
**over-approximate**: assume `HANDLERS[name]()` may call **every** value
the container holds, every `getattr` target, every registered callback.
That is imprecise in general and **degenerates to "any capability" once
the table is populated from outside the module** (plugins, a `getattr`
on a computed name, a tag from deserialized input). Capa sidesteps the
dichotomy by carrying authority in the handler closure's **type**, so the
dispatcher's record is sound *and* precise without resolving the runtime
target. This is **not** a claim that dataflow can never recover any
single case; it is that the real tools, run in good faith, lose, and the
sound alternative is the over-approximation Capa replaces with types.

### Python <-> Capa function correspondence (Q1)

Q1 attributes a fact to the **named** function, so T3 must be scored
against the Capa function that plays the **same role** as the Python
one. Most names coincide; the dispatcher functions keep the same name
on both sides (`dispatch`, `emit`, `run_action`, `run_pipeline`). Where
the faithful `.capa` transliteration renamed a function, the mapping is
recorded **explicitly** in the `capa_function` column of
[`ground_truth.csv`](ground_truth.csv) (e.g. the Python `_fetch` handler
is `fetch_handler` in Capa; `load_config` is the orchestrator
`load_full_config`; `stage_audit` is the factory `make_audit_stage`),
so the correspondence is auditable rather than guessed.

The `how` column records how each function reaches the capability:

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

## The four treatments

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

### T2b good-faith dataflow (CodeQL)
A CodeQL interprocedural-dataflow reachability query
([`scratch_codeql/capquery/CapabilityReachability.ql`](scratch_codeql/capquery/CapabilityReachability.ql),
**CodeQL 2.25.6**, `python-all` **7.1.2**). For each function it computes
the capability axes reachable from it through CodeQL's call graph
(points-to **union** dataflow-dispatch), using CodeQL's curated sink
concepts unioned with explicit API-graph sinks. This is the **strongest
real dataflow tool** we could put on the corpus, run in good faith: it
catches **100 % of direct sinks (36/36)** and **over-attributes nothing**
(every CodeQL fact is in the ground truth). Unlike Semgrep it follows
the **local call edge**, so it recovers the two `via-helper` facts.

But it loses **every** `via-dispatch` / `via-data` fact, including the
`command_registry` constant dict: CodeQL's points-to call graph **does
not traverse a dict-subscript** `HANDLERS[name]`, a `getattr` on a
computed name, a runtime-`append`-ed callback list, or a handler chosen
by deserialized data. So on Q1 it **ties Capa at 38/48**, and on Q2 it
**false-clears the 10 dispatcher facts** (its blank-on-dispatcher output,
read closed-world, is a clearance).

The CodeQL CLI (1.3GB) and the per-pair databases are **NOT** coupled to
this harness. The facts are generated once by
[`scratch_codeql/build_facts.py`](scratch_codeql/build_facts.py) and
committed as
[`scratch_codeql/codeql_facts.csv`](scratch_codeql/codeql_facts.csv);
the harness reads only that CSV, so it stays deterministic and CI-safe
(no CodeQL in CI). See
[`scratch_codeql/REPRODUCE.md`](scratch_codeql/REPRODUCE.md) to
regenerate.

### T3 Capa by construction
The per-function manifest from `python -m capa --manifest`. For **Q1**,
Capa attributes `C` to `F` iff `C` is in `F`'s
`transitively_reachable_capabilities` (declared + reachable through the
call graph). This is scored **per named function**, against the
`capa_function` from the ground truth - **not** as pair-level axis
coverage. The honest consequence: Capa attributes the two `via-helper`
facts (the helper's authority is on the caller's type) but does **not**
attribute the ten dispatcher facts, because it does not resolve which
handler runs. So on Q1 Capa **ties CodeQL exactly** (both 38/48), and
beats Semgrep only by the two via-helper facts.

For **Q2**, the manifest's `provably_excluded_capabilities` is the sound
exclusion set (proved in Agda). Capa false-clears `(F, C)` only if `C`
is in that set while `F` truly exercises `C`; this never happens, and
the dispatchers carry `provably_excluded = []`, so Capa false-clears
**zero** facts. This is where Capa separates from **both** real tools:
Semgrep and CodeQL, read closed-world, false-clear every dispatcher fact
they cannot see (12 and 10 respectively), while Capa reports those axes
as **not-determined** (neither reachable nor provably-excluded) and
therefore clears nothing.

## Honesty statement (read this before reading the numbers)

- **On Q1 (positive attribution) Capa does NOT win - it TIES the best
  dataflow tool.** Semgrep attributes **36/48**, CodeQL **38/48**, Capa
  **38/48**. CodeQL and Capa land on the **identical** 38; the two-fact
  edge over Semgrep is the `via-helper` cases (CodeQL follows the call
  edge, Capa carries the authority on the caller's type). On the ten
  dispatcher facts **neither CodeQL nor Capa attributes anything**: Capa
  does not vouch which handler a dispatcher runs, and neither does
  CodeQL. The Q1 story is a clean **three-way parity at the top**, and we
  say so. A "100%" here would have been a measurement artefact of the
  old, asymmetric axis-coverage scoring; that has been removed.
- **The real result is Q2 (false-clearance), and there Capa is 0/48.**
  Under closed-world SBOM semantics T1 false-clears all 48, Semgrep the
  12 facts it misses, **CodeQL the 10 dispatcher facts**, and Capa
  **none** - because it distinguishes *provably-excluded* (sound) from
  *not-determined*. That zero is the guarantee: used ⊆ declared and
  used ∩ provably-excluded = ∅, proved in Agda. The separation holds
  against the best dataflow tool, not only the pattern heuristic.
- **On direct calls, all three real-ish tools tie Capa on Q1.** For
  every `direct` fact T2, T2b, and T3 all attribute. Capa does not win
  the easy cases.
- **Both real tools' Q1 gaps are entirely indirection.** Every fact they
  miss is a `via-helper`, `via-dispatch`, or `via-data` fact (see
  [`false_negatives.csv`](false_negatives.csv)); neither misses a direct
  fact. CodeQL closes the 2 `via-helper` misses Semgrep has (it follows
  the local call edge), but the 10 `via-dispatch` / `via-data` facts are
  lost by **both**, across the whole opacity spectrum from the constant
  dict down. The Phase-1b guess that CodeQL would enumerate the
  `command_registry` constant table was **wrong and is corrected**:
  CodeQL's points-to does not traverse the dict-subscript at all.
- **The gap versus T1 is granularity, not detection.** T1 attributes 0
  per-function facts (Q1) and false-clears all 48 (Q2) because a
  dependency SBOM is package-granular, not because it "fails to detect"
  anything.
- No straw man, in **either** direction: the T2 ruleset is deliberately
  strong, and the T2b CodeQL query is good-faith (100 % direct recall,
  zero over-attribution), so a dispatcher miss is CodeQL's structural
  limit and not a hole in our query; the Phase-1b dispatchers genuinely
  exercise the authority (the handlers do real I/O), so the
  `via-dispatch` / `via-data` facts are not invented.

## Known divergences (recorded, not papered over)

- **`disk_cache`**: the `capa.capa` side declares `cache_set: Fs + Clock`
  and the pair README repeats that, but `naive.py`'s `cache_set` only
  writes the file (`Fs`); it makes **no** clock read. The ground truth
  follows the Python code (`cache_set` -> `Fs` only). This is a Capa-side
  over-declaration relative to the scored Python, not a study bug; it is
  noted here for the audit trail.

## Outputs

Running the harness writes three CSVs next to it. Each carries **both
questions** side by side; a Q1 number is never presented as if it
answered Q2.

- [`per_pair.csv`](per_pair.csv) - one row per pair: ground-truth count,
  the Q1 positive-attribution columns (`q1_t1_attr` / `q1_t2_attr` /
  `q1_t2b_attr` / `q1_t3_attr`) and the Q2 false-clearance columns
  (`q2_t1_falseclear` / `q2_t2_falseclear` / `q2_t2b_falseclear` /
  `q2_t3_falseclear`, where **lower is better**).
- [`aggregate.csv`](aggregate.csv) - one row per **(question,
  treatment)**, so a reader can never mistake a Q1 count for a Q2 count.
  The `T2b_codeql` rows carry the measured Phase-1c numbers (Q1 38/48,
  Q2 10/48).
- [`false_negatives.csv`](false_negatives.csv) - every **distinguishing**
  fact (one T2, T2b, or T3 fails to attribute), with per-treatment
  `t2_attributes` / `t2b_attributes` / `t3_attributes`, the closed-world
  `t2_false_clears` / `t2b_false_clears` / `t3_false_clears` verdicts
  (note `t3_false_clears` is `no` on every row - the soundness guarantee
  made visible), the `how` cause, the conservative class-level
  `dataflow_would_resolve` flag (`via-helper` yes; `via-dispatch` /
  `via-data` no), and a `t2b_codeql` column carrying the **literal**
  CodeQL verdict (`attributes` for the 2 via-helper facts, `misses` for
  the 10 dispatcher facts). The per-pair CodeQL verdict and the reason
  it loses each dispatcher live in each Phase-1b pair's README.

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
are pure functions of their input files. **T2b CodeQL is NOT invoked by
the harness**: it reads the pre-computed
[`scratch_codeql/codeql_facts.csv`](scratch_codeql/codeql_facts.csv), so
the 1.3GB CodeQL CLI is never needed to run the study or the tests. To
regenerate the CSV (install CodeQL 2.25.6, build the 25 databases, run
the query) follow
[`scratch_codeql/REPRODUCE.md`](scratch_codeql/REPRODUCE.md).

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

| Pair | Pattern | `how` | Provenance | CodeQL verdict (Phase 1c, measured) |
|---|---|---|---|---|
| [`command_registry`](dispatch_pairs/command_registry/) | constant `{name: handler}` dict, runtime key | via-dispatch | CLI subcommand / URL routers | **LOSES** (points-to does not traverse the dict-subscript, even constant) |
| [`event_bus`](dispatch_pairs/event_bus/) | callbacks in a list, registered at runtime, invoked in a loop | via-dispatch | signals, `pluggy`, webhooks, observer | **LOSES** (runtime-`append`-ed list, not resolved in the loop) |
| [`reflect_dispatch`](dispatch_pairs/reflect_dispatch/) | `getattr(self, "handle_" + name)` | via-dispatch | xmlrpc / `cmd.Cmd` / JSON-RPC / visitors | **LOSES** (computed attribute name) |
| [`tagged_factory`](dispatch_pairs/tagged_factory/) | handler chosen by a tag in deserialized data | via-data | JSON-RPC method, pickle / YAML tags | **LOSES** (handler from external data) |
| [`middleware_chain`](dispatch_pairs/middleware_chain/) | pipeline of stages passed in as a list parameter | via-dispatch | WSGI / ASGI middleware, data pipelines | **LOSES** (stages in a list parameter, not resolved) |

The column is the **measured** Phase-1c verdict, not a guess. CodeQL
loses all five, ordered above by **opacity** (constant dict at the
least-dynamic end, deserialized tag at the most). The Phase-1b
expectation that `command_registry` would resolve was corrected: the
dict-subscript defeats points-to regardless of the dict being constant.

`reflect_dispatch` records the one honest structural difference: Capa
has **no reflection** (no `getattr`), so the faithful equivalent keeps
the defining property -- a call target selected by a runtime-computed
name -- by indexing a `Map<String, Fun>` with the same computed string,
closed-world over the registered table instead of open-world over every
attribute. That absence is itself the security property.

## Status

| Phase | Scope | Status |
|---|---|---|
| **1a** | recall over the 20-pair `sbom_diff` corpus (direct + via-helper) | **done** |
| **1b** | add 5 pairs with **genuine dispatch / data indirection** (sink chosen via a callable, a computed name, or a data tag) | **done** ([`dispatch_pairs/`](dispatch_pairs/)) |
| **1c** | add **CodeQL** as a dataflow layer (T2b), measured over all 25 pairs | **done** (ties Capa on Q1 at 38/48; false-clears the 10 dispatcher facts on Q2; corrected the `command_registry` constant-dict expectation) |

**Where the corpus now stands:** the 20 Phase-1a pairs make the
**granularity** point over T1 (per-function vs per-package). On **Q1
(positive attribution)** the best dataflow tool and Capa are at an
**exact tie** (CodeQL 38/48, Capa 38/48, Semgrep 36/48): Capa is sound,
not omniscient, and does not see more than CodeQL. The real result is
**Q2 (false-clearance)**: under closed-world SBOM semantics T1
false-clears all 48, Semgrep the 12 facts it misses, **CodeQL the 10
dispatcher facts**, and **Capa false-clears 0** because it distinguishes
*provably-excluded* from *not-determined*. The 5 Phase-1b pairs supply
the indirection that drives both real tools' Q2 false-clearances; Phase
1c confirmed with a literal CodeQL run that the best dataflow tool loses
**every** dispatcher fact across the whole opacity spectrum, including
the constant dict the Phase-1b note had wrongly expected it to resolve.
The honest framing: dataflow tools optimize precision and accept
false-negatives, which is the wrong trade for an SBOM; a sound analysis
would have to over-approximate runtime dispatch and degrade with external
targets; Capa captures the authority via types instead.
