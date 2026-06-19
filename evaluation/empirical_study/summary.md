# Capability-recall study, Phase 1a + 1b results

Run over 25 hand-Python / Capa pairs: the 20 Phase-1a pairs in
[`../sbom_diff/`](../sbom_diff/) (direct + via-helper) and the 5
Phase-1b pairs in [`dispatch_pairs/`](dispatch_pairs/) (via-dispatch
+ via-data indirection, where the sink is selected at runtime through
a callable or a data table). Unit: one `(python_function, capability)`
fact. Regenerate with
`.venv/Scripts/python evaluation/empirical_study/run_study.py`
(requires the isolated semgrep venv; see [`README.md`](README.md)).

The study asks **two distinct questions** and scores all treatments by
the **same criterion** within each. They are reported in separate
tables and are **never** collapsed into a single number, because a
treatment can do well on one and badly on the other.

## The headline: false-clearance under closed-world SBOM semantics (Q2)

An SBOM is a **closed list**: what is not listed for a function is
implicitly **excluded**. Under that reading, a treatment commits a
**false-clearance** for a true fact `(F, C)` when it gives the consumer
no way to know `F` can exercise `C`. **Lower is better.**

| Treatment | False-clearances | of 48 |
|---|---|---|
| T1 dependency / PURL SBOM (package granularity) | **48 / 48** | clears every function (no per-function granularity at all) |
| T2 good-faith pattern heuristic (Semgrep) | **12 / 48** | clears every fact it cannot see (absence = exclusion) |
| T2b dataflow (CodeQL) | *pending (Phase 1c)* | |
| **T3 Capa by construction** | **0 / 48** | clears nothing it has not **soundly proved** absent |

This is the real argument for Capa. Capa's manifest gives each `(F, C)`
**three** states - *reachable*, *provably-excluded* (sound, proved in
Agda), or *not-determined* - and a false-clearance can only arise from
the provably-excluded state. Because that state is **sound** (used ⊆
declared; used ∩ provably-excluded = ∅), it never contains an axis the
function actually exercises. The ten dispatcher facts land in
*not-determined*, not *excluded*, so Capa clears nothing: **0
false-clearances by construction**. The heuristic, read closed-world,
clears all 12 facts it misses.

A skeptic could ask whether it is fair to give Capa an exclusion field
and deny one to Semgrep. The honest answer: a consumer who **ignored**
`provably_excluded` and read Capa's `reachable = []` closed-world -
exactly the only reading available for Semgrep's output, where absence =
exclusion - would **also** false-clear all ten dispatchers. What
separates Capa is not a softer scoring rule applied to it: it is that
Capa **offers** a *sound* exclusion channel (`provably_excluded`, with an
explicit *provably-excluded* vs *not-determined* distinction) a consumer
can rely on, while Semgrep's native output carries only positive
detections and no sound way to answer the exclusion question. The
per-treatment difference in how the rule is worded is a consequence of
the different output formats, not a scoring bias.

## The modest result: positive-attribution recall (Q1)

Does the treatment attribute `C` to the **named** function `F`?
Identical criterion for all three: `C` appears in the treatment's output
**for `F`** (not merely somewhere in the pair).

| Treatment | Positive attribution | Recall |
|---|---|---|
| T1 dependency / PURL SBOM (package granularity) | 0 / 48 | 0.0 % |
| T2 good-faith pattern heuristic (Semgrep) | 36 / 48 | 75.0 % |
| T2b dataflow (CodeQL) | *pending (Phase 1c)* | *pending* |
| T3 Capa by construction | **38 / 48** | **79.2 %** |

**On positive attribution Capa does NOT dramatically beat the
good-faith heuristic.** The two-fact edge (38 vs 36) is the two
`via-helper` facts, where the helper's authority sits on the caller's
Capa type. On the **ten dispatcher facts Capa attributes nothing**: it
does not vouch which handler a dispatcher runs, so it does not credit
the dispatcher with the handler's authority. The Q1 story is **parity**:
Capa's advantage is **not** attributing more - it is **never clearing a
function incorrectly** (Q2).

> An earlier version of this harness reported Capa at 48/48 (100 %) on a
> single "recall" column. That was a measurement artefact of an
> **asymmetric** scoring rule: Capa was credited at pair-level axis
> coverage (any function in the pair reaching the axis credited the
> dispatcher), while the heuristic was scored by positive attribution to
> the named function. Juxtaposing that "100 %" with the heuristic's
> "75 %" implied Capa positively attributes the capability to the
> dispatcher, which is false. The harness now scores both questions by
> the same per-function criterion; the honest Q1 number is 38/48.

## The spectrum (the structure of Phase 1b)

The study separates three regimes by how the authority is reached. The
columns show **Q1 (attributes?)** and **Q2 (false-clears?)** for the
pattern heuristic versus Capa.

| Regime | `how` | T2 attributes? (Q1) | T2 false-clears? (Q2) | T3 attributes? (Q1) | T3 false-clears? (Q2) |
|---|---|---|---|---|---|
| **direct** | `direct` | yes (sink is lexical) | no | yes | no |
| **via-helper** | `via-helper` | no | **yes** | **yes** (on caller's type) | no |
| **via-dispatch / via-data** | `via-dispatch`, `via-data` | no | **yes** | no (not vouched) | **no** (not-determined, sound) |

* On **direct** facts the heuristic ties Capa on Q1 and neither
  false-clears.
* On **via-helper** facts the heuristic misses and (closed-world)
  false-clears; Capa attributes the fact (the helper's authority is on
  the caller's type) and false-clears nothing. A dataflow tool would
  also attribute these by following the local call edge (Phase 1c).
* On **via-dispatch / via-data** facts **neither** the heuristic nor
  Capa positively attributes the dispatcher - but the heuristic
  **false-clears** it under closed-world semantics, while Capa reports
  *not-determined* and **false-clears nothing**. This is the crux: the
  separation is in Q2, not Q1.

## Per-pair results

Positive attribution (Q1) and false-clearances (Q2, lower is better):

| Pair | Corpus | GT | Q1 T1 | Q1 T2 | Q1 T3 | Q2 T1 | Q2 T2 | Q2 T3 |
|---|---|---|---|---|---|---|---|---|
| colorama | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| command_registry | 1b | 4 | 0/4 | 2/4 | **2/4** | 4/4 | 2/4 | **0/4** |
| config_loader | 1a | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 |
| csv_parser | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| disk_cache | 1a | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 |
| dotenv | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 |
| env_loader | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |
| event_bus | 1b | 4 | 0/4 | 2/4 | **2/4** | 4/4 | 2/4 | **0/4** |
| glob_walker | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |
| http_retry | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 |
| humanize | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| ini_loader | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |
| log_forwarder | 1a | 3 | 0/3 | 2/3 | **3/3** | 3/3 | 1/3 | **0/3** |
| middleware_chain | 1b | 4 | 0/4 | 2/4 | **2/4** | 4/4 | 2/4 | **0/4** |
| pathspec | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| rate_limiter | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 |
| reflect_dispatch | 1b | 4 | 0/4 | 2/4 | **2/4** | 4/4 | 2/4 | **0/4** |
| secret_rotator | 1a | 4 | 0/4 | 4/4 | 4/4 | 4/4 | 0/4 | 0/4 |
| session_token | 1a | 4 | 0/4 | 3/4 | **4/4** | 4/4 | 1/4 | **0/4** |
| short_uuid | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |
| slugify | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| tabulate | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| tagged_factory | 1b | 4 | 0/4 | 2/4 | **2/4** | 4/4 | 2/4 | **0/4** |
| textwrap | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| url_fetch | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 |

On each Phase-1b pair Q1 T2 = Q1 T3 = 2/4 (both attribute the two
`direct` handler facts, neither attributes the two dispatcher facts);
the difference is Q2, where T2 false-clears 2/4 and Capa 0/4.

## Distinguishing facts (a treatment fails to attribute)

| Pair | Function | Capability | Cause | T2 attr | T3 attr | T2 false-clears | T3 false-clears | Dataflow resolves? | T2b (literal) |
|---|---|---|---|---|---|---|---|---|---|
| command_registry | dispatch | Net | via-dispatch | no | no | **yes** | no | no | pending |
| command_registry | dispatch | Fs | via-dispatch | no | no | **yes** | no | no | pending |
| event_bus | emit | Fs | via-dispatch | no | no | **yes** | no | no | pending |
| event_bus | emit | Net | via-dispatch | no | no | **yes** | no | no | pending |
| log_forwarder | forward_log | Fs | via-helper | no | **yes** | **yes** | no | yes | pending |
| middleware_chain | run_pipeline | Env | via-dispatch | no | no | **yes** | no | no | pending |
| middleware_chain | run_pipeline | Fs | via-dispatch | no | no | **yes** | no | no | pending |
| reflect_dispatch | dispatch | Fs | via-dispatch | no | no | **yes** | no | no | pending |
| reflect_dispatch | dispatch | Net | via-dispatch | no | no | **yes** | no | no | pending |
| session_token | generate_token | Random | via-helper | no | **yes** | **yes** | no | yes | pending |
| tagged_factory | run_action | Fs | via-data | no | no | **yes** | no | no | pending |
| tagged_factory | run_action | Net | via-data | no | no | **yes** | no | no | pending |

Every row has `T3 false-clears = no`: the soundness guarantee made
visible. The two `via-helper` rows show `T3 attr = yes` (Capa carries
the helper's authority on the caller's type); the ten dispatcher rows
show `T3 attr = no` **and** `T3 false-clears = no` (not-determined, not
excluded). T2 false-clears all 12.

The `dataflow_would_resolve` column is the conservative **class-level**
expectation. The **per-pair** CodeQL expectation is finer and is
recorded in each Phase-1b pair's README, because a constant function
table (`command_registry`) is points-to-resolvable while a name from
external input (`reflect_dispatch`, `tagged_factory`) is not. The
`t2b_codeql` slot in [`false_negatives.csv`](false_negatives.csv) is
`pending` until a literal CodeQL run fills it in Phase 1c, **for both
questions**.

### Per-pair CodeQL expectation (recorded, not yet run)

| Pair | Indirection | CodeQL expectation | Why |
|---|---|---|---|
| command_registry | via-dispatch, constant dict | **likely resolves** | `HANDLERS = {...}` is a constant table; points-to enumerates its values |
| middleware_chain | via-dispatch, runtime list | **split** | literal default list is resolvable; a configuration-assembled stack is not |
| event_bus | via-dispatch, mutable list | **likely loses** | subscribers arrive via runtime `append`; the list contents cross the bus boundary |
| reflect_dispatch | via-dispatch, computed name | **loses** | target is `getattr(self, "handle_" + msg_type)`; no value to follow |
| tagged_factory | via-data, deserialized tag | **loses** | handler chosen by `json.loads(raw)["type"]`; the key is external data |

This is the **spectrum** the corpus exists to show: dispatch through a
constant table is within dataflow's reach, while dispatch through a
computed name or a deserialized tag is not. We surface both ends
honestly rather than only the cases where Capa wins.

## Corpus distribution

| Category | Count | Pairs |
|---|---|---|
| Pure (zero capability facts) | 7 | colorama, csv_parser, humanize, pathspec, slugify, tabulate, textwrap |
| Purely direct (T2 ties Capa on Q1) | 11 | config_loader, disk_cache, dotenv, env_loader, glob_walker, http_retry, ini_loader, rate_limiter, secret_rotator, short_uuid, url_fetch |
| Indirection, via-helper (dataflow resolves) | 2 | log_forwarder, session_token |
| Indirection, via-dispatch / via-data (needs types) | 5 | command_registry, event_bus, middleware_chain, reflect_dispatch, tagged_factory |

## What this corpus now establishes

**Establishes:**

- A capability-aware per-function SBOM is a strict **granularity** gain
  over a dependency SBOM: T1 attributes 0/48 per-function facts (Q1) and
  false-clears all 48 (Q2).
- On **positive attribution (Q1) Capa ties the good-faith heuristic**
  (38/48 vs 36/48). The honest message is parity: Capa is sound, not
  omniscient, and does not vouch which handler a dispatcher runs.
- The decisive result is **false-clearance (Q2)**: Capa commits **0
  false-clearances** under closed-world SBOM semantics, against 12 for
  the heuristic and 48 for the dependency SBOM. Capa never clears a
  function incorrectly because it distinguishes *provably-excluded*
  (sound, proved in Agda: used ⊆ declared, used ∩ provably-excluded = ∅)
  from *not-determined*. The dispatcher functions (`dispatch`, `emit`,
  `run_action`, `run_pipeline`) report `provably_excluded = []`, so no
  axis is cleared -- the honest record that their authority depends on
  what was registered into the table they receive.

**Still pending (Phase 1c):**

- The **literal** CodeQL verdict on each distinguishing fact, for
  **both** questions. The expectation is that CodeQL attributes (Q1) and
  avoids false-clearing (Q2) the via-helper facts and the constant-table
  dispatch (`command_registry`), but loses the computed-name and
  deserialized-tag facts (`reflect_dispatch`, `tagged_factory`) where
  only the type-carried capability still avoids the false-clearance. The
  `t2b_codeql` column is wired and waiting.
