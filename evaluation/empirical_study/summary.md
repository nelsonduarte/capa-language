# Capability-recall study, Phase 1a + 1b + 1c results

Run over 25 hand-Python / Capa pairs: the 20 Phase-1a pairs in
[`../sbom_diff/`](../sbom_diff/) (direct + via-helper) and the 5
Phase-1b pairs in [`dispatch_pairs/`](dispatch_pairs/) (via-dispatch
+ via-data indirection, where the sink is selected at runtime through
a callable or a data table). Unit: one `(python_function, capability)`
fact. Four treatments: **T1** dependency / PURL SBOM, **T2** Semgrep
pattern heuristic, **T2b** CodeQL dataflow (Phase 1c), **T3** Capa by
construction. Regenerate with
`.venv/Scripts/python evaluation/empirical_study/run_study.py`
(requires the isolated semgrep venv; see [`README.md`](README.md)).

The **T2b CodeQL** treatment reads pre-computed facts from
[`scratch_codeql/codeql_facts.csv`](scratch_codeql/codeql_facts.csv)
(CodeQL **2.25.6**, `python-all` **7.1.2**), so the harness never
invokes the 1.3GB CLI and stays deterministic. Regenerate those facts
with [`scratch_codeql/REPRODUCE.md`](scratch_codeql/REPRODUCE.md).

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
| T2b good-faith dataflow (CodeQL 2.25.6) | **10 / 48** | clears the ten dispatcher facts it cannot resolve |
| **T3 Capa by construction** | **0 / 48** | clears nothing it has not **soundly proved** absent |

This is the real argument for Capa, and **adding the best real dataflow
tool sharpens it rather than dulling it.** CodeQL false-clears **10/48**:
the ten via-dispatch / via-data dispatcher facts. It does better than
Semgrep by exactly the two `via-helper` facts (it follows the local call
edge Semgrep cannot), but on the dispatchers it leaves the function
**silently blank**, and under closed-world SBOM semantics blank = cleared.
CodeQL's native output has no explicit-exclusion field, so absence is the
only signal it can give, exactly as for Semgrep.

Capa's manifest, by contrast, gives each `(F, C)` **three** states -
*reachable*, *provably-excluded* (sound, proved in Agda), or
*not-determined* - and a false-clearance can only arise from the
provably-excluded state. Because that state is **sound** (used ⊆
declared; used ∩ provably-excluded = ∅), it never contains an axis the
function actually exercises. The ten dispatcher facts land in
*not-determined*, not *excluded*, so Capa clears nothing: **0
false-clearances by construction**. Both real tools clear every
dispatcher they cannot see.

A skeptic could ask whether it is fair to give Capa an exclusion field
and deny one to Semgrep and CodeQL. The honest answer: a consumer who
**ignored** `provably_excluded` and read Capa's `reachable = []`
closed-world - exactly the only reading available for Semgrep's and
CodeQL's output, where absence = exclusion - would **also** false-clear
all ten dispatchers. What separates Capa is not a softer scoring rule
applied to it: it is that Capa **offers** a *sound* exclusion channel
(`provably_excluded`, with an explicit *provably-excluded* vs
*not-determined* distinction) a consumer can rely on, while both real
tools carry only positive detections and no sound way to answer the
exclusion question. CodeQL is the strongest dataflow tool we could put on
the same corpus, and it still leaves the dispatcher blank. The
per-treatment difference in how the rule is worded is a consequence of
the different output formats, not a scoring bias.

The structural reason CodeQL leaves the dispatcher blank is not a bug we
could file. Dataflow analyses are tuned for **precision** (bug-finding),
and they accept **false-negatives** as the price of not drowning the user
in noise. For an SBOM / least-privilege record the false-negative is
exactly the dangerous direction: it under-reports authority. A *sound*
analysis would have to **over-approximate** the runtime dispatch - assume
`HANDLERS[name]()` may call *every* value the container can hold, every
`getattr` target, every registered callback - which is imprecise in
general and **degenerates to "any capability" as soon as the table is
populated from outside the module** (plugins, `getattr` on a computed
name, a tag from deserialized input). Capa sidesteps the dichotomy: it
carries the authority in the handler closure's **type**, so the
dispatcher's record is sound *and* precise without resolving the runtime
target at all. This is not a claim that dataflow *cannot in principle*
recover any single case; it is that the real tools, run in good faith,
lose, and the sound alternative is the imprecise over-approximation Capa
replaces with types.

## The modest result: positive-attribution recall (Q1)

Does the treatment attribute `C` to the **named** function `F`?
Identical criterion for all three: `C` appears in the treatment's output
**for `F`** (not merely somewhere in the pair).

| Treatment | Positive attribution | Recall |
|---|---|---|
| T1 dependency / PURL SBOM (package granularity) | 0 / 48 | 0.0 % |
| T2 good-faith pattern heuristic (Semgrep) | 36 / 48 | 75.0 % |
| T2b good-faith dataflow (CodeQL 2.25.6) | **38 / 48** | **79.2 %** |
| T3 Capa by construction | **38 / 48** | **79.2 %** |

**On positive attribution Capa does NOT beat the best dataflow tool -
it TIES it, exactly.** CodeQL and Capa both attribute **38/48**: the 36
direct facts plus the 2 via-helper facts, and **neither** attributes any
of the 10 dispatcher facts. CodeQL follows the via-helper call edges
Semgrep misses (hence 38 vs Semgrep's 36), and Capa carries the same two
facts on the caller's type, so the two land on the identical 38. **The
crucial honesty point: Capa does NOT see more than CodeQL on Q1.** It
does not vouch which handler a dispatcher runs, so it does not credit the
dispatcher with the handler's authority - neither does CodeQL. The Q1
story is a clean **three-way parity** between the best dataflow tool and
Capa; Capa's advantage is **not** attributing more, it is **never
clearing a function incorrectly** (Q2).

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
Semgrep heuristic, the CodeQL dataflow, and Capa.

| Regime | `how` | T2 attr / fc | T2b attr / fc | T3 attr / fc |
|---|---|---|---|---|
| **direct** | `direct` | yes / no | yes / no | yes / no |
| **via-helper** | `via-helper` | no / **yes** | **yes** / no | **yes** / no |
| **via-dispatch / via-data** | `via-dispatch`, `via-data` | no / **yes** | no / **yes** | no / **no** (sound) |

* On **direct** facts all three attribute (Q1) and none false-clear (Q2).
* On **via-helper** facts Semgrep misses and (closed-world) false-clears;
  **CodeQL attributes** the fact (it follows the local call edge) and so
  does Capa (the helper's authority is on the caller's type). Neither
  CodeQL nor Capa false-clears. This is the band where dataflow earns its
  two-fact lead over the pattern heuristic, and it ties Capa exactly.
* On **via-dispatch / via-data** facts **neither** real tool nor Capa
  positively attributes the dispatcher - but **both real tools
  false-clear** it under closed-world semantics, while Capa reports
  *not-determined* and **false-clears nothing**. This is the crux: the
  separation is in Q2, not Q1, and it holds against the best dataflow
  tool, not only against the pattern heuristic.

## Per-pair results

Positive attribution (Q1) and false-clearances (Q2, lower is better):

| Pair | Corpus | GT | Q1 T1 | Q1 T2 | Q1 T2b | Q1 T3 | Q2 T1 | Q2 T2 | Q2 T2b | Q2 T3 |
|---|---|---|---|---|---|---|---|---|---|---|
| colorama | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| command_registry | 1b | 4 | 0/4 | 2/4 | 2/4 | **2/4** | 4/4 | 2/4 | 2/4 | **0/4** |
| config_loader | 1a | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| csv_parser | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| disk_cache | 1a | 3 | 0/3 | 3/3 | 3/3 | 3/3 | 3/3 | 0/3 | 0/3 | 0/3 |
| dotenv | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| env_loader | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| event_bus | 1b | 4 | 0/4 | 2/4 | 2/4 | **2/4** | 4/4 | 2/4 | 2/4 | **0/4** |
| glob_walker | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| http_retry | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| humanize | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| ini_loader | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| log_forwarder | 1a | 3 | 0/3 | 2/3 | **3/3** | **3/3** | 3/3 | 1/3 | **0/3** | **0/3** |
| middleware_chain | 1b | 4 | 0/4 | 2/4 | 2/4 | **2/4** | 4/4 | 2/4 | 2/4 | **0/4** |
| pathspec | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| rate_limiter | 1a | 2 | 0/2 | 2/2 | 2/2 | 2/2 | 2/2 | 0/2 | 0/2 | 0/2 |
| reflect_dispatch | 1b | 4 | 0/4 | 2/4 | 2/4 | **2/4** | 4/4 | 2/4 | 2/4 | **0/4** |
| secret_rotator | 1a | 4 | 0/4 | 4/4 | 4/4 | 4/4 | 4/4 | 0/4 | 0/4 | 0/4 |
| session_token | 1a | 4 | 0/4 | 3/4 | **4/4** | **4/4** | 4/4 | 1/4 | **0/4** | **0/4** |
| short_uuid | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |
| slugify | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| tabulate | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| tagged_factory | 1b | 4 | 0/4 | 2/4 | 2/4 | **2/4** | 4/4 | 2/4 | 2/4 | **0/4** |
| textwrap | 1a | 0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 | 0/0 |
| url_fetch | 1a | 1 | 0/1 | 1/1 | 1/1 | 1/1 | 1/1 | 0/1 | 0/1 | 0/1 |

On each Phase-1b pair Q1 T2 = Q1 T2b = Q1 T3 = 2/4 (all three attribute
the two `direct` handler facts, none attributes the two dispatcher
facts); the difference is Q2, where **both** Semgrep and CodeQL
false-clear 2/4 while Capa false-clears 0/4. On the two via-helper pairs
(`log_forwarder`, `session_token`) CodeQL matches Capa (3/3, 4/4) and
beats Semgrep, because it follows the local call edge.

## Distinguishing facts (a treatment fails to attribute)

| Pair | Function | Capability | Cause | T2 attr | T2b attr | T3 attr | T2 fc | T2b fc | T3 fc | T2b (literal) |
|---|---|---|---|---|---|---|---|---|---|---|
| command_registry | dispatch | Net | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| command_registry | dispatch | Fs | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| event_bus | emit | Fs | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| event_bus | emit | Net | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| log_forwarder | forward_log | Fs | via-helper | no | **yes** | **yes** | **yes** | no | no | attributes |
| middleware_chain | run_pipeline | Env | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| middleware_chain | run_pipeline | Fs | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| reflect_dispatch | dispatch | Fs | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| reflect_dispatch | dispatch | Net | via-dispatch | no | no | no | **yes** | **yes** | no | misses |
| session_token | generate_token | Random | via-helper | no | **yes** | **yes** | **yes** | no | no | attributes |
| tagged_factory | run_action | Fs | via-data | no | no | no | **yes** | **yes** | no | misses |
| tagged_factory | run_action | Net | via-data | no | no | no | **yes** | **yes** | no | misses |

Every row has `T3 fc = no`: the soundness guarantee made visible. The
two `via-helper` rows show `T2b attr = T3 attr = yes` (CodeQL follows the
local call edge; Capa carries the helper's authority on the caller's
type), so neither false-clears them. The ten dispatcher rows show `T2b
attr = no` **and** `T2b fc = yes`: CodeQL misses them and, read
closed-world, clears them. T2 false-clears all 12; T2b false-clears the
10 dispatcher facts (it recovers the 2 via-helper facts T2 missed).

### Per-pair CodeQL verdict (Phase 1c, MEASURED)

The literal CodeQL verdict, run with the good-faith reachability query
([`scratch_codeql/capquery/CapabilityReachability.ql`](scratch_codeql/capquery/CapabilityReachability.ql),
CodeQL 2.25.6, `python-all` 7.1.2). Direct-fact recall is **36/36
(100 %)** and there is **zero over-attribution**, so the query is
genuinely good-faith: every dispatcher miss below is CodeQL's limit, not
a hole in the query.

| Pair | Indirection | Opacity | CodeQL verdict | Why it loses |
|---|---|---|---|---|
| command_registry | via-dispatch, constant dict, runtime key | **least dynamic** | **LOSES** | points-to does NOT traverse the dict-subscript `HANDLERS[name]`, even though the dict is a module-level constant; the handler edges are never followed |
| middleware_chain | via-dispatch, stages passed as a list param | local registration | **LOSES** | the stage callables arrive in a list parameter; the loop body call is not resolved through the list elements |
| event_bus | via-dispatch, callbacks appended at runtime | local registration | **LOSES** | subscribers are `append`-ed to a list at runtime and invoked in a loop; the list contents are not resolved |
| reflect_dispatch | via-dispatch, `getattr(self,"handle_"+name)` | input-driven | **LOSES** | the method name is built from runtime input; there is no value for points-to to follow |
| tagged_factory | via-data, handler from deserialized tag | input-driven | **LOSES** | the handler is chosen by `json.loads(raw)["type"]`; the selector is a field of external data |

**The Phase-1b expectation was corrected here.** Phase 1b guessed
`command_registry` would resolve because the dict is a constant table.
It does **not**: CodeQL's points-to call graph does not traverse a
dict-subscript at all, so the constancy of the table and the key is
irrelevant. The ordering above is therefore the **degree of opacity**,
not a recall split - **CodeQL loses across the whole spectrum**, from the
constant dict at the least-dynamic end to the deserialized tag at the
most-dynamic. A sound analysis would have to over-approximate every
subscript / `getattr` / loop call to all values the container can hold,
which is imprecise in general and degenerates to "any capability" once
the table is populated from outside the module. Capa carries the
authority in the closure's type instead, with no points-to budget and no
constant-table precondition.

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
- On **positive attribution (Q1) Capa ties the best dataflow tool
  exactly**: CodeQL and Capa both attribute 38/48, against Semgrep's
  36/48. The honest message is three-way parity at the top: Capa does
  **not** see more than CodeQL. Capa is sound, not omniscient, and does
  not vouch which handler a dispatcher runs - and neither does CodeQL.
- The decisive result is **false-clearance (Q2)**: Capa commits **0
  false-clearances** under closed-world SBOM semantics, against **10 for
  CodeQL**, 12 for Semgrep, and 48 for the dependency SBOM. The two real
  dataflow / pattern tools leave the dispatcher silently blank, which a
  closed-world SBOM reader takes as cleared. Capa never clears a function
  incorrectly because it distinguishes *provably-excluded* (sound, proved
  in Agda: used ⊆ declared, used ∩ provably-excluded = ∅) from
  *not-determined*. The dispatcher functions (`dispatch`, `emit`,
  `run_action`, `run_pipeline`) report `provably_excluded = []`, so no
  axis is cleared -- the honest record that their authority depends on
  what was registered into the table they receive.
- The separation holds against the **best** dataflow tool, not a
  strawman. CodeQL's good-faith query catches 100 % of direct sinks and
  over-attributes nothing, and still loses every dispatcher, including
  the supposedly-easy constant dict. The structural reason: dataflow
  tools optimize precision and accept false-negatives, but for an SBOM
  the false-negative is the dangerous direction; the sound alternative
  is an over-approximation that degenerates with external dispatch
  targets. Capa replaces that trade-off with types.

**Corrected this phase:**

- The Phase-1b note that CodeQL would "likely resolve" the
  `command_registry` constant dict was **wrong** and is now corrected
  everywhere (this file, `run_study.py`, and the pair READMEs). CodeQL's
  points-to call graph does not traverse the dict-subscript, so it loses
  the constant table for the same structural reason it loses the
  computed-name and deserialized-tag dispatchers. The reason is the
  subscript, not the dynamicity of the key.
