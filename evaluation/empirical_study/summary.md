# Capability-recall study, Phase 1a + 1b results

Run over 25 hand-Python / Capa pairs: the 20 Phase-1a pairs in
[`../sbom_diff/`](../sbom_diff/) (direct + via-helper) and the 5
Phase-1b pairs in [`dispatch_pairs/`](dispatch_pairs/) (via-dispatch
+ via-data indirection, where the sink is selected at runtime through
a callable or a data table). Unit of recall: one
`(python_function, capability)` fact. Regenerate with
`.venv/Scripts/python evaluation/empirical_study/run_study.py`
(requires the isolated semgrep venv; see [`README.md`](README.md)).

## Aggregate recall

| Treatment | Facts recovered | Recall |
|---|---|---|
| T1 dependency / PURL SBOM (package granularity) | 0 / 48 | 0.0 % |
| T2 good-faith pattern heuristic (Semgrep) | 36 / 48 | 75.0 % |
| T2b dataflow (CodeQL) | *pending (Phase 1c)* | *pending* |
| T3 Capa by construction | 48 / 48 | 100.0 % |

T2's recall fell from 92.9 % (Phase 1a alone) to 75.0 % when the
Phase-1b indirection pairs were added: every one of the 10 new T2
misses is a `via-dispatch` or `via-data` fact, the indirection the
pattern heuristic structurally cannot see. T3 stays at 100 %.

## The spectrum (the headline of Phase 1b)

The study now separates three regimes by how the authority is reached:

| Regime | `how` | T2 (pattern) | T2b dataflow (CodeQL), expected | T3 (Capa) |
|---|---|---|---|---|
| **direct** | `direct` | **hit** (sink is lexical) | hit | hit |
| **via-helper** | `via-helper` | miss | **hit** (follows the call edge) | hit |
| **via-dispatch / via-data** | `via-dispatch`, `via-data` | miss | **expected miss** (target chosen at runtime by a callable or data) | hit |

* On **direct** facts the pattern heuristic **ties** Capa. Capa does
  not win on the easy cases.
* On **via-helper** facts a dataflow tool would also recover the fact
  by following the local call edge; Capa's edge over T2 here is real
  but erased by T2b.
* On **via-dispatch / via-data** facts the call target is selected at
  runtime (a callable looked up in a table, or a handler chosen by a
  data tag). This is where the type-carried capability is expected to
  separate from interprocedural dataflow, and the Phase-1b pairs exist
  to test exactly that in Phase 1c.

## Per-pair recall

| Pair | Corpus | GT facts | T1 | T2 | T3 |
|---|---|---|---|---|---|
| colorama | 1a | 0 | 0/0 | 0/0 | 0/0 |
| command_registry | 1b | 4 | 0/4 | **2/4** | 4/4 |
| config_loader | 1a | 3 | 0/3 | 3/3 | 3/3 |
| csv_parser | 1a | 0 | 0/0 | 0/0 | 0/0 |
| disk_cache | 1a | 3 | 0/3 | 3/3 | 3/3 |
| dotenv | 1a | 2 | 0/2 | 2/2 | 2/2 |
| env_loader | 1a | 1 | 0/1 | 1/1 | 1/1 |
| event_bus | 1b | 4 | 0/4 | **2/4** | 4/4 |
| glob_walker | 1a | 1 | 0/1 | 1/1 | 1/1 |
| http_retry | 1a | 2 | 0/2 | 2/2 | 2/2 |
| humanize | 1a | 0 | 0/0 | 0/0 | 0/0 |
| ini_loader | 1a | 1 | 0/1 | 1/1 | 1/1 |
| log_forwarder | 1a | 3 | 0/3 | **2/3** | 3/3 |
| middleware_chain | 1b | 4 | 0/4 | **2/4** | 4/4 |
| pathspec | 1a | 0 | 0/0 | 0/0 | 0/0 |
| rate_limiter | 1a | 2 | 0/2 | 2/2 | 2/2 |
| reflect_dispatch | 1b | 4 | 0/4 | **2/4** | 4/4 |
| secret_rotator | 1a | 4 | 0/4 | 4/4 | 4/4 |
| session_token | 1a | 4 | 0/4 | **3/4** | 4/4 |
| short_uuid | 1a | 1 | 0/1 | 1/1 | 1/1 |
| slugify | 1a | 0 | 0/0 | 0/0 | 0/0 |
| tabulate | 1a | 0 | 0/0 | 0/0 | 0/0 |
| tagged_factory | 1b | 4 | 0/4 | **2/4** | 4/4 |
| textwrap | 1a | 0 | 0/0 | 0/0 | 0/0 |
| url_fetch | 1a | 1 | 0/1 | 1/1 | 1/1 |

Each Phase-1b pair scores T2 = 2/4: the two `direct` handler facts are
recovered, the two `via-dispatch` / `via-data` dispatcher facts are
not. T3 = 4/4 on every one.

## T2 false-negatives, classified by cause

| Pair | Function | Capability | Cause | Dataflow (CodeQL) resolves? | T2b (literal) |
|---|---|---|---|---|---|
| command_registry | dispatch | Net | via-dispatch | no (class default) | pending |
| command_registry | dispatch | Fs | via-dispatch | no (class default) | pending |
| event_bus | emit | Fs | via-dispatch | no | pending |
| event_bus | emit | Net | via-dispatch | no | pending |
| log_forwarder | forward_log | Fs | via-helper | yes | pending |
| middleware_chain | run_pipeline | Env | via-dispatch | no | pending |
| middleware_chain | run_pipeline | Fs | via-dispatch | no | pending |
| reflect_dispatch | dispatch | Fs | via-dispatch | no | pending |
| reflect_dispatch | dispatch | Net | via-dispatch | no | pending |
| session_token | generate_token | Random | via-helper | yes | pending |
| tagged_factory | run_action | Fs | via-data | no | pending |
| tagged_factory | run_action | Net | via-data | no | pending |

The `dataflow_would_resolve` column is the conservative **class-level**
expectation. The **per-pair** CodeQL expectation is finer and is
recorded in each Phase-1b pair's README, because a constant function
table (`command_registry`) is points-to-resolvable while a name from
external input (`reflect_dispatch`, `tagged_factory`) is not. The
`t2b_codeql` slot in [`false_negatives.csv`](false_negatives.csv) is
`pending` until a literal CodeQL run fills it in Phase 1c.

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
| Purely direct (T2 ties Capa) | 11 | config_loader, disk_cache, dotenv, env_loader, glob_walker, http_retry, ini_loader, rate_limiter, secret_rotator, short_uuid, url_fetch |
| Indirection, via-helper (dataflow resolves) | 2 | log_forwarder, session_token |
| Indirection, via-dispatch / via-data (needs types) | 5 | command_registry, event_bus, middleware_chain, reflect_dispatch, tagged_factory |

## What this corpus now establishes

**Establishes:**

- A capability-aware per-function SBOM is a strict **granularity**
  gain over a dependency SBOM: T3 = 48/48 per-function facts versus
  T1 = 0/48.
- The T2 gap is **entirely structural indirection**: every T2 miss is
  via-helper, via-dispatch, or via-data; T2 never misses a direct fact.
- Capa recovers **100 %** of facts, including all 10 dispatch/data
  facts that a pattern heuristic cannot see, by carrying the capability
  in the type. The dispatcher functions (`dispatch`, `emit`,
  `run_action`, `run_pipeline`) report no provably-excluded
  capabilities in the Capa manifest -- the honest record that their
  authority depends on what was registered into the table they receive.

**Still pending (Phase 1c):**

- The **literal** CodeQL verdict on each false-negative. The expectation
  is that CodeQL resolves the via-helper facts and the constant-table
  dispatch (`command_registry`), but loses the computed-name and
  deserialized-tag facts (`reflect_dispatch`, `tagged_factory`) where
  only the type-carried capability still recovers the authority. The
  `t2b_codeql` column is wired and waiting.
