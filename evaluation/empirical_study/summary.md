# Capability-recall study, Phase 1a results

Run over the 20 hand-Python / Capa pairs in
[`../sbom_diff/`](../sbom_diff/). Unit of recall: one
`(python_function, capability)` fact. Regenerate with
`.venv/Scripts/python evaluation/empirical_study/run_study.py`
(requires the isolated semgrep venv; see [`README.md`](README.md)).

## Aggregate recall

| Treatment | Facts recovered | Recall |
|---|---|---|
| T1 dependency / PURL SBOM (package granularity) | 0 / 28 | 0.0 % |
| T2 good-faith pattern heuristic (Semgrep) | 26 / 28 | 92.9 % |
| T3 Capa by construction | 28 / 28 | 100.0 % |

T1's 0 % is a **granularity** result, not a detection failure: a
dependency SBOM is package-granular and cannot carry per-function facts.
The corpus is stdlib-only, so a real Syft / cdxgen SBOM would be empty;
the T1 proxy (module-level imports) is the charitable upper bound and
still recovers zero per-function facts by construction.

## Per-pair recall

| Pair | Ground-truth facts | T1 | T2 | T3 |
|---|---|---|---|---|
| colorama | 0 | 0/0 | 0/0 | 0/0 |
| config_loader | 3 | 0/3 | 3/3 | 3/3 |
| csv_parser | 0 | 0/0 | 0/0 | 0/0 |
| disk_cache | 3 | 0/3 | 3/3 | 3/3 |
| dotenv | 2 | 0/2 | 2/2 | 2/2 |
| env_loader | 1 | 0/1 | 1/1 | 1/1 |
| glob_walker | 1 | 0/1 | 1/1 | 1/1 |
| http_retry | 2 | 0/2 | 2/2 | 2/2 |
| humanize | 0 | 0/0 | 0/0 | 0/0 |
| ini_loader | 1 | 0/1 | 1/1 | 1/1 |
| log_forwarder | 3 | 0/3 | **2/3** | 3/3 |
| pathspec | 0 | 0/0 | 0/0 | 0/0 |
| rate_limiter | 2 | 0/2 | 2/2 | 2/2 |
| secret_rotator | 4 | 0/4 | 4/4 | 4/4 |
| session_token | 4 | 0/4 | **3/4** | 4/4 |
| short_uuid | 1 | 0/1 | 1/1 | 1/1 |
| slugify | 0 | 0/0 | 0/0 | 0/0 |
| tabulate | 0 | 0/0 | 0/0 | 0/0 |
| textwrap | 0 | 0/0 | 0/0 | 0/0 |
| url_fetch | 1 | 0/1 | 1/1 | 1/1 |

## T2 false-negatives, classified by cause

| Pair | Function | Capability | Cause | Dataflow (CodeQL) resolves? |
|---|---|---|---|---|
| log_forwarder | forward_log | Fs | via-helper (`_read_tail`) | yes |
| session_token | generate_token | Random | via-helper (`_random_id`) | yes |

Both T2 misses are `via-helper`: the sink lives in a local helper the
function calls. An **interprocedural dataflow** tool (CodeQL) would
follow that call edge and recover both. There are **no** `via-dispatch`
or `via-data` facts in this corpus, i.e. no facts that would defeat
dataflow and require Capa's type system. That is the honest limit of the
20-pair corpus and the motivation for Phase 1b.

## Corpus distribution (the headline honesty point)

| Category | Count | Pairs |
|---|---|---|
| Pure (zero capability facts) | 7 | colorama, csv_parser, humanize, pathspec, slugify, tabulate, textwrap |
| Purely direct (T2 ties Capa) | 11 | config_loader, disk_cache, dotenv, env_loader, glob_walker, http_retry, ini_loader, rate_limiter, secret_rotator, short_uuid, url_fetch |
| Genuine indirection (T2 < Capa) | 2 | log_forwarder, session_token |

Of the 13 capability-bearing pairs, **11 are purely direct-call**, where
the good-faith pattern heuristic **ties** Capa fact-for-fact. Only **2**
pairs contain real indirection, and in both the indirection is
`via-helper`, which a dataflow tool would also resolve.

## What this corpus does, and does not, establish on its own

**Establishes (strong on these 20 pairs alone):**

- A capability-aware per-function SBOM is a strict **granularity** gain
  over a dependency SBOM: T3 = 28/28 per-function facts versus T1 = 0/28,
  because the dependency SBOM operates one level up (package, not
  function). This is the cleanest, most defensible claim from this set.
- Capa recovers **100 %** of facts including the indirect ones, with no
  ruleset to maintain and no false negatives, because the capabilities
  are carried by the type system.

**Does not establish on its own (needs Phase 1b / 1c):**

- That Capa beats **interprocedural dataflow**. The only indirection here
  is `via-helper`, which CodeQL would resolve. To separate Capa from
  dataflow we need `via-dispatch` / `via-data` pairs (Phase 1b) and a
  literal CodeQL run as a T2b layer (Phase 1c).
- On direct calls, **Capa does not beat a good pattern heuristic** - it
  ties it. The value on the easy cases is the *guarantee* (compiler-
  enforced, no ruleset drift), not extra recall.

In short: against **T1** the 20 pairs make a strong, finished point about
granularity. Against **T2** they show parity on the 92.9 % of facts that
are direct and a modest 2-fact edge on the indirect ones - an edge that a
dataflow tool would erase, which is exactly why Phase 1b exists.
