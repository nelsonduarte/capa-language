# Reproducing the CodeQL T2b dataflow facts

The study's CodeQL treatment (**T2b**, Phase 1c) reads a pre-computed
fact table, [`codeql_facts.csv`](codeql_facts.csv), so the study harness
([`../run_study.py`](../run_study.py)) and its tests never need the
1.3GB CodeQL CLI. This document is how to regenerate that CSV from
scratch. You only need it if you want to re-derive the facts or extend
the corpus; running the study itself does not.

## Pinned versions

| Component | Version | Why pinned |
|---|---|---|
| CodeQL CLI | **2.25.6** | the call-graph / points-to behaviour that loses the dispatchers is version-sensitive; pin it so the result is reproducible |
| `codeql/python-all` | **7.1.2** | the Python standard library used by the query (`semmle.python.*`, `ApiGraphs`, `Concepts`); ships inside the CLI bundle above |

Both are reported by `codeql version` and `codeql resolve qlpacks`.

## What is committed vs generated

Committed (small, the reproducible inputs and outputs):

- `capquery/` - the good-faith reachability query
  `CapabilityReachability.ql`, the three `Probe*.ql` diagnostics used to
  characterise why CodeQL loses each dispatcher, `qlpack.yml`, and the
  lock file.
- `build_facts.py` - the generator: stages each pair's `naive.py`,
  creates its database, runs the query, and consolidates the rows.
- `score_poc.py` - the original 9-pair proof-of-concept scorer.
- `codeql_facts.csv` - the consolidated `(pair, python_function,
  capability)` fact table over all 25 pairs (38 facts, 18 pairs; the 7
  pure-library pairs produce none).
- `REPRODUCE.md` - this file.

Git-ignored (heavy, machine-local; see `.gitignore`):

- `codeql/` - the CLI (~1.3GB).
- `db_<pair>/` - the per-pair CodeQL databases.
- `src_<pair>/` - the staged single-file extraction sources.
- `*.bqrs` - query-run binary result scratch.

## Steps

1. **Install CodeQL 2.25.6** under `codeql/` here. Download the bundle
   for your platform from the CodeQL CLI releases
   (`github.com/github/codeql-cli-binaries`, tag `v2.25.6`) and unpack
   it so that `scratch_codeql/codeql/codeql(.exe)` exists. Verify:

   ```sh
   ./codeql/codeql version          # -> 2.25.6
   ```

2. **Generate the facts** for all 25 pairs (creates any missing
   database, then runs the query against each):

   ```sh
   python build_facts.py            # incremental: reuses existing db_*
   python build_facts.py --rebuild  # force-recreate every database
   python build_facts.py --pair command_registry  # one pair, merged in
   ```

   This writes `codeql_facts.csv`. The output is deterministic (facts
   sorted by pair, then canonical axis order, then function).

3. **Sanity-check the query honesty** (optional; the study tests do this
   too): every `direct` ground-truth fact must be caught, and CodeQL
   must over-attribute nothing.

   ```sh
   python score_poc.py              # per-fact verdict for the 9 PoC pairs
   ```

   The study's own guard tests assert direct-fact recall is 100 % and
   over-attribution is zero over all 25 pairs; see
   `../test_run_study.py::test_codeql_catches_every_direct_ground_truth_fact`
   and `::test_codeql_never_over_attributes`.

## The query, in one paragraph

`CapabilityReachability.ql` computes, per function, the capability axes
reachable through CodeQL's call graph. It is deliberately **good-faith /
maximally generous**: it unions CodeQL's curated sink Concepts
(`FileSystemAccess`, `Http::Client::Request`, `SystemCommandExecution`)
with explicit API-graph sinks for every axis (`Fs`, `Net`, `Clock`,
`Env`, `Random`, `Proc`, `Stdio`), and propagates over the **union** of
two call resolvers - the points-to call graph (`FunctionObject`/
`CallableValue`, which would follow a constant function table if
points-to traversed the access path) and the dataflow-dispatch call
graph. Sinks inside comprehension scopes are lifted to the enclosing
real function. The result: 100 % direct-fact recall, both `via-helper`
facts recovered, and zero of the ten `via-dispatch` / `via-data`
dispatcher facts - because points-to does not traverse the
dict-subscript, the `getattr` on a computed name, the runtime-registered
callback list, or the externally-keyed data tag. That is the measured
T2b result; it is the limit of the tool, not of the query.

## Recording a query change

If you add a sink to `sinkCall` (e.g. to keep direct-fact recall at
100 % after adding a pair that uses a new API), note the exact sink in
the study `summary.md` so the change to the good-faith query is
auditable. As of Phase 1c **no** sink had to be added: the query as
written already catches every direct fact in the 25-pair corpus.
