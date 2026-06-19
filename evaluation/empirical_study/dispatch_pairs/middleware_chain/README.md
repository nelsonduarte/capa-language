# middleware_chain (via-dispatch, pipeline assembled at runtime)

A middleware / pipeline chain assembled at runtime: each stage is
a function, and the request flows through the list of stages.

## Pattern

```python
def run_pipeline(stages, req):
    for stage in stages:
        req = stage(req)
    return req

def default_pipeline(req):
    stages = [stage_uppercase, stage_inject_token, stage_audit]
    return run_pipeline(stages, req)
```

`stage_uppercase` is pure; `stage_audit` exercises `Fs`
(`open(..., "a")`); `stage_inject_token` exercises `Env`
(`os.environ.get`). `run_pipeline` reaches whatever stages were
assembled into the list.

## Provenance (where this appears in production)

* WSGI / ASGI middleware stacks: Django's `MIDDLEWARE` setting,
  Starlette's `Middleware` list, the `app = M1(M2(M3(app)))` fold.
* `logging` handler chains; `click` / `functools` decorator stacks;
  scikit-learn / pandas / Airflow data pipelines from a `steps`
  list; DRF / Flask `before_request` hook lists.

## Authority surface (ground-truth facts)

| Function | Capability | How |
|---|---|---|
| `stage_audit` | `Fs` | `direct` (the `open(..., "a")` is in its body) |
| `stage_inject_token` | `Env` | `direct` (the `os.environ.get` is in its body) |
| `run_pipeline` | `Fs` | `via-dispatch` (reached only via `stage(req)`) |
| `run_pipeline` | `Env` | `via-dispatch` (reached only via `stage(req)`) |

`stage_uppercase` is pure and contributes no fact. `run_pipeline`
genuinely reaches both authorities: with the default stage list it
reads the environment and writes the disk, both only through
`stage(req)`.

## Faithful transliteration?

Yes. The `.capa` keeps the SAME shape: a `List<Fun(String) ->
String>` of stages is assembled at runtime and `run_pipeline` folds
the request through each via `stage(current)`. The capability is
reached through the assembled stage, exactly as in the Python.

In Capa the authority is named:

* `stage_uppercase` is provably pure (a bare `Fun` value, no
  captured capability).
* `make_audit_stage` carries `Fs`, `make_token_stage` carries
  `Env` (the factories that capture the capability into the stage
  closures).
* `default_pipeline` (the assembly site) carries `Fs` AND `Env`.
* `run_pipeline` carries a `Fun` (the stage list) in its signature,
  so its manifest reports `provably_excluded_capabilities = []`.

On the dispatcher itself Capa attributes nothing: `run_pipeline`
reports `transitively_reachable_capabilities = []`, so T3 does NOT
credit `run_pipeline` with the `Fs` or `Env` authority -- it only
reports `provably_excluded_capabilities = []`. The two dispatch
facts the manifest carries are on the stage factories and on
`default_pipeline`, not on `run_pipeline`. Capa ties the tools on
Q1 here; the separation from the tools is Q2, not Q1: see below.

## Expected treatment behaviour

| Treatment | direct (`stage_audit:Fs`, `stage_inject_token:Env`) | via-dispatch (`run_pipeline:Fs`, `run_pipeline:Env`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `run_pipeline`) |
| T2b dataflow (CodeQL) | hit | **miss** (confirmed in Phase 1c) -- the stage callables arrive in a list and the `stage(req)` call in the loop is not resolved through the list elements |
| T3 Capa by construction | hit | **miss on attribution** (Q1: `run_pipeline` reach = `[]`, same as the tools) but **does NOT false-clear** (Q2: `provably_excluded = []`) |

On the two dispatcher facts Q1 T2 = Q1 T2b = Q1 T3 = 2/4 (per
`per_pair.csv`): all three attribute the two `direct` stage facts,
none attributes the two `run_pipeline` facts. The difference is
Q2: Semgrep and CodeQL each false-clear 2/4, Capa false-clears
0/4.

## CodeQL verdict (Phase 1c, measured)

**Loses.** Running the good-faith reachability query
(`scratch_codeql/capquery/CapabilityReachability.ql`, CodeQL
2.25.6, `python-all` 7.1.2) against `naive.py` attributes `Fs` to
`stage_audit` and `Env` to `stage_inject_token` (the direct sinks)
and reports NOTHING for `run_pipeline` (confirmed in
`scratch_codeql/codeql_facts.csv`, where `run_pipeline` never
appears). This is a SINGLE verdict, not a split: even with the
default `default_pipeline` that builds the list from a literal of
named functions, CodeQL does not resolve the `stage(req)` call in
the loop through the list elements, so the `Fs` / `Env` authority
never propagates to `run_pipeline`. Capa needs no such analysis:
`run_pipeline`'s manifest declines to exclude any capability, and
the assembly site names exactly what it holds.
