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

Pair axis coverage is `{Env, Fs}`, so T3 recovers both
`run_pipeline` facts.

## Expected treatment behaviour

| Treatment | direct (`stage_audit:Fs`, `stage_inject_token:Env`) | via-dispatch (`run_pipeline:Fs`, `run_pipeline:Env`) |
|---|---|---|
| T1 dependency SBOM | miss (package granularity) | miss |
| T2 pattern heuristic | **hit** | **miss** (no sink in `run_pipeline`) |
| T2b dataflow (CodeQL) | hit | **depends** -- when the stage list is a literal of named functions (as in `default_pipeline`), points-to can enumerate the elements and follow each `stage(req)` edge; when the list is assembled from an opaque `stages` argument the runner cannot see, it loses |
| T3 Capa by construction | hit | **hit** (axis coverage) |

## CodeQL expectation (recorded for Phase 1c, not yet run)

**Depends on assembly.** This pair deliberately straddles the
spectrum. `run_pipeline(stages, req)` takes the stage list as an
ARGUMENT, so analysing `run_pipeline` in isolation gives nothing to
resolve -- `stage` is an opaque callable. Analysing the whole
program, `default_pipeline` builds the list from a literal of named
functions, which points-to CAN enumerate, recovering the edges if
the engine inlines/contextualises the call into `run_pipeline`.
A real WSGI/ASGI stack assembled from configuration (a settings
list, an entry-point group) is on the opaque side. The honest
expectation is therefore "resolvable for the literal default,
unresolvable for the configuration-driven case" -- recorded as a
split, not a single verdict, and confirmed in Phase 1c. Capa needs
neither analysis: `run_pipeline`'s manifest already declines to
exclude any capability, and the assembly site names exactly what it
holds.
