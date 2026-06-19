"""A middleware / pipeline chain assembled at runtime: each stage
is a function, and the request flows through the list of stages.

This is the WSGI / ASGI middleware shape and the data-pipeline
shape, both ubiquitous in Python:

  * WSGI / ASGI: an application is wrapped in a list of middleware
    (`app = M1(M2(M3(app)))` or a `middlewares = [m1, m2, m3]`
    list the server folds over the request). Django's
    `MIDDLEWARE` setting and Starlette's `Middleware` stack are
    exactly this.
  * `logging` handler chains, `click`/`functools` decorator
    stacks, scikit-learn / pandas / Airflow data pipelines built
    from a `steps = [...]` list.
  * DRF / Flask request hooks (`before_request` lists).

The defining feature for this study: the stage list is assembled
at runtime (here from a `stages` argument), and `run_pipeline`
folds the request through every stage by calling `stage(req)`.
Some stages are pure (transform the request); some exercise a
capability (an auth stage that reads a secret from the
environment, an audit stage that writes the disk). The pipeline
runner's signature says nothing about which authorities the
assembled stages carry; it reaches whatever the assembled list
holds.

This file is the hand-Python comparison artefact; it is not run
by the test suite.
"""

import os


def stage_uppercase(req: str) -> str:
    # Pure: transform the request. No capability.
    return req.upper()


def stage_audit(req: str) -> str:
    # Fs: append the request to an on-disk audit trail. Real authority.
    with open("pipeline_audit.log", "a", encoding="utf-8") as f:
        f.write(req + "\n")
    return req


def stage_inject_token(req: str) -> str:
    # Env: read an API token from the environment and attach it. Real
    # authority -- the kind of "harmless-looking" middleware that
    # quietly reaches for a secret.
    token = os.environ.get("API_TOKEN", "")
    return req + " [token=" + token + "]"


def run_pipeline(stages: list, req: str) -> str:
    # The dispatch loop: fold the request through every assembled
    # stage. Each `stage(req)` may be pure or may read the disk or the
    # environment, depending on what was assembled into `stages`. No
    # capability sink is lexically present here.
    for stage in stages:
        req = stage(req)
    return req


def default_pipeline(req: str) -> str:
    # Wiring: assemble a stage list at runtime and run it.
    stages = [stage_uppercase, stage_inject_token, stage_audit]
    return run_pipeline(stages, req)
