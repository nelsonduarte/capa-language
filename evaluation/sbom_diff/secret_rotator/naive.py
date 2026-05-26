"""A naive Python "secret with TTL" rotator, of the shape that
appears in essentially every cloud-deployed Python service that
talks to a managed secrets store: `python-keyring` with caching,
`aws-secretsmanager-caching` (AWS's own client-side cache for SDK
secrets), `pydantic-settings` with `refresh_on` hooks, and
`vaultenv`. The exact code is illustrative; the *pattern* (one
allocation that reads the env once, one accessor that quietly
reads the wall clock and re-reads the env after a TTL expires) is
widespread.

The functional shape is a pair: `make_rotator(env_key,
ttl_seconds) -> dict` to allocate the cache holder and seed it
with one env read, and `get_secret(rotator: dict) -> str | None`
to return the cached value if still fresh, else re-read the env
and update the cache in place. Both signatures hide the fact
that the implementation reads `os.environ.get(...)` and
`time.time()`; even `make_rotator` reads both authorities to
seed the state. A reviewer reading the import block at the top
of the file sees `os` and `time`; a reviewer reading the function
bodies finds that both functions call into the env AND the
clock. The CycloneDX SBOM emitted by pip-licenses / syft for
this script would list both imports as top-level, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
functions that each declare the capabilities they use in their
parameter list:

  is_fresh        : pure
  refresh_state   : pure
  make_rotator    : Env + Clock
  get_secret      : Env + Clock
  main            : Stdio only

The pure / impure split matters: the freshness decision (`now -
cached_at < ttl`) and the state-update arithmetic are both pure
functions of (now, cached_at, ttl, fresh_value); the ONLY impure
parts are the single `os.environ.get(...)` read and the single
`time.time()` read at the top of each entry point. Capa exposes
that surgically; Python rolls it all into `os` + `time` and two
signatures that say nothing about which authorities they touch.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import os
import time


def _is_fresh(cached_at: float, now: float, ttl_seconds: int) -> bool:
    # Pure given `cached_at` and `now`: return True iff the cached
    # secret is younger than `ttl_seconds`. No env read, no clock
    # read. Zero capabilities.
    return now - cached_at < ttl_seconds


def _make_state(
    env_key: str,
    ttl_seconds: int,
    value: str | None,
    cached_at: float,
) -> dict:
    # Pure helper: bundle the four state fields into the dict shape
    # the rest of the module reads. No env read, no clock read. The
    # rotator state is a `dict` because Python has no lightweight
    # named record; the field names are load-bearing.
    return {
        "env_key": env_key,
        "ttl_seconds": ttl_seconds,
        "value": value,
        "cached_at": cached_at,
    }


def make_rotator(env_key: str, ttl_seconds: int = 60) -> dict:
    # Step 1: read the env once to seed the cache. Exercises Env.
    value = os.environ.get(env_key)

    # Step 2: read the wall clock once to stamp `cached_at`.
    # Exercises Clock.
    cached_at = time.time()

    # Step 3: bundle into the state dict via the pure helper above.
    return _make_state(env_key, ttl_seconds, value, cached_at)


def get_secret(rotator: dict) -> str | None:
    # Step 1: read the wall clock. Exercises Clock.
    now = time.time()

    # Step 2: pure freshness check against the stored `cached_at`
    # and `ttl_seconds`. If still fresh, return the cached value
    # without touching the env.
    if _is_fresh(rotator["cached_at"], now, rotator["ttl_seconds"]):
        return rotator["value"]

    # Step 3: stale. Re-read the env (Env) and update the state in
    # place; the freshness anchor advances to `now`.
    fresh = os.environ.get(rotator["env_key"])
    rotator["value"] = fresh
    rotator["cached_at"] = now
    return fresh


# A reviewer auditing these functions from the signatures alone
# has no way to know that `make_rotator` reads both the env AND
# the clock, or that `get_secret` reads the clock on every call
# and the env on every cache miss; both authorities are conflated
# under one signature in each function. The PURL SBOM proxy for
# this file lists `os` and `time` (both capability-bearing stdlib
# modules) but cannot attribute the env read to `make_rotator`
# and `get_secret`, the clock read to both, or prove `_is_fresh`
# and `_make_state` are pure given their inputs. Capa narrows
# Env and Clock to `make_rotator` and `get_secret` per-function
# and proves the freshness check and the state-update arithmetic
# are pure given (now, cached_at, ttl, fresh_value).
