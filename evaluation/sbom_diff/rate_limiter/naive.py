"""A naive Python token-bucket rate limiter, of the shape that
appears in essentially every Python API client SDK (the AWS SDK,
the Stripe client, GitHub's Octokit port) and in the standalone
rate-limiting libraries on PyPI: `pyrate-limiter`, `ratelimit`,
`aiolimiter`. The exact code is illustrative; the *pattern* (one
data structure plus one `try_acquire` call that quietly reads the
monotonic clock on every call) is widespread.

The functional shape is a pair: `make_bucket(capacity,
refill_per_sec) -> dict` to allocate the bucket state, and
`try_acquire(bucket: dict) -> bool` to attempt to consume one
token. Both signatures hide the fact that the implementation
reads `time.monotonic()`; even `make_bucket` reads the clock to
initialise `last_refill_ts`. A reviewer reading the import block
at the top of the file sees `time`; a reviewer reading the
function bodies finds that two of the three functions call into
the clock. The CycloneDX SBOM emitted by pip-licenses / syft for
this script would list `time` as a top-level import, with no
per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
five functions, each declaring the capabilities it uses in its
parameter list:

  refill_tokens : pure
  try_consume   : pure
  make_bucket   : Clock only
  try_acquire   : Clock only
  main          : Stdio only

The pure / Clock split matters: the refill arithmetic and the
consume decision are both pure given a pre-computed `now`, and
the only thing that needs the Clock cap is the single
`now_monotonic()` read at the top of each entry point. Capa
exposes that surgically; Python rolls it all into `time`.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import time


def make_bucket(capacity: int, refill_per_sec: float) -> dict:
    # Even allocation reads the clock: `last_refill_ts` has to be
    # seeded with the current monotonic time so the first refill
    # measures elapsed-since-construction correctly. Exercises Clock.
    return {
        "capacity": capacity,
        "refill_per_sec": refill_per_sec,
        "tokens": float(capacity),
        "last_refill_ts": time.monotonic(),
    }


def _refill(bucket: dict, now: float) -> None:
    # Pure given `now`: compute elapsed seconds since the last
    # refill, add `elapsed * refill_per_sec` tokens, cap at capacity,
    # update the timestamp. No clock read here.
    elapsed = now - bucket["last_refill_ts"]
    added = elapsed * bucket["refill_per_sec"]
    new_tokens = bucket["tokens"] + added
    if new_tokens > bucket["capacity"]:
        new_tokens = float(bucket["capacity"])
    bucket["tokens"] = new_tokens
    bucket["last_refill_ts"] = now


def try_acquire(bucket: dict) -> bool:
    # Step 1: read the monotonic clock. Exercises Clock.
    now = time.monotonic()

    # Step 2: refill the bucket up to `now` (pure given `now`).
    _refill(bucket, now)

    # Step 3: if at least one token is available, consume it and
    # return True; otherwise return False without touching the bucket.
    if bucket["tokens"] >= 1.0:
        bucket["tokens"] -= 1.0
        return True
    return False


# A reviewer auditing these functions from the signatures alone
# has no way to know that `make_bucket` and `try_acquire` both
# read the monotonic clock; the `dict` return type and the `bool`
# return type are silent on authority. The PURL SBOM proxy for
# this file lists `time` (a cap-bearing stdlib module) but cannot
# attribute the clock read to two of the three functions and prove
# the third (`_refill`) is pure given an elapsed time. Capa narrows
# Clock to `make_bucket` and `try_acquire` per-function and proves
# the refill arithmetic is pure given the elapsed time.
