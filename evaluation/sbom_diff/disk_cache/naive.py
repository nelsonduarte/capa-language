"""A naive Python disk cache with TTL, of the shape that appears
in essentially every Python HTTP client wrapper and offline-first
tool: `requests-cache` (10M+ downloads/month), `diskcache` (5M+
downloads/month), `cachetools`' filesystem-backed variants, and
the dozens of in-house `cache_get`/`cache_set` helpers every
data-pipeline codebase ships. The exact code is illustrative; the
*pattern* (one pair of functions that quietly reads both the
filesystem AND the clock on every call) is widespread.

The functional shape is a pair: `cache_get(path, ttl_seconds) ->
str | None` that returns the cached value if the file exists and
its mtime is within `ttl_seconds` of the current time, else
`None`; and `cache_set(path, value) -> None` that overwrites the
file with the new value. The freshness arithmetic itself is pure
(`now - mtime < ttl`), but it is hidden behind a `cache_get`
signature that names neither the disk read nor the clock read. A
reviewer reading the import block at the top of the file sees
`os` and `time`; a reviewer reading the function bodies finds
that `cache_get` reads the disk AND reads the wall clock, and
`cache_set` reads (well, writes) the disk. The CycloneDX SBOM
emitted by pip-licenses / syft for this script would list both
imports, with no per-function attribution.

The Capa equivalent (see `capa.capa`) splits the same logic into
functions that each declare the capabilities they use in their
parameter list:

  is_fresh            : pure
  parse_cached_entry  : pure
  format_cache_entry  : pure
  cache_get           : Fs + Clock
  cache_set           : Fs + Clock
  main                : Stdio only

The pure / impure split matters: the freshness decision (`now -
mtime < ttl`) is a pure function of (mtime, now, ttl), and the
only things that need capabilities are the file read/write and
the wall-clock read. Capa exposes that surgically; Python rolls
it all into `os` + `time` and two signatures that say nothing
about which authorities they touch.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import os
import time


def is_fresh(mtime: float, now: float, ttl_seconds: int) -> bool:
    # Pure given `mtime` and `now`: return True iff the cached
    # entry is younger than `ttl_seconds`. No disk read, no clock
    # read. Zero capabilities.
    return now - mtime < ttl_seconds


def cache_get(path: str, ttl_seconds: int) -> str | None:
    # Step 1: probe the filesystem for the cache file. Exercises Fs.
    if not os.path.exists(path):
        return None

    # Step 2: read the file's mtime from disk (Fs) and the current
    # wall-clock time (Clock); decide freshness with the pure
    # `is_fresh` helper above.
    mtime = os.path.getmtime(path)
    now = time.time()
    if not is_fresh(mtime, now, ttl_seconds):
        return None

    # Step 3: read the cached value off disk. Exercises Fs.
    with open(path, encoding="utf-8") as f:
        return f.read()


def cache_set(path: str, value: str) -> None:
    # Step 1: overwrite the cache file with the new value. Exercises
    # Fs. The mtime is implicitly updated by the OS as a side effect
    # of the write, which is what `cache_get`'s `getmtime` reads
    # back on the next call - the freshness anchor lives in
    # filesystem metadata, not inside the file.
    with open(path, "w", encoding="utf-8") as f:
        f.write(value)


# A reviewer auditing these functions from the signatures alone
# has no way to know that `cache_get` reads the disk AND reads
# the clock, or that `cache_set` writes the disk; both
# authorities are conflated under one signature in each function.
# The PURL SBOM proxy for this file lists `os` and `time` (both
# capability-bearing stdlib modules) but cannot attribute the
# disk read to `cache_get`, the disk write to `cache_set`, or
# the clock read to `cache_get` only - and it cannot prove
# `is_fresh` is pure given (mtime, now). Capa narrows Fs and
# Clock to `cache_get` and `cache_set` per-function and proves
# the freshness check is pure given a (current_time, mtime) pair.
