"""A naive Python gitignore-style path matcher, of the shape that
appears in every Python tool that walks a repository tree (the
PyPI `pathspec` library has ~50M downloads/month; `black`,
`isort`, `mypy`, and basically every Python repo walker depend
on it for their `--exclude` style flags).

The signatures
`matches_pattern(path: str, pattern: str) -> bool` and
`matches_any(path: str, patterns: list[str]) -> bool` exercise
NO capabilities at all - both functions are pure. But a PURL-
based SBOM emitted by syft / pip-licenses for this file would
list `re` as a stdlib import without any per-function
attribution. `re` is a capability-bearing module by category
(arbitrary regex compilation is a non-trivial computation
surface) but is used purely here: the pattern is compiled once
inside the function body and discarded; no Fs, Env, Net, or
Stdio call is reachable.

The Capa equivalent (see `capa.capa`) proves that not only the
two public functions but the recursive glob matcher behind them
is purity-verified by the compiler. Unlike `slugify`, there is
no Unicode-normalisation gap; unlike `textwrap`, the file does
import something PURL recognises, so the asymmetry shape is
identical to `slugify`: pip over-attributes `re` as opaque
dependency, Capa proves each function pure.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""

import re


def is_negation(pattern: str) -> bool:
    # Leading `!` flips the match (gitignore convention).
    return pattern.startswith("!")


def matches_pattern(path: str, pattern: str) -> bool:
    # Step 1: handle the leading `!` negation prefix. If present,
    # strip it and remember to invert the final result.
    negated = is_negation(pattern)
    if negated:
        pattern = pattern[1:]

    # Step 2: strip anchor markers. A leading `/` anchors the
    # pattern to the repository root; for this simplified subset
    # we treat every pattern as root-anchored, so the marker is
    # just dropped. A trailing `/` means "directory only"; the
    # subset matches it as a plain suffix, so the marker is also
    # dropped.
    if pattern.startswith("/"):
        pattern = pattern[1:]
    if pattern.endswith("/"):
        pattern = pattern[:-1]

    # Step 3: convert the gitignore glob to a regex. `re.escape`
    # turns every metacharacter into its escaped form; we then
    # un-escape the three glob metas we care about. `**` must be
    # replaced before `*` so it does not get clobbered by the
    # single-star rule (`re.escape` produces `\*\*` and `\*`,
    # which textually overlap).
    escaped = re.escape(pattern)
    escaped = escaped.replace(r"\*\*", ".*")
    escaped = escaped.replace(r"\*", "[^/]*")
    escaped = escaped.replace(r"\?", ".")

    # Step 4: full-string match. `re.fullmatch` returns None for a
    # non-match, which we coerce to a bool.
    matched = re.fullmatch(escaped, path) is not None

    # Step 5: apply the negation flip from step 1.
    if negated:
        return not matched
    return matched


def matches_any(path: str, patterns: list[str]) -> bool:
    # Greedy: stop at the first hit. The gitignore convention is
    # actually more subtle (later patterns can re-include earlier
    # excluded paths via `!`), but for the SBOM-diff study the
    # single-pass shape is enough to demonstrate the capability-
    # attribution diff.
    for pattern in patterns:
        if matches_pattern(path, pattern):
            return True
    return False


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list `re` as a stdlib import. `re` is capability-bearing
# by category (regex compilation is a non-trivial computation
# surface), but is used purely here: the compiled pattern never
# escapes the function body, no Fs / Env / Net / Stdio call is
# reachable from any helper. The naive SBOM over-attributes: it
# cannot tell that the import is a pure helper. The Capa
# equivalent has no regex library at all and implements the glob
# directly via recursion; every helper declares zero capabilities
# and the compiler enforces it - the same asymmetry shape as the
# `slugify/` pair.
