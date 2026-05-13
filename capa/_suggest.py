"""Pure helpers for the analyzer's "did you mean 'X'?" hints.

Five analyzer error families (undefined name, undefined type, no
method on type, no field on struct, unknown variant) carry a
``; did you mean 'X'?`` suffix when the analyzer can find a
plausible candidate in scope. The matching logic is generic
(Levenshtein with case-aware tie-breaking) and depends on no
analyzer state, so it lives here as a free function rather than
on the ``Analyzer`` class.
"""

from __future__ import annotations

from typing import Optional


def edit_distance(a: str, b: str) -> int:
    """Levenshtein distance between ``a`` and ``b``.

    Used only at error time, so the O(len(a) * len(b)) cost is
    not on the hot path. Inlined to avoid a stdlib dependency
    that doesn't exist.
    """
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr[j] = min(
                curr[j - 1] + 1,        # insertion
                prev[j] + 1,            # deletion
                prev[j - 1] + cost,     # substitution
            )
        prev = curr
    return prev[-1]


def suggest(needle: str, haystack: list[str]) -> Optional[str]:
    """Return the closest candidate from ``haystack`` to ``needle``
    if it is plausibly a typo, otherwise ``None``.

    Threshold scales with the length of ``needle``: distance 1
    is enough for any name, distance 2 for names >= 4 chars,
    distance 3 only for names >= 8 chars. Needles of two
    characters or fewer are never hinted (too many plausible
    candidates at that scale).

    Tie-breaking, in order: (1) same first letter (case-
    insensitive) so ``Pint`` prefers ``Point`` over ``Int``;
    (2) same first-letter case so ``reslt`` prefers a local
    ``result`` over the built-in ``Result``; (3) longer
    candidate (more specific). Names starting with ``_`` are
    excluded from the haystack (private-by-convention).
    """
    if len(needle) <= 2:
        return None
    first_char = needle[:1] if needle else ""

    def score(cand: str) -> tuple[int, int, int, int]:
        d = edit_distance(needle.lower(), cand.lower())
        same_letter = 0 if cand[:1].lower() == first_char.lower() else 1
        same_case = 0 if cand[:1] == first_char else 1
        return (d, same_letter, same_case, -len(cand))

    best: tuple[tuple[int, int, int, int], str] | None = None
    for cand in haystack:
        if not cand or cand.startswith("_"):
            continue
        s = score(cand)
        if best is None or s < best[0]:
            best = (s, cand)
    if best is None:
        return None
    d = best[0][0]
    name = best[1]
    if d == 0:
        return None  # exact match makes no sense as a suggestion
    if d == 1:
        return name
    if d == 2 and len(needle) >= 4:
        return name
    if d == 3 and len(needle) >= 8:
        return name
    return None


def hint_did_you_mean(needle: str, haystack: list[str]) -> str:
    """Render a ``; did you mean 'X'?`` suffix for an error
    message, or ``""`` when no plausible suggestion exists.
    The caller concatenates this onto the base message.
    """
    s = suggest(needle, haystack)
    if s is None:
        return ""
    return f"; did you mean {s!r}?"
