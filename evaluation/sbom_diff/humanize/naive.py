"""A naive Python human-friendly number / duration / size
formatter, of the shape that appears in essentially every Python
CLI tool that prints user-facing metrics (the PyPI `humanize`
library has ~30M downloads/month; this is the core of its public
API).

The signatures
`format_bytes(size: int) -> str`,
`format_duration(seconds: int) -> str`, and
`format_count(n: int, singular: str, plural: str | None = None) -> str`
exercise NO capabilities at all - all three functions are pure.
The top-level import block does not even reach a stdlib module
that could plausibly be capability-bearing: the file imports
nothing. A PURL-based SBOM emitted by syft / pip-licenses for
this file therefore has nothing to say beyond "this script
depends on Python itself".

The Capa equivalent (see `capa.capa`) proves that not only the
three public functions but every helper involved in unit
selection, integer-decimal formatting, and pluralisation is
purity-verified by the compiler. Unlike `slugify`, there is no
Unicode-normalisation asymmetry; unlike `textwrap`, the work is
arithmetic-heavy rather than string-shape, which exercises
Capa's number-to-string and branching paths in a way the other
pure-case pairs do not.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""


def format_bytes(size: int) -> str:
    # Binary (1024-based) units, one decimal place. The PyPI
    # `humanize` library exposes both binary and SI modes; this
    # naive form picks the binary one because it is what most CLI
    # disk-usage output uses (`du -h`, `ls -lh`, etc.).
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        # `(size * 10) // 1024` gives tenths of a KB as an integer,
        # so the formatted output never depends on floating-point
        # rounding. `1536` -> `15` tenths -> `"1.5 KB"`.
        tenths = (size * 10) // 1024
        return f"{tenths // 10}.{tenths % 10} KB"
    if size < 1024 * 1024 * 1024:
        tenths = (size * 10) // (1024 * 1024)
        return f"{tenths // 10}.{tenths % 10} MB"
    tenths = (size * 10) // (1024 * 1024 * 1024)
    return f"{tenths // 10}.{tenths % 10} GB"


def format_duration(seconds: int) -> str:
    # Hours / minutes / seconds, comma-separated, omitting zero
    # parts. The special case `0` returns `"0 seconds"` rather
    # than the empty string so the formatter is total over the
    # non-negative integers.
    if seconds == 0:
        return "0 seconds"
    hours = seconds // 3600
    remainder = seconds % 3600
    minutes = remainder // 60
    secs = remainder % 60

    parts: list[str] = []
    if hours > 0:
        parts.append(format_count(hours, "hour"))
    if minutes > 0:
        parts.append(format_count(minutes, "minute"))
    if secs > 0:
        parts.append(format_count(secs, "second"))
    return ", ".join(parts)


def format_count(n: int, singular: str, plural: str | None = None) -> str:
    # The default-plural convention here is the English `-s`
    # rule; callers pass an explicit `plural` for irregular nouns
    # ("child" / "children", "foot" / "feet", etc.).
    if plural is None:
        plural = singular + "s"
    return f"{n} {singular}" if n == 1 else f"{n} {plural}"


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list nothing capability-bearing: the file has no imports
# at all. The PURL SBOM is silent. That silence is itself a
# comparison failure: it cannot distinguish "this file does
# nothing" from "this file imports nothing PURL recognises as a
# capability". The Capa equivalent names each function and
# declares zero capabilities per function, with the compiler
# enforcing the absence of any Fs / Env / Net / Stdio call
# inside the helpers.
