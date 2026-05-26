"""A naive Python paragraph wrapper, of the shape that appears
in essentially every Python CLI tool that prints help text or
log messages (the stdlib `textwrap` module is the canonical
reference; this is the core of its public API).

The signatures
`wrap(text: str, width: int = 70) -> list[str]` and
`fill(text: str, width: int = 70) -> str` exercise NO
capabilities at all - both functions are pure. The top-level
import block does not even reach a stdlib module that could
plausibly be capability-bearing: the file imports nothing. A
PURL-based SBOM emitted by syft / pip-licenses for this file
therefore has nothing to say beyond "this script depends on
Python itself".

The Capa equivalent (see `capa.capa`) proves that not only the
two public functions but every helper involved in splitting
and packing words is purity-verified by the compiler. Unlike
`slugify`, there is no Unicode-normalisation asymmetry: word
boundaries are whitespace, which Capa's `String.split` handles
natively, so this pair is the cleanest pure-case match in the
study.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""


def wrap(text: str, width: int = 70) -> list[str]:
    # Step 1: split into words on any whitespace. `str.split()`
    # with no argument collapses runs of spaces, tabs, and
    # newlines into single separators and drops empty leading /
    # trailing tokens, which is the behaviour we want for a
    # greedy line packer.
    words = text.split()
    if not words:
        return []

    # Step 2: greedily pack words into lines no wider than
    # `width`. The convention here matches the stdlib's default
    # `break_long_words=False` mode: if a single word is wider
    # than `width`, it gets its own line rather than being split
    # mid-word, so the returned list may contain over-width
    # lines for pathological inputs.
    lines: list[str] = []
    current = words[0]
    for word in words[1:]:
        # The `+ 1` accounts for the single space that would be
        # inserted between `current` and `word` on the same line.
        if len(current) + 1 + len(word) <= width:
            current = current + " " + word
        else:
            lines.append(current)
            current = word
    lines.append(current)
    return lines


def fill(text: str, width: int = 70) -> str:
    # `fill` is the newline-joined sibling of `wrap`; the stdlib
    # exposes both because callers usually want one or the other
    # and never have to build the join themselves.
    return "\n".join(wrap(text, width))


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list nothing capability-bearing: the file has no imports
# at all. The PURL SBOM is silent. That silence is itself a
# comparison failure: it cannot distinguish "this file does
# nothing" from "this file imports nothing PURL recognises as a
# capability". The Capa equivalent names each function and
# declares zero capabilities per function, with the compiler
# enforcing the absence of any Fs / Env / Net / Stdio call
# inside the helpers.
