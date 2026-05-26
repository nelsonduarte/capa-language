"""A naive Python ANSI colour wrapper, of the shape that appears
in essentially every Python CLI tool that wants coloured terminal
output (PyPI `colorama` has ~50M downloads/month; the stdlib has
nothing equivalent, so people either pull in colorama or hand-roll
the half-dozen escape constants below).

The signatures `colored(text: str, fg: str = "") -> str`,
`bold(text: str) -> str`, and `strip_ansi(text: str) -> str`
exercise NO capabilities at all - every function is pure. They
produce strings; they do not print them. The top-level import
block is empty: this file imports nothing. A PURL-based SBOM
emitted by syft / pip-licenses for this file therefore has
nothing to say beyond "this script depends on Python itself".

This pair makes a distinction that the casual reader gets wrong.
"colorama is a terminal output library" is the folk-summary, and
it tempts a reader to file it under Stdio. The folk-summary is
wrong at the per-function level: `colored` and `bold` and
`strip_ansi` only construct and parse strings. The Stdio call is
the caller's `print(colored(...))`. PURL cannot tell those two
apart; Capa's per-function attribution can.

The Capa equivalent (see `capa.capa`) proves that the three
producer functions are purity-verified by the compiler, and that
only `main` (the demo entry point that actually emits the
strings) declares `Stdio`.

This file is not run by the test suite; it is included only as
the hand-Python comparison artefact for the SBOM-diff study
harness.
"""


# Foreground colour codes (Select Graphic Rendition / SGR). The
# byte 0x1B (ESC, octal 033) starts a Control Sequence Introducer
# when followed by '['; the trailing 'm' marks the sequence as an
# SGR command. Codes 30-37 are the eight base foreground colours.
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

# Resets all SGR attributes (colour, bold, underline) back to the
# terminal default. Every coloured run should end with this so
# subsequent output is not stained.
RESET = "\033[0m"

# Bold (technically "increased intensity"). Some terminals render
# it as a brighter colour rather than a heavier weight; the
# library's job is to emit the escape, not to police rendering.
BOLD = "\033[1m"


def colored(text: str, fg: str = "") -> str:
    # Empty `fg` means "no colour wrap"; return the input as-is so
    # callers can compose `colored(text, RED if error else "")`
    # without a conditional at every call site.
    if fg == "":
        return text
    return fg + text + RESET


def bold(text: str) -> str:
    return BOLD + text + RESET


def strip_ansi(text: str) -> str:
    # Char-by-char state machine: copy characters through, but on
    # ESC (0x1B) drop everything until and including the next 'm'.
    # This covers the SGR subset that `colored` and `bold` emit
    # (everything we produce above terminates on 'm'); a fuller
    # implementation would also handle the other CSI terminators,
    # but the round-trip claim this pair makes is about the SGR
    # subset we ourselves generate.
    out: list[str] = []
    i = 0
    n = len(text)
    while i < n:
        c = text[i]
        if c == "\033":
            i += 1
            while i < n and text[i] != "m":
                i += 1
            if i < n:
                i += 1  # consume the 'm'
        else:
            out.append(c)
            i += 1
    return "".join(out)


# A PURL-based SBOM emitted by syft / pip-licenses for this file
# would list nothing: the file has no imports at all, and the
# colorama PyPI package itself has no cap-bearing runtime
# dependencies (it is essentially the same set of escape-code
# constants plus a Windows console shim). The PURL SBOM is silent.
#
# That silence is the comparison failure this pair surfaces.
# Colorama strings are typically `print()`-ed by the caller, so
# the casual reader files the library under "Stdio". But the
# library itself only produces strings; the printing is the
# caller's responsibility. A PURL line `pkg:pypi/colorama@0.4.6`
# in a downstream SBOM conveys nothing about whether the consumer
# actually emits the coloured strings or just builds them (for
# tests, logs, structured output, etc.). The Capa version names
# every producer function and declares zero capabilities, with
# the compiler enforcing it; only `main` (the demo caller) holds
# `Stdio`, and only because it is the one that actually prints.
