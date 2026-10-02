"""Keep the ``unaudited_secret_sinks`` entry of ``docs/trust-model.md``
equal to the one constant in ``capa/manifest/_scope.py``.

The register entry sits between two marker comments in the document.
This script renders the entry from the constant and either rewrites the
block in place (the default) or, with ``--check``, exits 1 when the block
on disk differs from the rendering. ``tests/test_attestation_scope.py``
runs the check, so a hand edit of the block, or a change of the constant
without regeneration, fails the suite.

    python tools/gen_trust_register.py            # regenerate the block
    python tools/gen_trust_register.py --check    # exit 1 on drift

Exit codes: 0 up to date (or regenerated), 1 the block differs
(``--check`` only), 2 the document does not carry exactly one marker
pair, 3 the ``capa`` package that would supply the constant is not the
one in this checkout (nothing is read from it and nothing is written),
4 this checkout's scope module does not import or does not render its
sentence, for instance because a clause would name an empty set
(nothing is written).

The document's own line endings are preserved.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = REPO_ROOT / "docs" / "trust-model.md"

EXIT_DRIFT = 1
EXIT_MARKERS = 2
EXIT_FOREIGN_CAPA = 3
EXIT_SCOPE_UNRENDERED = 4

BEGIN = (
    "<!-- BEGIN GENERATED: unaudited_secret_sinks scope "
    "(tools/gen_trust_register.py) -->"
)
END = "<!-- END GENERATED: unaudited_secret_sinks scope -->"

WIDTH = 72


class ForeignCapa(Exception):
    """The importable ``capa`` is not the one beside this script."""


class ScopeUnrendered(Exception):
    """Importing the key and the sentence from this checkout's scope module
    raised, for instance because it refuses to render a clause over an
    empty name set."""


def _constants() -> tuple[str, str]:
    """The key and the sentence, imported from this repository's package.

    The repository root is put first on the import path, and the package
    that actually loads is checked to sit under it: with no ``capa/``
    beside ``tools/``, an editable install or a ``PYTHONPATH`` entry would
    otherwise supply another tree's constant and the register would be
    verified, or rewritten, against the wrong sentence."""
    sys.path.insert(0, str(REPO_ROOT))
    try:
        import capa
    except ImportError as e:
        raise ForeignCapa(f"no capa package importable ({e})") from e
    loaded = Path(capa.__file__).resolve()
    if REPO_ROOT.resolve() not in loaded.parents:
        raise ForeignCapa(f"capa imported from {loaded}, not from {REPO_ROOT}")
    # Any error here is the scope module's own (the package is this
    # checkout's), so it is reported as such and never as a marker problem.
    try:
        from capa.manifest._scope import (
            UNAUDITED_SECRET_SINKS_SCOPE, UNAUDITED_SECRET_SINKS_SCOPE_KEY,
        )
    except Exception as e:
        raise ScopeUnrendered(
            f"capa/manifest/_scope.py does not render its sentence "
            f"({type(e).__name__}: {e})",
        ) from e
    return UNAUDITED_SECRET_SINKS_SCOPE_KEY, UNAUDITED_SECRET_SINKS_SCOPE


def render_block(key: str, sentence: str) -> list[str]:
    """The register entry as document lines, markers excluded."""
    entry = textwrap.wrap(
        f"- **What `unaudited_secret_sinks` attests.** {sentence}",
        width=WIDTH, subsequent_indent="  ",
        break_long_words=False, break_on_hyphens=False,
    )
    carriage = textwrap.wrap(
        "Every `--manifest`, `--manifest-digest`, `--compose-sbom` and "
        "`--conformance-report` document carries this sentence verbatim "
        f"under the top-level `{key}` key. This entry is generated from "
        "`capa/manifest/_scope.py`: change the constant there and run "
        "`python tools/gen_trust_register.py`.",
        width=WIDTH, initial_indent="  ", subsequent_indent="  ",
        break_long_words=False, break_on_hyphens=False,
    )
    return entry + [""] + carriage


def expected_text(current: str) -> str:
    """``current`` with the block between the markers replaced by the
    rendering. Raises ``ForeignCapa`` before anything else when the
    importable package is not this checkout's, then ``ScopeUnrendered``
    when its scope module does not yield the sentence, and ``ValueError``
    when the document does not carry exactly one BEGIN and one END marker,
    in that order: a second block would be a copy this script never
    checks."""
    rendered = render_block(*_constants())
    begins, ends = current.count(BEGIN), current.count(END)
    if (begins, ends) != (1, 1):
        raise ValueError(
            f"expected exactly one marker pair, found {begins} BEGIN and "
            f"{ends} END",
        )
    if current.index(BEGIN) > current.index(END):
        raise ValueError("END marker precedes BEGIN marker")
    newline = "\r\n" if "\r\n" in current else "\n"
    head, rest = current.split(BEGIN, 1)
    _stale, tail = rest.split(END, 1)
    block = newline.join([BEGIN, *rendered, END])
    return head + block + tail


def main(argv: list[str]) -> int:
    check = "--check" in argv
    with open(REGISTER, encoding="utf-8", newline="") as fh:
        current = fh.read()
    try:
        expected = expected_text(current)
    except ValueError as e:
        print(
            f"{REGISTER}: {e}; expected exactly {BEGIN!r} ... {END!r}",
            file=sys.stderr,
        )
        return EXIT_MARKERS
    except ForeignCapa as e:
        print(f"{REGISTER}: refusing to run: {e}", file=sys.stderr)
        return EXIT_FOREIGN_CAPA
    except ScopeUnrendered as e:
        print(f"{REGISTER}: refusing to run: {e}", file=sys.stderr)
        return EXIT_SCOPE_UNRENDERED
    if current == expected:
        if not check:
            print(f"{REGISTER}: up to date")
        return 0
    if check:
        print(
            f"{REGISTER}: the generated unaudited_secret_sinks block differs "
            f"from capa/manifest/_scope.py; run "
            f"python tools/gen_trust_register.py", file=sys.stderr,
        )
        return EXIT_DRIFT
    with open(REGISTER, "w", encoding="utf-8", newline="") as fh:
        fh.write(expected)
    print(f"{REGISTER}: regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
