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

Exit codes, one per condition; every refusal (2 to 7) prints one line
naming its cause and writes nothing:

- 0: up to date, or regenerated;
- 1: the block differs from the rendering (``--check`` only); no other
  condition uses this code;
- 2: the document does not carry exactly one BEGIN and one END marker, in
  that order;
- 3: the ``capa`` package that would supply the constant is not the one in
  this checkout, or there is none (nothing is read from it);
- 4: this checkout's scope module raises when the key and the sentence are
  imported from it, for instance because a clause would name an empty set
  (``SystemExit`` included);
- 5: importing this checkout's ``capa`` package raises, ``SystemExit``
  included (the error is named);
- 6: the register document cannot be read or written (the error is named);
- 7: any other error, a defect of this script (the error is named).

Not mapped: an interrupt (``KeyboardInterrupt``) ends the process as an
interrupt does. The document's own line endings are preserved.
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
EXIT_PACKAGE_RAISED = 5
EXIT_REGISTER_UNREADABLE = 6
EXIT_GENERATOR_ERROR = 7

BEGIN = (
    "<!-- BEGIN GENERATED: unaudited_secret_sinks scope "
    "(tools/gen_trust_register.py) -->"
)
END = "<!-- END GENERATED: unaudited_secret_sinks scope -->"

WIDTH = 72


class Refusal(Exception):
    """A condition under which the script writes nothing; ``code`` is its
    exit code."""

    code = EXIT_GENERATOR_ERROR


class MarkerProblem(Refusal):
    """The document does not carry exactly one marker pair in order."""

    code = EXIT_MARKERS


class ForeignCapa(Refusal):
    """The importable ``capa`` is not the one beside this script."""

    code = EXIT_FOREIGN_CAPA


class ScopeUnrendered(Refusal):
    """Importing the key and the sentence from this checkout's scope module
    raised, for instance because it refuses to render a clause over an
    empty name set."""

    code = EXIT_SCOPE_UNRENDERED


class PackageRaised(Refusal):
    """Importing this checkout's own ``capa`` package raised."""

    code = EXIT_PACKAGE_RAISED


class RegisterUnreadable(Refusal):
    """The register document cannot be read or written."""

    code = EXIT_REGISTER_UNREADABLE


# What an import of this checkout's package or scope module can raise that
# is reported as that import's failure: any error, and a SystemExit, which
# would otherwise end the script with its own code and no message.
_IMPORT_FAILURES = (Exception, SystemExit)


def _named(e: BaseException) -> str:
    return f"{type(e).__name__}: {e}"


def _constants() -> tuple[str, str]:
    """The key and the sentence, imported from this repository's package.

    The repository root is put first on the import path, and the package
    that actually loads is checked to sit under it: with no ``capa/``
    beside ``tools/``, an editable install or a ``PYTHONPATH`` entry would
    otherwise supply another tree's constant and the register would be
    verified, or rewritten, against the wrong sentence. An error raised
    while this checkout's own package is imported is that package's, and
    is reported as such."""
    sys.path.insert(0, str(REPO_ROOT))
    own = (REPO_ROOT / "capa" / "__init__.py").is_file()
    try:
        import capa
    except _IMPORT_FAILURES as e:
        if own:
            raise PackageRaised(f"importing capa/ raised {_named(e)}") from e
        raise ForeignCapa(f"no capa package beside tools/ ({_named(e)})") from e
    loaded = Path(capa.__file__).resolve()
    if REPO_ROOT.resolve() not in loaded.parents:
        raise ForeignCapa(f"capa imported from {loaded}, not from {REPO_ROOT}")
    try:
        from capa.manifest._scope import (
            UNAUDITED_SECRET_SINKS_SCOPE, UNAUDITED_SECRET_SINKS_SCOPE_KEY,
        )
    except _IMPORT_FAILURES as e:
        raise ScopeUnrendered(
            f"capa/manifest/_scope.py does not render its sentence ({_named(e)})",
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
    rendering. Raises ``ForeignCapa``, ``PackageRaised`` or
    ``ScopeUnrendered`` before anything else when the constant cannot be
    obtained from this checkout, then ``MarkerProblem`` unless the document
    carries exactly one BEGIN and one END marker, in that order: a second
    block would be a copy this script never checks."""
    rendered = render_block(*_constants())
    begins, ends = current.count(BEGIN), current.count(END)
    if (begins, ends) != (1, 1):
        raise MarkerProblem(
            f"expected exactly one marker pair, found {begins} BEGIN and "
            f"{ends} END; expected exactly {BEGIN!r} ... {END!r}",
        )
    if current.index(BEGIN) > current.index(END):
        raise MarkerProblem(
            f"END marker precedes BEGIN marker; expected exactly {BEGIN!r} ... {END!r}",
        )
    newline = "\r\n" if "\r\n" in current else "\n"
    head, rest = current.split(BEGIN, 1)
    _stale, tail = rest.split(END, 1)
    block = newline.join([BEGIN, *rendered, END])
    return head + block + tail


def _run(check: bool) -> int:
    try:
        with open(REGISTER, encoding="utf-8", newline="") as fh:
            current = fh.read()
    except (OSError, UnicodeDecodeError) as e:
        raise RegisterUnreadable(f"the register cannot be read ({_named(e)})") from e
    expected = expected_text(current)
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
    try:
        with open(REGISTER, "w", encoding="utf-8", newline="") as fh:
            fh.write(expected)
    except OSError as e:
        raise RegisterUnreadable(f"the register cannot be written ({_named(e)})") from e
    print(f"{REGISTER}: regenerated")
    return 0


def main(argv: list[str]) -> int:
    """Run the check or the regeneration and map every refusal, and every
    error this script does not anticipate, to its own exit code: none of
    them is ever reported as drift or as another condition."""
    try:
        return _run("--check" in argv)
    except MarkerProblem as e:
        print(f"{REGISTER}: {e}", file=sys.stderr)
        return e.code
    except Refusal as e:
        print(f"{REGISTER}: refusing to run: {e}", file=sys.stderr)
        return e.code
    except Exception as e:
        print(
            f"{REGISTER}: refusing to run: an error this script does not "
            f"anticipate ({_named(e)})", file=sys.stderr,
        )
        return EXIT_GENERATOR_ERROR


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
