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

The document's own line endings are preserved.
"""

from __future__ import annotations

import sys
import textwrap
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTER = REPO_ROOT / "docs" / "trust-model.md"

BEGIN = (
    "<!-- BEGIN GENERATED: unaudited_secret_sinks scope "
    "(tools/gen_trust_register.py) -->"
)
END = "<!-- END GENERATED: unaudited_secret_sinks scope -->"

WIDTH = 72


def _constants() -> tuple[str, str]:
    """The key and the sentence, imported from this repository's package
    (the repository root is put first on the import path so an editable
    install of another checkout cannot be read by mistake)."""
    sys.path.insert(0, str(REPO_ROOT))
    from capa.manifest._scope import (
        UNAUDITED_SECRET_SINKS_SCOPE, UNAUDITED_SECRET_SINKS_SCOPE_KEY,
    )
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
    rendering. Raises ``ValueError`` when a marker is missing."""
    newline = "\r\n" if "\r\n" in current else "\n"
    head, rest = current.split(BEGIN, 1)
    _stale, tail = rest.split(END, 1)
    block = newline.join([BEGIN, *render_block(*_constants()), END])
    return head + block + tail


def main(argv: list[str]) -> int:
    check = "--check" in argv
    with open(REGISTER, encoding="utf-8", newline="") as fh:
        current = fh.read()
    try:
        expected = expected_text(current)
    except ValueError:
        print(
            f"{REGISTER}: register markers not found; expected "
            f"{BEGIN!r} ... {END!r}", file=sys.stderr,
        )
        return 2
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
        return 1
    with open(REGISTER, "w", encoding="utf-8", newline="") as fh:
        fh.write(expected)
    print(f"{REGISTER}: regenerated")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
