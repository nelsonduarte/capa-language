"""Filesystem-traversal attack category.

Each program here is a Capa source string that tries to read a
sensitive file from a function that does NOT declare the Fs
capability. All programs are expected to be rejected by
``capa --check`` because:

- ``Fs()`` as a call resolves to a capability symbol; the
  analyzer rejects capability construction at call sites since
  commit 67d9878 (capability-forge fix). Before that fix, the
  --python backend silently obtained unrestricted filesystem
  authority.
- Aliasing trickery (renaming the cap via let, smuggling through
  a tuple, hiding as a struct field) hits the existing discipline
  checks (`_check_no_capability` on let / var / struct field /
  return-type).

A new variation that escapes the static check is a real finding
and should be reported in §5.5 of the paper.

The harness calls ``generate()`` which returns a list of
``Attack`` records: each carries an id, the source string, and a
human-readable description for the failure report.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Attack:
    """A single attack program in this category."""

    attack_id: str
    description: str
    source: str


CATEGORY_NAME = "cat_fs_traversal"

CATEGORY_DESCRIPTION = (
    "Programs that try to read sensitive files (/etc/passwd, "
    ".bashrc, README.md as a stand-in on Windows) from functions "
    "that did NOT declare the Fs capability in their signature. "
    "Expected outcome: every program is rejected by `capa --check` "
    "with a 'capability cannot be constructed at a call site' or "
    "'capability cannot appear in ...' diagnostic. A program that "
    "passes --check is a static-soundness escape."
)


def generate() -> list[Attack]:
    """Return the attack panel for this category.

    Slice 1 ships three hand-written attacks; slice 6 will expand
    each to ~20 mutations (rename identifiers, vary the target
    path, vary the wrapper structure). For slice 1 the goal is
    end-to-end harness validation, not coverage.
    """
    return [
        Attack(
            attack_id="fs_traversal_direct_call",
            description=(
                "Direct construction of Fs inside main(stdio: Stdio) "
                "and read of /etc/passwd. This is the exact pattern "
                "that surfaced the soundness hole on 2026-05-24."
            ),
            source=(
                'fun main(stdio: Stdio)\n'
                '    let fs = Fs()\n'
                '    match fs.read("/etc/passwd")\n'
                '        Ok(text) -> stdio.println(text)\n'
                '        Err(_) -> stdio.eprintln("denied")\n'
            ),
        ),
        Attack(
            attack_id="fs_traversal_in_helper",
            description=(
                "Forge Fs inside a helper called by main. Verifies "
                "the check is not main-specific."
            ),
            source=(
                'fun leak() -> String\n'
                '    let fs = Fs()\n'
                '    match fs.read("/etc/passwd")\n'
                '        Ok(text) -> return text\n'
                '        Err(_) -> return "denied"\n'
                'fun main(stdio: Stdio)\n'
                '    stdio.println(leak())\n'
            ),
        ),
        Attack(
            attack_id="fs_traversal_relative_path",
            description=(
                "Direct Fs forge reading a relative path that exists "
                "on the harness CWD (README.md). Catches the case "
                "where /etc/passwd OSError masks the leak on Windows."
            ),
            source=(
                'fun main(stdio: Stdio)\n'
                '    let fs = Fs()\n'
                '    match fs.read("README.md")\n'
                '        Ok(text) -> stdio.println(text)\n'
                '        Err(_) -> stdio.eprintln("denied")\n'
            ),
        ),
    ]
