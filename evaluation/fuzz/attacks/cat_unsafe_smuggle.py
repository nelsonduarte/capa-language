"""Unsafe-escape smuggling attack category.

Capa's ``Unsafe`` capability is the documented escape hatch for
calling into arbitrary Python (`py_import`, `py_invoke`). The
discipline says: only functions that declare ``Unsafe`` may
reach those primitives.

This category tries to invoke ``py_import`` / ``py_invoke`` from
functions that do NOT declare ``Unsafe``. Each attempt should be
rejected by the analyzer because the primitives are
capability-gated.

A successful escape here is paper-critical: it would mean the
Unsafe boundary, the load-bearing escape valve, is itself
porous.
"""

from __future__ import annotations

from evaluation.fuzz.attacks.cat_fs_traversal import Attack

CATEGORY_NAME = "cat_unsafe_smuggle"

CATEGORY_DESCRIPTION = (
    "Programs that try to invoke py_import / py_invoke (the "
    "Unsafe-gated Python escape hatches) from functions that "
    "did NOT declare the Unsafe capability."
)

DANGEROUS_MODULES = [
    "os", "subprocess", "socket", "shutil", "ctypes",
    "urllib.request", "requests", "pathlib", "ssl",
    "marshal",
]


def generate():
    out: list[Attack] = []
    for mod in DANGEROUS_MODULES:
        out.append(Attack(
            attack_id=f"unsafe_py_import_{mod.replace('.', '_')}",
            description=f"py_import({mod!r}) without Unsafe.",
            source=(
                'fun main(stdio: Stdio)\n'
                f'    let m = py_import("{mod}")\n'
                '    stdio.println("smuggled")\n'
            ),
        ))
        out.append(Attack(
            attack_id=f"unsafe_py_import_helper_{mod.replace('.', '_')}",
            description=f"py_import({mod!r}) inside a no-Unsafe helper.",
            source=(
                'fun smuggle()\n'
                f'    let _ = py_import("{mod}")\n'
                'fun main(stdio: Stdio)\n'
                '    smuggle()\n'
                '    stdio.println("smuggled")\n'
            ),
        ))
    return out
