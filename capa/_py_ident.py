"""Python-identifier sanitisation shared across emitters.

Both the legacy AST->Python transpiler and the CIR->Python emitter
render Capa names straight into Python source, so both must suffix any
name that collides with a Python keyword (a method ``with``, a field
``class``, a parameter ``in``). Keeping the keyword set and the
suffixing rule in one place means a def site and every use site of the
same name agree by construction, instead of two hand-synced copies of
the table drifting apart.
"""

from __future__ import annotations


# Reserved Python identifiers (the ``keyword.kwlist`` set). A Capa name
# equal to any of these cannot be emitted verbatim, so ``_safe_ident``
# suffixes it. ``match`` / ``case`` are soft keywords (legal as plain
# identifiers) and are deliberately absent.
_PY_KEYWORDS = {
    "False", "None", "True", "and", "as", "assert", "async", "await",
    "break", "class", "continue", "def", "del", "elif", "else", "except",
    "finally", "for", "from", "global", "if", "import", "in", "is",
    "lambda", "nonlocal", "not", "or", "pass", "raise", "return", "try",
    "while", "with", "yield",
}


def _safe_ident(name: str) -> str:
    """Suffix names that collide with Python keywords."""
    if name in _PY_KEYWORDS:
        return name + "_"
    return name
