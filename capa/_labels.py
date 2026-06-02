"""Information-flow security labels (roadmap S2).

A minimal two-point lattice -- the deliberate ergonomic choice over
arbitrary principal labels (Jif-style), which the Pony lesson says
kill usability:

    PUBLIC  ⊑  SECRET

``PUBLIC`` is the bottom (default for any unlabelled value);
``SECRET`` is the top (tainted). The join (⊔, least upper bound) of
two labels is the more-restricted one: ``public ⊔ secret = secret``.
A value may flow to a sink only if its label is ``⊑`` the sink's
required label; the dangerous flow is ``secret`` data reaching a
``public`` sink, which only ``declassify`` may bridge.

Kept as plain strings (``"public"`` / ``"secret"``) so the labels
serialise straight into the AST (``TypeExpr.label``), the manifest,
and diagnostics with no wrapper type. The helpers below are the only
place the ordering is encoded, so a future v2 that adds intermediate
levels changes one module.
"""

from __future__ import annotations

from typing import Optional

PUBLIC = "public"
SECRET = "secret"

# Source-level spellings accepted after ``@`` on a type.
VALID_LABELS = frozenset({PUBLIC, SECRET})

# Rank for the lattice ordering; higher = more restricted.
_RANK = {PUBLIC: 0, SECRET: 1}


def normalize(label: Optional[str]) -> str:
    """Map an optional (possibly ``None``) label to a concrete lattice
    point. Unlabelled defaults to ``PUBLIC`` (the bottom)."""
    return label if label in VALID_LABELS else PUBLIC


def join(a: Optional[str], b: Optional[str]) -> str:
    """Least upper bound: the more-restricted of two labels. This is
    how a derived value (``a + b``, ``f(a, b)``) inherits taint --
    ``secret`` if any operand is ``secret``, else ``public``."""
    a, b = normalize(a), normalize(b)
    return a if _RANK[a] >= _RANK[b] else b


def join_all(labels) -> str:
    """Join an iterable of labels; ``PUBLIC`` over an empty iterable."""
    out = PUBLIC
    for lbl in labels:
        out = join(out, lbl)
    return out


def flows_to(src: Optional[str], dst: Optional[str]) -> bool:
    """True if a value labelled ``src`` may flow to a position
    requiring ``dst`` -- i.e. ``src ⊑ dst``. The only forbidden flow
    is ``secret -> public``; everything else is permitted."""
    return _RANK[normalize(src)] <= _RANK[normalize(dst)]
