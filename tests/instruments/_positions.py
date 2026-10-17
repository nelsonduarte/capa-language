"""The strict condition-position family as the instruments read it: ONE
place.

The table lives in ``tests.implicit_flow._generated``; a private extension
(``_private.load_module("strict_positions")``) may add positions. The
strict-positions gate and the release differential's seeded negative
corpus both read the family through ``write_programs``, so neither can see
a different set of positions from the other.
"""

from __future__ import annotations

from pathlib import Path

from tests.implicit_flow._generated import CONDITION_POSITIONS, generate_conditions
from tests.instruments._private import load_module
from tests.instruments._runner import Program


def positions() -> dict:
    """The public positions plus the private extension's, when loaded."""
    table = dict(CONDITION_POSITIONS)
    ext = load_module("strict_positions")
    if ext is not None:
        table.update(ext.CONDITION_POSITIONS)
    return table


def write_programs(directory) -> list:
    """Every (position, secret | public) program of the family written into
    ``directory``: ``[(program, source, verdict), ...]``."""
    d = Path(directory)
    d.mkdir(parents=True, exist_ok=True)
    out = []
    for name, src, verdict in generate_conditions(positions()):
        p = d / (name + ".capa")
        p.write_text(src, encoding="utf-8", newline="\n")
        out.append((Program(p.name, p), src, verdict))
    return out
