"""The grammar COMPLETENESS PIN of instrument (a).

Every Expr / Stmt / Pattern node class of ``capa.capa_ast`` must be
PRODUCED in a generated body (the shared header does not count: it is the
same in every program and varies nothing) or listed in ``EXCLUDED`` with a
reason. A class that is neither fails the pin, so a new node class fails
it by construction; a class both excluded and produced is a stale
exclusion and fails too. At least one match arm must carry a guard.
"""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from typing import Optional

from tests.instruments.absolute._rule import EXCLUDED, HEADER

BASES = ("Expr", "Stmt", "Pattern")


def node_classes() -> dict:
    """``{class name: base name}`` for every concrete AST node class."""
    from capa import capa_ast as A
    bases = {n: getattr(A, n) for n in BASES}
    out = {}
    for name in dir(A):
        c = getattr(A, name)
        if isinstance(c, type) and dataclasses.is_dataclass(c):
            for bn, b in bases.items():
                if issubclass(c, b) and c is not b:
                    out[name] = bn
    return out


def body_of(src: str) -> str:
    if not src.startswith(HEADER):
        raise ValueError("a generated program must start with the shared header")
    return src[len(HEADER):]


def classes_in(src: str) -> tuple:
    """``(class names produced, guarded arm count)`` of one source."""
    from capa import Lexer, Parser
    seen, guards = set(), 0

    def walk(o):
        nonlocal guards
        if dataclasses.is_dataclass(o) and not isinstance(o, type):
            seen.add(type(o).__name__)
            if type(o).__name__ == "MatchArm" and getattr(o, "guard", None) is not None:
                guards += 1
            for f in dataclasses.fields(o):
                walk(getattr(o, f.name))
        elif isinstance(o, (list, tuple)):
            for x in o:
                walk(x)
        elif isinstance(o, dict):
            for x in o.values():
                walk(x)
    walk(Parser(Lexer(src).lex(), source=src).parse_module())
    return seen, guards


@dataclass
class PinResult:
    produced: dict
    uncovered: list
    stale: list
    guarded_arms: int
    programs: int

    @property
    def green(self) -> bool:
        return not self.uncovered and not self.stale and self.guarded_arms > 0

    def report(self) -> str:
        return ("%s programs=%d guarded_arms=%d produced=%s uncovered=%s stale_exclusions=%s" % (
            "GREEN" if self.green else "RED", self.programs, self.guarded_arms,
            {b: "%d of %d" % (len(v["produced"]), v["total"]) for b, v in self.produced.items()},
            self.uncovered, self.stale))


def pin(sources, excluded: Optional[dict] = None) -> PinResult:
    """``excluded`` defaults to the grammar's ``EXCLUDED``; a test may pass
    its own table to prove a stale exclusion is reported."""
    if excluded is None:
        excluded = EXCLUDED
    all_classes = node_classes()
    seen, guards, n = set(), 0, 0
    for src in sources:
        s, gd = classes_in(body_of(src))
        seen |= s
        guards += gd
        n += 1
    produced = {}
    uncovered = []
    for bn in BASES:
        total = sorted(c for c, b in all_classes.items() if b == bn)
        produced[bn] = {"total": len(total), "produced": sorted(c for c in total if c in seen)}
        uncovered += [c for c in total if c not in seen and c not in excluded]
    stale = sorted(c for c in excluded if c in seen)
    return PinResult(produced, uncovered, stale, guards, n)
