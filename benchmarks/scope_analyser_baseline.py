"""Hand-Python baseline for scope_analyser.capa. Idiomatic Python
using dataclasses and native lists. Mirrors the algorithm and
shape exactly so the comparison is fair.
"""

from dataclasses import dataclass


DECL_LET = "let"
DECL_VAR = "var"
DECL_CONST = "const"


@dataclass
class Decl:
    name: str
    kind: str


@dataclass
class Binding:
    name: str
    scope_index: int
    kind: str


def build_decls(n: int) -> list[Decl]:
    result: list[Decl] = []
    for i in range(n):
        r = i % 3
        if r == 0:
            kind = DECL_LET
        elif r == 1:
            kind = DECL_VAR
        else:
            kind = DECL_CONST
        result.append(Decl(name=f"v{i}", kind=kind))
    return result


def analyse_scopes(program: list[Decl]) -> list[Binding]:
    bindings: list[Binding] = []
    for idx, d in enumerate(program):
        bindings.append(Binding(name=d.name, scope_index=idx % 5, kind=d.kind))
    return bindings


def workload() -> int:
    decls = build_decls(1000)
    bindings = analyse_scopes(decls)
    return len(bindings)
