"""The corpora of instrument (a): what is generated, with which kinds, and
the positive controls per outcome class.

A corpus is ``(name, family, count, seed)`` over a kind set; the public
corpora use the public kinds and a private extension may add corpora over
the extended kinds, so the public programs are byte-identical whether or
not the extension is present (their register entries stay valid). The
anchors are a corpus too, with their HAND-WRITTEN expectations. The four
controls assert the harness itself: each must read exactly its outcome
class before any register is consulted.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tests.instruments._outcome import ABORT, OK, expectation_text, expected_of
from tests.instruments._runner import Program
from tests.instruments.absolute._rule import HEADER, MAIN, STMT, Gen, anchors, check_anchors, program


@dataclass(frozen=True)
class CorpusSpec:
    name: str
    family: str
    count: int
    seed: int
    #: Restrict the STATEMENT kinds to these (expression kinds stay).
    only: Optional[tuple] = None


PUBLIC_CORPORA = (
    CorpusSpec("mix", "mix", 200, 4242),
    CorpusSpec("ovf", "stmt", 60, 4243, only=("ovf",)),
)


def kinds_for(spec: CorpusSpec, kinds: dict) -> dict:
    if spec.only is None:
        return dict(kinds)
    return {n: k for n, k in kinds.items() if k.category != STMT or n in spec.only}


class AnchorFailure(AssertionError):
    pass


def write_program(directory: Path, name: str, src: str, exit: str, stdout: str) -> Program:
    base = Path(directory) / name
    base.with_suffix(".capa").write_text(src, encoding="utf-8", newline="\n")
    base.with_suffix(".expected").write_text(expectation_text(exit, stdout), encoding="utf-8", newline="\n")
    return Program(name + ".capa", base.with_suffix(".capa"))


def write_corpus(directory: Path, spec: CorpusSpec, kinds: dict, anchor_list: Optional[list] = None) -> list:
    """Generate ``spec`` into ``directory``. Refuses to write anything while
    the evaluator fails an anchor."""
    fails = check_anchors(Gen(random.Random(0), kinds), anchor_list)
    if fails:
        raise AnchorFailure("the evaluator fails %d anchor(s): %s" % (
            len(fails), [(a.title, want, got) for a, want, got in fails]))
    Path(directory).mkdir(parents=True, exist_ok=True)
    rnd = random.Random(spec.seed)
    ks = kinds_for(spec, kinds)
    out = []
    for i in range(spec.count):
        src, (exit, stdout) = program(rnd, spec.family, ks)
        out.append(write_program(directory, "%s_%04d" % (spec.name, i), src, exit, stdout))
    return out


def write_anchor_programs(directory: Path, anchor_list: list) -> list:
    """The anchors as programs, with the HAND-WRITTEN expectation."""
    Path(directory).mkdir(parents=True, exist_ok=True)
    return [write_program(directory, "anchor_" + a.slug, a.source, a.expected_exit, a.expected_stdout)
            for a in anchor_list]


#: name -> (source, expected exit, expected stdout, {leg: asserted outcome type})
CONTROLS = {
    "ctl_timeout": (
        "fun main(stdio: Stdio)\n    var i = 0\n    while true\n        i = i + 1\n    stdio.println(\"never\")\n",
        OK, "never\n", {"check": "CORRECT", "run": "TIMEOUT", "ir": "TIMEOUT", "wasm": "TIMEOUT"}),
    "ctl_refused": (
        "fun main(stdio: Stdio)\n    let x: Int = \"s\"\n    stdio.println(\"${x}\")\n",
        OK, "s\n", {"check": "REFUSED", "run": "REFUSED", "ir": "REFUSED", "wasm": "REFUSED"}),
    "ctl_wrong": (
        "fun main(stdio: Stdio)\n    stdio.println(\"one\")\n",
        OK, "two\n", {"check": "CORRECT", "run": "WRONG", "ir": "WRONG", "wasm": "WRONG"}),
    "ctl_abort": (
        "fun main(stdio: Stdio)\n    let big: Int = 9223372036854775807\n    stdio.println(\"before\")\n"
        "    stdio.println(\"${big + 1}\")\n",
        ABORT, "before\n", {"check": "CORRECT", "run": "CORRECT", "ir": "CORRECT", "wasm": "CORRECT"}),
    # A guard carrying a call is refused by the CIR Python emitter today
    # (UnsupportedInIR, the breadcrumb the command line prints): the one
    # leg that cannot lower it must read BROKEN, the others CORRECT. When
    # that gap closes this control reads CORRECT on every leg and must be
    # replaced by another compile-phase shape, or retired with its class.
    "ctl_broken": (
        HEADER + MAIN + "    match t(stdio, 1)\n        1 if t(stdio, 2) > 0 -> stdio.println(\" g\")\n"
        "        _ -> stdio.println(\" o\")\n",
        OK, "[1][2] g\n", {"check": "CORRECT", "run": "CORRECT", "ir": "BROKEN", "wasm": "CORRECT"}),
}


def write_controls(directory: Path) -> list:
    Path(directory).mkdir(parents=True, exist_ok=True)
    return [write_program(directory, name, src, exit, stdout)
            for name, (src, exit, stdout, _asserted) in CONTROLS.items()]


def expectation(prog: Program) -> tuple:
    return expected_of(Path(prog.path).with_suffix(".expected").read_text(encoding="utf-8"))


def source_text(prog: Program) -> str:
    return Path(prog.path).read_text(encoding="utf-8")
