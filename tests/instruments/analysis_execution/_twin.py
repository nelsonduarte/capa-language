"""The twin builder, its guards and the verdict of instrument (b).

For each case (a single file whose first line declares the verdict it
expects):

1. ANALYSIS of the labelled program, in-process and never executed: ok,
   information-flow errors and warnings through ONE classifier, the
   implicit-flow harness's regex applied to both lists. The TIER is ERROR
   when an IFC error was raised, WARN when only a warning, else SILENT.
2. TWIN: every ``<env>.get("literal")`` of an ``Env`` parameter becomes
   ``Some(MARKER)`` and the parameter is renamed so the unused capability
   is legal. The builder reports how many sites it substituted.
3. GUARDS, before any execution: the twin is parsed and analysed, and
   every method call whose receiver the ANALYZER types as a capability is
   looked up in the compiler's own secret-source table; a call to a
   source method on a receiver the analyzer could not type counts too.
   An alias (``let e2 = env``), a field, a parameter: whatever the
   analyzer types, the scan sees. Any hit is SECRET-IN-TWIN and the twin
   is NOT run. Zero substitutions is NOMARKER, more than one is
   MULTI-SOURCE (one source site per case), a twin the checker refuses is
   TWIN-BROKEN; none of these is ever CLEAN.
4. EXECUTION of the twin through the bounded runner, one working
   directory per (case, leg); the OBSERVED text of a leg is its stdout,
   its stderr, the abort message and EVERY file written under that
   directory, so a sink that writes a file under any name is read.
5. VERDICT, one per case, carrying the tier:
     FLAGGED-CONFIRMED    flagged at the expected tier AND the marker reached an observable on every leg
     FLAGGED-UNCONFIRMED  flagged, but the marker reached no observable on some leg (the twin lost it)
     TIER-DOWNGRADE       a @strict_ifc program flagged only at WARN
     MISMATCH             silent, and the marker reached an observable
     CLEAN                silent, the twin ran on every leg, the marker appeared nowhere
     TWIN-PARTIAL         silent, the twin ran on some legs only (never CLEAN)
     TWIN-BROKEN / NOMARKER / SECRET-IN-TWIN / MULTI-SOURCE / NOTWIN / REFUSED
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from tests.implicit_flow._harness import check_source, ifc_errors, ifc_warnings
from tests.instruments._outcome import (
    BROKEN, CORRECT, OK, REFUSED, TIMEOUT, VOID, outcome_type, wrong,
)
from tests.instruments._runner import Program, run_leg

MARKER = "MKR-QA-PUBLIC"
EXPECT_LINE = re.compile(r"^//\s*expect:\s*([A-Z\-]+)\s*$")

FLAGGED_CONFIRMED = "FLAGGED-CONFIRMED"
FLAGGED_UNCONFIRMED = "FLAGGED-UNCONFIRMED"
TIER_DOWNGRADE = "TIER-DOWNGRADE"
MISMATCH = "MISMATCH"
CLEAN = "CLEAN"
TWIN_PARTIAL = "TWIN-PARTIAL"
TWIN_BROKEN = "TWIN-BROKEN"
NOMARKER = "NOMARKER"
SECRET_IN_TWIN = "SECRET-IN-TWIN"
MULTI_SOURCE = "MULTI-SOURCE"
NOTWIN = "NOTWIN"

#: Verdicts a case may EXPECT.
EXPECTABLE = (FLAGGED_CONFIRMED, CLEAN)
#: Verdicts that mean the instrument could not measure the case.
NOT_MEASURED = (TWIN_PARTIAL, TWIN_BROKEN, NOMARKER, SECRET_IN_TWIN, MULTI_SOURCE, NOTWIN)

TWIN_FAULTS = ("swaporder", "nosubst", "emptymarker")

LEG = "verdict"


@dataclass(frozen=True)
class Case:
    name: str
    path: Path
    source: str
    expected: str


def load_cases(directory) -> list:
    """Every ``.capa`` under ``directory`` with its declared expectation.
    A case without one, or expecting a verdict a case may not expect, fails
    the loader."""
    out = []
    for p in sorted(Path(directory).glob("*.capa")):
        src = p.read_text(encoding="utf-8")
        m = EXPECT_LINE.match(src.splitlines()[0] if src else "")
        if m is None or m.group(1) not in EXPECTABLE:
            raise ValueError("%s: the first line must declare `// expect: <%s>`" % (p.name, " | ".join(EXPECTABLE)))
        out.append(Case(p.name, p, src, m.group(1)))
    return out


@dataclass(frozen=True)
class Analysis:
    ok: bool
    tier: str
    strict: bool
    errors: tuple


def analyse(src: str) -> Analysis:
    res = check_source(src)
    tier = "ERROR" if ifc_errors(res) else ("WARN" if ifc_warnings(res) else "SILENT")
    return Analysis(res.ok, tier, "@strict_ifc" in src, tuple(e.message for e in res.errors))


def build_twin(src: str, marker: str = MARKER, fault: Optional[str] = None) -> tuple:
    """``(twin source or None, substitutions)``. ``fault`` plants a
    deliberate builder error for the self-tests: ``swaporder`` renames
    before substituting (so nothing matches), ``nosubst`` never
    substitutes, ``emptymarker`` substitutes an empty marker."""
    params = set(re.findall(r"\b(\w+)\s*:\s*Env\b", src))
    if not params:
        return None, 0
    if fault == "emptymarker":
        marker = ""
    n = 0
    for p in sorted(params):
        get_re = r"\b" + re.escape(p) + r"\.get\(\s*\"[^\"]*\"\s*\)"
        rename = (r"\b" + re.escape(p) + r"\b", "_" + p)
        if fault == "swaporder":
            src = re.sub(*rename, src)
            src, k = re.subn(get_re, 'Some("%s")' % marker, src)
        elif fault == "nosubst":
            k = 0
            src = re.sub(*rename, src)
        else:
            src, k = re.subn(get_re, 'Some("%s")' % marker, src)
            src = re.sub(*rename, src)
        n += k
    return src, n


def secret_sources_in(src: str) -> tuple:
    """``(hits, analysis result)``: every call of a secret-source method on
    a receiver the analyzer types as that capability, every source-method
    call on a receiver it could not type, and any ``@secret`` annotation."""
    from capa import Lexer, Parser, analyze
    from capa import capa_ast as A
    from capa.analyzer._ifc_tables import _SECRET_SOURCES
    from capa.typesys import TyName
    source_methods = {m for _c, m in _SECRET_SOURCES}
    mod = Parser(Lexer(src).lex(), source=src).parse_module()
    res = analyze(mod, source=src)
    hits = []
    for node in A.walk(mod):
        if not isinstance(node, A.MethodCall) or node.method not in source_methods:
            continue
        ty = res.types.get(id(node.receiver))
        if ty is None:
            hits.append("untyped receiver of .%s(" % node.method)
        elif isinstance(ty, TyName) and (ty.name, node.method) in _SECRET_SOURCES:
            hits.append("%s.%s(" % (ty.name, node.method))
    if "@secret" in src:
        hits.append("@secret")
    return hits, res


@dataclass
class Verdict:
    case: str
    verdict: str
    tier: str
    n_subst: int = 0
    seen: tuple = ()
    ran: tuple = ()
    detail: str = ""
    leg_outcome: str = ""

    def outcome(self, expected: str) -> str:
        """The register outcome of the case against its expectation."""
        if self.leg_outcome:
            return self.leg_outcome
        if self.verdict == REFUSED:
            return REFUSED
        if self.verdict in NOT_MEASURED:
            return BROKEN
        if self.verdict == expected:
            return CORRECT
        return wrong([self.verdict, self.tier])


def _observed(row: dict, cwd: Path) -> str:
    parts = [row.get("stdout", ""), row.get("stderr", ""), row.get("exc", "")]
    for p in sorted(Path(cwd).rglob("*")):
        if p.is_file():
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def prepare(case: Case, work: Path, fault: Optional[str] = None) -> tuple:
    """Everything before execution: ``(verdict or None, twin path, analysis, n_subst)``.
    A verdict here means the case is decided without running anything."""
    an = analyse(case.source)
    if not an.ok and an.tier != "ERROR":
        return Verdict(case.name, REFUSED, an.tier, detail=an.errors[0] if an.errors else ""), None, an, 0
    twin, n = build_twin(case.source, fault=fault)
    if twin is None:
        return Verdict(case.name, NOTWIN, an.tier), None, an, 0
    d = Path(work) / case.name[:-5]
    d.mkdir(parents=True, exist_ok=True)
    tp = d / "twin.capa"
    tp.write_text(twin, encoding="utf-8", newline="\n")
    try:
        hits, tres = secret_sources_in(twin)
    except Exception as e:
        return Verdict(case.name, TWIN_BROKEN, an.tier, n, detail="twin parse: " + type(e).__name__), tp, an, n
    if hits:
        return Verdict(case.name, SECRET_IN_TWIN, an.tier, n, detail=",".join(hits)), tp, an, n
    if n == 0:
        return Verdict(case.name, NOMARKER, an.tier, n), tp, an, n
    if n > 1:
        return Verdict(case.name, MULTI_SOURCE, an.tier, n, detail="one source site per case: split it"), tp, an, n
    if not tres.ok:
        return Verdict(case.name, TWIN_BROKEN, an.tier, n,
                       detail="twin refused: " + (tres.errors[0].message if tres.errors else "")), tp, an, n
    return None, tp, an, n


def decide(case: Case, an: Analysis, n: int, rows: dict, cwds: dict, legs) -> Verdict:
    """The verdict from the twin's per-leg rows (``{leg: row}``) and the
    working directory each leg ran in."""
    seen, ran = [], []
    for leg in legs:
        row = rows.get(leg)
        if row is None:
            continue
        o = outcome_type(row["outcome"])
        if o in (TIMEOUT, VOID):
            return Verdict(case.name, o, an.tier, n, leg_outcome=o, detail=leg)
        if row["outcome"] == OK:
            ran.append(leg)
        if o != BROKEN and MARKER in _observed(row, cwds[leg]):
            seen.append(leg)
    if an.tier != "SILENT":
        if an.strict and an.tier != "ERROR":
            v = TIER_DOWNGRADE
        elif set(seen) >= set(legs):
            v = FLAGGED_CONFIRMED
        else:
            v = FLAGGED_UNCONFIRMED
    elif seen:
        v = MISMATCH
    elif len(ran) == len(legs):
        v = CLEAN
    elif ran:
        v = TWIN_PARTIAL
    else:
        v = TWIN_BROKEN
    return Verdict(case.name, v, an.tier, n, tuple(seen), tuple(ran))


def run_cases(tree, cases: list, work: Path, legs, fault: Optional[str] = None,
              bound: Optional[float] = None) -> dict:
    """``{case name: Verdict}`` over ``cases``; the twins run through the
    bounded runner, one child per leg, one working directory per (case, leg)."""
    work = Path(work)
    verdicts: dict = {}
    pending: dict = {}
    for case in cases:
        v, tp, an, n = prepare(case, work, fault)
        if v is not None:
            verdicts[case.name] = v
        else:
            pending[case.name] = (case, tp, an, n)
    if pending:
        rows_by_leg: dict = {}
        cwds: dict = {name: {} for name in pending}
        for leg in legs:
            programs = []
            for name, (case, tp, an, n) in pending.items():
                cwd = tp.parent / leg
                cwd.mkdir(exist_ok=True)
                cwds[name][leg] = cwd
                programs.append(Program(name, tp, cwd))
            kwargs = {"bound": bound} if bound is not None else {}
            rows_by_leg[leg] = run_leg(tree, leg, programs, workdir=work, **kwargs)
        for name, (case, tp, an, n) in pending.items():
            rows = {leg: rows_by_leg[leg].get(name) for leg in legs}
            verdicts[name] = decide(case, an, n, rows, cwds[name], legs)
    return verdicts
