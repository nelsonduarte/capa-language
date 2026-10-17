"""The words of instrument (a)'s register entries: ONE table, ONE predicate,
ONE check.

Every reason an ``absolute`` entry may carry is a row: its exact text, the
programme step that closes it (``closes_in``), the legs and the outcome
type it may describe, the body shapes it claims (``needs``), the shapes
that make another row the right one (``excludes``), and the observation it
claims on the leg (a named predicate over the observed row and the rule's
expectation). A reason not in the table, a ``closes_in`` that is not the
row's, a body without a claimed shape, a body with an excluded one, or an
observation that does not hold is a mismatch.

A shape is read from the program BODY (the shared header stripped), parsed
with the compiler's own parser, by ONE walker over a table of detectors;
never from the source text, since the header alone would then claim
whatever it declares in every program.

``PUBLIC`` holds the rows, detectors and observations the public register
uses. A private configuration extends it (``ReasonTable.extended``) and
applies the same predicate and check to the merged register.

What ``check`` cannot see: the words of an entry whose outcome moved on
the tree under test. The register diff reports that entry; ``check`` lists
it as moved and does not judge it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from capa import Lexer, Parser
from capa import capa_ast as A
from tests.instruments import _register as REG
from tests.instruments._outcome import BROKEN, outcome_type, run_outcome
from tests.instruments.absolute._corpus import expectation, source_text
from tests.instruments.absolute._rule import HEADER

INSTRUMENT = "absolute"


# ---- the walker ----

def body_of(program) -> str:
    """The body of a generated program: its source with the shared header
    stripped. A program that does not start with the header is refused."""
    src = source_text(program)
    if not src.startswith(HEADER):
        raise ValueError("%s does not start with the shared header" % program.name)
    return src[len(HEADER):]


def body_shapes(body: str, detectors: dict) -> frozenset:
    """The shapes of a program body: every shape whose detector holds on
    some node of the parsed body."""
    found = set()
    for n in A.walk(Parser(Lexer(body).lex(), source=body).parse_module()):
        for shape, detect in detectors.items():
            if detect(n):
                found.add(shape)
    return frozenset(found)


def _has_call(node) -> bool:
    return any(isinstance(n, (A.Call, A.MethodCall)) for n in A.walk(node))


GUARD_CALL = "guard_call"


def _guard_carries_a_call(n) -> bool:
    return isinstance(n, A.MatchArm) and n.guard is not None and _has_call(n.guard)


# ---- the rows ----

def _unsupported_in_ir(row: dict, expected: tuple) -> bool:
    """The CIR Python emitter raised UnsupportedInIR before the program ran."""
    return "UnsupportedInIR" in row.get("exc", "")


@dataclass(frozen=True)
class Reason:
    key: str
    text: str
    closes_in: str
    legs: tuple
    outcome: str
    needs: frozenset
    excludes: frozenset = frozenset()
    observed: Optional[str] = None

    def separated_from(self, other: "Reason") -> bool:
        """Whether a column other than the shapes keeps this row and
        ``other`` from matching one entry. None here; an extension's rows
        may carry one."""
        return False


@dataclass
class Check:
    checked: int = 0
    judged_observations: int = 0
    mismatches: list = field(default_factory=list)
    moved: list = field(default_factory=list)

    def report(self) -> str:
        lines = ["checked %d entries, %d observations judged, %d mismatches, %d moved (not judged)"
                 % (self.checked, self.judged_observations, len(self.mismatches), len(self.moved))]
        lines += ["  MISMATCH %s: %s" % m for m in self.mismatches[:60]]
        lines += ["  MOVED %s" % m for m in self.moved[:20]]
        return "\n".join(lines)


def absolute_entries(entries: dict) -> dict:
    return {k: e for k, e in entries.items() if REG.split_key(k)[0] == INSTRUMENT}


@dataclass(frozen=True)
class ReasonTable:
    rows: tuple
    detectors: dict
    observations: dict

    def extended(self, rows=(), detectors=None, observations=None) -> "ReasonTable":
        """This table plus an extension's rows, detectors and observations.
        A name the extension shares with this table is refused."""
        detectors, observations = dict(detectors or {}), dict(observations or {})
        for mine, theirs in ((self.detectors, detectors), (self.observations, observations)):
            if set(mine) & set(theirs):
                raise ValueError("the extension redefines %s" % sorted(set(mine) & set(theirs)))
        return ReasonTable(self.rows + tuple(rows), {**self.detectors, **detectors},
                           {**self.observations, **observations})

    @property
    def by_text(self) -> dict:
        return {r.text: r for r in self.rows}

    def program_shapes(self, program) -> frozenset:
        return body_shapes(body_of(program), self.detectors)

    def failures(self, reason: Reason, leg: str, outcome: str, shapes: frozenset, observation=None) -> list:
        """The clauses of ``reason`` that do not hold for one entry. The
        observation clause is judged only when ``observation`` (``(row,
        expected)``) is given. THE predicate: a seeding picks the rows with
        none, the check reports the entry's row when it has some."""
        out = []
        if leg not in reason.legs:
            out.append("leg %s is not one of %s" % (leg, reason.legs))
        if outcome_type(outcome) != reason.outcome:
            out.append("outcome %s is not %s" % (outcome_type(outcome), reason.outcome))
        if reason.needs - shapes:
            out.append("the body lacks %s" % sorted(reason.needs - shapes))
        if reason.excludes & shapes:
            out.append("the body carries %s" % sorted(reason.excludes & shapes))
        if (reason.observed is not None and observation is not None
                and not self.observations[reason.observed](*observation)):
            out.append("the observation %s does not hold" % reason.observed)
        return out

    def check(self, entries: dict, by_mid: dict, observed: dict) -> Check:
        """Every ``absolute`` entry against its row: the text is a row,
        ``closes_in`` is the row's, every clause of the row holds.
        ``by_mid``: ``{member id: program}``; ``observed``: ``{(member id,
        leg): (row, expected)}`` for the pairs whose row claims an
        observation."""
        res = Check()
        by_text = self.by_text
        for k, e in sorted(absolute_entries(entries).items()):
            res.checked += 1
            _inst, mid, leg = REG.split_key(k)
            reason = by_text.get(e["reason"])
            if reason is None:
                res.mismatches.append((k, "no table row for the reason %r" % e["reason"]))
                continue
            if e["closes_in"] != reason.closes_in:
                res.mismatches.append((k, "closes_in %r is not the row's %r" % (e["closes_in"], reason.closes_in)))
            program = by_mid.get(mid)
            if program is None:
                res.mismatches.append((k, "no generated program has this member id"))
                continue
            observation = None
            if reason.observed is not None:
                observation = observed.get((mid, leg))
                if observation is None:
                    res.mismatches.append((k, "%s claims an observation but the pair was not run" % reason.key))
                    continue
                if run_outcome(observation[1], observation[0]) != e["outcome"]:
                    res.moved.append(k)
                    observation = None
                else:
                    res.judged_observations += 1
            for f in self.failures(reason, leg, e["outcome"], self.program_shapes(program), observation):
                res.mismatches.append((k, "%s: %s" % (reason.key, f)))
        return res

    def problems(self) -> list:
        """Problems with the table itself: a duplicate text, a shape or an
        observation it does not define, or two rows that could both match
        one entry (no shape one needs and the other excludes, and no other
        column, separates them)."""
        out = []
        if len(self.by_text) != len(self.rows):
            out.append("duplicate reason text")
        for r in self.rows:
            if not (r.needs | r.excludes) <= set(self.detectors):
                out.append("%s names a shape the walker does not report" % r.key)
            if r.observed is not None and r.observed not in self.observations:
                out.append("%s names an unknown observation %s" % (r.key, r.observed))
        for i, a in enumerate(self.rows):
            for b in self.rows[i + 1:]:
                if a.outcome != b.outcome or not set(a.legs) & set(b.legs):
                    continue
                by_shape = (a.needs & b.excludes) or (b.needs & a.excludes)
                if not (by_shape or a.separated_from(b) or b.separated_from(a)):
                    out.append("%s and %s can both match one entry" % (a.key, b.key))
        return out


PUBLIC = ReasonTable(
    rows=(
        Reason("GUARD_CALL", "the CIR Python emitter refuses a guard that carries a call (UnsupportedInIR); the "
               "command line falls back to the legacy transpiler", "step 2 (emitter gaps)", ("ir",), BROKEN,
               needs=frozenset({GUARD_CALL}), observed="unsupported_in_ir"),
    ),
    detectors={GUARD_CALL: _guard_carries_a_call},
    observations={"unsupported_in_ir": _unsupported_in_ir},
)


def observed_rows(rows: dict, programs: list) -> dict:
    """``{(member id, leg): (row, expected)}`` from a run's ``{(name, leg):
    row}``, for ``check``."""
    by_name = {p.name: p for p in programs}
    out = {}
    for (name, leg), row in rows.items():
        p = by_name.get(name)
        if p is not None:
            out[(REG.member_id(name, source_text(p)), leg)] = (row, expectation(p))
    return out

