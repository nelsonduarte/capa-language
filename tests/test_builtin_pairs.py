"""The related-operation table over ``capa.builtins.METHODS``, and its guards.

Seam 2 of .claude/STDLIB_DESIGN.md section 5, as corrected by
.claude/STDLIB_CONTEST_1.md item 5.

WHAT THIS IS

``METHODS`` is a flat list. Nothing in it can say that ``Map.set`` is
defined in terms of an inverse (``Map.remove``) it does not have, so
"half a pair" was not a computable property of the surface and
completeness was maintained by a human noticing. ``_PAIRS`` names the
groups of operations that are defined in terms of each other, and every
entry is in exactly one of two states:

- COMPLETE: every member is declared (``absent`` is empty, no reason);
- EXCUSED: the members in ``absent`` are not declared and ``reason``
  says why, in writing.

There is no third state, so a contributor who adds ``Map.remove`` without
retiring its excuse, or ships ``List.pop`` without deciding about the
names next to it, gets a red build naming the entry.

THIS IS A SECOND LIST OF METHOD NAMES, DELIBERATELY. The relation "is the
inverse or mirror of" cannot be computed from the table (a set of names
does not know which of its members answer each other), so the members are
hand-written here. What keeps a hand-written list honest is guarding it
in BOTH directions against the single source:

- every ``present`` member must be declared: a member the table treats as
  present that has since been removed or renamed is red (stale-present);
- every ``absent`` member must NOT be declared: an excused absence that
  has since been declared is red (stale-excused; retire the excuse);
- an entry with an ``absent`` half must carry a reason, and an entry with
  none must not.

Capability owners are excluded by construction: a missing capability
method is a refusal to grant authority, not an oversight, and this
predicate must never turn a security boundary into a checklist to fill
in. ``test_owners_the_guard_never_reaches_are_exactly_the_capabilities``
pins that the exemption is the capability set and nothing more, so it
cannot quietly grow.

Synonyms (``JsonValue.as_num`` / ``as_number``) are in scope only as
COMPLETE groups whose members must stay declared together; the rule that
rejects a NEW synonym (one name per concept) is a naming decision the
design records in prose, not a completeness property, and no shape here
tries to express it.

Seeded with the design's sixteen half-pairs plus the members the contest
found omitted, ALL excused: this increment adds no surface.
"""

from __future__ import annotations

import typing
import unittest

from capa.builtins import METHODS
from capa.typesys import CAPABILITY_NAMES

from tests._declared_methods import declared_methods


class _Pair(typing.NamedTuple):
    """One group of related operations. Members are ``(owner, method)``."""

    present: tuple[tuple[str, str], ...]
    absent: tuple[tuple[str, str], ...]
    reason: typing.Optional[str]


def _complete(*members: tuple[str, str]) -> _Pair:
    return _Pair(present=tuple(members), absent=(), reason=None)


def _excused(present, absent, reason: str) -> _Pair:
    return _Pair(present=tuple(present), absent=tuple(absent), reason=reason)


_STEP_4 = "scheduled for design migration step 4 (Removal); this increment adds no surface"
_STEP_5 = "scheduled for design migration step 5 (String text verbs); this increment adds no surface"
_STEP_7 = "scheduled for design migration step 7 (Aggregation, Map / Set transforms); this increment adds no surface"

_PAIRS: tuple[_Pair, ...] = (
    # ---- complete today -------------------------------------------------
    _complete(("Set", "add"), ("Set", "remove")),
    _complete(("Option", "is_some"), ("Option", "is_none")),
    _complete(("Result", "is_ok"), ("Result", "is_err")),
    _complete(("Result", "ok"), ("Result", "err")),
    _complete(("String", "trim_start"), ("String", "trim_end")),
    _complete(("String", "starts_with"), ("String", "ends_with")),
    _complete(("String", "to_upper"), ("String", "to_lower")),
    _complete(("Map", "keys"), ("Map", "values")),
    _complete(("List", "first"), ("List", "last")),
    _complete(("Range", "first"), ("Range", "last")),
    # Synonyms: both names must stay declared together.
    _complete(("JsonValue", "as_num"), ("JsonValue", "as_number")),
    # ---- the design's sixteen half-pairs, excused ------------------------
    _excused([("Map", "set")], [("Map", "remove")], _STEP_4),
    _excused(
        [("List", "push")], [("List", "pop")],
        _STEP_4 + "; pop also collides with list.pop and must pass the "
        "inherited-name quarantine in tests/test_method_emit_agreement.py",
    ),
    _excused([("String", "index_of")], [("String", "find_index")], _STEP_5),
    _excused([("List", "find_index")], [("List", "index_of")], _STEP_7),
    _excused([("Set", "is_subset")], [("Set", "is_superset")], _STEP_7),
    _excused(
        [("List", "map"), ("List", "filter"), ("List", "fold")],
        [("Map", "map"), ("Map", "filter"), ("Map", "fold")],
        "Map.filter is scheduled for step 4 (the Map.remove workaround needs "
        "it); the design names map_values rather than map and no fold, so "
        "those two stay excused until step 7 decides them",
    ),
    _excused(
        [("List", "map"), ("List", "filter"), ("List", "fold")],
        [("Set", "map"), ("Set", "filter"), ("Set", "fold")],
        _STEP_7,
    ),
    _excused(
        [("List", "sorted_by"), ("List", "reverse"), ("List", "enumerate"),
         ("List", "zip"), ("List", "flat_map")],
        [("Range", "sorted_by"), ("Range", "reverse"), ("Range", "enumerate"),
         ("Range", "zip"), ("Range", "flat_map")],
        "design section 6 leaves Range parity to step 7: either add the "
        "five (each needs a _RANGE_DESUGAR_METHODS entry) or excuse them "
        "with to_list() as the intended door",
    ),
    # ---- members the contest found the design omitted, excused ---------
    _excused(
        [("Set", "to_list")], [("List", "to_set")],
        "no to_set exists anywhere; not scheduled by the design; excused "
        "pending a decision",
    ),
    _excused(
        [("Map", "pairs")], [("List", "to_map")],
        "no to_map exists anywhere; not scheduled by the design; excused "
        "pending a decision",
    ),
    _excused(
        [("String", "split")], [("String", "join")],
        "the design puts join on List (section 6), so a String.join is a "
        "naming decision rather than a missing half; excused in writing",
    ),
)


def _is_declared(member: tuple[str, str]) -> bool:
    owner, method = member
    return method in declared_methods(owner)


class TestPairsTableShape(unittest.TestCase):
    def test_every_entry_is_complete_or_excused(self):
        for i, pair in enumerate(_PAIRS):
            with self.subTest(entry=i, present=pair.present):
                self.assertTrue(pair.present, "an entry must name what is present")
                if pair.absent:
                    self.assertTrue(
                        isinstance(pair.reason, str) and pair.reason.strip(),
                        f"entry {i} excuses {pair.absent} without a written reason",
                    )
                else:
                    self.assertIsNone(
                        pair.reason,
                        f"entry {i} is complete but carries a reason; a reason "
                        f"belongs only to an absence",
                    )

    def test_no_entry_names_a_capability_owner(self):
        for i, pair in enumerate(_PAIRS):
            for owner, _method in pair.present + pair.absent:
                with self.subTest(entry=i, owner=owner):
                    self.assertNotIn(
                        owner, CAPABILITY_NAMES,
                        "capability surfaces are security decisions; the "
                        "completeness predicate must not reach them",
                    )


class TestPairsAgreeWithTheDeclarationTable(unittest.TestCase):
    def test_every_present_member_is_declared(self):
        """Stale-present: the table treats a member as present that the
        declaration table no longer has."""
        for i, pair in enumerate(_PAIRS):
            for member in pair.present:
                with self.subTest(entry=i, member=member):
                    self.assertTrue(
                        _is_declared(member),
                        f"{member} is named as present in _PAIRS but "
                        f"capa.builtins.METHODS does not declare it",
                    )

    def test_every_excused_member_is_really_absent(self):
        """Stale-excused: a member excused as absent has since been
        declared; the excuse must be retired (and the entry becomes
        complete, or the remaining absences get a fresh reason)."""
        for i, pair in enumerate(_PAIRS):
            for member in pair.absent:
                with self.subTest(entry=i, member=member):
                    self.assertFalse(
                        _is_declared(member),
                        f"{member} is excused as absent in _PAIRS but "
                        f"capa.builtins.METHODS now declares it; retire the "
                        f"excuse",
                    )

    def test_owners_the_guard_never_reaches_are_exactly_the_capabilities(self):
        """The exemption is the capability set, by construction and by
        measurement: every other owner of METHODS is named by at least
        one entry, so a new non-capability owner cannot sit outside the
        predicate unnoticed, and the exemption cannot quietly grow."""
        reached = {owner for pair in _PAIRS for owner, _m in pair.present}
        unreached = {owner for owner in METHODS if owner not in reached}
        self.assertEqual(
            unreached, {owner for owner in METHODS if owner in CAPABILITY_NAMES},
        )


if __name__ == "__main__":
    unittest.main()
