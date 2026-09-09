"""Every ``(owner, method)`` key in the IFC tables names a declared method.

The information-flow pass keys several tables by ``(owner, method)``:
the public sinks and secret sources, the container mutators, the two
constant-time tables, the combinator specs and the structure ops. A key
naming a method ``capa.builtins.METHODS`` does not declare is dead: a
renamed or misspelt method silently stops being a sink, a source, a
mutator, a combinator, a structure op or a timing oracle. For the tables
that fail OPEN on a missing key (``_CT_INDEX_METHODS``,
``_CT_SHORT_CIRCUIT_METHODS``, ``_CONTAINER_MUTATORS``) dead means the
protection is gone with no diagnostic at all. Contest item 2 of
.claude/STDLIB_CONTEST_1.md asks for this guard; the design's connection
map had covered two of the tables.

This guard changes no table's semantics. Making the fail-open tables fail
closed is a separate tracked security item.

The set of tables is DISCOVERED, not listed. Every module of the
``capa.analyzer`` package is imported and every module-level container
holding AT LEAST ONE ``(str, str)`` key is a CANDIDATE, whichever
analyzer module defines it.

DISCOVERY IS FAIL-CLOSED (increment 2, pentest finding F1). It used to
keep a container only if ALL its keys were pairs, so a table carrying
one non-pair key -- a ``"__schema__"`` marker, a three-tuple key --
vanished from discovery entirely and its real entries stopped being
checked with no diagnostic. That evasion is measured: a NEW table of
that shape passed this module with zero reds. The rule is now stated
once, in ``_classify_table``:

    a module-level container in ``capa.analyzer`` holding at least one
    ``(str, str)`` key is a CANDIDATE; every candidate must be fully
    pair-keyed, and therefore guardable key by key, or it is a defect.

There is no exemption list: measured on the tree that adopted this
rule, 7 candidates were found and 0 flagged, so the fail-closed
direction costs nothing today and a future mixed-key table has to be
made guardable rather than being silently dropped.

That is the bound, stated: a table of the same shape defined OUTSIDE
the package (the backends keep such tables for their own mappings) is
not reached (pentest shape G11), neither is one nested as a VALUE
inside another container (G2), nor one that is empty at import time and
filled later (G5). Those three stay open and are tracked separately.
Discovery does scan ``list`` and ``tuple`` containers as well as
``dict`` / ``set`` / ``frozenset``, so a pair-keyed table in one of
those shapes is at least SEEN; making its keys checkable key by key is
what the fully-pair-keyed requirement buys. The names found today are
pinned so a table that vanishes or changes shape is also visible, and
one name bound to two different tables in two modules fails rather than
hiding one.
"""

from __future__ import annotations

import importlib
import pkgutil
import unittest

import capa.analyzer
from capa.builtins import METHODS

from tests._declared_methods import declared_methods


#: The owner-and-method tables known today, pinned so the discovery below
#: cannot silently shrink.
_KNOWN_TABLES = frozenset({
    "_PUBLIC_SINKS",
    "_SECRET_SOURCES",
    "_CONTAINER_MUTATORS",
    "_CT_INDEX_METHODS",
    "_CT_SHORT_CIRCUIT_METHODS",
    "_COMBINATOR_SPECS",
    "_STRUCTURE_OPS",
})


def _is_owner_method_key(key) -> bool:
    return (
        isinstance(key, tuple) and len(key) == 2
        and all(isinstance(part, str) for part in key)
    )


#: Container kinds a table may be spelled as. ``list`` / ``tuple`` are
#: scanned too so a pair-keyed table in one of those shapes is at least
#: seen by discovery rather than silently skipped.
_TABLE_KINDS = (dict, set, frozenset, list, tuple)


def _classify_table(value) -> tuple[bool, list]:
    """THE discovery rule, stated once and used by every caller.

    Returns ``(is_candidate, non_pair_keys)``. A module-level container
    holding at least one ``(str, str)`` key is a CANDIDATE; the keys of
    a candidate that are NOT pairs are what makes it unguardable, and
    are returned so the failure can name them.

    Both the "which tables does this module guard" question and the
    "is any discovered table unguardable" question are answered from
    this one function, so the guarded set and the flagged set cannot
    drift apart.
    """
    if not isinstance(value, _TABLE_KINDS):
        return False, []
    try:
        keys = list(value)
    except TypeError:
        return False, []
    if not any(_is_owner_method_key(k) for k in keys):
        return False, []
    return True, [k for k in keys if not _is_owner_method_key(k)]


def _is_owner_method_table(value) -> bool:
    """A candidate, whether or not it is fully pair-keyed. Discovery is
    deliberately WIDER than "checkable": a mixed-key table must be
    discovered so ``test_every_discovered_table_is_fully_pair_keyed``
    can fail on it, rather than dropping out of sight."""
    candidate, _non_pairs = _classify_table(value)
    return candidate


def _analyzer_modules():
    """Every module of the ``capa.analyzer`` package, the package itself
    included, imported so its module-level tables exist."""
    yield capa.analyzer
    prefix = capa.analyzer.__name__ + "."
    for info in pkgutil.walk_packages(capa.analyzer.__path__, prefix=prefix):
        yield importlib.import_module(info.name)


def _discover_tables() -> dict[str, object]:
    """name -> table, over every analyzer module. A re-imported name
    (``_ifc`` and ``_ifc_summary`` re-import the ``_ifc_tables`` tables)
    is the same object and is recorded once; the same name bound to a
    DIFFERENT object in another module is refused, so a second table
    cannot hide behind a first one's name."""
    found: dict[str, object] = {}
    for module in _analyzer_modules():
        for name, value in vars(module).items():
            if name.startswith("__") or not _is_owner_method_table(value):
                continue
            if name in found and found[name] is not value:
                raise AssertionError(
                    f"{name} is bound to two different (owner, method)-keyed "
                    f"tables in capa.analyzer (seen again in "
                    f"{module.__name__}); rename one so both are guarded"
                )
            found[name] = value
    return found


class TestIfcTableKeysAreDeclared(unittest.TestCase):
    def test_discovered_tables_are_the_known_ones(self):
        self.assertEqual(
            set(_discover_tables()), set(_KNOWN_TABLES),
            "the set of (owner, method)-keyed IFC tables changed; add the "
            "new one to _KNOWN_TABLES (it is guarded automatically) or "
            "remove the vanished one",
        )

    def test_every_discovered_table_is_fully_pair_keyed(self):
        """The fail-CLOSED half of discovery (F1). A table carrying a
        non-pair key used to disappear from discovery, taking its real
        entries' protection with it. Now it is discovered and named
        here instead. Measured on the tree that adopted the rule: 7
        candidates, 0 flagged, so no exemption list is needed."""
        unguardable = {}
        for name, table in sorted(_discover_tables().items()):
            _candidate, non_pairs = _classify_table(table)
            if non_pairs:
                unguardable[name] = sorted(map(repr, non_pairs))[:3]
        self.assertEqual(
            unguardable, {},
            "an (owner, method)-keyed IFC table carries keys that are "
            "not (str, str) pairs, so its entries cannot be checked "
            "against capa.builtins.METHODS key by key. Discovery used "
            "to DROP such a table silently and every entry in it "
            "stopped being guarded; make the table fully pair-keyed, or "
            "move the non-pair data to its own container: "
            f"{unguardable}",
        )

    def test_every_key_names_a_declared_method(self):
        for name, table in sorted(_discover_tables().items()):
            for owner, method in sorted(
                k for k in table if _is_owner_method_key(k)
            ):
                with self.subTest(table=name, owner=owner, method=method):
                    self.assertIn(
                        owner, METHODS,
                        f"{name} keys on owner {owner!r}, which "
                        f"capa.builtins.METHODS does not know",
                    )
                    self.assertIn(
                        method, declared_methods(owner),
                        f"{name} keys on {owner}.{method}, which "
                        f"capa.builtins.METHODS does not declare; the entry "
                        f"is dead and, for a fail-open table, the protection "
                        f"it was meant to give is gone",
                    )


if __name__ == "__main__":
    unittest.main()
