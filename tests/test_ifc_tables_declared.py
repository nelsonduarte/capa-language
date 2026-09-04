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

The set of tables is DISCOVERED from the two IFC modules, not listed: any
module-level dict / set / frozenset whose keys are all ``(str, str)``
pairs is a table this guard covers, so an eighth one cannot be added
outside it. The names found today are pinned so a table that vanishes or
changes shape is also visible.
"""

from __future__ import annotations

import unittest

from capa.analyzer import _ifc, _ifc_tables
from capa.builtins import METHODS


_IFC_MODULES = (_ifc_tables, _ifc)

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


def _discover_tables() -> dict[str, object]:
    """name -> table, for every module-level dict / set / frozenset in the
    IFC modules whose keys (or elements) are all ``(str, str)`` pairs.
    ``_ifc`` re-imports the ``_ifc_tables`` names, so the same object is
    found under the same name twice and deduplicated by name."""
    found: dict[str, object] = {}
    for module in _IFC_MODULES:
        for name, value in vars(module).items():
            if name.startswith("__") or not isinstance(value, (dict, set, frozenset)):
                continue
            keys = list(value)
            if keys and all(_is_owner_method_key(k) for k in keys):
                found[name] = value
    return found


def _declared(owner: str) -> set[str]:
    return {m for (m, _ty, _params) in METHODS.get(owner, [])}


class TestIfcTableKeysAreDeclared(unittest.TestCase):
    def test_discovered_tables_are_the_known_ones(self):
        self.assertEqual(
            set(_discover_tables()), set(_KNOWN_TABLES),
            "the set of (owner, method)-keyed IFC tables changed; add the "
            "new one to _KNOWN_TABLES (it is guarded automatically) or "
            "remove the vanished one",
        )

    def test_every_key_names_a_declared_method(self):
        for name, table in sorted(_discover_tables().items()):
            for owner, method in sorted(table):
                with self.subTest(table=name, owner=owner, method=method):
                    self.assertIn(
                        owner, METHODS,
                        f"{name} keys on owner {owner!r}, which "
                        f"capa.builtins.METHODS does not know",
                    )
                    self.assertIn(
                        method, _declared(owner),
                        f"{name} keys on {owner}.{method}, which "
                        f"capa.builtins.METHODS does not declare; the entry "
                        f"is dead and, for a fail-open table, the protection "
                        f"it was meant to give is gone",
                    )


if __name__ == "__main__":
    unittest.main()
