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
``capa.analyzer`` package is imported and any module-level dict / set /
frozenset whose keys (or elements) are all ``(str, str)`` pairs is a
table this guard covers, whichever analyzer module defines it. That is
the bound, stated: a table of the same shape defined OUTSIDE the package
(the backends keep such tables for their own mappings) is not reached,
and neither is a table whose keys are not all two-string tuples or that
is empty at import time. Adding a guard over the backend tables is a
separate decision. The names found today are pinned so a table that
vanishes or changes shape is also visible, and one name bound to two
different tables in two modules fails rather than hiding one.
"""

from __future__ import annotations

import importlib
import pkgutil
import unittest

import capa.analyzer
from capa.builtins import METHODS


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


def _is_owner_method_table(value) -> bool:
    if not isinstance(value, (dict, set, frozenset)):
        return False
    keys = list(value)
    return bool(keys) and all(_is_owner_method_key(k) for k in keys)


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
