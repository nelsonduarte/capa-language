"""``CapaSet`` - the runtime set type used by Capa programs.

Capa's ``Set<T>`` is *insertion-ordered*. The Wasm backend stores a
set as a linear element array, which iterates in the order elements
were first added; for the Python backend to produce byte-identical
output we cannot use a raw Python ``set`` (which iterates in hash
order). Instead we back ``CapaSet`` with a ``dict`` (insertion-ordered
since CPython 3.7), using the elements as keys and ignoring the
values. This gives O(1) membership and dedup while preserving the
order of first insertion.

The method surface mirrors the Capa ``Set`` API exactly: ``add``,
``remove``, ``contains``, ``length``, ``is_empty``, ``to_list``.
``__iter__`` / ``__len__`` / ``__contains__`` are provided so that a
Capa ``for x in set`` loop, ``len(set)``, and ``x in set`` all behave
and iterate in insertion order.
"""

from __future__ import annotations

from ._list import CapaList


class CapaSet:
    """Insertion-ordered set backed by a ``dict``.

    Elements must be hashable. Capa structs are frozen dataclasses, and
    scalars / String / tuples / payloadless variants hash natively, so
    every element type Capa allows in a ``Set`` is usable here.
    Re-adding an existing element is a no-op and does *not* move it
    (matching ``dict`` key semantics), so the order is the order of
    *first* insertion.
    """

    __slots__ = ("_d",)

    def __init__(self, iterable=None):
        # Accept an optional iterable so ``CapaSet(some_list)`` and any
        # ``new_set()``-style construction work uniformly. The dict
        # comprehension dedups while keeping first-seen order.
        self._d = {} if iterable is None else {x: None for x in iterable}

    def add(self, x):
        # ``dict`` assignment dedups by ==/hash and, for an existing
        # key, leaves its position untouched (insertion order is the
        # order of first add).
        self._d[x] = None

    def remove(self, x):
        # Discard-safe: removing an absent element is a no-op, matching
        # the Capa surface (Set.remove never raises).
        self._d.pop(x, None)

    def contains(self, x) -> bool:
        return x in self._d

    def length(self) -> int:
        return len(self._d)

    def is_empty(self) -> bool:
        return len(self._d) == 0

    def to_list(self) -> CapaList:
        # Insertion order falls out of the dict's key order.
        return CapaList(self._d)

    def __iter__(self):
        return iter(self._d)

    def __len__(self) -> int:
        return len(self._d)

    def __contains__(self, x) -> bool:
        return x in self._d

    def __repr__(self) -> str:
        return f"CapaSet({list(self._d)!r})"
