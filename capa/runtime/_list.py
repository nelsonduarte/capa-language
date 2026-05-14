"""``CapaList`` - the runtime list type used by Capa programs.

A thin subclass of Python's ``list`` that adds the methods the Capa
type checker expects: ``length``, ``push``, ``contains``, plus
higher-order ``map`` / ``filter`` / ``fold`` and the ``Option``-
returning indexed accessors ``first`` / ``last`` / ``get``.
"""

from __future__ import annotations

from ._result import None_, Some


class CapaList(list):
    """Subclass of ``list`` that exposes methods expected by the Capa
    checker: ``length``, ``push``, ``contains``, ``map``, ``filter``,
    ``fold``.

    Higher-order functions (`map`, `filter`, `fold`) take Python
    callables and return new ``CapaList`` instances for chaining.
    """

    def length(self):
        return len(self)

    def push(self, x):
        self.append(x)

    def contains(self, x):
        return x in self

    def map(self, f):
        return CapaList(f(x) for x in self)

    def filter(self, p):
        return CapaList(x for x in self if p(x))

    def fold(self, init, f):
        acc = init
        for x in self:
            acc = f(acc, x)
        return acc

    def is_empty(self):
        return len(self) == 0

    def first(self):
        return Some(self[0]) if len(self) > 0 else None_

    def last(self):
        return Some(self[-1]) if len(self) > 0 else None_

    def get(self, i):
        if 0 <= i < len(self):
            return Some(self[i])
        return None_


class CapaRange:
    """A lazy integer range. Backs the Capa ``Range<T>`` built-in
    type produced by the ``a..b`` and ``a..=b`` syntactic forms.

    The legitimate operations on a range are bounded queries
    (``length``, ``contains``) and explicit materialisation
    (``to_list``). ``filter`` / ``map`` / ``fold`` are not on the
    Range surface; users that need them call ``.to_list()``
    first so the choice to allocate is explicit. The Python
    ``__iter__`` is implemented so a Capa ``for x in range_val``
    iterates lazily, matching what the transpiler emits for the
    direct ``for x in a..b`` form (which bypasses CapaRange
    entirely and uses Python's ``range`` straight).
    """

    __slots__ = ("_range",)

    def __init__(self, start, stop):
        self._range = range(start, stop)

    def length(self):
        return len(self._range)

    def contains(self, x):
        return x in self._range

    def is_empty(self):
        return len(self._range) == 0

    def to_list(self):
        return CapaList(self._range)

    def __iter__(self):
        return iter(self._range)

    def __repr__(self):
        r = self._range
        return f"CapaRange({r.start}, {r.stop})"
