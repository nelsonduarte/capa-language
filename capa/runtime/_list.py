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
