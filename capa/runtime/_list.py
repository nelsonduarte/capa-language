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

    def find(self, p):
        """First element matching the predicate, as ``Option<T>``."""
        for x in self:
            if p(x):
                return Some(x)
        return None_

    def find_index(self, p):
        """Index of first element matching the predicate, as ``Option<Int>``."""
        for i, x in enumerate(self):
            if p(x):
                return Some(i)
        return None_

    def sorted_by(self, cmp):
        """Return a new ``CapaList`` sorted by the user-supplied
        comparator. ``cmp(a, b)`` is a Capa function returning a
        negative Int (``a < b``), zero (``a == b``), or a positive
        Int (``a > b``). Stable. The receiver is not mutated.

        Implementation: bridge the comparator into a Python
        ``key=cmp_to_key(...)``-style adapter inline so we do not
        pull in ``functools`` just for this. The cost is one
        comparator call per merge-sort comparison, same as Python.
        """
        # Local class because we cannot rely on functools.cmp_to_key
        # producing a CapaList-friendly call shape, and the adapter
        # is one screen long.
        class _K:
            __slots__ = ("v",)
            def __init__(self, v): self.v = v
            def __lt__(self, other): return cmp(self.v, other.v) < 0
            def __eq__(self, other): return cmp(self.v, other.v) == 0
            def __le__(self, other): return cmp(self.v, other.v) <= 0
            def __gt__(self, other): return cmp(self.v, other.v) > 0
            def __ge__(self, other): return cmp(self.v, other.v) >= 0
            def __ne__(self, other): return cmp(self.v, other.v) != 0
        return CapaList(sorted(self, key=_K))


class CapaRange:
    """A lazy integer range. Backs the Capa ``Range<T>`` built-in
    type produced by the ``a..b`` and ``a..=b`` syntactic forms.

    The bounded queries (``length``, ``contains``, ``is_empty``) are
    answered directly against the wrapped Python ``range`` without
    materialising. The transform methods (``map`` / ``filter`` /
    ``fold``) and the indexed queries (``first`` / ``last`` / ``get``
    / ``find`` / ``find_index``) carry the same surface as their
    ``CapaList`` homonyms and are defined as ``self.to_list().method(
    ...)``: ``r.map(f)`` is byte-identical to ``r.to_list().map(f)``.
    The Python ``__iter__`` is implemented so a Capa ``for x in
    range_val`` iterates lazily, matching what the transpiler emits
    for the direct ``for x in a..b`` form (which bypasses CapaRange
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

    # Transform + indexed queries delegate to the materialised list so
    # the semantics are, by construction, exactly to_list().method(...).
    def map(self, f):
        return self.to_list().map(f)

    def filter(self, p):
        return self.to_list().filter(p)

    def fold(self, init, f):
        return self.to_list().fold(init, f)

    def first(self):
        return self.to_list().first()

    def last(self):
        return self.to_list().last()

    def get(self, i):
        return self.to_list().get(i)

    def find(self, p):
        return self.to_list().find(p)

    def find_index(self, p):
        return self.to_list().find_index(p)

    def __iter__(self):
        return iter(self._range)

    def __repr__(self):
        r = self._range
        return f"CapaRange({r.start}, {r.stop})"
