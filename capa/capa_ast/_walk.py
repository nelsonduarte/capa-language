"""Canonical AST child-enumeration helpers.

A single reflective definition of "what are the direct :class:`Node`
children of a node" for every consumer that needs to walk the tree
(the formatter's comment-map pass, and later the borrow checker, the
LSP walkers, the dumper, etc.). Keeping one definition here removes the
per-consumer hand-copies of the same dataclass-field walk.

The enumeration is reflective over ``__dataclass_fields__`` rather than
a hand-maintained per-node children map: adding a node or a field never
requires touching this file. It is deliberately NOT a visitor / double
dispatch framework; both helpers are plain generators.

- :func:`children` yields the direct child nodes of one node.
- :func:`walk` is the pre-order transitive closure.
"""

from __future__ import annotations

from typing import Iterator, Union

from ._base import Node


def children(node: Node) -> Iterator[Node]:
    """Yield the direct child :class:`Node` instances of ``node``.

    Fields are visited in dataclass declaration order; list and tuple
    fields are visited in element order. For each field value ``v``:

    - a :class:`Node` is yielded directly;
    - a list yields each :class:`Node` item, and for a tuple item its
      :class:`Node` elements (one level of unwrapping, which covers
      the ``list[tuple[...]]`` fields such as ``StructLit.fields``,
      ``StructPat.fields`` and ``IfStmt.elif_arms``);
    - a bare tuple yields its :class:`Node` elements (defensive: no
      current node has a top-level tuple-of-Node field, so this yields
      nothing today, but it keeps the walk safe if one is added);
    - anything else (scalar, ``None``, or the :class:`Pos` carried in
      ``pos``, which is not a :class:`Node`) is skipped.
    """
    for f in node.__dataclass_fields__.values():
        v = getattr(node, f.name, None)
        if isinstance(v, Node):
            yield v
        elif isinstance(v, list):
            for item in v:
                if isinstance(item, Node):
                    yield item
                elif isinstance(item, tuple):
                    for sub in item:
                        if isinstance(sub, Node):
                            yield sub
        elif isinstance(v, tuple):
            for sub in v:
                if isinstance(sub, Node):
                    yield sub


def walk(node: Union[Node, list, tuple]) -> Iterator[Node]:
    """Pre-order traversal yielding ``node`` and every descendant.

    A :class:`Node` is yielded first, then its :func:`children` are
    walked in order. A list or tuple root is not itself a node, so its
    elements are walked in turn (each element that is a node, or a
    nested list/tuple, is recursed into).
    """
    if isinstance(node, Node):
        yield node
        for c in children(node):
            yield from walk(c)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from walk(item)
