"""Python interop, gated by the ``Unsafe`` capability.

``py_import`` and ``py_invoke`` are the only two ways a Capa program
can call into arbitrary Python. Both require an ``Unsafe`` instance
as their first argument; the static type system rejects the call
otherwise. The runtime here does a final defensive check
(``_require_unsafe``) so that mis-generated code does not silently
bypass the boundary.
"""

from __future__ import annotations

from ._capabilities import Unsafe


def _require_unsafe(unsafe, op: str):
    if not isinstance(unsafe, Unsafe):
        raise RuntimeError(
            f"{op} requires an Unsafe capability as first argument; "
            f"got {type(unsafe).__name__}. This should have been caught "
            f"by the Capa type checker."
        )


def py_import(unsafe, name: str):
    """Import a Python module by name (e.g. ``"os.path"``), returning the
    module object. Equivalent to ``import name`` in Python, but requires
    the ``Unsafe`` capability.

    The return type is deliberately untyped (``TyUnknown`` in the
    checker): anything coming from the Python side of the boundary has
    no guarantees from the capability system, and the language reflects
    this loss of guarantee by letting the programmer navigate dynamically.
    """
    import importlib
    _require_unsafe(unsafe, "py_import")
    return importlib.import_module(name)


def py_invoke(unsafe, callable_, args):
    """Invoke a Python ``callable`` with the argument list ``args``.
    Requires the ``Unsafe`` capability. ``args`` can be a list/CapaList
    or any iterable.
    """
    _require_unsafe(unsafe, "py_invoke")
    return callable_(*args)
