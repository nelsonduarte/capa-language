"""Type-specific method dispatch mixin.

The Capa surface API for ``String``, ``Map``, and ``Set`` does not
match Python's idiomatic method names (``length`` vs ``len``,
``contains`` vs ``in``, etc.), so each call has to be lowered into
the appropriate Python construct. The ``Transpiler`` uses the
analyzer's ``types`` mapping to recognise the receiver type, then
delegates to one of these helpers.

- ``_emit_method_call``: top-level dispatcher. Falls back to a
  direct ``recv.method(args)`` call for user-defined types.
- ``_emit_string_method`` / ``_emit_map_method`` /
  ``_emit_set_method``: per-type translation tables.
"""

from __future__ import annotations

from .. import capa_ast as A
from ..typesys import TyName


class _MethodsMixin:
    def _emit_method_call(self, e: A.MethodCall) -> str:
        """Emits a method call. For receivers of types with a built-in
        method API (String, Map, Set), maps to Python constructs. For
        other types (CapaList, user structs), emits a direct Python
        method call.
        """
        from . import _safe_ident
        recv = self._emit_expr(e.receiver)
        args_code = [self._emit_expr(a) for a in e.args]

        # Type-aware dispatch. Built-in method maps (String, Map, Set)
        # see only positional arguments because the analyzer rejects
        # named arguments on builtins.
        recv_ty = self.types.get(id(e.receiver))
        if isinstance(recv_ty, TyName):
            if recv_ty.name == "String":
                return self._emit_string_method(e.method, recv, args_code)
            if recv_ty.name == "Map":
                return self._emit_map_method(e.method, recv, args_code)
            if recv_ty.name == "Set":
                return self._emit_set_method(e.method, recv, args_code)
            if recv_ty.name == "Range":
                return self._emit_range_method(e.method, recv, args_code)

        # User-defined methods: respect named arguments.
        args = self._emit_call_arg_list(e.args, e.arg_names)
        return f"{recv}.{_safe_ident(e.method)}({args})"

    def _emit_string_method(
        self, method: str, recv: str, args: list[str],
    ) -> str:
        """Maps a Capa String method to the equivalent Python construct."""
        from . import _safe_ident
        if method == "length":
            return f"len({recv})"
        if method == "contains":
            return f"({args[0]} in {recv})"
        if method == "starts_with":
            return f"{recv}.startswith({args[0]})"
        if method == "ends_with":
            return f"{recv}.endswith({args[0]})"
        if method == "to_upper":
            return f"{recv}.upper()"
        if method == "to_lower":
            return f"{recv}.lower()"
        if method == "trim":
            return f"{recv}.strip()"
        if method == "split":
            return f"CapaList({recv}.split({args[0]}))"
        if method == "replace":
            return f"{recv}.replace({args[0]}, {args[1]})"
        if method == "is_empty":
            return f"({recv} == '')"
        if method == "char_at":
            # Option<String>: Some(s[i]) if 0 <= i < len(s) else None_.
            return (
                f"(Some({recv}[{args[0]}]) "
                f"if 0 <= {args[0]} < len({recv}) else None_)"
            )
        if method == "substring":
            # Python slice semantics: forgiving on out-of-range; the
            # Capa surface mirrors that.
            return f"{recv}[{args[0]}:{args[1]}]"
        if method == "index_of":
            # Option<Int>: Some(idx) if found, None_ otherwise. Hoist
            # the .find() call into a one-shot lambda so it executes
            # exactly once even when recv / args are complex
            # expressions.
            return (
                f"(lambda _i: Some(_i) if _i >= 0 else None_)"
                f"({recv}.find({args[0]}))"
            )
        return f"{recv}.{_safe_ident(method)}({', '.join(args)})"

    def _emit_map_method(
        self, method: str, recv: str, args: list[str],
    ) -> str:
        """Maps a Capa Map method to a Python construct.

        Map is represented as a Python ``dict``. ``get`` returns an
        ``Option`` (Some/None_) - we emit a ternary expression.
        ``set`` is mutation - we use ``__setitem__`` to keep the
        method as an expression (returns None).
        """
        from . import _safe_ident
        if method == "length":
            return f"len({recv})"
        if method == "contains_key":
            return f"({args[0]} in {recv})"
        if method == "get":
            # Option<V>: Some(m[k]) if key exists, None_ otherwise.
            return f"(Some({recv}[{args[0]}]) if {args[0]} in {recv} else None_)"
        if method == "set":
            # Mutation. Assignment in Python is not an expression, but
            # ``dict.__setitem__`` is. Returns None.
            return f"{recv}.__setitem__({args[0]}, {args[1]})"
        if method == "keys":
            return f"CapaList({recv}.keys())"
        if method == "values":
            return f"CapaList({recv}.values())"
        if method == "pairs":
            return f"CapaList({recv}.items())"
        if method == "is_empty":
            return f"(len({recv}) == 0)"
        return f"{recv}.{_safe_ident(method)}({', '.join(args)})"

    def _emit_set_method(
        self, method: str, recv: str, args: list[str],
    ) -> str:
        """Maps a Capa Set method to a Python construct.

        Set is represented as a Python ``set``. ``add`` and ``remove``
        exist with the same names.
        """
        from . import _safe_ident
        if method == "length":
            return f"len({recv})"
        if method == "contains":
            return f"({args[0]} in {recv})"
        if method == "add":
            return f"{recv}.add({args[0]})"
        if method == "remove":
            return f"{recv}.discard({args[0]})"  # discard is safe (does not raise)
        if method == "to_list":
            return f"CapaList({recv})"
        if method == "is_empty":
            return f"(len({recv}) == 0)"
        return f"{recv}.{_safe_ident(method)}({', '.join(args)})"

    def _emit_range_method(
        self, method: str, recv: str, args: list[str],
    ) -> str:
        """Maps a Capa ``Range<T>`` method to a Python construct.

        Range is the lazy iterable produced by ``a..b`` and
        ``a..=b``. The runtime class is ``CapaRange``, a thin
        wrapper around Python's ``range``. ``length`` /
        ``contains`` / ``is_empty`` are answered by the wrapped
        range without materialising; ``to_list`` produces a
        fresh ``CapaList`` and is the user's explicit opt-in
        for the full ``List<T>`` method surface.
        """
        from . import _safe_ident
        if method == "length":
            return f"{recv}.length()"
        if method == "contains":
            return f"{recv}.contains({args[0]})"
        if method == "is_empty":
            return f"{recv}.is_empty()"
        if method == "to_list":
            return f"{recv}.to_list()"
        return f"{recv}.{_safe_ident(method)}({', '.join(args)})"
