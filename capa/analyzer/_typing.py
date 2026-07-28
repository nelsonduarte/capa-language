"""Typing machinery mixin: TyVar generation and substitution.

These methods operate on the analyzer's type-substitution state
(``_ty_subs``, ``_fresh_counter``). They are extracted from the
monolithic ``Analyzer`` class as a mixin so the substitution and
fresh-variable logic can be read in isolation from the
discipline / dispatch / item checking layers.

The mixin assumes ``self`` has the fields set up by
``Analyzer.__init__`` (``_ty_subs: dict[str, Ty]``,
``_fresh_counter: int``).
"""

from __future__ import annotations

from ..typesys import (
    Ty, TyFun, TyName, TyTuple, TyUnknown, TyVar, is_flexible, occurs_in,
)


def _has_flexible(t: Ty) -> bool:
    """True if ``t`` mentions any FLEXIBLE ``?`` inference variable, at
    any depth. A type that is free of flexible variables is fully
    determined (it may still contain a RIGID generic parameter, which is
    fixed-but-unknown within its scope, not open). Used by
    ``_pin_flexible`` to pin an open element variable ONLY to a genuinely
    concrete counterpart."""
    if isinstance(t, TyVar):
        return is_flexible(t)
    if isinstance(t, TyName):
        return any(_has_flexible(a) for a in t.args)
    if isinstance(t, TyTuple):
        return any(_has_flexible(e) for e in t.elements)
    if isinstance(t, TyFun):
        return any(_has_flexible(p) for p in t.params) or _has_flexible(t.ret)
    return False


class _TypingMixin:
    _ty_subs: dict[str, Ty]
    _fresh_counter: int

    def _is_inference_unknown(self, ty: Ty) -> bool:
        """True only for a GENUINE inference-unknown: the ``TyUnknown``
        singleton or a FLEXIBLE ``?`` inference variable. Both legitimately
        resolve elsewhere, so a member-access / call / index fall-through
        that reaches one must stay permissive.

        This is the FAIL-CLOSED test at the analyzer's four member/call/index
        terminals: after every modeled branch (struct field, nominal method
        dispatch, List index, constant tuple index, ``TyFun`` inline callee,
        ...) has had its chance, a receiver / callee that is NOT an inference
        unknown is a CONCRETE type no branch matched -- so the operation is
        unsupported or ill-typed and is rejected, whatever the type kind
        (tuple, function, unit, a user sum, a typestate, any built-in, any
        future kind), with no per-kind enumeration to keep in sync. Resolves
        first so an inference variable since bound to a concrete type is
        judged on its real shape."""
        resolved = self._resolve_ty(ty)
        return resolved is TyUnknown or is_flexible(resolved)

    def _fresh_ty_var(self, prefix: str) -> TyVar:
        """Create a TyVar with a unique name. The prefix makes
        debug output readable (``?lst_0``, ``?map_3``)."""
        name = f"?{prefix}_{self._fresh_counter}"
        self._fresh_counter += 1
        return TyVar(name)

    def _fresh_method_ty_var(self, prefix: str) -> TyVar:
        """Create a unique RIGID (no ``?`` prefix) TyVar for alpha-renaming
        a generic method's own type parameter at a call site. Unlike
        ``_fresh_ty_var`` the name has no ``?`` prefix, so
        ``_commit_fresh_substitutions`` skips it (it is call-local and must
        not survive, exactly like the method's original type-param names)
        and never dereferences the self-referential ``T -> T`` receiver seed
        the method dispatcher records. The ``#`` marker cannot occur in a
        user-written identifier, so the name is collision-free."""
        name = f"{prefix}#m{self._fresh_counter}"
        self._fresh_counter += 1
        return TyVar(name)

    def _pin_flexible(self, a: Ty, b: Ty) -> None:
        """Pin a still-open container element type discovered by handing
        the container into a slot that fixes a CONCRETE element type.

        Walks ``a`` and ``b`` in parallel. Wherever one side resolves to a
        FLEXIBLE ``?`` inference variable and the other to a fully
        determined type, records the binding in ``_ty_subs`` so every later
        use of the ORIGINAL binding is checked against that type. This is
        what closes the empty-container launder: after ``fill(xs)`` fixes
        ``xs``'s element to ``Int``, reading ``xs[0]`` back at ``String`` is
        rejected.

        Purely additive and conservative:

        - Two open variables pin nothing (``a`` handed to a slot that is
          itself generic in the element stays polymorphic -- scenario 4).
        - A variable is pinned only to a counterpart with NO flexible
          variable (``_has_flexible``), i.e. only when the destination
          genuinely fixes it to a concrete type.
        - An existing binding is never overridden (``_resolve_ty`` returns
          the representative; a bound variable is no longer flexible), so
          the first fixing wins.
        - The occurs-check refuses a self-referential binding.

        The recursion reaches a container nested inside a tuple, another
        container, a struct field, or a function type, so a nested handoff
        pins too (scenario 3)."""
        a = self._resolve_ty(a)
        b = self._resolve_ty(b)
        a_flex = is_flexible(a)
        b_flex = is_flexible(b)
        if a_flex and b_flex:
            return
        if a_flex:
            if not _has_flexible(b) and not occurs_in(a.name, b):
                self._ty_subs[a.name] = b
            return
        if b_flex:
            if not _has_flexible(a) and not occurs_in(b.name, a):
                self._ty_subs[b.name] = a
            return
        if (
            isinstance(a, TyName) and isinstance(b, TyName)
            and a.name == b.name and len(a.args) == len(b.args)
        ):
            for x, y in zip(a.args, b.args):
                self._pin_flexible(x, y)
        elif (
            isinstance(a, TyTuple) and isinstance(b, TyTuple)
            and len(a.elements) == len(b.elements)
        ):
            for x, y in zip(a.elements, b.elements):
                self._pin_flexible(x, y)
        elif (
            isinstance(a, TyFun) and isinstance(b, TyFun)
            and len(a.params) == len(b.params)
        ):
            for x, y in zip(a.params, b.params):
                self._pin_flexible(x, y)
            self._pin_flexible(a.ret, b.ret)

    def _resolve_ty(self, ty: Ty) -> Ty:
        """Apply ``_ty_subs`` recursively. Unbound TyVars come
        back as themselves; the result is the type "as known so
        far", subsequent calls may refine it further."""
        if isinstance(ty, TyVar):
            sub = self._ty_subs.get(ty.name)
            if sub is None:
                return ty
            # Path compression: dereference recursively.
            return self._resolve_ty(sub)
        if isinstance(ty, TyName):
            if not ty.args:
                return ty
            return TyName(
                ty.name, tuple(self._resolve_ty(a) for a in ty.args),
            )
        if isinstance(ty, TyTuple):
            return TyTuple(
                tuple(self._resolve_ty(e) for e in ty.elements),
            )
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._resolve_ty(p) for p in ty.params),
                self._resolve_ty(ty.ret),
                param_labels=ty.param_labels,
                ret_label=ty.ret_label,
            )
        return ty

    def _commit_fresh_substitutions(self, mapping: dict[str, Ty]) -> None:
        """After a call with inference, persist into ``_ty_subs``
        the substitutions for fresh TyVars (those whose name
        starts with ``?``). TyVars that correspond to declared
        type params of a function are local to the call and
        should not survive."""
        for var_name, ty in mapping.items():
            if var_name.startswith("?"):
                self._ty_subs[var_name] = self._apply_mapping(ty, mapping)

    def _apply_mapping(self, ty: Ty, mapping: dict[str, Ty]) -> Ty:
        """Like ``_resolve_ty`` but using a transient ``mapping``
        on top of ``_ty_subs`` (consulted as a fallback for
        TyVars the mapping does not cover)."""
        if isinstance(ty, TyVar):
            sub = mapping.get(ty.name)
            if sub is None:
                return self._resolve_ty(ty)
            return self._apply_mapping(sub, mapping)
        if isinstance(ty, TyName):
            if not ty.args:
                return ty
            return TyName(
                ty.name,
                tuple(self._apply_mapping(a, mapping) for a in ty.args),
            )
        if isinstance(ty, TyTuple):
            return TyTuple(
                tuple(self._apply_mapping(e, mapping) for e in ty.elements),
            )
        if isinstance(ty, TyFun):
            return TyFun(
                tuple(self._apply_mapping(p, mapping) for p in ty.params),
                self._apply_mapping(ty.ret, mapping),
                param_labels=ty.param_labels,
                ret_label=ty.ret_label,
            )
        return ty
