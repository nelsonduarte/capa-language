"""Call and method-dispatch mixin.

Five methods that together implement the call-checking story:

- ``_resolve_named_args``: validate ``f(name: value)``-style
  arguments and produce a permutation into parameter order.
- ``_check_call``: typecheck a free-function call or a variant
  constructor.
- ``_check_call_with_inference``: shared inference + checking
  workhorse used by both free calls and method dispatch.
- ``_check_method_call``: typecheck ``receiver.method(args)``;
  splits into capability vs regular type paths.
- ``_check_method_dispatch``: the inference + checking step for
  the regular-type path of a method call.

The mixin assumes ``self`` has the analyzer state set up in
``Analyzer.__init__`` and pulls helpers (``_check_expr``,
``_check_no_aliasing``, ``_mark_consumed_args``,
``_compatible_with_impls``, ``_commit_fresh_substitutions``,
``_hint_did_you_mean``, ``_err``) from the other mixins.
"""

from __future__ import annotations

from typing import Optional

from .. import capa_ast as A
from ..typesys import (
    CAPABILITY_NAMES, Ty, TyFun, TyName, TyUnknown,
    compatible, instantiate, substitute, ty_str, unify,
)


class _DispatchMixin:
    def _resolve_named_args(
        self,
        e: "A.Call | A.MethodCall",
        param_names: list[str],
        callee_label: str,
        fun_ty: Optional["TyFun"] = None,
    ) -> Optional[list[int]]:
        """Validate ``e.arg_names`` and return a permutation that
        puts the arguments into parameter order.

        Returns a list ``perm`` such that ``e.args[perm[i]]`` is
        the argument bound to the i-th parameter, or ``None`` if
        the named arguments are not well-formed (positional after
        named, unknown name, duplicate, missing or extra). When
        no name appears in ``e.arg_names``, returns the identity
        permutation without consulting ``param_names`` (so plain
        calls work even for builtins that don't track names).
        """
        names = e.arg_names
        if not any(n is not None for n in names):
            return list(range(len(e.args)))

        if not param_names:
            self._err(
                f"call to {callee_label}: named arguments are not "
                f"supported here",
                e.pos,
            )
            return None

        seen_named = False
        for i, n in enumerate(names):
            if n is None:
                if seen_named:
                    self._err(
                        f"call to {callee_label}: positional argument "
                        f"cannot follow a named argument",
                        e.args[i].pos,
                    )
                    return None
            else:
                seen_named = True

        if len(e.args) != len(param_names):
            sig = f" (signature: {ty_str(fun_ty)})" if fun_ty is not None else ""
            self._err(
                f"call to {callee_label}: expected {len(param_names)} "
                f"arguments, got {len(e.args)}{sig}",
                e.pos,
            )
            return None

        assigned: list[Optional[int]] = [None] * len(param_names)
        name_to_param = {p: i for i, p in enumerate(param_names)}

        for i, n in enumerate(names):
            if n is not None:
                break
            assigned[i] = i

        for i, n in enumerate(names):
            if n is None:
                continue
            param_idx = name_to_param.get(n)
            if param_idx is None:
                self._err(
                    f"call to {callee_label}: unknown parameter name "
                    f"{n!r}",
                    e.args[i].pos,
                )
                return None
            if assigned[param_idx] is not None:
                self._err(
                    f"call to {callee_label}: parameter {n!r} given "
                    f"more than once",
                    e.args[i].pos,
                )
                return None
            assigned[param_idx] = i

        for i, a in enumerate(assigned):
            if a is None:
                self._err(
                    f"call to {callee_label}: missing argument for "
                    f"parameter {param_names[i]!r}",
                    e.pos,
                )
                return None

        return assigned  # type: ignore[return-value]

    def _check_call(self, e: A.Call) -> Ty:
        # Aliasing is independent of whether the callee resolves
        # or not, so it runs first.
        self._check_no_aliasing(
            [(a, f"argument {i + 1}") for i, a in enumerate(e.args)]
        )
        # Evaluate args first to report independent errors even
        # when the callee fails.
        arg_tys = [self._check_expr(a) for a in e.args]

        if isinstance(e.callee, A.Ident):
            from . import SymbolKind
            sym = self.scope.lookup(e.callee.name)
            if sym is not None:
                self.bindings[id(e.callee)] = sym
                if sym.kind == SymbolKind.FUNCTION:
                    if isinstance(sym.ty, TyFun):
                        perm = self._resolve_named_args(
                            e, sym.param_names, repr(sym.name),
                            fun_ty=sym.ty,
                        )
                        if perm is None:
                            return instantiate(
                                sym.ty.ret, sym.type_params, {},
                            )
                        reordered_args = [e.args[j] for j in perm]
                        reordered_tys = [arg_tys[j] for j in perm]
                        ret_ty = self._check_call_with_inference(
                            e, sym.ty, reordered_tys, sym.name,
                            sym.type_params, reordered_args,
                        )
                        if sym.consuming_params:
                            self._mark_consumed_args(
                                reordered_args, sym.consuming_params,
                            )
                        return ret_ty
                    return TyUnknown
                if sym.kind == SymbolKind.VARIANT:
                    if sym.variant_payload_ty is None:
                        self._err(
                            f"variant {sym.name!r} takes no payload",
                            e.pos,
                        )
                        return TyUnknown
                    if len(arg_tys) != 1:
                        self._err(
                            f"variant {sym.name!r} takes 1 argument, "
                            f"got {len(arg_tys)}",
                            e.pos,
                        )
                    mapping: dict[str, Ty] = {}
                    if arg_tys:
                        unify(sym.variant_payload_ty, arg_tys[0], mapping)
                        substituted_payload = substitute(
                            sym.variant_payload_ty, mapping,
                        )
                        if not compatible(substituted_payload, arg_tys[0]):
                            self._err(
                                f"variant {sym.name!r}: expected payload "
                                f"{ty_str(substituted_payload)}, "
                                f"got {ty_str(arg_tys[0])}",
                                e.args[0].pos,
                            )
                    if sym.variant_owner is not None:
                        owner = sym.variant_owner
                        args = tuple(
                            mapping.get(p, TyUnknown)
                            for p in owner.type_params
                        )
                        return TyName(owner.name, args)
                    return TyUnknown
                # Resolved Ident whose symbol is neither a function
                # nor a variant: a local binding, parameter, or
                # constant. Callable iff its type is a function
                # type (e.g. a lambda assigned to ``let f = fun (x:
                # Int) -> Int => x * 2``); otherwise the runtime
                # would raise ``TypeError: ... is not callable`` and
                # we should surface that at compile time.
                if sym.kind in (
                    SymbolKind.LOCAL,
                    SymbolKind.LOCAL_VAR,
                    SymbolKind.PARAM,
                    SymbolKind.CONSTANT,
                ):
                    if isinstance(sym.ty, TyFun):
                        # Function-typed local / param: lambda-style
                        # call. Fall through to the generic
                        # non-Ident path below, which type-checks
                        # the callee but does not enforce arity /
                        # arg types yet. Leaving the TyUnknown
                        # return matches the pre-existing behaviour
                        # for these call shapes.
                        pass
                    else:
                        self._err(
                            f"{sym.name!r} is not callable; it has type "
                            f"{ty_str(sym.ty)}",
                            e.pos,
                        )
                        return TyUnknown
        # Non-Ident callee forms (method-result, lambda, parens):
        # v1 checker does not check the call shape on these. Still
        # type-check the callee so its own diagnostics fire.
        self._check_expr(e.callee)
        return TyUnknown

    def _check_call_with_inference(
        self,
        e: A.Call,
        fun_ty: TyFun,
        arg_tys: list[Ty],
        name: str,
        type_params: list[str],
        reordered_args: Optional[list[A.Expr]] = None,
    ) -> Ty:
        """Check a function call, performing local inference of
        ``type_params``.

        Strategy: unify each parameter type (which may contain
        ``TyVar`` referencing the ``type_params``) with the
        corresponding argument type, accumulating substitutions.
        Then check that each argument is compatible with the
        substituted parameter, and return the substituted return
        type. ``TyVar``s not inferred from any parameter become
        ``TyUnknown`` in the result.

        ``reordered_args`` lets the caller pass arguments
        rearranged into parameter order (named-argument path).
        When ``None``, ``e.args`` is used directly.
        """
        args_in_order = (
            reordered_args if reordered_args is not None else e.args
        )

        if len(fun_ty.params) != len(arg_tys):
            self._err(
                f"call to {name!r}: expected {len(fun_ty.params)} arguments, "
                f"got {len(arg_tys)} (signature: {ty_str(fun_ty)})",
                e.pos,
            )
            return instantiate(fun_ty.ret, type_params, {})

        mapping: dict[str, Ty] = {}
        for param_ty, arg_ty in zip(fun_ty.params, arg_tys):
            unify(param_ty, arg_ty, mapping)

        for i, (param_ty, arg_ty) in enumerate(zip(fun_ty.params, arg_tys)):
            substituted = substitute(param_ty, mapping)
            if not self._compatible_with_impls(substituted, arg_ty):
                self._err(
                    f"call to {name!r}: argument {i + 1} expects "
                    f"{ty_str(substituted)}, got {ty_str(arg_ty)}",
                    args_in_order[i].pos,
                )

        self._commit_fresh_substitutions(mapping)
        return instantiate(fun_ty.ret, type_params, mapping)

    def _check_method_call(self, e: A.MethodCall) -> Ty:
        # The receiver occupies a call slot; a cap passed as
        # receiver and also as argument is aliasing.
        slots: list[tuple[A.Expr, str]] = [(e.receiver, "receiver")]
        slots.extend((a, f"argument {i + 1}") for i, a in enumerate(e.args))
        self._check_no_aliasing(slots)

        recv_ty = self._check_expr(e.receiver)
        arg_tys = [self._check_expr(a) for a in e.args]

        from . import SymbolKind

        # Capabilities: consult registered methods. For built-in
        # capabilities the method table is closed, so an unknown
        # method is a real error with a "did you mean" hint.
        if isinstance(recv_ty, TyName) and recv_ty.name in CAPABILITY_NAMES:
            cap_sym = self.global_scope.lookup(recv_ty.name)
            if cap_sym is not None:
                method_sym = cap_sym.methods.get(e.method)
                if method_sym is not None and isinstance(method_sym.ty, TyFun):
                    return self._check_method_dispatch(
                        e, cap_sym, method_sym, recv_ty, arg_tys,
                    )
                if cap_sym.methods:
                    hint = self._hint_did_you_mean(
                        e.method, list(cap_sym.methods.keys()),
                    )
                    self._err(
                        f"capability {recv_ty.name!r} has no method "
                        f"{e.method!r}{hint}",
                        e.pos,
                    )
            return TyUnknown

        if isinstance(recv_ty, TyName):
            type_sym = self.global_scope.lookup(recv_ty.name)
            if type_sym is not None and type_sym.kind in (
                SymbolKind.TYPE_STRUCT, SymbolKind.TYPE_SUM,
            ):
                method_sym = type_sym.methods.get(e.method)
                if method_sym is None:
                    hint = self._hint_did_you_mean(
                        e.method, list(type_sym.methods.keys()),
                    )
                    self._err(
                        f"type {recv_ty.name!r} has no method "
                        f"{e.method!r}{hint}",
                        e.pos,
                    )
                    return TyUnknown
                return self._check_method_dispatch(
                    e, type_sym, method_sym, recv_ty, arg_tys,
                )

        return TyUnknown

    def _check_method_dispatch(
        self,
        e: A.MethodCall,
        type_sym,
        method_sym,
        recv_ty: TyName,
        arg_tys: list[Ty],
    ) -> Ty:
        """Dispatch a method call: substitute the type's type
        params with the receiver's args, apply inference to the
        method's remaining type params, check args, and return
        the substituted return type.
        """
        if not isinstance(method_sym.ty, TyFun):
            return TyUnknown
        method_fun_ty = method_sym.ty

        # Initial mapping: the type's type_params -> receiver
        # type args. E.g. for ``Caixa<Int>`` the receiver has
        # ``args=(Int,)`` and the type has ``type_params=["T"]``;
        # the mapping becomes ``{"T": Int}``.
        mapping: dict[str, Ty] = {}
        if len(type_sym.type_params) == len(recv_ty.args):
            for param, arg in zip(type_sym.type_params, recv_ty.args):
                mapping[param] = arg

        perm = self._resolve_named_args(
            e, method_sym.param_names, f"{recv_ty.name}.{e.method!r}",
            fun_ty=method_fun_ty,
        )
        if perm is None:
            all_type_params = type_sym.type_params + method_sym.type_params
            return instantiate(method_fun_ty.ret, all_type_params, mapping)
        reordered_args = [e.args[j] for j in perm]
        reordered_tys = [arg_tys[j] for j in perm]

        if len(method_fun_ty.params) != len(reordered_tys):
            self._err(
                f"call to {recv_ty.name}.{e.method!r}: expected "
                f"{len(method_fun_ty.params)} arguments, got "
                f"{len(reordered_tys)}",
                e.pos,
            )
            return instantiate(method_fun_ty.ret, method_sym.type_params, mapping)

        for param_ty, arg_ty in zip(method_fun_ty.params, reordered_tys):
            substituted = substitute(param_ty, mapping)
            unify(substituted, arg_ty, mapping)

        for i, (param_ty, arg_ty) in enumerate(
            zip(method_fun_ty.params, reordered_tys)
        ):
            substituted = substitute(param_ty, mapping)
            if not self._compatible_with_impls(substituted, arg_ty):
                self._err(
                    f"call to {recv_ty.name}.{e.method!r}: argument "
                    f"{i + 1} expects {ty_str(substituted)}, got "
                    f"{ty_str(arg_ty)}",
                    reordered_args[i].pos,
                )

        self._commit_fresh_substitutions(mapping)

        all_type_params = type_sym.type_params + method_sym.type_params
        ret_ty = instantiate(method_fun_ty.ret, all_type_params, mapping)

        if method_sym.consuming_params:
            self._mark_consumed_args(reordered_args, method_sym.consuming_params)

        return ret_ty
