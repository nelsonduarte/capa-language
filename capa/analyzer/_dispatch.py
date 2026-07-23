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
    instantiate, substitute, ty_str, unify,
)


class _DispatchMixin:
    def _is_internal_builtin(self, sym) -> bool:
        """True when ``sym`` is an underscore-prefixed BUILTIN
        function (compiler-internal plumbing such as ``_capa_chr``)
        and the current source is user code. The bundled JSON
        parser (``capa/ir/_builtin_json.capa``) is analyzed with
        ``internal=True`` and keeps access. User-defined functions
        whose names start with ``_`` carry a real source position,
        never ``BUILTIN_POS``, so they are unaffected."""
        from . import SymbolKind
        from ..builtins import BUILTIN_POS
        return (
            not self.internal
            and sym.kind == SymbolKind.FUNCTION
            and sym.name.startswith("_")
            and sym.pos == BUILTIN_POS
        )

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
        # Evaluate args first so their types populate ``self.types``;
        # the aliasing check needs that for FieldAccess paths
        # (``f(box.cap, box.cap)``). Aliasing is still independent
        # of whether the callee resolves.
        arg_tys = [self._check_expr(a) for a in e.args]
        self._check_no_aliasing(
            [(a, f"argument {i + 1}") for i, a in enumerate(e.args)]
        )

        if isinstance(e.callee, A.Ident):
            from . import SymbolKind
            sym = self.scope.lookup(e.callee.name)
            if sym is not None:
                self.bindings[id(e.callee)] = sym
                if sym.kind == SymbolKind.CAPABILITY:
                    self._err(
                        f"capability {sym.name!r} cannot be constructed at "
                        f"a call site; capabilities only flow through "
                        f"function parameters (declare "
                        f"{sym.name.lower()}: {sym.name} on this function "
                        f"and let the caller pass it in). Constructing a "
                        f"capability locally would let any function "
                        f"silently obtain authority it never declared.",
                        e.pos,
                    )
                    return TyName(sym.name)
                if sym.kind == SymbolKind.TYPE_STRUCT and sym.name == "IoError":
                    # ``IoError(msg)`` / ``IoError(msg, cause)`` is the
                    # one built-in value type Capa constructs with call
                    # syntax. Until 2026-07 this fell through to
                    # TyUnknown, so any aggregate slot holding one --
                    # ``[IoError(..)]``, ``(IoError(..), 1)``,
                    # ``Some(IoError(..))`` -- inferred as ``?`` and the
                    # Wasm backend defaulted the slot to a scalar i64
                    # while the value is an i32 record pointer
                    # (validator rejection at run time). Typing the
                    # constructor result here lets the element / payload
                    # inference carry the real type. The arguments were
                    # already checked above; arity / argument mistakes
                    # keep their pre-existing runtime behaviour rather
                    # than growing new compile-time rejections.
                    from ..builtins import BUILTIN_POS
                    if sym.pos == BUILTIN_POS:
                        return TyName("IoError")
                if sym.kind == SymbolKind.FUNCTION:
                    # Underscore-prefixed BUILTIN functions (e.g.
                    # ``_capa_chr``) are compiler-internal plumbing
                    # for the bundled JSON parser, not language
                    # surface. Only internal sources (the bundled
                    # ``capa/ir/_builtin_json.capa``, analyzed with
                    # ``internal=True``) may call them; user-defined
                    # functions that happen to start with ``_`` have
                    # a real source position and are unaffected.
                    if self._is_internal_builtin(sym):
                        self._err(
                            f"{sym.name!r} is an internal compiler "
                            f"builtin and cannot be called from user "
                            f"code; it is not part of the Capa "
                            f"language surface",
                            e.pos,
                        )
                        return TyUnknown
                    # Roadmap S2.5: declassify has a bespoke call shape
                    # (a required ``reason:`` string literal) that the
                    # generic named-arg path cannot express, so it is
                    # checked directly. The binding is recorded above,
                    # so ``_is_declassify_call`` recognises it here and
                    # in the label pass.
                    if self._is_declassify_call(e):
                        return self._check_declassify(e, arg_tys)
                    if isinstance(sym.ty, TyFun):
                        perm = self._resolve_named_args(
                            e, sym.param_names, repr(sym.name),
                            fun_ty=sym.ty,
                        )
                        if perm is None:
                            return instantiate(
                                sym.ty.ret, sym.type_params, {},
                            )
                        # Roadmap S2.6: cross-function sink-parameter
                        # flow -- a @secret argument bound to a callee
                        # parameter that reaches a public sink inside
                        # the callee is a boundary leak. ``perm`` is in
                        # parameter order, so it doubles as the
                        # param-index -> arg-index map.
                        self._check_ifc_call_summary(e, sym, perm)
                        # ``panic(message)`` writes to stderr, so the
                        # builtin is a public sink like Stdio.eprintln.
                        # A user function named ``panic`` shadows the
                        # builtin (real source pos, not BUILTIN_POS)
                        # and is covered by the summary check above.
                        from ..builtins import BUILTIN_POS
                        if sym.name == "panic" and sym.pos == BUILTIN_POS:
                            self._check_ifc_panic_sink(e)
                        # Cross-function mutation effect: a callee that
                        # stores a secret-derived value into a field of
                        # one of its parameters -- or pushes one into a
                        # container reached through one -- taints the
                        # caller's binding whole-value (closes gap 1).
                        self._check_ifc_call_field_effect(e, sym, perm)
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
                    expected = sym.variant_payload_tys
                    if not expected:
                        self._err(
                            f"variant {sym.name!r} takes no payload",
                            e.pos,
                        )
                        return TyUnknown
                    if len(arg_tys) != len(expected):
                        plural = "argument" if len(expected) == 1 else "arguments"
                        self._err(
                            f"variant {sym.name!r} takes {len(expected)} "
                            f"{plural}, got {len(arg_tys)}",
                            e.pos,
                        )
                    mapping: dict[str, Ty] = {}
                    for i, exp_ty in enumerate(expected):
                        if i >= len(arg_tys):
                            break
                        unify(exp_ty, arg_tys[i], mapping)
                        substituted_payload = substitute(exp_ty, mapping)
                        if not self._assignable(
                            substituted_payload, arg_tys[i], e.args[i]
                        ):
                            self._err(
                                f"variant {sym.name!r}: argument {i + 1} "
                                f"expected {ty_str(substituted_payload)}, "
                                f"got {ty_str(arg_tys[i])}",
                                e.args[i].pos,
                            )
                        # Audit hole D (2026-06): reject a capability
                        # smuggled into a generic variant payload, mirroring
                        # the function-call and struct-literal checks, so a
                        # value carried in ``Wrap(stdio)`` cannot be exercised
                        # behind a ``T`` without appearing in the manifest.
                        self._reject_cap_leak_via_substitution(
                            exp_ty, substituted_payload, sym.name,
                            e.args[i].pos, slot=f"argument {i + 1}",
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
                        # call. Check arity for an actionable error,
                        # then return the function's declared return
                        # type so downstream typing flows through.
                        # (Pre-2026-05-25 this returned TyUnknown,
                        # which propagated as ``?`` through the
                        # lowerer and tripped the Wasm backend with
                        # an i64 fallback that the validator
                        # rejected at runtime.)
                        fun_ty = sym.ty
                        if len(fun_ty.params) != len(arg_tys):
                            self._err(
                                f"call to {sym.name!r}: expected "
                                f"{len(fun_ty.params)} arguments, got "
                                f"{len(arg_tys)} (signature: "
                                f"{ty_str(fun_ty)})",
                                e.pos,
                            )
                        return fun_ty.ret
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

    def _resolve_inferred_lambda_args(
        self,
        param_tys: "list[Ty]",
        args_in_order: "list[A.Expr]",
        arg_tys: "list[Ty]",
        mapping: "dict[str, Ty]",
    ) -> None:
        """Second pass over the arguments of a call whose generic
        params were just fixed by the receiver / non-lambda arguments.
        For each argument that is a lambda with inferred annotations,
        push the (substituted) expected ``Fun(..)`` parameter type,
        re-check the lambda so its omitted types are filled in and its
        body is checked, and write its real type back into ``arg_tys``
        (and ``self.types``). The lambda's resulting type is unified
        back into ``mapping`` so a result-only type variable (``U`` in
        ``map``'s ``fun(T, U)``) gets fixed from the lambda's body and
        the call's return type and the assignability check see it.

        Only lambdas that are still pending inference are touched, so a
        fully annotated lambda (or any other argument) is left exactly
        as today: no behavioural change off the inference path."""
        for i, arg in enumerate(args_in_order):
            if not isinstance(arg, A.LambdaExpr):
                continue
            if id(arg) not in self._pending_inferred_lambdas:
                continue
            if i >= len(param_tys):
                continue
            expected = param_tys[i]
            if not isinstance(expected, TyFun):
                # No higher-order shape in this slot: cannot infer.
                # Leave it pending so the flush emits the clear error.
                continue
            real_ty = self._recheck_lambda_with_expected(arg, expected)
            arg_tys[i] = real_ty
            # Fix any result-only type variable (e.g. ``U`` in
            # ``map``'s ``fun(T, U) -> List<U>``) from the lambda's
            # now-known body type, so the call's return type carries it.
            if isinstance(real_ty, TyFun):
                unify(expected, real_ty, mapping)

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

        # Non-lambda arguments fixed the generic params above; now that
        # the expected ``Fun(..)`` type of each lambda slot is known,
        # re-check any lambda whose annotations were left to be
        # inferred, updating ``arg_tys`` with its real type before the
        # assignability checks below run against it.
        self._resolve_inferred_lambda_args(
            fun_ty.params, args_in_order, arg_tys, mapping,
        )

        # Higher-order IFC precision (Phase B2'). With every closure
        # argument's ``TyFun.ret_label`` now fixed and ``mapping``
        # recording which type-vars were inferred, derive the element-
        # granular result split of a USER-DEFINED generic higher-order
        # call from its signature by parametricity (a no-op for a call
        # whose result is not a container-with-type-var). This is the
        # free-call analogue of ``_record_combinator_split`` at the method
        # seam; ``fun_ty`` still carries its ``TyVar``s here (before
        # ``instantiate``), so the classifier can see where each
        # parameter's type-var lands in the result.
        self._record_call_split(
            e, fun_ty, mapping, args_in_order, arg_tys,
        )

        for i, (param_ty, arg_ty) in enumerate(zip(fun_ty.params, arg_tys)):
            substituted = substitute(param_ty, mapping)
            if not self._assignable(substituted, arg_ty, args_in_order[i]):
                self._err(
                    f"call to {name!r}: argument {i + 1} expects "
                    f"{ty_str(substituted)}, got {ty_str(arg_ty)}",
                    args_in_order[i].pos,
                )
            self._reject_cap_leak_via_substitution(
                param_ty, substituted, name, args_in_order[i].pos,
                slot=f"argument {i + 1}",
            )

        self._commit_fresh_substitutions(mapping)
        ret_substituted = instantiate(fun_ty.ret, type_params, mapping)
        self._reject_cap_leak_via_substitution(
            fun_ty.ret, ret_substituted, name, e.pos,
            slot="return type",
        )
        return ret_substituted

    def _check_method_call(self, e: A.MethodCall) -> Ty:
        from . import SymbolKind

        # Feature #4 (F1): a call to a typed foreign component,
        # ``Bureau.submit(net, payload)``. The receiver is a bare Ident
        # naming an EXTERN_COMPONENT symbol -- a callable namespace, not a
        # value -- so it is intercepted BEFORE ``_check_expr(e.receiver)``
        # (which would reject referencing a non-value name).
        if isinstance(e.receiver, A.Ident):
            recv_sym = self.scope.lookup(e.receiver.name)
            if (
                recv_sym is not None
                and recv_sym.kind == SymbolKind.EXTERN_COMPONENT
            ):
                self.bindings[id(e.receiver)] = recv_sym
                return self._check_foreign_call(e, recv_sym)

        # Receiver + args first so their types populate
        # ``self.types`` for the FieldAccess-aware aliasing check.
        recv_ty = self._check_expr(e.receiver)
        arg_tys = [self._check_expr(a) for a in e.args]

        # The receiver occupies a call slot; a cap passed as
        # receiver and also as argument is aliasing.
        slots: list[tuple[A.Expr, str]] = [(e.receiver, "receiver")]
        slots.extend((a, f"argument {i + 1}") for i, a in enumerate(e.args))
        self._check_no_aliasing(slots)

        # Roadmap S2.4: information-flow sink check. When the receiver
        # is a built-in capability whose method exfiltrates data
        # (Stdio.println, Net.post, Fs.write, ...), a ``@secret``
        # argument reaching it is a flow violation unless it was
        # declassified. Runs on the labels _check_expr just recorded
        # for the args.
        self._check_ifc_sink(e, recv_ty)

        # Roadmap S2: a secret pushed / added / set into a mutable
        # container taints the container binding, so a later read does
        # not launder it back to public.
        self._check_ifc_container_mutation(e, recv_ty)

        # Roadmap S2 (higher-order IFC): inserting a secret-returning
        # closure into a public-declared container launders the secret
        # through the container's declared element / value type.
        self._check_container_closure_store(e, recv_ty)

        # Roadmap S4: in a @constant_time function, a lookup keyed by a
        # secret (list.get / map.get / set.contains / str.char_at) is a
        # data-dependent memory access.
        self._check_ct_method_index(e, recv_ty)

        # Roadmap S4: in a @constant_time function, a short-circuiting
        # String / List compare method (starts_with / ends_with / contains
        # / index_of) on a @secret operand is a timing oracle, the
        # method-call analogue of ``==`` on a secret.
        self._check_ct_method_compare(e, recv_ty)

        from . import SymbolKind

        # Capabilities: consult registered methods. Covers both
        # built-in caps (Stdio, Fs, ...) whose method tables are
        # populated by ``capa.builtins.register_builtins`` and
        # user-defined caps (``capability Logger``,
        # ``capability ReadOnlyFs``, ...) whose method tables
        # are populated by ``_declarations.py`` when the cap is
        # declared. The branch fires whenever the receiver
        # resolves to a CAPABILITY symbol -- the prior check on
        # ``recv_ty.name in CAPABILITY_NAMES`` only caught
        # built-ins, leaving user-cap method calls typed as
        # TyUnknown (which propagated as ``?`` through the
        # lowerer and broke the Wasm backend on any user-cap
        # method call result).
        # ``capability X`` lands as SymbolKind.CAPABILITY and
        # ``trait X`` as SymbolKind.TRAIT, but both populate the
        # same ``sym.methods`` table (see ``_declarations.py``) and
        # both can have a method called through a value typed as the
        # trait/cap. Route both through the same dispatch path so a
        # method called on a TRAIT-typed receiver gets its DECLARED
        # return type. Without the TRAIT case here the call fell
        # through to TyUnknown, which propagated as ``?`` through the
        # lowerer and broke the Wasm backend (a String return read
        # back as a single i64 instead of (ptr, len)).
        if isinstance(recv_ty, TyName):
            cap_sym = self.global_scope.lookup(recv_ty.name)
            if (
                cap_sym is not None
                and cap_sym.kind in (SymbolKind.CAPABILITY, SymbolKind.TRAIT)
            ):
                kind_word = (
                    "capability" if cap_sym.kind == SymbolKind.CAPABILITY
                    else "trait"
                )
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
                        f"{kind_word} {recv_ty.name!r} has no method "
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
                # Roadmap S3.5: a method from ``impl Type[State]`` is
                # only callable when the typestate receiver is in that
                # state. The receiver's current state is on its TyName.
                req = getattr(method_sym, "required_state", None)
                if req is not None and getattr(recv_ty, "state", None) != req:
                    got = recv_ty.state or "no state"
                    self._err(
                        f"method {e.method!r} requires "
                        f"{recv_ty.name}[{req}], but the receiver is "
                        f"{recv_ty.name}[{got}]",
                        e.pos,
                    )
                return self._check_method_dispatch(
                    e, type_sym, method_sym, recv_ty, arg_tys,
                )

        return TyUnknown

    def _check_foreign_call(self, e: A.MethodCall, comp_sym) -> Ty:
        """Typecheck a call to a typed foreign-component method
        (feature #4, F1): ``Bureau.submit(net, payload)``.

        The QUARANTINE RULE falls out of three independent guarantees:

        1. the method signature was checked at declaration time, so its
           only capability parameters are built-in host caps (never
           ``Unsafe``, never a user cap), and no capability hides inside a
           crossing value type (see ``_check_foreign_method_sig``);
        2. arguments are typechecked positionally against that fixed
           signature, so a value cannot be passed where the declared
           parameter type does not accept it -- an extra capability
           argument fails the arity / type check, and a capability where a
           non-capability crossing type is expected is a type error;
        3. the ambient capability discipline already guarantees a
           capability VALUE can only be a parameter of the enclosing
           function (capabilities cannot be constructed, let-bound, or
           returned), so the boundary can receive ONLY capabilities the
           caller itself was granted -- there is no ambient authority to
           smuggle. The no-aliasing check additionally forbids handing the
           same capability to the boundary twice in one call.

        The composed authority for the boundary stays TOP / unproven in
        the SBOM: the runtime that would make the bound SOUND is F2.
        """
        method_sym = comp_sym.methods.get(e.method)

        # Evaluate args first so their types populate ``self.types`` for
        # the FieldAccess-aware aliasing check, then run the no-aliasing
        # check over the argument slots (the receiver is a namespace, not
        # a capability, so it is not a slot).
        arg_tys = [self._check_expr(a) for a in e.args]
        self._check_no_aliasing(
            [(a, f"argument {i + 1}") for i, a in enumerate(e.args)]
        )

        label = f"{comp_sym.name}.{e.method}"
        if method_sym is None or not isinstance(method_sym.ty, TyFun):
            hint = self._hint_did_you_mean(
                e.method, list(comp_sym.methods.keys()),
            )
            self._err(
                f"foreign component {comp_sym.name!r} has no method "
                f"{e.method!r}{hint}",
                e.pos,
            )
            return TyUnknown

        fun_ty = method_sym.ty
        perm = self._resolve_named_args(
            e, method_sym.param_names, repr(label), fun_ty=fun_ty,
        )
        if perm is None:
            return fun_ty.ret
        reordered_args = [e.args[j] for j in perm]
        reordered_tys = [arg_tys[j] for j in perm]

        if len(fun_ty.params) != len(reordered_tys):
            self._err(
                f"call to {label!r}: expected {len(fun_ty.params)} "
                f"arguments, got {len(reordered_tys)} (signature: "
                f"{ty_str(fun_ty)})",
                e.pos,
            )
            return fun_ty.ret

        for i, (param_ty, arg_ty) in enumerate(
            zip(fun_ty.params, reordered_tys)
        ):
            if not self._assignable(param_ty, arg_ty, reordered_args[i]):
                self._err(
                    f"call to {label!r}: argument {i + 1} expects "
                    f"{ty_str(param_ty)}, got {ty_str(arg_ty)}",
                    reordered_args[i].pos,
                )
        return fun_ty.ret

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

        # Calling a user-defined impl method that lacks the `self`
        # parameter via ``receiver.method()`` is a real error: the
        # runtime would pass ``receiver`` as the first positional
        # argument and Python raises ``TypeError: name() takes 0
        # positional arguments but 1 was given``. Capa allows
        # static-like methods at the impl level (``fun zero() ->
        # Ponto`` as a constructor) but has no public call syntax
        # for them; reject the dot call here.
        #
        # The check is gated on ``type_sym.pos != BUILTIN_POS`` so
        # it does not fire on built-in capability methods
        # (``stdio.println``) or built-in type methods
        # (``json.as_object``, ``xs.length``): those methods are
        # registered in ``capa/builtins.py`` without an explicit
        # ``self`` and dispatch through a different runtime path
        # where the receiver is bound implicitly.
        from ..builtins import BUILTIN_POS as _BPOS
        if type_sym.pos != _BPOS and not method_sym.has_self:
            self._err(
                f"method {recv_ty.name}.{e.method!r} has no 'self' "
                f"parameter; it cannot be called via receiver."
                f"method() (Capa has no static-method call syntax)",
                e.pos,
            )
            return TyUnknown

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
        # Roadmap S2.6: cross-function sink-parameter flow at a method
        # call. ``perm`` maps each explicit parameter to its argument;
        # the receiver binds to ``self`` (summary param index 0).
        self._check_ifc_method_call_summary(
            e, type_sym, method_sym, recv_ty, perm,
        )
        # Cross-function mutation effect (closes gap 1): a method that
        # stores a secret-derived value into a field of ``self`` / a
        # parameter -- or pushes one into a container reached through
        # either -- taints the caller's binding whole-value.
        self._check_ifc_method_call_field_effect(
            e, method_sym, recv_ty, perm,
        )
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

        # The receiver type and the non-lambda arguments have now fixed
        # the method's generic params (``T`` from the receiver's
        # element type, ``U`` from the lambda's body once known). The
        # expected ``Fun(..)`` type of each lambda argument slot is the
        # substituted parameter type; re-check any lambda whose
        # annotations were inferred so its real type is in
        # ``reordered_tys`` before the assignability pass below.
        # ``map`` / ``filter`` / ``fold`` / ``find`` / ``flat_map`` and
        # the other higher-order list / range methods all land here.
        substituted_params = [
            substitute(p, mapping) for p in method_fun_ty.params
        ]
        self._resolve_inferred_lambda_args(
            substituted_params, reordered_args, reordered_tys, mapping,
        )

        # Higher-order IFC precision (Phase B1). With every closure
        # argument's ``TyFun.ret_label`` now fixed, publish the built-in
        # combinator's element-granular result label into the IFC channel
        # (a no-op for non-combinator methods). The built-in combinators
        # -- List / Range map/filter/fold/flat_map, Option map/and_then/
        # filter, Result map/and_then/map_err -- are all METHODS, so this
        # is the only seam B1 needs; user-defined generic higher-order
        # functions (the free-call seam) arrive in B2/B3.
        self._record_combinator_split(
            e, recv_ty.name, reordered_args, reordered_tys,
        )

        for i, (param_ty, arg_ty) in enumerate(
            zip(method_fun_ty.params, reordered_tys)
        ):
            substituted = substitute(param_ty, mapping)
            if not self._assignable(substituted, arg_ty, reordered_args[i]):
                self._err(
                    f"call to {recv_ty.name}.{e.method!r}: argument "
                    f"{i + 1} expects {ty_str(substituted)}, got "
                    f"{ty_str(arg_ty)}",
                    reordered_args[i].pos,
                )
            self._reject_cap_leak_via_substitution(
                param_ty, substituted, f"{recv_ty.name}.{e.method!r}",
                reordered_args[i].pos, slot=f"argument {i + 1}",
            )

        self._commit_fresh_substitutions(mapping)

        all_type_params = type_sym.type_params + method_sym.type_params
        ret_ty = instantiate(method_fun_ty.ret, all_type_params, mapping)
        self._reject_cap_leak_via_substitution(
            method_fun_ty.ret, ret_ty, f"{recv_ty.name}.{e.method!r}",
            e.pos, slot="return type",
        )

        if method_sym.consuming_params:
            self._mark_consumed_args(reordered_args, method_sym.consuming_params)

        # Roadmap S1: a ``consume self`` method discharges the linear
        # obligation on its receiver (``h.close()`` releases ``h``).
        if getattr(method_sym, "consumes_self", False) and isinstance(
            e.receiver, A.Ident
        ):
            self._linear_discharge(e.receiver.name)

        return ret_ty
