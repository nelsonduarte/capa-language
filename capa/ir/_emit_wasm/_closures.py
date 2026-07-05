"""Closures + HOF emission mixin (Phase 6E).

Owns every part of the closure-conversion machinery:

- Discovery: walking every function body to find ``MakeLambda``
  instructions, computing each one's free-variable set, env layout,
  and Wasm signature, and assigning a function-table index.
- Module-level emission: ``(type $sig_N ...)`` declarations,
  ``(table $fnref ...)``, ``(elem ...)``, and the lifted top-level
  functions themselves.
- ``MakeLambda`` instruction emission: env-record allocation, per-
  capture stores, and the packed-i64 closure value
  ``(fn_idx << 32) | env_ptr``.
- Closure invocation: unpack the closure value and dispatch via
  ``call_indirect`` against the matching ``(type $sig_N)``.
- HOFs on ``List<Int>``: ``map`` / ``filter`` / ``fold``, plus the
  inline list-push helper that ``filter`` uses to avoid clobbering
  the outer scrutinee scratch.

Depends on the layout mixin for size/alignment helpers, the
strings mixin for ``_push_string_value_as_ptr_len``, and the lists
mixin for list-header layout constants (imported here directly
from ``_layout``).
"""

from __future__ import annotations

from typing import Optional

from .._nodes import (
    Call, Function, Instr, MakeLambda, MethodCall, Module, Value,
    If, While, For, Match, FormatStr,
    Pattern, PatIdent, PatVariant,
)
from .._capa_types import BUILTIN_CAPS
from .._walk import walk_instrs
from ._layout import (
    WasmEmissionError,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _align_up,
    _store_op_for_size,
)


class _ClosureEmissionMixin:
    # ----- module-level closure emission ------------------------

    def _emit_closure_types_and_table(self) -> None:
        """Emit the ``(type $sig_N ...)`` declarations for every
        unique closure signature, then a single ``(table $fnref
        N N funcref)`` + ``(elem ...)`` to populate the function
        table with the lifted lambda names followed by the
        function-ref thunks. The order of elem entries matches
        each entry's ``fn_idx`` (lambdas first, then thunks)."""
        # Sort by sig_idx for determinism.
        sig_pairs = sorted(self._closure_sig_keys.items(), key=lambda kv: kv[1])
        for sig_key, sig_idx in sig_pairs:
            # ``sig_key`` is "(<params>) -> <result>"; convert to
            # WAT ``(type $sig_N (func (param ...) (result ...)))``
            params_part, _, result_part = sig_key.partition(") -> ")
            params_part = params_part.lstrip("(")
            param_clauses = "".join(
                f" (param {t})" for t in params_part.split()
            )
            result_clause = (
                f" (result {result_part})"
                if result_part and result_part != "()"
                else ""
            )
            self._write(
                f"(type $sig_{sig_idx} (func{param_clauses}{result_clause}))"
            )
        n = len(self._lifted_lambdas) + len(self._fn_ref_thunks)
        self._write(f"(table $fnref {n} {n} funcref)")
        lambda_names = [f"${l['name']}" for l in self._lifted_lambdas]
        thunk_names = [
            f"${t['name']}" for t in self._fn_ref_thunks.values()
        ]
        names = " ".join(lambda_names + thunk_names)
        self._write(f"(elem (i32.const 0) {names})")

    def _register_fn_ref_thunks(self, module) -> None:
        """Walk every IR instruction in the module and, for each
        ``Value(kind='global', ty='Fun(...)')`` found in an
        argument position, register a thunk that wraps the named
        free function so it can be passed as a closure value.

        Idempotent per (fn_name, sig_key): repeated references to
        the same function with the same target signature share a
        single thunk. fn_idx assignment is contiguous after the
        lifted lambdas so the closure table layout stays linear:
        ``[lambda_0, ..., lambda_M, thunk_<name1>_<sig1>, ...]``.

        Runs before the closure table is emitted so ``_push_value``
        can resolve the fn_idx for a global Fun reference without
        having to grow the table on the fly during body emit."""
        from .._nodes import (
            Call, MethodCall, For, If, While, Match, MakeLambda,
            AssignConst, Reassign, BinOp, UnaryOp, Index, FieldAccess,
            FieldStore, Return, TryUnwrap, FormatStr, Value as IrValue,
            MakeList, MakeTuple, MakeStruct,
        )

        # Map global-fun callee names to their Function for sig
        # lookup. Used by the thunk emitter to know the underlying
        # function's param + return types.
        fn_by_name = {fn.name: fn for fn in module.functions}

        def visit_value(v) -> None:
            if v is None or not isinstance(v, IrValue):
                return
            if v.kind != "global":
                return
            if not (v.ty and v.ty.startswith("Fun")):
                return
            target = fn_by_name.get(v.name)
            if target is None:
                # ``v.name`` is something other than a top-level
                # function (e.g. a constant whose type happens to
                # be Fun). Leave it for _push_value to surface as
                # an error -- this discovery pass only handles
                # actual function references.
                return
            # Slices 25.2 - 25.6 (2026-05-30): Fs / Net / Db / Proc
            # / Env / Clock are un-erased and count toward the
            # closure signature; other caps stay erased.
            arg_capa_tys = [
                p.ty for p in target.params
                if (
                    p.ty not in BUILTIN_CAPS
                    or p.ty in (
                        "Fs", "Net", "Db", "Proc", "Env", "Clock",
                    )
                )
            ]
            ret_capa_ty = target.return_type or "Unit"
            try:
                sig_key = self._closure_sig_key_for(arg_capa_tys, ret_capa_ty)
            except WasmEmissionError:
                # The function's signature contains a type the
                # closure ABI can't encode (e.g. Unit param). Leave
                # it for emit-time so the error message names the
                # call site.
                return
            key = (v.name, sig_key)
            if key in self._fn_ref_thunks:
                return
            # Register sig in the closure sig table if not yet.
            if sig_key not in self._closure_sig_keys:
                self._closure_sig_keys[sig_key] = len(self._closure_sig_keys)
            sig_idx = self._closure_sig_keys[sig_key]
            # fn_idx starts after the lifted lambdas + any
            # already-registered thunks; the table elem list is
            # emitted in (lambdas, thunks) order.
            fn_idx = len(self._lifted_lambdas) + len(self._fn_ref_thunks)
            self._fn_ref_thunks[key] = {
                "name": f"thunk_{v.name}_{sig_idx}",
                "fn_idx": fn_idx,
                "sig_idx": sig_idx,
                "sig_key": sig_key,
                "underlying": v.name,
                "params": list(target.params),
                "return_type": ret_capa_ty,
            }

        def visit_instrs(instrs) -> None:
            for instr in instrs:
                # Sweep every IR field that may carry a Value.
                if isinstance(instr, Call):
                    for a in instr.args:
                        visit_value(a)
                elif isinstance(instr, MethodCall):
                    visit_value(instr.receiver)
                    for a in instr.args:
                        visit_value(a)
                elif isinstance(instr, AssignConst):
                    visit_value(instr.src)
                elif isinstance(instr, Reassign):
                    visit_value(instr.src)
                elif isinstance(instr, BinOp):
                    visit_value(instr.left)
                    visit_value(instr.right)
                elif isinstance(instr, UnaryOp):
                    visit_value(instr.operand)
                elif isinstance(instr, Index):
                    visit_value(instr.receiver)
                    visit_value(instr.index)
                elif isinstance(instr, FieldAccess):
                    visit_value(instr.receiver)
                elif isinstance(instr, FieldStore):
                    visit_value(instr.receiver)
                    visit_value(instr.src)
                elif isinstance(instr, Return):
                    visit_value(instr.value)
                elif isinstance(instr, TryUnwrap):
                    visit_value(instr.src)
                elif isinstance(instr, FormatStr):
                    for part in instr.parts:
                        if isinstance(part, IrValue):
                            visit_value(part)
                elif isinstance(instr, (MakeList, MakeTuple)):
                    # A top-level function used as a ``Fun(...)``
                    # value can appear as an element of a list or
                    # tuple literal (``[add1, add1]`` /
                    # ``(add1, add1)``). Without visiting the
                    # elements the thunk for that fn-ref is never
                    # registered and emit fails with "no thunk
                    # registered for sig". Nested aggregates are
                    # already separate MakeList/MakeTuple instrs in
                    # ANF, so the top-level walk reaches each one.
                    for el in instr.elements:
                        visit_value(el)
                elif isinstance(instr, MakeStruct):
                    # ``S { op: add1 }`` -- a Fun-typed struct field
                    # initialised with a top-level function ref.
                    for _fname, fval in instr.fields:
                        visit_value(fval)
                # MakeMap / MakeSet literals are always empty in Capa
                # (values are added via ``.set(...)`` MethodCalls,
                # already visited above); MakeRange only ever carries
                # Int endpoints, never a Fun, so neither needs a case.
                # Recurse into nested instruction lists.
                if isinstance(instr, If):
                    visit_value(instr.cond)
                    visit_instrs(instr.then_body)
                    visit_instrs(instr.else_body)
                elif isinstance(instr, While):
                    visit_instrs(instr.cond_setup)
                    visit_value(instr.cond)
                    visit_instrs(instr.body)
                elif isinstance(instr, For):
                    visit_value(instr.iter)
                    visit_instrs(instr.body)
                elif isinstance(instr, Match):
                    visit_value(instr.scrutinee)
                    for arm in instr.arms:
                        visit_instrs(arm.body)
                elif isinstance(instr, MakeLambda):
                    visit_instrs(instr.body)

        for fn in module.functions:
            visit_instrs(fn.body)
        for impl in module.impls:
            for method in impl.methods:
                visit_instrs(method.body)

    def _emit_fn_ref_thunk(self, thunk: dict) -> None:
        """Emit the thunk function for a global Fun reference.
        Body: drop ``$env`` (always 0 for thunks), forward each
        user arg verbatim, ``call $<underlying>``, return.

        String args / return are split across two i32 slots (ptr,
        len) per the existing Wasm String ABI; the thunk threads
        them through unchanged. Other types use the size-dispatched
        single-slot encoding."""
        name = thunk["name"]
        params = thunk["params"]
        ret_ty = thunk["return_type"]
        underlying = thunk["underlying"]
        # Header.
        param_clauses = ["(param $env i32)"]
        for p in params:
            if p.ty in BUILTIN_CAPS:
                # The thunk's wasm sig has no cap params (closure
                # ABI omits them); the underlying function would
                # take cap args via its declared-caps mechanism,
                # which isn't possible from a closure-call. We
                # silently skip cap params: a Fun-typed value
                # cannot legally carry a cap (the analyzer's type
                # check rejects it earlier), so this never fires
                # in well-typed code. Keeps the loop simple.
                #
                # Slices 25.2 - 25.6: Fs / Net / Db / Proc / Env /
                # Clock are un-erased - the closure ABI must thread
                # their i32 handles the same way it threads any
                # other scalar.
                if p.ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    param_clauses.append(f"(param ${p.name} i32)")
                continue
            if p.ty == "String":
                param_clauses.append(f"(param ${p.name}_ptr i32)")
                param_clauses.append(f"(param ${p.name}_len i32)")
            else:
                param_clauses.append(f"(param ${p.name} {self._wasm_type(p.ty)})")
        result_str = ""
        if ret_ty == "String":
            # String result lowers to (i32 i32) multi-value.
            result_str = " (result i32) (result i32)"
        elif ret_ty and ret_ty != "Unit":
            result_str = f" (result {self._wasm_type(ret_ty)})"
        self._write(
            f"(func ${name} {' '.join(param_clauses)}{result_str}"
        )
        self._indent += 1
        # Forward each user arg to the underlying function. ``$env``
        # is intentionally ignored: thunks have no captured state.
        for p in params:
            if p.ty in BUILTIN_CAPS:
                if p.ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    self._write(f"local.get ${p.name}")
                continue
            if p.ty == "String":
                self._write(f"local.get ${p.name}_ptr")
                self._write(f"local.get ${p.name}_len")
            else:
                self._write(f"local.get ${p.name}")
        self._write(f"call ${underlying}")
        self._indent -= 1
        self._write(")")

    def _emit_lifted_lambda(self, lifted: dict) -> None:
        """Emit a top-level Wasm function for a lifted lambda.
        The first param is always ``$env`` (i32 pointer to the
        env record, or 0 for no-capture lambdas). Body emission
        uses ``self._current_captures`` so captured local
        references load from env instead of looking up a Wasm
        local that does not exist."""
        # Save outer state.
        prev_fn = self._current_fn
        prev_captures = self._current_captures
        prev_block_counter = self._block_counter
        prev_loop_labels = self._loop_labels

        # Synthesise a fn-shaped record so existing
        # _collect_locals / _emit_instr paths consult the right
        # ``fn.locals`` (we use ``Function`` with an empty
        # ``locals`` dict + the lambda's own params + the body).
        synth_fn = Function(
            name=lifted["name"],
            params=lifted["params"],
            return_type=lifted["return_type"] or "Unit",
            declared_caps=[],
            body=lifted["body"],
            locals=lifted["locals"],
        )
        self._current_fn = synth_fn
        self._current_captures = lifted["captures"]
        self._block_counter = 0
        self._loop_labels = []

        # Header.
        param_clauses = ["(param $env i32)"]
        for p in lifted["params"]:
            # String params lower to a (ptr, len) pair of i32s;
            # check before _wasm_type because _wasm_type raises
            # on "String" (no single-value encoding).
            if p.ty == "String":
                param_clauses.append(f"(param ${p.name}_ptr i32)")
                param_clauses.append(f"(param ${p.name}_len i32)")
            else:
                ty = self._wasm_type(p.ty)
                param_clauses.append(f"(param ${p.name} {ty})")
        params_str = " ".join(param_clauses)
        result_str = (
            f" (result {lifted['result_wasm_ty']})"
            if lifted["result_wasm_ty"] else ""
        )
        self._write(
            f"(func ${lifted['name']} (type $sig_{lifted['sig_idx']}) "
            f"{params_str}{result_str}"
        )
        self._indent += 1
        # Declare locals. Same logic as a regular function: walk
        # body for every introduced dst.
        param_names = {p.name for p in lifted["params"]} | {"env"}
        local_decls = self._collect_locals(synth_fn, param_names)
        for name, ty in local_decls.items():
            self._write(f"(local ${name} {ty})")
        self._emit_body(lifted["body"])
        if lifted["result_wasm_ty"]:
            self._write("unreachable")
        self._indent -= 1
        self._write(")")

        # Restore outer state.
        self._current_fn = prev_fn
        self._current_captures = prev_captures
        self._block_counter = prev_block_counter
        self._loop_labels = prev_loop_labels

    # ----- discovery --------------------------------------------

    def _discover_lambdas(self, module: Module) -> None:
        """Walk every function AND impl-method body, collect
        MakeLambda instructions, compute the env layout +
        signature for each and assign fn_idx (function table
        index). String literals inside lambda bodies are interned
        by ``_discover`` (the shared module walk recurses into
        MakeLambda bodies), so this pass only handles the lift
        bookkeeping.

        Impl methods go through ``_impl_method_view`` so the
        registration is keyed on the MANGLED method name -- the
        name ``self._current_fn.name`` carries when the method
        body is emitted -- and so capture-type lookup sees
        ``self``'s concrete type.

        Nested lambdas use flat envs: every inner closure gets its
        own env record holding all the names it references from
        any outer scope (no env-of-env chain). The scope-stack
        ``scopes`` carries the immediate-enclosing-lambda's
        ``params`` / ``locals`` / ``captures`` so the inner's
        capture-type lookup can walk the outer's view; the
        ``parent_fn`` parameter stays the enclosing function /
        method so ``_register_lambda`` can find a body-local's
        type in the lowerer's flat ``fn.locals`` map."""

        def visit(
            instrs: list[Instr],
            parent_fn: Function,
            scopes: list[dict],
        ) -> None:
            # ``into_lambdas=False``: each nesting level handles
            # its own MakeLambda instructions so the scope stack
            # is pushed/popped around exactly one lambda body.
            for instr in walk_instrs(instrs, into_lambdas=False):
                if isinstance(instr, MakeLambda):
                    # ``parent_scope_name`` is the immediate
                    # enclosing emission unit's name. At MakeLambda
                    # emit time ``self._current_fn`` is either the
                    # enclosing Function (no scopes pushed) or the
                    # synthesised lifted function for the outer
                    # lambda (scopes[-1]["name"]); key the
                    # registration the same way.
                    if scopes:
                        parent_scope_name = scopes[-1]["name"]
                    else:
                        parent_scope_name = parent_fn.name
                    self._register_lambda(
                        instr, parent_fn,
                        parent_scope_name=parent_scope_name,
                        outer_scope=scopes[-1] if scopes else None,
                    )
                    # Push this lambda's scope, recurse into its
                    # body, pop. The freshly registered lambda is
                    # at the end of ``_lifted_lambdas`` -- its
                    # ``params`` / ``locals`` / ``captures`` are
                    # what an even-deeper nested lambda would need.
                    lifted = self._lifted_lambdas[-1]
                    scopes.append(lifted)
                    try:
                        visit(instr.body, parent_fn, scopes)
                    finally:
                        scopes.pop()

        for fn in module.functions:
            visit(fn.body, fn, [])
        for impl in module.impls:
            for method in impl.methods:
                visit(method.body, self._impl_method_view(impl, method), [])

    def _register_lambda(
        self,
        instr: MakeLambda,
        parent_fn: Function,
        parent_scope_name: Optional[str] = None,
        outer_scope: Optional[dict] = None,
    ) -> None:
        """Compute captures + env layout + signature for one
        lambda; append the resulting record to ``_lifted_lambdas``
        and assign it an fn_idx.

        ``parent_fn`` is the top-level Function the lambda is
        ultimately nested inside (used for the flat ``fn.locals``
        map the lowerer populated). ``outer_scope`` is the
        immediate enclosing lambda's lifted record (or ``None``
        when the lambda sits directly inside a Function); its
        ``params`` / ``locals`` / ``captures`` are consulted in
        priority order before falling through to ``parent_fn``.
        ``parent_scope_name`` is the name the MakeLambda emit
        site will see in ``self._current_fn.name`` -- it's the
        outer lambda's lifted name for nested cases, the
        top-level function's name otherwise."""
        # ------- free-variable analysis -------
        own_params: set[str] = {p.name for p in instr.params}
        defined_in_body: set[str] = set()

        def collect_defs(instrs: list[Instr]) -> None:
            for i in instrs:
                dst = getattr(i, "dst", None)
                if dst:
                    defined_in_body.add(dst)
                if isinstance(i, For):
                    defined_in_body.add(i.name)
                    collect_defs(i.body)
                elif isinstance(i, If):
                    collect_defs(i.then_body)
                    collect_defs(i.else_body)
                elif isinstance(i, While):
                    collect_defs(i.cond_setup)
                    collect_defs(i.body)
                elif isinstance(i, Match):
                    for arm in i.arms:
                        # A guard's ANF prelude introduces its own
                        # temporaries (a ``Some(n) if n > 5`` guard
                        # lowers to a Bool BinOp into ``_ir_tN``).
                        # They are defined in this lambda body just
                        # like body temps, so they must enter
                        # ``defined_in_body`` -- otherwise the lifted
                        # function's locals sweep falls back to the
                        # default i64 shape and a Bool guard result
                        # (i32) trips the Wasm validator (i32 vs i64).
                        if getattr(arm, "guard_setup", None):
                            collect_defs(arm.guard_setup)
                        collect_defs(arm.body)
                        # Pattern-bound names also count as defined.
                        self._collect_pattern_names(arm.pattern, defined_in_body)

        collect_defs(instr.body)

        # Free-variable set for this lambda. Direct references in
        # the body contribute, AND references inside any nested
        # MakeLambda body that the nested lambda itself cannot
        # satisfy (i.e. not in the nested's own params or
        # body-defined locals). This is the standard
        # ``free_vars(outer) = free_vars(direct) ∪
        #   (free_vars(nested) - nested.params - nested.locals)``
        # rule -- a nested closure's unbound names must be
        # supplied by some enclosing scope, and if the outer is
        # that enclosing scope, the outer must capture them too
        # (and then pass them through into the nested's env at
        # MakeLambda emit time).
        referenced: set[str] = set()

        def free_vars(
            body_instrs: list[Instr],
            shadow_params: set[str],
            shadow_locals: set[str],
        ) -> set[str]:
            out: set[str] = set()

            def collect(v: Value) -> None:
                if v.kind in ("local", "param") and v.name:
                    if v.name in shadow_params or v.name in shadow_locals:
                        return
                    out.add(v.name)

            def collect_callee(callee: Optional[str]) -> None:
                # A ``Call``'s callee is a bare name, not a Value, so
                # ``_values_of`` never yields it. When that name is a
                # higher-order function CAPTURED from an enclosing
                # scope -- ``compose(f, g) => fun(x) => g(f(x))`` where
                # ``f`` / ``g`` appear only as call targets, never as
                # plain values -- the free-variable set would miss it
                # and the lifted body would emit ``call $f`` for a
                # static function that does not exist. Add the callee
                # iff it is not shadowed by the lambda's own params /
                # locals and resolves to a Fun type somewhere in the
                # enclosing scope (a top-level function or builtin
                # resolves to Unknown and is correctly left alone).
                if not callee:
                    return
                if callee in shadow_params or callee in shadow_locals:
                    return
                cap_ty = self._resolve_capture_type(
                    callee, parent_fn, outer_scope,
                )
                if cap_ty.startswith("Fun"):
                    out.add(callee)

            def walk(instrs: list[Instr]) -> None:
                for i in instrs:
                    if isinstance(i, MakeLambda):
                        # Compute the nested lambda's own
                        # shadowed set and propagate only the
                        # unsatisfied free variables upward.
                        inner_params = {p.name for p in i.params}
                        inner_defs: set[str] = set()
                        # Mirror ``collect_defs`` for the nested
                        # body so its locally-bound names shadow
                        # any outer reference.
                        def nested_defs(ins: list[Instr]) -> None:
                            for ii in ins:
                                dst = getattr(ii, "dst", None)
                                if dst:
                                    inner_defs.add(dst)
                                if isinstance(ii, For):
                                    inner_defs.add(ii.name)
                                    nested_defs(ii.body)
                                elif isinstance(ii, If):
                                    nested_defs(ii.then_body)
                                    nested_defs(ii.else_body)
                                elif isinstance(ii, While):
                                    nested_defs(ii.cond_setup)
                                    nested_defs(ii.body)
                                elif isinstance(ii, Match):
                                    for arm in ii.arms:
                                        if getattr(arm, "guard_setup", None):
                                            nested_defs(arm.guard_setup)
                                        nested_defs(arm.body)
                                        self._collect_pattern_names(
                                            arm.pattern, inner_defs,
                                        )
                        nested_defs(i.body)
                        nested_free = free_vars(
                            i.body, inner_params, inner_defs,
                        )
                        for n in nested_free:
                            if (n not in shadow_params
                                    and n not in shadow_locals):
                                out.add(n)
                        # Skip the standard value walk for
                        # MakeLambda; its dst is not a reference.
                        continue
                    collect_callee(getattr(i, "callee_name", None))
                    for v in self._values_of(i):
                        collect(v)
                    if isinstance(i, If):
                        collect(i.cond)
                        walk(i.then_body)
                        walk(i.else_body)
                    elif isinstance(i, While):
                        walk(i.cond_setup)
                        collect(i.cond)
                        walk(i.body)
                    elif isinstance(i, For):
                        collect(i.iter)
                        walk(i.body)
                    elif isinstance(i, Match):
                        collect(i.scrutinee)
                        for arm in i.arms:
                            # A guard (and its ANF prelude) can read
                            # captured names that the arm body never
                            # touches -- ``Some(n) if n > threshold``
                            # references the enclosing ``threshold``
                            # only inside the guard. Symmetric to
                            # ``collect_defs`` above, both must be
                            # walked or the capture is dropped from the
                            # env layout and the lifted body emits a
                            # ``local.get`` for a name that was never
                            # allocated (unknown local at Wasm validate
                            # time).
                            if getattr(arm, "guard_setup", None):
                                walk(arm.guard_setup)
                            if getattr(arm, "guard", None) is not None:
                                collect(arm.guard)
                            walk(arm.body)

            walk(body_instrs)
            return out

        referenced = free_vars(instr.body, own_params, defined_in_body)
        captures_names = referenced  # shadows already subtracted

        # ------- env layout -------
        env_layout: dict[str, tuple[int, str]] = {}
        offset = 0
        # Sort for deterministic layouts (helps debugging + tests).
        for name in sorted(captures_names):
            capa_ty = self._resolve_capture_type(
                name, parent_fn, outer_scope,
            )
            if capa_ty in BUILTIN_CAPS:
                # Capability captures are free at the Wasm level.
                # Slices 25.2 - 25.6: except Fs / Net / Db / Proc /
                # Env / Clock which are now i32 handles the lambda
                # must close over so the restriction follows the cap
                # into the closure body (otherwise the lambda would
                # see whatever default the host bridge invented,
                # defeating the cross-function soundness these
                # slices deliver).
                if capa_ty not in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    continue
            size = (
                self._size_of(capa_ty)
                if capa_ty not in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ) else 4
            )
            offset = _align_up(offset, size)
            env_layout[name] = (offset, capa_ty)
            offset += size
        env_size = _align_up(offset, 8) if offset > 0 else 0

        # ------- signature -------
        # ``(param i32) (param ...) -> (result ...)`` rendered as
        # a stable string so duplicates dedupe. The leading i32 is
        # always the env_ptr (first param of every lifted lambda).
        # String params lower as a (ptr, len) pair of i32s
        # ("multi-value"); the call-site + body emit code already
        # expects the same convention (see _emit_closure_call and
        # _emit_lifted_lambda's `${name}_ptr` / `${name}_len`
        # locals). Other shapes (Int / Bool / Float / Fun /
        # struct / List / Map / Set / tuple / sum) are single
        # Wasm values and route through _wasm_type.
        param_wasm_tys = ["i32"]  # env_ptr always first
        for p in instr.params:
            if p.ty == "String":
                param_wasm_tys.append("i32")
                param_wasm_tys.append("i32")
                continue
            try:
                t = self._wasm_type(p.ty)
            except WasmEmissionError as e:
                # Multi-value lowering for non-scalar collection
                # types in lambda position would still be needed
                # in principle; today every non-String type the
                # backend supports has a single-value encoding via
                # _wasm_type, so this branch only fires for genuine
                # gaps (unknown types, unresolved tyvars, etc.).
                raise WasmEmissionError(
                    f"lambda param {p.name!r} has type {p.ty!r}, "
                    f"which the Wasm backend cannot encode. "
                    f"Workaround: use the Python backend "
                    f"(``capa --run``), or refactor the lambda. "
                    f"Original: {e}"
                ) from e
            if not t:
                raise WasmEmissionError(
                    f"lambda param {p.name!r} has Unit type, which "
                    f"has no Wasm encoding"
                )
            param_wasm_tys.append(t)
        # Return type. String returns lower as multi-value
        # ``(result i32 i32)``; everything else is a single
        # Wasm value. ``""`` means no result (Unit-returning).
        if instr.return_type == "String":
            result_ty = "i32 i32"
        else:
            try:
                result_ty = (
                    self._wasm_type(instr.return_type)
                    if instr.return_type else ""
                )
            except WasmEmissionError as e:
                raise WasmEmissionError(
                    f"lambda return type {instr.return_type!r} not "
                    f"supported by the Wasm closure lowering. "
                    f"Workaround: use the Python backend, or "
                    f"refactor the lambda body to return a scalar. "
                    f"Original: {e}"
                ) from e
        sig_key = f"({' '.join(param_wasm_tys)}) -> {result_ty or '()'}"
        if sig_key not in self._closure_sig_keys:
            self._closure_sig_keys[sig_key] = len(self._closure_sig_keys)
        sig_idx = self._closure_sig_keys[sig_key]

        # Copy out the body's locals from the top-level function's
        # locals dict so the synthesised lifted function carries
        # precise types for ``_collect_locals``. The lowerer flattens
        # every introduced local (including those created inside any
        # depth of nested lambda) into the outermost function's
        # locals map, so ``parent_fn.locals`` is the single source
        # of truth even for deeply nested lambdas.
        body_locals: dict[str, str] = {}
        for name in defined_in_body:
            if name in parent_fn.locals:
                body_locals[name] = parent_fn.locals[name]

        fn_idx = len(self._lifted_lambdas)
        lifted_name = f"lambda_{fn_idx}"
        self._lifted_lambdas.append({
            "name": lifted_name,
            "params": list(instr.params),
            "return_type": instr.return_type,
            "body": instr.body,
            "locals": body_locals,
            "captures": env_layout,
            "env_size": env_size,
            "param_wasm_tys": param_wasm_tys,
            "result_wasm_ty": result_ty,
            "sig_key": sig_key,
            "sig_idx": sig_idx,
            "fn_idx": fn_idx,
        })
        # ``parent_scope_name`` is the lifted-lambda name for nested
        # cases (so the inner MakeLambda emit -- which runs while
        # ``self._current_fn`` is the outer's synth function -- finds
        # the right entry) and the top-level function name otherwise.
        key_parent = parent_scope_name or parent_fn.name
        self._lambda_by_dst[(key_parent, instr.dst)] = fn_idx

    def _collect_pattern_names(self, pat: Pattern, out: set[str]) -> None:
        if isinstance(pat, PatIdent):
            out.add(pat.name)
            return
        if isinstance(pat, PatVariant):
            for sub in pat.payloads:
                self._collect_pattern_names(sub, out)
            return
        # PatWildcard / PatLiteral introduce no names.

    @staticmethod
    def _params_lookup(fn: Function, name: str) -> Optional[str]:
        for p in fn.params:
            if p.name == name:
                return p.ty
        return None

    @staticmethod
    def _resolve_capture_type(
        name: str,
        parent_fn: Function,
        outer_scope: Optional[dict],
    ) -> str:
        """Look up the Capa type of a captured name for a lambda
        being registered. Priority order:

        1. Outer scope's locals (names defined inside the outer
           lambda body, like ``let x = ...``).
        2. Outer scope's params.
        3. Outer scope's captures (the outer lambda is itself
           closing over them -- the inner needs its own copy).
        4. Top-level function's locals.
        5. Top-level function's params.

        Falls through to ``"Unknown"`` if absent everywhere. The
        flat-env design copies the value at MakeLambda emit time,
        so the chain stops at one level: the inner doesn't reach
        through the outer's env at run time, it just gets the
        same value stored directly in its own env."""
        if outer_scope is not None:
            scope_locals: dict[str, str] = outer_scope.get("locals", {}) or {}
            ty = scope_locals.get(name)
            if ty:
                return ty
            for p in outer_scope.get("params", []) or []:
                if p.name == name:
                    return p.ty
            scope_caps: dict[str, tuple[int, str]] = (
                outer_scope.get("captures", {}) or {}
            )
            if name in scope_caps:
                return scope_caps[name][1]
        # Fall through to the top-level function (the lowerer's
        # flat locals map carries every name introduced anywhere
        # under it, including pattern-bound names and lambda
        # params -- but lambda params live on the MakeLambda
        # instruction, not in ``fn.locals``, so the param-list
        # walk above is still needed for the outer-lambda-param
        # case).
        ty2 = parent_fn.locals.get(name)
        if ty2:
            return ty2
        for p in parent_fn.params:
            if p.name == name:
                return p.ty
        return "Unknown"

    # ----- MakeLambda + closure_call ----------------------------

    def _emit_make_lambda(self, instr: MakeLambda) -> None:
        """Materialise a closure value for ``instr.dst``. If the
        lambda captures any non-capability locals, allocate an env
        record on the heap and store each capture's bits at its
        layout offset. Pack (fn_idx, env_ptr) into an i64 and bind
        the dst.

        Captures of String locals store two i32s (ptr, len). Other
        types store via the size-dispatched store opcode."""
        # The discovery pass keyed lifted lambdas by
        # (parent_fn_name, dst); use the current function's name
        # to disambiguate when multiple functions reuse the same
        # ``_ir_lambdaN`` dst (the IR's fresh-local counter resets
        # per function).
        parent_name = self._current_fn.name if self._current_fn else ""
        fn_idx = self._lambda_by_dst.get((parent_name, instr.dst))
        if fn_idx is None:
            raise WasmEmissionError(
                f"MakeLambda for {instr.dst!r} not registered by the "
                f"discover pass; lifted-lambda table is out of sync"
            )
        lifted = self._lifted_lambdas[fn_idx]
        env_size = lifted["env_size"]
        env_layout = lifted["captures"]
        if env_size > 0:
            self._write(f"i32.const {env_size}")
            self._write("call $alloc")
            self._write("local.set $_lam_env_tmp")
            # Store each capture. The push routes through
            # ``_push_value`` / ``_push_string_value_as_ptr_len``
            # so that a name which is itself an outer capture (we
            # are emitting an inner MakeLambda inside the outer
            # lambda's body) loads from the outer's ``$env`` rather
            # than a Wasm local that doesn't exist. The flat-env
            # design copies the value into the inner's env right
            # here -- no run-time env chain.
            for name, (offset, capa_ty) in env_layout.items():
                if capa_ty == "String":
                    self._write("local.get $_lam_env_tmp")
                    cap_val = Value(kind="local", name=name, ty="String")
                    self._push_string_value_as_ptr_len(cap_val)
                    # Stack: [..., env_tmp, ptr, len].
                    # Store ptr at offset, len at offset+4.
                    self._write("local.set $_str_a_len")
                    self._write("local.set $_str_a_ptr")
                    self._write("local.get $_str_a_ptr")
                    self._write(f"i32.store offset={offset}")
                    self._write("local.get $_lam_env_tmp")
                    self._write("local.get $_str_a_len")
                    self._write(f"i32.store offset={offset + 4}")
                elif capa_ty == "Float":
                    # Float captures must round-trip through the
                    # env record as f64 (not i64). Pre-audit-2 the
                    # write used ``_store_op_for_size(8)`` =
                    # ``i64.store`` which the wasm verifier rejects
                    # for an f64 operand. The symmetric load in
                    # ``_push_value``'s capture path is f64.load,
                    # so writing as f64 keeps the round-trip
                    # consistent.
                    self._write("local.get $_lam_env_tmp")
                    cap_val = Value(kind="local", name=name, ty=capa_ty)
                    self._push_value(cap_val)
                    self._write(f"f64.store offset={offset}")
                else:
                    size = self._size_of(capa_ty)
                    self._write("local.get $_lam_env_tmp")
                    cap_val = Value(kind="local", name=name, ty=capa_ty)
                    self._push_value(cap_val)
                    self._write(f"{_store_op_for_size(size)} offset={offset}")
        else:
            self._write("i32.const 0")
            self._write("local.set $_lam_env_tmp")
        # Pack closure: (fn_idx_i64 << 32) | env_ptr_i64
        self._write(f"i64.const {fn_idx}")
        self._write("i64.const 32")
        self._write("i64.shl")
        self._write("local.get $_lam_env_tmp")
        self._write("i64.extend_i32_u")
        self._write("i64.or")
        self._write(f"local.set ${instr.dst}")

    def _emit_closure_call(self, instr: Call, callee_ty: str) -> None:
        """Invoke a closure value (i64) via call_indirect. The
        closure carries fn_idx (high 32) and env_ptr (low 32).
        Push env_ptr first, then user-level args, then fn_idx;
        call_indirect with the matching ``(type $sig_N)``."""
        # Look up the lambda's signature. We don't have the exact
        # sig_idx without referencing one of the lifted lambdas;
        # take the first lambda whose result_wasm_ty + param_wasm_tys
        # match the callee's Capa type. For Phase 6E we trust the
        # IR's typing: callee_ty is "Fun(<args>) -> <result>", so
        # we parse it back to a sig key.
        sig_key = self._fun_type_to_sig_key(callee_ty)
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"closure call of type {callee_ty!r} has no matching "
                f"sig in the lifted-lambda table (key {sig_key!r})"
            )
        # Push env_ptr (first arg of the lifted lambda).
        self._push_value(Value(kind="local", name=instr.callee_name, ty=callee_ty))
        self._write("i32.wrap_i64")
        # Push the user-level args. Slices 25.2 - 25.6: Fs / Net /
        # Db / Proc / Env / Clock are un-erased and threaded as i32
        # handles; other built-in caps stay erased.
        for arg in instr.args:
            if arg.ty in BUILTIN_CAPS:
                if arg.ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    self._push_value(arg)
                continue
            if arg.ty == "String":
                self._push_string_value_as_ptr_len(arg)
            else:
                self._push_value(arg)
        # Push fn_idx (top of stack for call_indirect).
        self._push_value(Value(kind="local", name=instr.callee_name, ty=callee_ty))
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        if instr.dst is not None:
            dst_ty = self._dst_capa_ty(instr.dst)
            if (
                dst_ty
                and (
                    dst_ty not in BUILTIN_CAPS
                    or dst_ty in (
                        "Fs", "Net", "Db", "Proc", "Env", "Clock",
                    )
                )
                and dst_ty not in ("Unit",)
            ):
                if dst_ty == "String":
                    self._set_string_dst(instr.dst)
                else:
                    self._write(f"local.set ${instr.dst}")

    def _fun_type_to_sig_key(self, capa_ty: str) -> str:
        """Convert ``"Fun(Int, Int) -> Int"`` -> ``"(i32 i64 i64) -> i64"``.
        The leading i32 is for the env_ptr (always first param of
        a lifted lambda). Used at closure-call sites to find the
        matching sig_idx."""
        # Strip the leading "Fun" and outer parens.
        if not capa_ty.startswith("Fun"):
            raise WasmEmissionError(
                f"expected Fun type, got {capa_ty!r}"
            )
        rest = capa_ty[3:].strip()
        if not rest.startswith("("):
            raise WasmEmissionError(
                f"malformed Fun type {capa_ty!r}; expected ``Fun(...) -> R``"
            )
        # Find matching close paren accounting for nested parens.
        depth = 0
        close_idx = -1
        for i, ch in enumerate(rest):
            if ch == "(":
                depth += 1
            elif ch == ")":
                depth -= 1
                if depth == 0:
                    close_idx = i
                    break
        if close_idx < 0:
            raise WasmEmissionError(
                f"unbalanced parens in Fun type {capa_ty!r}"
            )
        params_str = rest[1:close_idx]
        tail = rest[close_idx + 1:].strip()
        if tail.startswith("->"):
            ret_ty_str = tail[2:].strip()
        else:
            ret_ty_str = ""
        # Each param is a Capa type; split on top-level commas.
        # Arrow-aware so a higher-order param that is itself a
        # ``Fun(...) -> R`` value does not split at the wrong comma.
        param_capa_tys: list[str] = []
        if params_str.strip():
            from .._lower_helpers import _split_top_level
            param_capa_tys = _split_top_level(params_str)
        # Build wasm sig: env_ptr + each param + result.
        wasm_params = ["i32"]
        for pt in param_capa_tys:
            if pt == "String":
                wasm_params.append("i32")
                wasm_params.append("i32")
            else:
                wasm_params.append(self._wasm_type(pt))
        # Multi-value return for String: must match the encoding
        # _register_lambda produced, otherwise sig_idx lookup
        # misses and call_indirect can't dispatch.
        if ret_ty_str == "String":
            wasm_result = "i32 i32"
        else:
            wasm_result = (
                self._wasm_type(ret_ty_str) if ret_ty_str else ""
            )
        return f"({' '.join(wasm_params)}) -> {wasm_result or '()'}"

    # ----- HOFs on List<T> --------------------------------------
    #
    # Each HOF (map / filter / fold) is parameterised by the
    # element type of the receiver and, for map / fold, by the
    # output / accumulator type. Element-type dispatch routes
    # through three small helpers:
    #
    # - ``_wasm_arg_tys_for(ty)`` returns the Wasm wire types a
    #   value of Capa type ``ty`` occupies as a closure argument
    #   (String -> two i32s; Int / pointer / Bool -> one i32/i64;
    #   Float -> one f64).
    # - ``_emit_load_elem_for_call(elem_ty)`` consumes an i32
    #   slot-address on the operand stack and leaves the
    #   ready-to-call argument(s) for that element type.
    # - ``_emit_store_closure_result(out_ty, addr_local)`` consumes
    #   the closure's return values (in stack order) and stores
    #   them into a freshly written element slot at the address
    #   held in ``$<addr_local>``.
    #
    # Pointer-shape outputs (struct / sum / List / Map / Set) and
    # ``List<Bool>`` are unsupported today: pointer-shape because
    # the new-list allocation would need an alloc-and-store that
    # closures rarely return; ``List<Bool>`` because the data
    # array stride is 4 bytes which conflicts with the 8-byte
    # stride hardcoded into the filter / fold loops. Both raise a
    # specific ``WasmEmissionError`` so users see a clear message
    # instead of a generic wasm-verifier failure.

    def _emit_list_hof(self, instr: MethodCall, elem_ty: str) -> None:
        """Emit a HOF (map / filter / fold) for a ``List<T>``
        receiver. Dispatches to the per-method emitter; each one
        consults ``elem_ty`` (and, for map / fold, the output /
        accumulator type) to pick the right load / pack /
        call_indirect shape."""
        if instr.method == "map":
            self._emit_list_map(instr, elem_ty)
            return
        if instr.method == "filter":
            self._emit_list_filter(instr, elem_ty)
            return
        if instr.method == "fold":
            self._emit_list_fold(instr, elem_ty)
            return
        if instr.method == "flat_map":
            self._emit_list_flat_map(instr, elem_ty)
            return
        raise WasmEmissionError(
            f"unhandled List HOF {instr.method!r}"
        )

    # ----- closure-sig helpers ----------------------------------

    def _wasm_arg_tys_for(self, capa_ty: str) -> list[str]:
        """Return the Wasm wire types ``capa_ty`` occupies as a
        closure-call argument. String lowers to two i32s (ptr,
        len); Float to f64; Int to i64; Bool / pointer-shape to
        i32. Unknown / Unit raise."""
        if capa_ty == "String":
            return ["i32", "i32"]
        if capa_ty == "Float":
            return ["f64"]
        if capa_ty == "Int":
            return ["i64"]
        if capa_ty == "Bool":
            return ["i32"]
        if self._is_pointer_shape_ty(capa_ty):
            return ["i32"]
        if capa_ty.startswith("Fun"):
            return ["i64"]
        raise WasmEmissionError(
            f"List HOF: cannot encode Capa type {capa_ty!r} as a "
            f"closure argument (no Wasm wire mapping)"
        )

    def _wasm_result_tys_for(self, capa_ty: str) -> list[str]:
        """Same as ``_wasm_arg_tys_for`` but for the result side.

        The one deliberate divergence from the argument mapping:
        a Unit RESULT is legal (a Unit-returning function lowers to
        a Wasm function with an empty result clause), whereas a Unit
        ARGUMENT has no wire encoding. Returning ``[]`` here yields
        the ``... -> ()`` sig key that ``_closure_sig_key_for``
        renders, matching exactly what ``_fun_type_to_sig_key``
        produces at the call site (``_wasm_type("Unit") == ""``).
        Without this the thunk-discovery pass raised on a
        Unit-returning fn-ref and silently skipped registering its
        thunk, so emit later failed to find one for ``... -> ()``."""
        if capa_ty in ("Unit", "()"):
            return []
        return self._wasm_arg_tys_for(capa_ty)

    def _closure_sig_key_for(
        self, arg_capa_tys: list[str], ret_capa_ty: str,
    ) -> str:
        """Build the sig key for a closure with the given
        non-env Capa-level argument types and result type. The
        env_ptr (i32) is always prepended."""
        wasm_params: list[str] = ["i32"]
        for at in arg_capa_tys:
            wasm_params.extend(self._wasm_arg_tys_for(at))
        result_wasm = self._wasm_result_tys_for(ret_capa_ty)
        return (
            f"({' '.join(wasm_params)}) -> "
            f"{' '.join(result_wasm) if result_wasm else '()'}"
        )

    # ----- per-element load / store helpers ---------------------

    def _emit_load_elem_for_call(self, elem_ty: str) -> None:
        """Given a slot address on the operand stack, load the
        element and leave the operand-stack shape that
        ``_wasm_arg_tys_for(elem_ty)`` describes (so the value(s)
        can be passed straight into a ``call_indirect`` after
        env_ptr / fn_idx are sandwiched around them).

        - String: i64.load -> unpack into ($_str_a_ptr,
          $_str_a_len), then push both as i32s. The pair stays
          available to the caller through the two locals.
        - Float: i64.load + f64.reinterpret_i64. The slot bytes
          ARE the IEEE-754 bit pattern (we made sure of that in
          ``_emit_make_list`` / ``_emit_list_push``), and the
          bit-reinterpret has zero cost at the wasm level.
        - Int: i64.load.
        - Bool: i32.load (the slot's low 4 bytes hold the i32).
        - pointer-shape (struct/sum/List/Map/Set/tuple): i32.load.
        """
        if elem_ty == "String":
            self._write("i64.load")
            self._emit_unpack_i64_to_string("_str_a_ptr", "_str_a_len")
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            return
        if elem_ty == "Float":
            self._write("i64.load")
            self._write("f64.reinterpret_i64")
            return
        if elem_ty == "Int":
            self._write("i64.load")
            return
        if elem_ty == "Bool":
            self._write("i32.load")
            return
        if self._is_pointer_shape_ty(elem_ty):
            self._write("i32.load")
            return
        raise WasmEmissionError(
            f"List HOF: cannot load List<{elem_ty}> element "
            f"(no Wasm load sequence)"
        )

    def _emit_store_closure_result_into_slot(
        self, out_ty: str, addr_local: str, slot_size: int = 8,
    ) -> None:
        """The closure's return value(s) are on top of the operand
        stack (in stack order per ``_wasm_result_tys_for``). Pop
        them into temporary locals if necessary, then store at the
        slot whose i32 address is in ``$<addr_local>``.

        ``slot_size`` is the on-disk stride for the destination
        list's element (4 for ``List<Bool>``, 8 otherwise). When
        the slot is 4 bytes the Bool branch must use ``i32.store``
        to avoid clobbering the next slot.

        - Int: i64.store -- bytes are the i64 directly.
        - Float: stash into ``$_alloc_tmp_f64`` (declared by the
          json branch already, or now by the HOF branch), then
          ``f64.store`` to write the IEEE-754 bytes.
        - Bool: ``i32.store`` into a 4-byte slot;
          ``i64.extend_i32_u + i64.store`` into an 8-byte slot
          (the high 4 bytes end up zero, which Bool loads on an
          8-byte slot ignore).
        - String: closure returns two i32s (ptr, len). Pop into
          ``$_str_a_ptr`` / ``$_str_a_len`` then pack as
          ``ptr | (len << 32)`` and store as i64.
        - pointer-shape: ``i32.store`` into a 4-byte slot (the
          closure result is already an i32 pointer, no extend);
          ``i64.extend_i32_u + i64.store`` into an 8-byte slot.
        """
        if out_ty == "Int":
            # Stack: [..., addr, val_i64]; flip so i64.store sees
            # (addr, val). The driver pushes addr BEFORE the call.
            self._write("i64.store")
            return
        if out_ty == "Float":
            # Stack: [..., addr, val_f64]; f64.store consumes both.
            self._write("f64.store")
            return
        if out_ty == "Bool":
            # Stack: [..., addr, val_i32]. For a 4-byte slot the
            # val is already i32-shaped and stores cleanly. For an
            # 8-byte slot we widen so the upper 4 bytes are written
            # too (otherwise alloc leftovers would leak into Bool
            # loads on the wider stride).
            if slot_size == 4:
                self._write("i32.store")
            else:
                self._write("i64.extend_i32_u")
                self._write("i64.store")
            return
        if out_ty == "String":
            # Stack: [..., addr, ptr_i32, len_i32]. Pack into i64.
            # We don't have addr available before the call to push
            # last, so the driver layout is:
            #   [addr] -> call -> [addr, ptr, len]
            # Pop (ptr, len) into the str_a locals, then push
            # ptr | (len << 32) and store.
            self._write("local.set $_str_a_len")
            self._write("local.set $_str_a_ptr")
            # The address is still on the stack as the next-to-top
            # before the call left, but the call's two results
            # landed above it. After two local.sets the stack top
            # is the original addr. Push packed i64:
            self._write("local.get $_str_a_len")
            self._write("i64.extend_i32_u")
            self._write("i64.const 32")
            self._write("i64.shl")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("drop")
            self._write("local.get $_str_a_ptr")
            self._write("i64.extend_i32_u")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.or")
            self._write("i64.store")
            return
        if self._is_pointer_shape_ty(out_ty):
            # Stack: [..., addr, val_i32]. The closure result is
            # already an i32 pointer. For a 4-byte slot store it
            # directly; for an 8-byte slot widen to i64 first so the
            # upper 4 bytes are written too (mirrors the Bool branch).
            if slot_size == 4:
                self._write("i32.store")
            else:
                self._write("i64.extend_i32_u")
                self._write("i64.store")
            return
        raise WasmEmissionError(
            f"List HOF: cannot store closure result of type "
            f"{out_ty!r} into a list slot"
        )

    def _emit_push_value_for_arg(self, v: Value, capa_ty: str) -> None:
        """Push a Value onto the operand stack with the wire
        shape ``_wasm_arg_tys_for(capa_ty)`` describes. Strings
        push as (ptr, len) two i32s; everything else routes through
        the standard ``_push_value``."""
        if capa_ty == "String":
            self._push_string_value_as_ptr_len(v)
            return
        self._push_value(v)

    def _emit_invoke_closure_inline(
        self, sig_idx: int, closure_local: str,
    ) -> None:
        """Emit the fn_idx push + call_indirect tail of a closure
        call. The env_ptr and user args must already be on the
        operand stack in the right order; this helper appends
        only the (fn_idx, call_indirect) suffix."""
        self._write(f"local.get ${closure_local}")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")

    def _hof_elem_slot_size(self, elem_ty: str) -> int:
        """Slot size on the data array for a HOF element. Delegates to
        ``_size_of`` so the HOF path and the base list path
        (make_list / push / index / for-iter) share one stride
        decision and cannot diverge: Int / Float / String / Fun are 8
        bytes, Bool and pointer-shape (struct / tuple / sum / nested
        collection, stored as a single i32 pointer) are 4 bytes."""
        return self._size_of(elem_ty)

    # ----- map --------------------------------------------------

    def _emit_list_map(self, instr: MethodCall, elem_ty: str) -> None:
        """``xs.map(f) -> List<U>``: allocate a new list of same
        length, iterate xs and store f(xs[i]) at new[i]. ``U``
        comes from the closure's declared return type, taken off
        the dst local's recorded type."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Output element type: read from the dst's List<U>.
        dst_ty = self._dst_capa_ty(dst) or "List<Int>"
        if not (dst_ty.startswith("List<") and dst_ty.endswith(">")):
            raise WasmEmissionError(
                f"List.map: dst {dst!r} has non-List type {dst_ty!r}"
            )
        out_elem_ty = dst_ty[5:-1].strip()
        sig_key = self._closure_sig_key_for([elem_ty], out_elem_ty)
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.map: no lambda registered with sig {sig_key!r} "
                f"(elem={elem_ty!r}, out={out_elem_ty!r})"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        in_stride = self._hof_elem_slot_size(elem_ty)
        out_stride = self._hof_elem_slot_size(out_elem_ty)
        # Stash xs and the closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        # len = xs.length()
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        # Allocate new list header.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        # Allocate data array = len * out_stride bytes.
        self._write("local.get $_m_tag")
        self._write(f"i32.const {out_stride}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        # Header: len, cap, data_ptr.
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_m_tag")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Iterate i = 0 .. len.
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._block_counter += 1
        loop = f"$Hmap{self._block_counter}_loop"
        exit_ = f"$Hmap{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Compute new-list slot address into $_lam_new_data so it
        # survives the closure call (the operand stack would lose
        # it otherwise: String returns are two-value). Re-read the
        # data pointer from the dst header each iteration so we
        # don't have to keep it in a scratch local -- the Bool elem
        # stash path reuses ``$_alloc_tmp`` and would clobber it.
        self._write(f"local.get ${dst}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write(f"i32.const {out_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_lam_new_data")
        # Compute xs[i] slot address and load element into closure-
        # call arg shape.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write(f"i32.const {in_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        # Push env_ptr (i32) before the slot-address consumes the
        # i32.load? No -- the load consumes the address. We need
        # the load first, then push env / args around it.
        # Concretely:
        #   compute elem_addr -> stack: [elem_addr]
        #   _emit_load_elem_for_call -> stack: [<arg wire tys>]
        # but we want the call layout [env, <args>, fn_idx]. So
        # load into temporary locals first.
        self._emit_load_elem_for_call(elem_ty)
        # The elem is now decoded into either a single value
        # (Int/Float/Bool/ptr -> i64/f64/i32) on the stack OR
        # two i32s (String). Stash before we set up the call frame.
        self._hof_stash_elem(elem_ty, prefix="_str_a")
        # Address of dst slot lives in $_lam_new_data.
        self._write("local.get $_lam_new_data")
        # env_ptr.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # Push the stashed element back.
        self._hof_push_stashed_elem(elem_ty, prefix="_str_a")
        # fn_idx + call_indirect.
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")
        # Store the result into the dst slot.
        self._emit_store_closure_result_into_slot(
            out_elem_ty, "_lam_new_data", slot_size=out_stride,
        )
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _hof_stash_elem(self, elem_ty: str, prefix: str) -> None:
        """Pop the just-loaded element off the stack into hidden
        scratch local(s) so the closure-call header (env_ptr) can
        be pushed below it without disturbing the slot address
        already there. The corresponding ``_hof_push_stashed_elem``
        re-pushes them in the same order."""
        if elem_ty == "String":
            # Already saved by _emit_unpack_i64_to_string into
            # $_str_a_ptr / $_str_a_len; the two i32s on top of the
            # stack are duplicates. Drop them.
            self._write("drop")
            self._write("drop")
            return
        if elem_ty == "Float":
            self._write("local.set $_alloc_tmp_f64")
            return
        if elem_ty == "Int":
            self._write("local.set $_alloc_tmp_i64")
            return
        if elem_ty == "Bool":
            self._write("local.set $_alloc_tmp")
            return
        # pointer-shape
        self._write("local.set $_alloc_tmp")

    def _hof_push_stashed_elem(self, elem_ty: str, prefix: str) -> None:
        if elem_ty == "String":
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            return
        if elem_ty == "Float":
            self._write("local.get $_alloc_tmp_f64")
            return
        if elem_ty == "Int":
            self._write("local.get $_alloc_tmp_i64")
            return
        if elem_ty == "Bool":
            self._write("local.get $_alloc_tmp")
            return
        self._write("local.get $_alloc_tmp")

    # ----- filter -----------------------------------------------

    def _emit_list_filter(
        self, instr: MethodCall, elem_ty: str,
    ) -> None:
        """``xs.filter(p) -> List<T>``: iterate xs, push elements
        for which the predicate returns nonzero into a fresh list
        with the same element type."""
        recv = instr.receiver
        p_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        sig_key = self._closure_sig_key_for([elem_ty], "Bool")
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.filter: no lambda registered with sig {sig_key!r}"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        elem_stride = self._hof_elem_slot_size(elem_ty)
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(p_arg)
        self._write("local.set $_lam_fn_tmp")
        # Allocate the new list (empty, cap 8).
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 8")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"i32.const {8 * elem_stride}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Iterate xs.
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        self._block_counter += 1
        loop = f"$Hfilt{self._block_counter}_loop"
        exit_ = f"$Hfilt{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Save the packed source slot bits before unpacking, so
        # the post-filter copy can re-emit the same bytes to the
        # destination list (we don't want to re-pack a String from
        # ptr/len which would lose the packed-i64 identity).
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write(f"i32.const {elem_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        # Stash the slot address so we can re-read after the
        # predicate call without recomputing.
        self._write("local.tee $_lam_new_data")
        # Load the raw slot bytes into $_alloc_tmp_i64. 4-byte-stride
        # slots (Bool and pointer-shape) are loaded as i32 then
        # widened to i64 so the downstream push / decode paths can
        # share the same scratch local; 8-byte slots load directly.
        if self._hof_elem_slot_size(elem_ty) == 4:
            self._write("i32.load")
            self._write("i64.extend_i32_u")
        else:
            self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # Build the predicate call. Push env_ptr, then the
        # decoded args, then fn_idx + call_indirect.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._hof_push_decoded_from_packed_i64(elem_ty)
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")
        self._write("if")
        self._indent += 1
        # Append: re-emit the packed slot bytes onto the new list.
        # ``_emit_inline_packed_list_push`` reads from
        # $_alloc_tmp_i64 and stores via i64.store / i32.store
        # depending on slot_size. Bool elements stride 4 bytes;
        # everything else strides 8 with identical i64 ABI.
        self._emit_inline_packed_list_push(dst, slot_size=elem_stride)
        self._indent -= 1
        self._write("end")
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    def _hof_push_decoded_from_packed_i64(self, elem_ty: str) -> None:
        """Decode an element value already saved in
        ``$_alloc_tmp_i64`` and push it onto the operand stack in
        closure-arg shape. The packed i64 is the literal slot
        contents; for Int that's the i64 directly, for Float the
        bit pattern, for String the (ptr, len) pair, for
        Bool / pointer-shape the value zero-extended."""
        if elem_ty == "String":
            self._write("local.get $_alloc_tmp_i64")
            self._emit_unpack_i64_to_string("_str_a_ptr", "_str_a_len")
            self._write("local.get $_str_a_ptr")
            self._write("local.get $_str_a_len")
            return
        if elem_ty == "Float":
            self._write("local.get $_alloc_tmp_i64")
            self._write("f64.reinterpret_i64")
            return
        if elem_ty == "Int":
            self._write("local.get $_alloc_tmp_i64")
            return
        if elem_ty == "Bool":
            # Slot is 4 bytes for Bool, but this path never runs
            # because filter bails early on Bool. Still handle for
            # safety.
            self._write("local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            return
        # pointer-shape: i64 packs the i32 pointer in low bits.
        self._write("local.get $_alloc_tmp_i64")
        self._write("i32.wrap_i64")

    def _emit_inline_packed_list_push(
        self, list_local: str, slot_size: int = 8,
    ) -> None:
        """Append the value held in ``$_alloc_tmp_i64`` to the list
        whose pointer is in ``$<list_local>``. Grows the data array
        via ``memory.copy`` when at capacity. The slot stride is 8
        for every Int / Float / String / pointer-shape element and
        4 for ``List<Bool>``; callers that know they're handling a
        4-byte element pass ``slot_size=4`` so the alloc / memcpy /
        per-slot store all collapse to half-width writes."""
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_lam_grow_len")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("local.set $_lam_grow_cap")
        self._write("local.get $_lam_grow_len")
        self._write("local.get $_lam_grow_cap")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("local.get $_lam_grow_cap")
        self._write("i32.const 2")
        self._write("i32.mul")
        self._write("local.tee $_lam_grow_cap")
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 8")
        self._write("local.set $_lam_grow_cap")
        self._indent -= 1
        self._write("end")
        self._write("local.get $_lam_grow_cap")
        self._write(f"i32.const {slot_size}")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_lam_new_data")
        self._write("local.get $_lam_new_data")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write(f"i32.const {slot_size}")
        self._write("i32.mul")
        self._write("memory.copy")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_new_data")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_cap")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._indent -= 1
        self._write("end")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write(f"i32.const {slot_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.get $_alloc_tmp_i64")
        if slot_size == 4:
            # The packed slot bits were already wrapped into the
            # low 4 bytes of $_alloc_tmp_i64 by the caller's load
            # path (i32.load + i64.extend_i32_u); narrow back to
            # i32 before the half-width store.
            self._write("i32.wrap_i64")
            self._write("i32.store")
        else:
            self._write("i64.store")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    # ----- flat_map ---------------------------------------------

    def _emit_list_flat_map(self, instr: MethodCall, elem_ty: str) -> None:
        """``xs.flat_map(f) -> List<U>``: apply ``f`` to each element
        (``f`` returns a ``List<U>``) and concatenate the resulting
        lists in order. Allocate a fresh empty result list, iterate
        ``xs``, call ``f(xs[i])`` to obtain an inner list pointer, then
        walk that inner list and append every element to the result.
        Byte-identical to the Python ``CapaList`` flat_map (in-order
        concatenation), including empty / interleaved-empty inner
        lists which contribute nothing."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        dst_ty = self._dst_capa_ty(dst) or "List<Int>"
        if not (dst_ty.startswith("List<") and dst_ty.endswith(">")):
            raise WasmEmissionError(
                f"List.flat_map: dst {dst!r} has non-List type {dst_ty!r}"
            )
        out_elem_ty = dst_ty[5:-1].strip()
        out_stride = self._hof_elem_slot_size(out_elem_ty)
        # The closure returns a List<U>, which is a pointer-shape value
        # (single i32). The sig is ``(env, <elem args>) -> i32``.
        sig_key = self._closure_sig_key_for([elem_ty], dst_ty)
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.flat_map: no lambda registered with sig "
                f"{sig_key!r} (elem={elem_ty!r}, out={dst_ty!r})"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        in_stride = self._hof_elem_slot_size(elem_ty)
        # Stash xs and the closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        # Allocate the result list (empty, cap 8).
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 8")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write(f"i32.const {8 * out_stride}")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        self._write(f"local.get ${dst}")
        self._write("local.get $_alloc_tmp")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        # Outer loop: i = 0 .. len(xs).
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._block_counter += 1
        oloop = f"$Hfmap{self._block_counter}_oloop"
        oexit = f"$Hfmap{self._block_counter}_oexit"
        iloop = f"$Hfmap{self._block_counter}_iloop"
        iexit = f"$Hfmap{self._block_counter}_iexit"
        self._write(f"block {oexit}")
        self._indent += 1
        self._write(f"loop {oloop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {oexit}")
        # Compute xs[i] slot address and decode for the closure call.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write(f"i32.const {in_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        self._emit_load_elem_for_call(elem_ty)
        self._hof_stash_elem(elem_ty, prefix="_str_a")
        # Closure call frame: env_ptr, decoded element, fn_idx.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._hof_push_stashed_elem(elem_ty, prefix="_str_a")
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")
        # The closure returned an inner List<U> pointer (i32). Stash it.
        self._write("local.set $_fmap_inner")
        # Inner loop: j = 0 .. len(inner). Append inner[j] to dst.
        self._write("local.get $_fmap_inner")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_fmap_n")
        self._write("i32.const 0")
        self._write("local.set $_fmap_i")
        self._write(f"block {iexit}")
        self._indent += 1
        self._write(f"loop {iloop}")
        self._indent += 1
        self._write("local.get $_fmap_i")
        self._write("local.get $_fmap_n")
        self._write("i32.ge_s")
        self._write(f"br_if {iexit}")
        # Load inner[j] raw slot bits into $_alloc_tmp_i64 (shape-
        # agnostic: 4-byte slots widen to i64, 8-byte load directly),
        # then append via the shared grow-push helper.
        self._write("local.get $_fmap_inner")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_fmap_i")
        self._write(f"i32.const {out_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        if out_stride == 4:
            self._write("i32.load")
            self._write("i64.extend_i32_u")
        else:
            self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        self._emit_inline_packed_list_push(dst, slot_size=out_stride)
        # j++.
        self._write("local.get $_fmap_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_fmap_i")
        self._write(f"br {iloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # i++.
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {oloop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")

    # ----- fold -------------------------------------------------

    def _emit_list_fold(
        self, instr: MethodCall, elem_ty: str,
    ) -> None:
        """``xs.fold(init, f) -> U``: start with init (type U),
        apply f(acc, x) per element, bind dst to the final acc.
        U comes from the dst local's declared type; the closure's
        sig is ``(env, U_args, T_args) -> U_results``."""
        recv = instr.receiver
        init_arg = instr.args[0]
        f_arg = instr.args[1]
        dst = instr.dst
        if dst is None:
            return
        acc_ty = self._dst_capa_ty(dst) or "Int"
        sig_key = self._closure_sig_key_for([acc_ty, elem_ty], acc_ty)
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.fold: no lambda registered with sig {sig_key!r} "
                f"(acc={acc_ty!r}, elem={elem_ty!r})"
            )
        sig_idx = self._closure_sig_keys[sig_key]
        elem_stride = self._hof_elem_slot_size(elem_ty)
        # acc = init. For String this binds two locals (_ptr/_len);
        # other types bind one.
        if acc_ty == "String":
            self._push_string_value_as_ptr_len(init_arg)
            self._set_string_dst(dst)
        else:
            self._push_value(init_arg)
            self._write(f"local.set ${dst}")
        # Save xs and closure.
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(f_arg)
        self._write("local.set $_lam_fn_tmp")
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_m_tag")
        self._write("i32.const 0")
        self._write("local.set $_lam_idx")
        self._block_counter += 1
        loop = f"$Hfold{self._block_counter}_loop"
        exit_ = f"$Hfold{self._block_counter}_exit"
        self._write(f"block {exit_}")
        self._indent += 1
        self._write(f"loop {loop}")
        self._indent += 1
        self._write("local.get $_lam_idx")
        self._write("local.get $_m_tag")
        self._write("i32.ge_s")
        self._write(f"br_if {exit_}")
        # Load element into $_alloc_tmp_i64 (the packed slot bits)
        # before the call frame -- we'll decode in arg position.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write(f"i32.const {elem_stride}")
        self._write("i32.mul")
        self._write("i32.add")
        # 4-byte-stride elements (Bool and pointer-shape) occupy
        # 4-byte slots; widen to i64 so the decode helper can share
        # the scratch local. 8-byte slots load directly.
        if self._hof_elem_slot_size(elem_ty) == 4:
            self._write("i32.load")
            self._write("i64.extend_i32_u")
        else:
            self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # acc = f(env, acc, x). Push env, acc (Capa Value
        # representing the dst local with its declared type),
        # then x, then fn_idx + call.
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # Push acc.
        acc_val = Value(kind="local", name=dst, ty=acc_ty)
        self._emit_push_value_for_arg(acc_val, acc_ty)
        # Push x decoded.
        self._hof_push_decoded_from_packed_i64(elem_ty)
        # Call.
        self._emit_invoke_closure_inline(sig_idx, "_lam_fn_tmp")
        # Bind result back into the acc local.
        if acc_ty == "String":
            self._set_string_dst(dst)
        else:
            self._write(f"local.set ${dst}")
        # i++
        self._write("local.get $_lam_idx")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_lam_idx")
        self._write(f"br {loop}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
