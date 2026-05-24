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
from ._layout import (
    WasmEmissionError,
    _BUILTIN_CAPS,
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
        table with the lifted lambda names. The order of elem
        entries matches each lambda's ``fn_idx``."""
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
        n = len(self._lifted_lambdas)
        self._write(f"(table $fnref {n} {n} funcref)")
        names = " ".join(f"${l['name']}" for l in self._lifted_lambdas)
        self._write(f"(elem (i32.const 0) {names})")

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
        for instr in lifted["body"]:
            self._emit_instr(instr)
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
        """Walk every function's body, collect MakeLambda
        instructions, compute the env layout + signature for each
        and assign fn_idx (function table index). Also intern
        strings that appear in lambda bodies; discovery passes
        normally see the function body, but MakeLambda bodies are
        a separate Instr list.

        Lambdas inside lambdas are rejected here -- nested closure
        records would need an env-of-env shape that Phase 6E does
        not support."""

        def visit(instrs: list[Instr], parent_fn: Function, inside_lambda: bool) -> None:
            for instr in instrs:
                if isinstance(instr, MakeLambda):
                    if inside_lambda:
                        raise WasmEmissionError(
                            "Phase 6E: lambdas inside lambdas are "
                            "not supported (would need env-of-env)"
                        )
                    self._register_lambda(instr, parent_fn)
                # Discover-time string interning for the lambda body
                # has already been handled by ``_discover`` -- it
                # walks parent_fn.body and intern_strings any
                # ``lit_str`` Values it finds. MakeLambda's body is
                # NOT a child of parent_fn.body for that walk, so
                # we re-walk it here:
                if isinstance(instr, MakeLambda):
                    self._discover_instrs(instr.body)
                    visit(instr.body, parent_fn, True)
                if isinstance(instr, If):
                    visit(instr.then_body, parent_fn, inside_lambda)
                    visit(instr.else_body, parent_fn, inside_lambda)
                elif isinstance(instr, While):
                    visit(instr.cond_setup, parent_fn, inside_lambda)
                    visit(instr.body, parent_fn, inside_lambda)
                elif isinstance(instr, For):
                    visit(instr.body, parent_fn, inside_lambda)
                elif isinstance(instr, Match):
                    for arm in instr.arms:
                        visit(arm.body, parent_fn, inside_lambda)

        for fn in module.functions:
            visit(fn.body, fn, False)

    def _register_lambda(self, instr: MakeLambda, parent_fn: Function) -> None:
        """Compute captures + env layout + signature for one
        lambda; append the resulting record to ``_lifted_lambdas``
        and assign it an fn_idx."""
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
                        collect_defs(arm.body)
                        # Pattern-bound names also count as defined.
                        self._collect_pattern_names(arm.pattern, defined_in_body)

        collect_defs(instr.body)

        referenced: set[str] = set()

        def collect_refs(v: Value) -> None:
            if v.kind in ("local", "param") and v.name:
                referenced.add(v.name)

        def visit_for_refs(instrs: list[Instr]) -> None:
            for i in instrs:
                for v in self._values_of(i):
                    collect_refs(v)
                if isinstance(i, If):
                    collect_refs(i.cond)
                    visit_for_refs(i.then_body)
                    visit_for_refs(i.else_body)
                elif isinstance(i, While):
                    visit_for_refs(i.cond_setup)
                    collect_refs(i.cond)
                    visit_for_refs(i.body)
                elif isinstance(i, For):
                    collect_refs(i.iter)
                    visit_for_refs(i.body)
                elif isinstance(i, Match):
                    collect_refs(i.scrutinee)
                    for arm in i.arms:
                        visit_for_refs(arm.body)

        visit_for_refs(instr.body)

        captures_names = (referenced - defined_in_body - own_params)

        # ------- env layout -------
        env_layout: dict[str, tuple[int, str]] = {}
        offset = 0
        # Sort for deterministic layouts (helps debugging + tests).
        for name in sorted(captures_names):
            capa_ty = (
                parent_fn.locals.get(name)
                or self._params_lookup(parent_fn, name)
                or "Unknown"
            )
            if capa_ty in _BUILTIN_CAPS:
                # Capability captures are free at the Wasm level.
                continue
            size = self._size_of(capa_ty)
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

        # Copy out the body's locals from the parent function's
        # locals dict so the synthesised lifted function carries
        # precise types for ``_collect_locals``.
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
        self._lambda_by_dst[(parent_fn.name, instr.dst)] = fn_idx

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
            # Store each capture.
            for name, (offset, capa_ty) in env_layout.items():
                if capa_ty == "String":
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}_ptr")
                    self._write(f"i32.store offset={offset}")
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}_len")
                    self._write(f"i32.store offset={offset + 4}")
                else:
                    size = self._size_of(capa_ty)
                    self._write("local.get $_lam_env_tmp")
                    self._write(f"local.get ${name}")
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
        # Push the user-level args.
        for arg in instr.args:
            if arg.ty in _BUILTIN_CAPS:
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
            if dst_ty and dst_ty not in _BUILTIN_CAPS and dst_ty not in ("Unit",):
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
        param_capa_tys: list[str] = []
        if params_str.strip():
            buf = ""
            d = 0
            for ch in params_str:
                if ch in "(<":
                    d += 1
                elif ch in ")>":
                    d -= 1
                if ch == "," and d == 0:
                    param_capa_tys.append(buf.strip())
                    buf = ""
                    continue
                buf += ch
            if buf.strip():
                param_capa_tys.append(buf.strip())
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

    # ----- HOFs on List<Int> ------------------------------------

    def _emit_list_hof(self, instr: MethodCall, elem_ty: str) -> None:
        """Emit a Phase 6E HOF (map / filter / fold) for a
        ``List<Int>`` receiver. The closure argument is unpacked
        per element and invoked via ``call_indirect``.

        Phase 6E ships only List<Int>; other element types raise."""
        if elem_ty != "Int":
            raise WasmEmissionError(
                f"Phase 6E: List<{elem_ty}>.{instr.method} not supported "
                f"(only List<Int> HOFs)"
            )
        if instr.method == "map":
            self._emit_list_map(instr)
            return
        if instr.method == "filter":
            self._emit_list_filter(instr)
            return
        if instr.method == "fold":
            self._emit_list_fold(instr)
            return
        raise WasmEmissionError(
            f"unhandled List HOF {instr.method!r}"
        )

    def _emit_invoke_closure(
        self, closure_value: Value, elem_pushes: list[str],
        sig_key: str,
    ) -> None:
        """Emit the (env, args, fn_idx) push + call_indirect for a
        closure value, given pre-emitted instruction strings for
        each non-env arg in ``elem_pushes``. The closure value
        ``closure_value`` is an i64; the sig is looked up by
        ``sig_key``.

        Lower-level helper used by the HOF dispatchers."""
        sig_idx = self._closure_sig_keys.get(sig_key)
        if sig_idx is None:
            raise WasmEmissionError(
                f"no closure sig {sig_key!r} registered"
            )
        # env_ptr (low 32 bits)
        self._push_value(closure_value)
        self._write("i32.wrap_i64")
        # args
        for s in elem_pushes:
            self._write(s)
        # fn_idx (high 32 bits)
        self._push_value(closure_value)
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")

    def _emit_list_map(self, instr: MethodCall) -> None:
        """``xs.map(f) -> List<Int>``: allocate a new list of same
        length, iterate xs and store f(xs[i]) at new[i]."""
        recv = instr.receiver
        f_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 -> i64
        sig_key = "(i32 i64) -> i64"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.map: no lambda registered with sig {sig_key!r}"
            )
        # Save xs and the closure in scratch locals.
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
        # Allocate data array = len * 8 bytes.
        self._write("local.get $_m_tag")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_alloc_tmp")
        # Store len, cap, data_ptr into header.
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
        # Load xs[i] (i64 element).
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # new[i] = f(env, xs[i]); compute address first.
        self._write("local.get $_alloc_tmp")  # data_ptr
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        # Push closure call args.
        sig_idx = self._closure_sig_keys[sig_key]
        # env_ptr
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        # the element (i64)
        self._write("local.get $_alloc_tmp_i64")
        # fn_idx
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        self._write("i64.store")
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

    def _emit_list_filter(self, instr: MethodCall) -> None:
        """``xs.filter(p) -> List<Int>``: iterate xs, push elements
        where the predicate returns nonzero into a fresh list."""
        recv = instr.receiver
        p_arg = instr.args[0]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 -> i32 (Bool result)
        sig_key = "(i32 i64) -> i32"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.filter: no lambda registered with sig {sig_key!r}"
            )
        self._push_value(recv)
        self._write("local.set $_m_scrut")
        self._push_value(p_arg)
        self._write("local.set $_lam_fn_tmp")
        # New empty list with initial cap 8 -- _emit_list_push will
        # grow if needed.
        self._write(f"i32.const {_LIST_HEADER_SIZE}")
        self._write("call $alloc")
        self._write(f"local.set ${dst}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 0")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")
        self._write(f"local.get ${dst}")
        self._write("i32.const 8")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._write("i32.const 64")  # 8 * 8 bytes
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
        # Load element.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # Call predicate.
        sig_idx = self._closure_sig_keys[sig_key]
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
        # If true, append to new list. Use the existing push helper
        # inline so grow + store happens correctly.
        self._write("if")
        self._indent += 1
        # Inline list.push: stash dst into _m_scrut briefly? The
        # push helper reads from receiver via _m_scrut, which we
        # have already used for xs. To avoid clobbering, we
        # inline a minimal push here that knows about i64 elems.
        self._emit_inline_int_list_push(dst, "_alloc_tmp_i64")
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

    def _emit_inline_int_list_push(
        self, list_local: str, value_local: str,
    ) -> None:
        """Append an i64 value (in ``$<value_local>``) to the list
        whose pointer is in ``$<list_local>``. Grows the data
        array via memory.copy if at capacity. Distinct from
        ``_emit_list_push`` which expects the receiver as a Value
        and uses different scratch locals; this version reads from
        named locals so the filter loop can reuse it without
        clobbering its own scrutinee scratch."""
        # Load len, cap.
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.set $_lam_grow_len")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_CAP_OFFSET}")
        self._write("local.set $_lam_grow_cap")
        # if len >= cap, grow.
        self._write("local.get $_lam_grow_len")
        self._write("local.get $_lam_grow_cap")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        # new_cap = max(cap * 2, 8)
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
        # new_data = alloc(new_cap * 8)
        self._write("local.get $_lam_grow_cap")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("call $alloc")
        self._write("local.set $_lam_new_data")
        # memcpy(new_data, old_data, len * 8)
        self._write("local.get $_lam_new_data")
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("memory.copy")
        # store new data_ptr + cap
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_new_data")
        self._write(f"i32.store offset={_LIST_DATA_OFFSET}")
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_cap")
        self._write(f"i32.store offset={_LIST_CAP_OFFSET}")
        self._indent -= 1
        self._write("end")
        # store at data[len]
        self._write(f"local.get ${list_local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(f"local.get ${value_local}")
        self._write("i64.store")
        # len++
        self._write(f"local.get ${list_local}")
        self._write("local.get $_lam_grow_len")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write(f"i32.store offset={_LIST_LEN_OFFSET}")

    def _emit_list_fold(self, instr: MethodCall) -> None:
        """``xs.fold(init, f) -> T`` (T = Int): start with init,
        for each element apply f(acc, x), bind dst to acc."""
        recv = instr.receiver
        init_arg = instr.args[0]
        f_arg = instr.args[1]
        dst = instr.dst
        if dst is None:
            return
        # Sig: env_ptr (i32) + i64 + i64 -> i64
        sig_key = "(i32 i64 i64) -> i64"
        if sig_key not in self._closure_sig_keys:
            raise WasmEmissionError(
                f"List.fold: no lambda registered with sig {sig_key!r}"
            )
        # acc = init
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
        # Loop.
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
        # Load element.
        self._write("local.get $_m_scrut")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_lam_idx")
        self._write("i32.const 8")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("i64.load")
        self._write("local.set $_alloc_tmp_i64")
        # acc = f(env, acc, x)
        sig_idx = self._closure_sig_keys[sig_key]
        self._write("local.get $_lam_fn_tmp")
        self._write("i32.wrap_i64")
        self._write(f"local.get ${dst}")  # acc
        self._write("local.get $_alloc_tmp_i64")  # x
        self._write("local.get $_lam_fn_tmp")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")
        self._write(f"call_indirect (type $sig_{sig_idx})")
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
