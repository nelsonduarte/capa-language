"""Match-expression emission mixin.

Owns the lowering of ``match`` against sum types (the only scrutinee
kind currently supported) into a nested if-else cascade in Wasm.
The arm emitter handles variant-payload binding, including the
String packed-i64 unpack into ``${name}_ptr`` / ``${name}_len``
locals and the pointer-shaped-payload unwrap.

When any arm carries a ``guard`` (the ``case PAT if EXPR:`` shape
in source), the emitter switches to a flat-block-with-labeled-exit
strategy: every arm's pattern-check + guard-check is a NESTED if;
a failed guard falls through to the next arm naturally, and a
matched arm escapes via ``br $match_done<N>`` to the surrounding
block. Guard-free matches keep the legacy nested cascade to
avoid regressing the existing test corpus.

Depends on ``_RuntimeHelpersMixin`` and the layout/value-push
plumbing in the main ``WasmEmitter``: ``_sum_layouts``,
``_struct_layouts``, ``_current_fn``, ``_push_value``,
``_emit_instr``, ``_write``, ``_indent``.
"""

from __future__ import annotations

from .._nodes import (
    Match, MatchArm, PatVariant, PatIdent, PatLiteral, PatWildcard, PatTuple,
)
from .._lower_pattern import PatOr, PatStruct
from ._layout import (
    WasmEmissionError,
    _OPTION_LAYOUT, _RESULT_LAYOUT,
    _load_op_for_size,
)


def _match_has_guards(instr: Match) -> bool:
    """True iff any arm in ``instr`` carries a non-None guard.
    Selects between the legacy nested-cascade path (no guards)
    and the flat-block-with-labeled-exit path (at least one
    guard)."""
    return any(arm.guard is not None for arm in instr.arms)


class _MatchEmissionMixin:
    def _emit_match(self, instr: Match) -> None:
        """Lower a sum-type match. The scrutinee is an i32 pointer;
        we load the discriminant from offset 0 and dispatch via a
        nested if-else chain (one level per arm), extracting each
        variant's payload into the arm-bound local before running
        the arm body. Phase 6C does not yet emit ``br_table`` for
        dense discriminants -- nested ``if`` is correct and easier
        to read in WAT dumps; an optimisation phase can switch to
        ``br_table`` when contiguous tags warrant it.

        Reuses ``$_m_scrut`` and ``$_m_tag`` locals declared at the
        top of the enclosing function; nested matches are safe
        because each Match consumes the locals before recursing
        into arm bodies.
        """
        # Use the effective type so a ``match self`` inside an impl
        # method resolves to the impl's owning (possibly monomorphised)
        # type via fn.locals rather than the lowerer's ``Unknown``.
        scrut_ty = self._effective_value_ty(instr.scrutinee) or instr.scrutinee.ty
        if scrut_ty == "Bool":
            self._emit_bool_match(instr)
            return
        if scrut_ty == "String":
            self._emit_string_match(instr)
            return
        if scrut_ty == "Int":
            self._emit_int_match(instr)
            return
        if scrut_ty == "Float":
            self._emit_float_match(instr)
            return
        # Tuple scrutinee: ``match pair; (a, b) -> ...``. The
        # scrutinee is an i32 pointer to a tuple heap record (16
        # bytes for arity 2); each arm's pattern is either a
        # PatTuple of matching arity, an identifier that binds the
        # whole tuple, or a wildcard.
        if (scrut_ty.startswith("(") and scrut_ty.endswith(")")
                and scrut_ty != "()"):
            self._emit_tuple_match(instr, scrut_ty)
            return
        # Struct scrutinee: ``match p; P { x: 0, y } -> ...``. The
        # scrutinee is an i32 pointer to a struct heap record; each
        # arm destructures named fields via the struct layout offsets.
        from ._layout import _strip_type_qualifiers
        struct_head = _strip_type_qualifiers(scrut_ty)
        if struct_head in self._struct_layouts:
            self._emit_struct_match(instr, struct_head)
            return
        # Sum-layout lookups strip generic args: ``Option<Int>`` ->
        # ``Option``. The built-in Option / Result and user-defined
        # sums are all keyed by the bare type name.
        sum_layout = self._sum_layouts.get(scrut_ty.split("<", 1)[0])
        if sum_layout is None:
            raise WasmEmissionError(
                f"Match on scrutinee of type {scrut_ty!r}: only sum "
                f"types, Bool, String, and tuples are supported. "
                f"Int match lands in a later phase (or stays "
                f"statement-form via if/elif)."
            )
        scrut_local = "_m_scrut"
        tag_local = "_m_tag"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        self._write(f"local.get ${scrut_local}")
        self._write("i32.load")
        self._write(f"local.set ${tag_local}")
        if _match_has_guards(instr):
            self._emit_sum_match_with_guards(
                instr, scrut_local, tag_local, sum_layout,
            )
            return
        # Emit arms as a nested if/else chain. Track how many
        # ``if`` statements we open so we can close them all at the
        # end. ``else`` blocks open implicitly when we cascade.
        opened = 0
        for arm in instr.arms:
            opened += self._emit_match_arm(arm, scrut_local, tag_local, sum_layout)
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_bool_match(self, instr: Match) -> None:
        """Lower a Bool-scrutinee match. The scrutinee is an i32
        (0/1); each arm pattern is ``PatLiteral(kind="bool")`` (with
        value True/False), ``PatWildcard``, or ``PatIdent`` (binds
        the scrutinee unconditionally). The arms cascade through
        nested if/else just like the sum-type path. When any arm
        carries a guard we switch to the flat-block-with-labeled
        -exit form so a failed guard falls through to the next
        arm naturally."""
        scrut_local = "_m_scrut"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        if _match_has_guards(instr):
            self._emit_bool_match_with_guards(instr, scrut_local)
            return
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatLiteral) and pat.kind == "bool":
                self._write(f"local.get ${scrut_local}")
                if not pat.value:
                    self._write("i32.eqz")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatIdent):
                # Catch-all that binds the scrutinee to a name. Bind
                # then run the body inline; subsequent arms are dead
                # but the IR/analyzer guarantees this is the last arm
                # in practice.
                self._write(f"local.get ${scrut_local}")
                self._write(f"local.set ${pat.name}")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"Bool match: pattern {type(pat).__name__} not "
                f"supported (PatLiteral / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_int_match(self, instr: Match) -> None:
        """Lower an Int-scrutinee match. The scrutinee is an i64;
        each arm pattern is ``PatLiteral(kind="int")`` (compare the
        scrutinee against the literal via ``i64.eq``), ``PatIdent``
        (catch-all that binds the scrutinee to a name), or
        ``PatWildcard`` (catch-all that ignores the value). The arms
        cascade through nested if/else exactly like the Bool path,
        but - like the String path - over an arbitrary number of
        literal arms (Bool maxes out at two distinct values, Int
        does not). The analyzer guarantees a default (ident/wildcard)
        arm is present, so the cascade always terminates.

        The i64 scrutinee is stashed in the dedicated ``$_m_scrut_i64``
        local; the shared ``$_m_scrut`` is i32 and cannot hold it.
        When any arm carries a guard we switch to the flat-block
        -with-labeled-exit form so a failed guard falls through to
        the next arm naturally.

        Expression-form (``let x = match n ...``) and statement-form
        both work without special-casing here: the lowering already
        appends the assignment to the result local at the tail of
        each arm body, so emitting the arm bodies verbatim is
        sufficient."""
        scrut_local = "_m_scrut_i64"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        if _match_has_guards(instr):
            self._emit_int_match_with_guards(instr, scrut_local)
            return
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatOr):
                # ``1 | 2 -> body``: fire when the scrutinee equals
                # any alternative. Predicate ORs the per-literal
                # i64.eq checks; binding-free by construction.
                self._emit_scalar_or_predicate(pat, scrut_local, "i64")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatLiteral) and pat.kind in ("int", "char"):
                # Compare scrutinee against the literal. ``int()`` is
                # defensive: lowering stores the literal as a Python
                # int already, but a stray str would otherwise emit a
                # malformed ``i64.const``. Negative literals are
                # valid (``i64.const -1``). A Char literal lowers to
                # ``kind="char"`` carrying its Unicode code point, so
                # the same i64.eq scalar comparison applies (a Char is
                # an integer code point at runtime).
                self._write(f"local.get ${scrut_local}")
                self._write(f"i64.const {int(pat.value)}")
                self._write("i64.eq")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatIdent):
                # Catch-all that binds the scrutinee to a name. Bind
                # then run the body inline; subsequent arms are dead
                # but the IR/analyzer guarantees this is the last arm
                # in practice.
                self._write(f"local.get ${scrut_local}")
                self._write(f"local.set ${pat.name}")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"Int match: pattern {type(pat).__name__} not "
                f"supported; literal / identifier / wildcard only"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_float_match(self, instr: Match) -> None:
        """Lower a Float-scrutinee match. The scrutinee is an f64;
        each arm pattern is ``PatLiteral(kind="float")`` (compare the
        scrutinee against the literal via ``f64.eq``, matching
        Python's ``==`` semantics exactly, including NaN never
        comparing equal), ``PatIdent`` (catch-all that binds the
        scrutinee to a name), or ``PatWildcard`` (catch-all that
        ignores the value). Structurally identical to the Int path
        but over f64; the scrutinee lives in the dedicated
        ``$_m_scrut_f64`` local (the i32 / i64 scratch cannot hold an
        f64). The analyzer guarantees a default arm so the cascade
        always terminates."""
        scrut_local = "_m_scrut_f64"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        if _match_has_guards(instr):
            self._emit_float_match_with_guards(instr, scrut_local)
            return
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatOr):
                self._emit_scalar_or_predicate(pat, scrut_local, "f64")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatLiteral) and pat.kind == "float":
                self._write(f"local.get ${scrut_local}")
                self._write(f"f64.const {float(pat.value)}")
                self._write("f64.eq")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatIdent):
                self._write(f"local.get ${scrut_local}")
                self._write(f"local.set ${pat.name}")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"Float match: pattern {type(pat).__name__} not "
                f"supported; literal / identifier / wildcard only"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_float_match_with_guards(
        self, instr: Match, scrut_local: str,
    ) -> None:
        """Flat-block emission for a Float match where at least one
        arm carries a guard. Mirrors ``_emit_int_match_with_guards``
        but compares via ``f64.eq``; the scrutinee (f64) lives in
        ``$_m_scrut_f64``."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatOr):
                def push_predicate(p=pat):
                    self._emit_scalar_or_predicate(p, scrut_local, "f64")

                def bind_payloads():
                    return
            elif isinstance(pat, PatLiteral) and pat.kind == "float":
                def push_predicate(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"f64.const {float(p.value)}")
                    self._write("f64.eq")

                def bind_payloads():
                    return
            elif isinstance(pat, PatIdent):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"local.set ${p.name}")
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            else:
                raise WasmEmissionError(
                    f"Float match (guarded): pattern "
                    f"{type(pat).__name__} not supported; "
                    f"literal / identifier / wildcard only"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    def _emit_nested_variant_arm(
        self, arm: MatchArm, scrut_local: str, tag_local: str,
        sum_layout: dict,
    ) -> int:
        """Emit a variant arm whose payload contains a nested
        PatVariant (one level deep). Cascades into the next arm
        on mismatch like the flat case, but the if's condition
        combines outer + inner tag checks via i32.and so a
        partial match (outer tag matches, inner does not) still
        falls through to the next arm.

        Example: ``Err(Missing(name))`` against
        ``Result<Args, ArgError>``:

        - Outer tag check: result.tag == 1 (Err)
        - Eagerly extract Err's payload at offset 8 as an i32
          pointer (the ArgError), stash in $_m_scrut_inner
        - Inner tag check: argerror.tag == <Missing's tag>
        - AND the two; the arm's if takes both at once
        - In then: extract Missing's own payloads (the name
          binder) from $_m_scrut_inner
        - else cascades to the next arm

        Limitation: only one level of nesting is implemented. A
        triple-nested ``Some(Err(Missing(x)))`` would need a
        $_m_scrut_inner2 scratch and another AND clause; the
        emit code would generalise straightforwardly but no
        program in the demo set needs it."""
        pat = arm.pattern
        outer_tag, outer_payloads = sum_layout["variants"][pat.name]
        # Exactly one nested PatVariant; the analyzer guarantees
        # the payload arity matches the variant's declared shape.
        nested_idx, nested_pat = next(
            (i, p) for i, p in enumerate(pat.payloads)
            if isinstance(p, PatVariant)
        )
        outer_offset, _outer_size, outer_payload_ty = outer_payloads[nested_idx]
        # Resolve the inner sum layout. The lowerer leaves the
        # payload type as 'Any' for builtin sums (Option/Result),
        # so we look up the nested variant's owning sum via
        # _variant_to_sum.
        inner_sum_name = self._variant_to_sum.get(nested_pat.name)
        if inner_sum_name is None:
            raise WasmEmissionError(
                f"nested variant {nested_pat.name!r} has no known "
                f"parent sum; was the type declared in module.types?"
            )
        inner_sum_layout = self._sum_layouts[inner_sum_name]
        inner_tag, inner_payloads = inner_sum_layout["variants"][nested_pat.name]

        # 1. Eager extract: outer's inner-ptr payload into scratch.
        # The slot is i64-uniform (sum payloads always go via the
        # i64.extend / i64.load path); we read it back as i32.
        self._write(f"local.get ${scrut_local}")
        self._write(f"i64.load offset={outer_offset}")
        self._write("i32.wrap_i64")
        self._write("local.set $_m_scrut_inner")

        # 2. Combined tag check: outer.tag == outer_tag AND
        #    inner.tag == inner_tag.
        self._write(f"local.get ${tag_local}")
        self._write(f"i32.const {outer_tag}")
        self._write("i32.eq")
        self._write("local.get $_m_scrut_inner")
        self._write("i32.load")
        self._write(f"i32.const {inner_tag}")
        self._write("i32.eq")
        self._write("i32.and")

        # 3. Single if for the combined check; the else carries
        # the next arm's cascade.
        self._write("if")
        self._indent += 1

        # 4. Extract the inner variant's payload binders. Mirrors
        # the flat PatVariant binding code but reads from
        # $_m_scrut_inner.
        for sub_pat, (offset, size, _ty) in zip(
            nested_pat.payloads, inner_payloads,
        ):
            if isinstance(sub_pat, PatIdent):
                self._bind_variant_payload(
                    sub_pat, offset, size, _ty,
                    scrut_local_name="_m_scrut_inner",
                )
            elif isinstance(sub_pat, PatWildcard):
                continue
            else:
                raise WasmEmissionError(
                    f"Phase 6J: triple-nested pattern "
                    f"{type(sub_pat).__name__} inside "
                    f"{nested_pat.name!r}'s payload not yet "
                    f"supported (max nesting depth is 2)"
                )

        # 5. Run the arm body.
        self._emit_body(arm.body)

        # 6. Open the else cascade for the next arm.
        self._indent -= 1
        self._write("else")
        self._indent += 1
        return 1

    def _bind_variant_payload(
        self, sub_pat: PatIdent, offset: int, size: int,
        payload_ty: str, scrut_local_name: str,
    ) -> None:
        """Extract a PatIdent's payload from a scrutinee local into
        the bind's Wasm local(s). Factored out so both the flat
        variant arm path and the nested arm path can share the
        type-dispatch (String packed-i64, pointer-shaped,
        Float, scalar)."""
        bind_ty = (
            self._current_fn.locals.get(sub_pat.name, "")
            if self._current_fn else ""
        )
        if bind_ty in ("", "Unknown", "?") or bind_ty.startswith("?"):
            bind_ty = payload_ty
            if self._current_fn is not None and bind_ty != "Any":
                self._current_fn.locals[sub_pat.name] = bind_ty
        if bind_ty == "String":
            self._write(f"local.get ${scrut_local_name}")
            self._write(f"i64.load offset={offset}")
            self._emit_unpack_i64_to_string(
                f"{sub_pat.name}_ptr", f"{sub_pat.name}_len",
            )
            return
        if size == 8 and self._is_pointer_shape_ty(bind_ty):
            # Pointer-shaped payload: tuples join structs/sums/
            # collections here because their record lives on the
            # heap, with the pointer i64-extended into the variant
            # slot. ``Result<(JsonValue, Int), _>`` is the path that
            # surfaced this; without the tuple branch the load
            # produced an i64 and the assignment to the i32 tuple
            # binder tripped the Wasm validator.
            self._write(f"local.get ${scrut_local_name}")
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${sub_pat.name}")
            return
        if bind_ty == "Float":
            self._write(f"local.get ${scrut_local_name}")
            self._write(f"f64.load offset={offset}")
            self._write(f"local.set ${sub_pat.name}")
            return
        if bind_ty == "Bool" and size == 8:
            # Bool payloads live i64-extended in the uniform 8-byte
            # slot; narrow back to i32 for the local.
            self._write(f"local.get ${scrut_local_name}")
            self._write("i64.load offset=" + str(offset))
            self._write("i32.wrap_i64")
            self._write(f"local.set ${sub_pat.name}")
            return
        self._write(f"local.get ${scrut_local_name}")
        self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${sub_pat.name}")

    def _emit_string_match(self, instr: Match) -> None:
        """Lower a String-scrutinee match. Stashes the receiver
        (ptr, len) into the existing String scratch locals, then
        compares each arm's literal pattern via ``$str_eq``. Arms
        cascade through if/else like the sum-type and Bool paths.

        Supported patterns: ``PatLiteral(kind="str")``, ``PatIdent``
        (catch-all bind), ``PatWildcard``. Other patterns raise."""
        # Stash receiver into the String-scratch (ptr, len) pair.
        # Reusing _str_a_* since these only live across the match
        # body and there are no nested String methods at the same
        # level competing for the same scratch. _push_value would
        # try ``local.get $<name>`` which doesn't exist for String
        # values; use the ptr+len helper instead.
        self._push_string_value_as_ptr_len(instr.scrutinee)
        self._write("local.set $_str_a_len")
        self._write("local.set $_str_a_ptr")
        if _match_has_guards(instr):
            self._emit_string_match_with_guards(instr)
            return
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatLiteral) and pat.kind == "str":
                # Intern the pattern string, push (ptr, len) twice
                # via the existing helper, call $str_eq.
                offset, length = self._intern_string(pat.value)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
                self._write("local.get $_str_a_ptr")
                self._write("local.get $_str_a_len")
                self._write("call $str_eq")
                self._write("if")
                self._indent += 1
                self._emit_body(arm.body)
                self._indent -= 1
                self._write("else")
                self._indent += 1
                opened += 1
                continue
            if isinstance(pat, PatIdent):
                # Catch-all binding the receiver to a name. Copy the
                # (ptr, len) pair into the bind's locals so the body
                # can refer to it as a normal String local.
                self._write("local.get $_str_a_ptr")
                self._write(f"local.set ${pat.name}_ptr")
                self._write("local.get $_str_a_len")
                self._write(f"local.set ${pat.name}_len")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"String match: pattern {type(pat).__name__} not "
                f"supported (PatLiteral / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_tuple_match(self, instr: Match, scrut_ty: str) -> None:
        """Lower a tuple-scrutinee match. The scrutinee is an i32
        pointer to a tuple heap record; each arm pattern is either:

        - PatTuple of matching arity: bind / check each element.
          Sub-patterns may be PatIdent (bind the slot), PatWildcard
          (skip), or PatLiteral (compare; arm falls through to the
          next when the literal doesn't match).
        - PatIdent: catch-all that binds the whole tuple pointer.
        - PatWildcard: catch-all that ignores the value.

        Tuple patterns with arity mismatch or sub-patterns we do
        not yet support (nested PatVariant / PatTuple / PatStruct)
        raise. Bool-match-style if/else cascading handles literal
        arms; the final identifier / wildcard arm closes the
        cascade without opening a new ``if``."""
        # Local import to avoid circular dependency: _tuples.py
        # imports from this module via the WasmEmitter MRO.
        from ._tuples import _tuple_elem_types
        elem_tys = _tuple_elem_types(scrut_ty)
        arity = len(elem_tys)
        scrut_local = "_m_scrut"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        if _match_has_guards(instr):
            self._emit_tuple_match_with_guards(
                instr, scrut_ty, elem_tys, arity, scrut_local,
            )
            return
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatTuple):
                if len(pat.elements) != arity:
                    raise WasmEmissionError(
                        f"Tuple match: arm arity {len(pat.elements)} "
                        f"does not match scrutinee arity {arity} "
                        f"({scrut_ty})"
                    )
                # Literal sub-patterns produce a per-arm guard
                # condition. Build the combined condition by
                # ANDing together each literal check; bind the
                # PatIdent slots inside the if-true branch.
                literal_checks: list[tuple[int, PatLiteral]] = []
                for idx, sub in enumerate(pat.elements):
                    if isinstance(sub, PatLiteral):
                        literal_checks.append((idx, sub))
                    elif isinstance(sub, (PatIdent, PatWildcard)):
                        continue
                    else:
                        raise WasmEmissionError(
                            f"Tuple match: sub-pattern "
                            f"{type(sub).__name__} not yet supported "
                            f"(PatIdent / PatWildcard / PatLiteral "
                            f"only at the moment)"
                        )
                if literal_checks:
                    # Push each per-slot comparison, AND them all.
                    for n, (idx, lit_pat) in enumerate(literal_checks):
                        self._emit_tuple_slot_eq(
                            scrut_local, idx, elem_tys[idx], lit_pat,
                        )
                        if n > 0:
                            self._write("i32.and")
                    self._write("if")
                    self._indent += 1
                    self._emit_tuple_arm_binds(
                        scrut_local, elem_tys, pat.elements,
                    )
                    self._emit_body(arm.body)
                    self._indent -= 1
                    self._write("else")
                    self._indent += 1
                    opened += 1
                    continue
                # Catch-all tuple pattern (only PatIdent / PatWildcard
                # sub-patterns): always matches; bind, run body,
                # stop emitting further arms (they're dead).
                self._emit_tuple_arm_binds(
                    scrut_local, elem_tys, pat.elements,
                )
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatIdent):
                self._write(f"local.get ${scrut_local}")
                self._write(f"local.set ${pat.name}")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"Tuple match: pattern {type(pat).__name__} not "
                f"supported (PatTuple / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_tuple_slot_eq(
        self, scrut_local: str, idx: int, elem_ty: str,
        lit_pat: PatLiteral,
    ) -> None:
        """Push an i32 0/1 onto the stack: 1 iff tuple slot ``idx``
        equals the literal in ``lit_pat``. Uses the tuple's uniform
        8-byte slot layout (offset = idx * 8)."""
        offset = idx * 8
        if lit_pat.kind == "int":
            self._write(f"local.get ${scrut_local}")
            self._write(f"i64.load offset={offset}")
            self._write(f"i64.const {int(lit_pat.value)}")
            self._write("i64.eq")
            return
        if lit_pat.kind == "bool":
            self._write(f"local.get ${scrut_local}")
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write(f"i32.const {1 if lit_pat.value else 0}")
            self._write("i32.eq")
            return
        if lit_pat.kind == "str":
            # String slot is packed (ptr | len << 32); compare via
            # $str_eq against the literal interned in data segment.
            offset_ptr, length = self._intern_string(lit_pat.value)
            self._write(f"local.get ${scrut_local}")
            self._write(f"i64.load offset={offset}")
            self._write(f"local.tee $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write(f"i32.const {offset_ptr}")
            self._write(f"i32.const {length}")
            self._write("call $str_eq")
            return
        raise WasmEmissionError(
            f"Tuple match: literal kind {lit_pat.kind!r} not supported"
        )

    def _emit_tuple_arm_binds(
        self, scrut_local: str, elem_tys: list,
        elements: list,
    ) -> None:
        """Bind tuple slots into their PatIdent locals. Slot encoding
        mirrors ``_store_tuple_slot`` / ``_emit_tuple_index``: i64
        for Int, f64 for Float, i32 wrap for pointer-shape, packed
        i64 split for String."""
        for idx, sub in enumerate(elements):
            if not isinstance(sub, PatIdent):
                continue
            offset = idx * 8
            ty = elem_tys[idx] if idx < len(elem_tys) else "Unknown"
            head = ty.split("<", 1)[0]
            if ty == "String":
                self._write(f"local.get ${scrut_local}")
                self._write(f"i64.load offset={offset}")
                self._write("local.tee $_alloc_tmp_i64")
                self._write("i32.wrap_i64")
                self._write(f"local.set ${sub.name}_ptr")
                self._write("local.get $_alloc_tmp_i64")
                self._write("i64.const 32")
                self._write("i64.shr_u")
                self._write("i32.wrap_i64")
                self._write(f"local.set ${sub.name}_len")
                continue
            if ty == "Float":
                self._write(f"local.get ${scrut_local}")
                self._write(f"f64.load offset={offset}")
                self._write(f"local.set ${sub.name}")
                continue
            if ty == "Bool":
                self._write(f"local.get ${scrut_local}")
                self._write(f"i64.load offset={offset}")
                self._write("i32.wrap_i64")
                self._write(f"local.set ${sub.name}")
                continue
            if (head in self._struct_layouts
                    or head in self._sum_layouts
                    or ty.startswith(("List", "Map", "Set"))
                    or (ty.startswith("(") and ty.endswith(")")
                        and ty != "()")):
                self._write(f"local.get ${scrut_local}")
                self._write(f"i64.load offset={offset}")
                self._write("i32.wrap_i64")
                self._write(f"local.set ${sub.name}")
                continue
            # Default: Int / Unknown -> i64 store.
            self._write(f"local.get ${scrut_local}")
            self._write(f"i64.load offset={offset}")
            self._write(f"local.set ${sub.name}")

    def _emit_struct_match(self, instr: Match, struct_name: str) -> None:
        """Lower a struct-scrutinee match. The scrutinee is an i32
        pointer to a struct heap record; each arm is a ``PatStruct``
        that destructures named fields. Field encoding follows the
        struct layout (NON-uniform: Int = i64, Float = f64, Bool =
        i64-narrowed, String = two adjacent i32s ptr@off/len@off+4,
        pointer-shape = i32), not the uniform 8-byte tuple slot
        stride. A literal sub-pattern contributes to the arm's
        predicate; a PatIdent binds the field; PatWildcard skips; a
        nested PatStruct recurses (one level is exercised by the
        oracle, deeper nesting works by the same recursion).

        Arms cascade through if/else like the tuple path: an arm with
        literal field checks opens an ``if`` whose ``else`` carries
        the next arm; a fully-irrefutable arm (only binds / wildcards)
        binds, runs the body, and stops the cascade. The analyzer
        guarantees the arm set is exhaustive."""
        layout = self._struct_layouts[struct_name]
        scrut_local = "_m_scrut"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatStruct):
                checks = self._struct_pattern_checks(pat, layout, scrut_local)
                if checks:
                    # Refutable arm: AND the field predicates.
                    for n, emit_check in enumerate(checks):
                        emit_check()
                        if n > 0:
                            self._write("i32.and")
                    self._write("if")
                    self._indent += 1
                    self._emit_struct_pattern_binds(pat, layout, scrut_local)
                    self._emit_body(arm.body)
                    self._indent -= 1
                    self._write("else")
                    self._indent += 1
                    opened += 1
                    continue
                # Irrefutable struct arm: bind + run, cascade stops.
                self._emit_struct_pattern_binds(pat, layout, scrut_local)
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatIdent):
                self._write(f"local.get ${scrut_local}")
                self._write(f"local.set ${pat.name}")
                self._emit_body(arm.body)
                break
            if isinstance(pat, PatWildcard):
                self._emit_body(arm.body)
                break
            raise WasmEmissionError(
                f"Struct match: pattern {type(pat).__name__} not "
                f"supported (PatStruct / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _struct_pattern_checks(
        self, pat: PatStruct, layout: dict, scrut_local: str,
    ) -> list:
        """Return a list of 0-arg callables, each of which pushes an
        i32 0/1 predicate for one literal (or nested-refutable) field
        of the struct pattern. An empty list means the pattern is
        irrefutable (only binds / wildcards). PatIdent / PatWildcard
        sub-patterns contribute no check. A nested PatStruct field
        contributes its own (recursively gathered) field checks,
        loading the nested struct pointer first."""
        checks: list = []
        for fname, sub in pat.fields:
            f_info = layout["fields"].get(fname)
            if f_info is None:
                raise WasmEmissionError(
                    f"struct {pat.type_name}: field {fname!r} not "
                    f"found in layout"
                )
            offset, size, field_ty = f_info
            if isinstance(sub, (PatIdent, PatWildcard)):
                continue
            if isinstance(sub, PatLiteral):
                checks.append(self._struct_field_eq_thunk(
                    scrut_local, offset, size, field_ty, sub,
                ))
                continue
            if isinstance(sub, PatStruct):
                # Nested struct field: load its i32 pointer into the
                # shared inner scratch, then gather the nested
                # pattern's own field checks against that pointer.
                nested_layout = self._struct_layouts.get(
                    sub.type_name,
                )
                if nested_layout is None:
                    raise WasmEmissionError(
                        f"struct match: nested struct type "
                        f"{sub.type_name!r} has no known layout"
                    )

                def emit_nested(
                    off=offset, sp=sub, nl=nested_layout,
                ):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"i32.load offset={off}")
                    self._write("local.set $_m_scrut_inner")
                    inner = self._struct_pattern_checks(
                        sp, nl, "_m_scrut_inner",
                    )
                    if not inner:
                        self._write("i32.const 1")
                        return
                    for n, emit_check in enumerate(inner):
                        emit_check()
                        if n > 0:
                            self._write("i32.and")

                checks.append(emit_nested)
                continue
            raise WasmEmissionError(
                f"struct match: field {fname!r} sub-pattern "
                f"{type(sub).__name__} not supported (literal / "
                f"identifier / wildcard / nested struct only)"
            )
        return checks

    def _struct_field_eq_thunk(
        self, scrut_local: str, offset: int, size: int, field_ty: str,
        lit_pat: PatLiteral,
    ):
        """Return a 0-arg callable that pushes an i32 0/1: 1 iff the
        struct field at ``offset`` (with declared type ``field_ty``,
        ``size`` bytes) equals the literal in ``lit_pat``. Field
        encoding follows the struct layout: Int = i64, Float = f64,
        Bool = i32 (4-byte slot), String = two i32s (ptr@offset,
        len@offset+4)."""
        kind = lit_pat.kind

        def thunk():
            if kind in ("int", "char"):
                self._write(f"local.get ${scrut_local}")
                self._write(f"i64.load offset={offset}")
                self._write(f"i64.const {int(lit_pat.value)}")
                self._write("i64.eq")
                return
            if kind == "float":
                self._write(f"local.get ${scrut_local}")
                self._write(f"f64.load offset={offset}")
                self._write(f"f64.const {float(lit_pat.value)}")
                self._write("f64.eq")
                return
            if kind == "bool":
                # Bool fields occupy a 4-byte i32 slot in struct
                # layout (see _layout._STRUCT_FIELD_SIZES); load via
                # the size-appropriate op rather than assuming i64.
                self._write(f"local.get ${scrut_local}")
                self._write(f"{_load_op_for_size(size)} offset={offset}")
                if size == 8:
                    self._write("i32.wrap_i64")
                self._write(f"i32.const {1 if lit_pat.value else 0}")
                self._write("i32.eq")
                return
            if kind == "str":
                # String field: ptr@offset, len@offset+4 (two i32s).
                lit_off, length = self._intern_string(lit_pat.value)
                self._write(f"i32.const {lit_off}")
                self._write(f"i32.const {length}")
                self._write(f"local.get ${scrut_local}")
                self._write(f"i32.load offset={offset}")
                self._write(f"local.get ${scrut_local}")
                self._write(f"i32.load offset={offset + 4}")
                self._write("call $str_eq")
                return
            raise WasmEmissionError(
                f"struct match: literal kind {kind!r} not supported "
                f"for field equality"
            )

        return thunk

    def _emit_struct_pattern_binds(
        self, pat: PatStruct, layout: dict, scrut_local: str,
    ) -> None:
        """Bind the PatIdent fields of a struct pattern into their
        locals, loading each from the struct record by layout offset.
        Field encoding follows the struct layout (see
        ``_emit_field_access``): String = two i32 loads into the
        bind's (ptr, len) pair, Float = f64, Bool = i64-narrowed,
        pointer-shape = i32 (loaded directly, NOT i64-wrapped, because
        struct slots store pointer fields as a bare i32 at their
        offset), Int / scalar = sized load. Nested PatStruct fields
        recurse against the loaded inner pointer."""
        for fname, sub in pat.fields:
            offset, size, field_ty = layout["fields"][fname]
            if isinstance(sub, PatWildcard):
                continue
            if isinstance(sub, PatLiteral):
                continue
            if isinstance(sub, PatStruct):
                self._write(f"local.get ${scrut_local}")
                self._write(f"i32.load offset={offset}")
                self._write("local.set $_m_scrut_inner")
                nested_layout = self._struct_layouts[sub.type_name]
                self._emit_struct_pattern_binds(
                    sub, nested_layout, "_m_scrut_inner",
                )
                continue
            if isinstance(sub, PatIdent):
                self._bind_struct_field(sub.name, offset, size, field_ty,
                                        scrut_local)
                continue
            raise WasmEmissionError(
                f"struct match: field {fname!r} bind sub-pattern "
                f"{type(sub).__name__} not supported"
            )

    def _bind_struct_field(
        self, name: str, offset: int, size: int, field_ty: str,
        scrut_local: str,
    ) -> None:
        """Load a single struct field into the bind local(s). Mirrors
        ``_emit_field_access``'s per-type load rules so a bound field
        carries the same Wasm shape downstream code expects."""
        head = field_ty.split("<", 1)[0]
        if field_ty == "String":
            self._write(f"local.get ${scrut_local}")
            self._write(f"i32.load offset={offset}")
            self._write(f"local.set ${name}_ptr")
            self._write(f"local.get ${scrut_local}")
            self._write(f"i32.load offset={offset + 4}")
            self._write(f"local.set ${name}_len")
            return
        if field_ty == "Float":
            self._write(f"local.get ${scrut_local}")
            self._write(f"f64.load offset={offset}")
            self._write(f"local.set ${name}")
            return
        if field_ty == "Bool":
            self._write(f"local.get ${scrut_local}")
            self._write(f"{_load_op_for_size(size)} offset={offset}")
            self._write(f"local.set ${name}")
            return
        if (head in self._struct_layouts
                or head in self._sum_layouts
                or field_ty.startswith(("List", "Map", "Set"))
                or (field_ty.startswith("(") and field_ty.endswith(")")
                    and field_ty != "()")):
            # Pointer-shape field: struct slots store the i32 pointer
            # directly (see _emit_make_struct), so load it as i32.
            self._write(f"local.get ${scrut_local}")
            self._write(f"i32.load offset={offset}")
            self._write(f"local.set ${name}")
            return
        # Default Int / scalar: sized load.
        self._write(f"local.get ${scrut_local}")
        self._write(f"{_load_op_for_size(size)} offset={offset}")
        self._write(f"local.set ${name}")

    def _emit_match_arm(
        self, arm: MatchArm, scrut_local: str, tag_local: str,
        sum_layout: dict,
    ) -> int:
        """Emit one arm. Returns the number of new ``if`` blocks
        opened (0 for a wildcard, 1 for a variant arm). The caller
        emits matching ``end`` instructions after all arms are
        processed."""
        pat = arm.pattern
        # Or-pattern arm (``A | B -> body``) against a sum scrutinee:
        # the body fires when the discriminant matches ANY of the
        # alternatives' tags. Alternatives are binding-free by
        # construction (the lowerer rejects payload binders), so we
        # OR the per-alternative tag comparisons and open a single if.
        if isinstance(pat, PatOr):
            self._emit_sum_or_predicate(pat, tag_local, sum_layout)
            self._write("if")
            self._indent += 1
            if self._or_pattern_binds(pat):
                self._emit_sum_or_pattern_binds(
                    pat, tag_local, scrut_local, sum_layout,
                )
            self._emit_body(arm.body)
            self._indent -= 1
            self._write("else")
            self._indent += 1
            return 1
        # If any payload sub-pattern is itself a PatVariant, the
        # arm needs a combined two-level tag check; delegate.
        if isinstance(pat, PatVariant) and any(
            isinstance(p, PatVariant) for p in pat.payloads
        ):
            return self._emit_nested_variant_arm(
                arm, scrut_local, tag_local, sum_layout,
            )
        if isinstance(pat, PatVariant):
            tag, payload_layouts = sum_layout["variants"][pat.name]
            self._write(f"local.get ${tag_local}")
            self._write(f"i32.const {tag}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            for sub_pat, (offset, size, _ty) in zip(
                pat.payloads, payload_layouts,
            ):
                if isinstance(sub_pat, PatIdent):
                    bind_ty = (
                        self._current_fn.locals.get(sub_pat.name, "")
                        if self._current_fn else ""
                    )
                    # If the analyzer didn't propagate a precise type
                    # to the bind (Unknown / missing -- happens for
                    # builtin sum types like JsonValue where the
                    # pattern-side type inference is incomplete), fall
                    # back to the payload type declared in the sum
                    # layout. The layout always knows what the variant
                    # carries.
                    if bind_ty in ("", "Unknown", "?") or bind_ty.startswith("?"):
                        bind_ty = _ty
                        if self._current_fn is not None and bind_ty != "Any":
                            self._current_fn.locals[sub_pat.name] = bind_ty
                    if bind_ty == "String":
                        # String payload is packed into the i64
                        # slot: low 32 bits = ptr, high 32 bits =
                        # len. Unpack into the bind's (ptr, len)
                        # locals so downstream String operations
                        # work transparently.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._emit_unpack_i64_to_string(
                            f"{sub_pat.name}_ptr", f"{sub_pat.name}_len",
                        )
                    elif size == 8 and self._is_pointer_shape_ty(bind_ty):
                        # Pointer-shaped payload (struct / sum /
                        # collection / tuple) stored in the uniform
                        # 8-byte slot via i64.extend; unpack with
                        # i32.wrap_i64. Tuples surfaced this when a
                        # JSON parser used Result<(JsonValue, Int),
                        # String> as the Ok arm; the previous code
                        # fell through to the default branch and
                        # tried to store an i64 into the i32 tuple
                        # local.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}")
                    elif bind_ty == "Float":
                        # Float payload stored as f64 in the slot.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"f64.load offset={offset}")
                        self._write(f"local.set ${sub_pat.name}")
                    elif bind_ty == "Bool" and size == 8:
                        # Bool stored i64-extended; narrow back.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}")
                    else:
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"{_load_op_for_size(size)} offset={offset}")
                        self._write(f"local.set ${sub_pat.name}")
                elif isinstance(sub_pat, PatWildcard):
                    continue
                else:
                    # PatVariant is handled by _emit_nested_variant_arm
                    # via the upfront detector at the top of this
                    # method, so we only see non-variant nested
                    # patterns here.
                    raise WasmEmissionError(
                        f"Phase 6C: nested pattern "
                        f"{type(sub_pat).__name__} inside variant "
                        f"payload not yet supported"
                    )
            self._emit_body(arm.body)
            # Cascade into the else block where the next arm lives.
            self._indent -= 1
            self._write("else")
            self._indent += 1
            return 1
        if isinstance(pat, PatIdent):
            # Bare-identifier catch-all that binds the whole scrutinee
            # pointer to a name (mirrors the Int / Bool / String /
            # tuple paths). The analyzer guarantees this is the last
            # arm, so we run the body inline without opening an if and
            # stop the cascade.
            self._write(f"local.get ${scrut_local}")
            self._write(f"local.set ${pat.name}")
            self._emit_body(arm.body)
            return 0
        if isinstance(pat, PatWildcard):
            # Catch-all: body emits inside the current cascade
            # (which is the open ``else`` of the previous arm).
            self._emit_body(arm.body)
            return 0
        raise WasmEmissionError(
            f"Phase 6C: match arm pattern {type(pat).__name__} not "
            f"supported (PatVariant + PatWildcard are the current set)"
        )

    def _emit_sum_or_predicate(
        self, pat: PatOr, tag_local: str, sum_layout: dict,
    ) -> None:
        """Push an i32 0/1 predicate: 1 iff the discriminant in
        ``$tag_local`` equals ANY of the or-pattern's alternative
        variant tags. A ``PatWildcard`` alternative degenerates to a
        constant-true predicate. This emits only the predicate; any
        payload binding for binding alternatives is handled separately
        by ``_emit_sum_or_pattern_binds`` after the predicate gates
        entry (a variant alternative's payload binder is ignored
        here)."""
        emitted = 0
        for alt in pat.alternatives:
            if isinstance(alt, PatWildcard):
                self._write("i32.const 1")
            elif isinstance(alt, PatVariant):
                tag, _payloads = sum_layout["variants"][alt.name]
                self._write(f"local.get ${tag_local}")
                self._write(f"i32.const {tag}")
                self._write("i32.eq")
            else:
                raise WasmEmissionError(
                    f"or-pattern alternative {type(alt).__name__} not "
                    f"supported against a sum scrutinee (variant / "
                    f"wildcard only)"
                )
            if emitted > 0:
                self._write("i32.or")
            emitted += 1

    def _or_pattern_binds(self, pat: PatOr) -> bool:
        """True iff any alternative of ``pat`` carries a payload binder
        (a variant alternative with a ``PatIdent`` payload). A
        binding-free or-pattern (payload-less variants, wildcards) ORs
        its predicates and runs the body with nothing to bind; a
        binding or-pattern needs the runtime alternative-dispatch that
        ``_emit_sum_or_pattern_binds`` performs."""
        for alt in pat.alternatives:
            if isinstance(alt, PatVariant) and any(
                isinstance(p, PatIdent) for p in alt.payloads
            ):
                return True
        return False

    def _emit_sum_or_pattern_binds(
        self, pat: PatOr, tag_local: str, scrut_local: str,
        sum_layout: dict,
    ) -> None:
        """Populate the shared binders of a binding or-pattern. The
        OR predicate has already gated entry (one alternative's tag
        matched the scrutinee); here we discover WHICH alternative
        matched by re-checking each variant alternative's tag and,
        on the match, load its payload(s) into the shared bind
        local(s). Because the analyzer proved every alternative binds
        the same names, each branch writes the same locals; only one
        branch runs (the tags are distinct), so the binders end up
        holding the matched variant's payload. Wildcard / payload-less
        alternatives contribute no binds."""
        for alt in pat.alternatives:
            if not isinstance(alt, PatVariant):
                continue
            if not any(isinstance(p, PatIdent) for p in alt.payloads):
                continue
            tag, payload_layouts = sum_layout["variants"][alt.name]
            self._write(f"local.get ${tag_local}")
            self._write(f"i32.const {tag}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            self._emit_variant_payload_binds(alt, tuple(payload_layouts), scrut_local)
            self._indent -= 1
            self._write("end")

    def _emit_scalar_or_predicate(
        self, pat: PatOr, scrut_local: str, scalar: str,
    ) -> None:
        """Push an i32 0/1 predicate: 1 iff the scalar scrutinee in
        ``$scrut_local`` equals ANY of the or-pattern's literal
        alternatives. ``scalar`` selects the comparison opcode:
        ``"i64"`` (Int / Char code point) or ``"f64"`` (Float). A
        ``PatWildcard`` alternative degenerates to constant-true."""
        emitted = 0
        for alt in pat.alternatives:
            if isinstance(alt, PatWildcard):
                self._write("i32.const 1")
            elif isinstance(alt, PatLiteral):
                self._write(f"local.get ${scrut_local}")
                if scalar == "f64":
                    self._write(f"f64.const {float(alt.value)}")
                    self._write("f64.eq")
                else:
                    self._write(f"i64.const {int(alt.value)}")
                    self._write("i64.eq")
            else:
                raise WasmEmissionError(
                    f"or-pattern alternative {type(alt).__name__} not "
                    f"supported against a scalar scrutinee (literal / "
                    f"wildcard only)"
                )
            if emitted > 0:
                self._write("i32.or")
            emitted += 1

    # ----------------------------------------------------------------
    # Guarded match emission (flat block + br on success).
    #
    # When any arm has a ``guard``, we cannot reuse the nested
    # if/else cascade because "pattern matched but guard failed"
    # must fall through to the NEXT arm rather than skip the entire
    # match. The shape we emit is:
    #
    #     block $match_done<N>
    #       <arm0 predicate>
    #       if
    #         <arm0 guard setup>
    #         <arm0 guard value>     ;; absent: skip both lines
    #         if                     ;; absent: skip the inner if
    #           <arm0 payload binds>
    #           <arm0 body>
    #           br $match_done<N>
    #         end                    ;; only when guard was present
    #       end
    #       <arm1 predicate>
    #       if ... end
    #       ...
    #     end
    #
    # An arm whose pattern is an unconditional catch-all (bare
    # PatIdent / PatWildcard) AND has no guard still uses the
    # block-plus-br shape: the predicate pushes ``i32.const 1`` so
    # the surrounding ``if`` always fires, the body runs, and the
    # ``br`` exits the match. This costs one redundant branch per
    # such arm relative to the nested-cascade path but keeps the
    # emit code uniform; the JIT collapses the dead else trivially.
    # ----------------------------------------------------------------

    def _emit_guarded_arm(
        self, arm: MatchArm, push_predicate, bind_payloads,
        done_label: str,
    ) -> None:
        """Emit one arm in the flat-block form. ``push_predicate``
        is a 0-arg callable that pushes an i32 boolean (1 iff the
        arm's pattern matches the scrutinee). ``bind_payloads`` is
        a 0-arg callable that emits the local stores that take
        sub-pattern data out of the scrutinee record; it runs
        INSIDE the outer-if before the guard prelude so the guard
        (and the body) can both reference the bound locals.
        ``done_label`` is the surrounding block's exit label (with
        leading ``$``).

        Binding ahead of the guard rather than inside the inner-if
        lets ``Ok(n) if n > 5`` work without redundant loads; the
        cost is that a guard-failure-on-arm-N leaves the binders
        populated for one extra instruction window, which is
        harmless because (1) the locals are not pointers the GC
        scans (we have no GC), and (2) the next matching arm
        rebinds before reading."""
        push_predicate()
        self._write("if")
        self._indent += 1
        bind_payloads()
        if arm.guard is not None:
            # Guard prelude (the ANF instructions producing
            # intermediate locals the guard Value references)
            # runs as normal instructions after the pattern's
            # binders are populated; the guard Value then decides
            # whether we enter the body.
            for setup_instr in arm.guard_setup:
                self._emit_instr(setup_instr)
            self._push_value(arm.guard)
            self._write("if")
            self._indent += 1
            self._emit_body(arm.body)
            self._write(f"br {done_label}")
            self._indent -= 1
            self._write("end")
        else:
            self._emit_body(arm.body)
            self._write(f"br {done_label}")
        self._indent -= 1
        self._write("end")

    def _open_match_done_block(self) -> str:
        """Open a fresh ``block $match_done<N>`` and return the
        label (with leading ``$``). The caller closes it by
        decrementing indent and writing ``end``."""
        self._block_counter += 1
        label = f"$match_done{self._block_counter}"
        self._write(f"block {label}")
        self._indent += 1
        return label

    def _close_match_done_block(self) -> None:
        """Symmetric to ``_open_match_done_block``."""
        self._indent -= 1
        self._write("end")

    # ------- Bool-scrutinee, guard-present path -------------------

    def _emit_bool_match_with_guards(
        self, instr: Match, scrut_local: str,
    ) -> None:
        """Flat-block emission for a Bool match where at least one
        arm carries a guard. Each arm's predicate is i32.const 1
        for catch-all patterns, ``scrut == lit`` for PatLiteral."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatLiteral) and pat.kind == "bool":
                def push_predicate(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    if not p.value:
                        self._write("i32.eqz")

                def bind_payloads():
                    return  # no payloads for a Bool literal arm
            elif isinstance(pat, PatIdent):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"local.set ${p.name}")
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            else:
                raise WasmEmissionError(
                    f"Bool match (guarded): pattern "
                    f"{type(pat).__name__} not supported "
                    f"(PatLiteral / PatIdent / PatWildcard only)"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    # ------- Int-scrutinee, guard-present path --------------------

    def _emit_int_match_with_guards(
        self, instr: Match, scrut_local: str,
    ) -> None:
        """Flat-block emission for an Int match where at least one
        arm carries a guard. The scrutinee (i64) lives in
        ``$_m_scrut_i64`` (the caller already set it); each arm's
        predicate is ``scrut == lit`` (``i64.eq``) for a PatLiteral,
        or ``i32.const 1`` (always true) for a catch-all. An ident
        catch-all binds the scrutinee in ``bind_payloads`` so the
        guard and body can reference it."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatOr):
                def push_predicate(p=pat):
                    self._emit_scalar_or_predicate(p, scrut_local, "i64")

                def bind_payloads():
                    return  # or-pattern alternatives are binding-free
            elif isinstance(pat, PatLiteral) and pat.kind in ("int", "char"):
                def push_predicate(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"i64.const {int(p.value)}")
                    self._write("i64.eq")

                def bind_payloads():
                    return  # no payloads for an Int literal arm
            elif isinstance(pat, PatIdent):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"local.set ${p.name}")
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            else:
                raise WasmEmissionError(
                    f"Int match (guarded): pattern "
                    f"{type(pat).__name__} not supported; "
                    f"literal / identifier / wildcard only"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    # ------- String-scrutinee, guard-present path -----------------

    def _emit_string_match_with_guards(self, instr: Match) -> None:
        """Flat-block emission for a String match where at least
        one arm carries a guard. The receiver lives in
        ``$_str_a_ptr`` / ``$_str_a_len`` (the caller already set
        them); each arm's predicate is ``$str_eq`` against an
        interned literal, or ``i32.const 1`` for catch-alls."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatLiteral) and pat.kind == "str":
                offset, length = self._intern_string(pat.value)

                def push_predicate(o=offset, l=length):
                    self._write(f"i32.const {o}")
                    self._write(f"i32.const {l}")
                    self._write("local.get $_str_a_ptr")
                    self._write("local.get $_str_a_len")
                    self._write("call $str_eq")

                def bind_payloads():
                    return
            elif isinstance(pat, PatIdent):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write("local.get $_str_a_ptr")
                    self._write(f"local.set ${p.name}_ptr")
                    self._write("local.get $_str_a_len")
                    self._write(f"local.set ${p.name}_len")
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            else:
                raise WasmEmissionError(
                    f"String match (guarded): pattern "
                    f"{type(pat).__name__} not supported "
                    f"(PatLiteral / PatIdent / PatWildcard only)"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    # ------- Tuple-scrutinee, guard-present path ------------------

    def _emit_tuple_match_with_guards(
        self, instr: Match, scrut_ty: str, elem_tys: list,
        arity: int, scrut_local: str,
    ) -> None:
        """Flat-block emission for a tuple match where at least one
        arm carries a guard. Predicate is the AND of the per-slot
        literal comparisons (or ``i32.const 1`` when the arm has no
        literal sub-patterns); the binders for the arm's PatIdent
        sub-patterns run only on full match + guard pass."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatTuple):
                if len(pat.elements) != arity:
                    raise WasmEmissionError(
                        f"Tuple match: arm arity {len(pat.elements)} "
                        f"does not match scrutinee arity {arity} "
                        f"({scrut_ty})"
                    )
                literal_checks: list[tuple[int, PatLiteral]] = []
                for idx, sub in enumerate(pat.elements):
                    if isinstance(sub, PatLiteral):
                        literal_checks.append((idx, sub))
                    elif isinstance(sub, (PatIdent, PatWildcard)):
                        continue
                    else:
                        raise WasmEmissionError(
                            f"Tuple match (guarded): sub-pattern "
                            f"{type(sub).__name__} not yet supported "
                            f"(PatIdent / PatWildcard / PatLiteral "
                            f"only at the moment)"
                        )

                def push_predicate(
                    checks=tuple(literal_checks), e=elem_tys,
                ):
                    if not checks:
                        self._write("i32.const 1")
                        return
                    for n, (idx, lit_pat) in enumerate(checks):
                        self._emit_tuple_slot_eq(
                            scrut_local, idx, e[idx], lit_pat,
                        )
                        if n > 0:
                            self._write("i32.and")

                def bind_payloads(p=pat, e=elem_tys):
                    self._emit_tuple_arm_binds(
                        scrut_local, e, p.elements,
                    )
            elif isinstance(pat, PatIdent):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"local.set ${p.name}")
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            else:
                raise WasmEmissionError(
                    f"Tuple match (guarded): pattern "
                    f"{type(pat).__name__} not supported "
                    f"(PatTuple / PatIdent / PatWildcard only)"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    # ------- Sum-type scrutinee, guard-present path ---------------

    def _emit_sum_match_with_guards(
        self, instr: Match, scrut_local: str, tag_local: str,
        sum_layout: dict,
    ) -> None:
        """Flat-block emission for a sum-type match where at least
        one arm carries a guard. Each arm's predicate is the tag
        comparison (or a combined outer + inner tag check for
        nested-variant arms); the body binds variant payloads
        inside the inner-if-guard branch."""
        done_label = self._open_match_done_block()
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatVariant) and any(
                isinstance(p, PatVariant) for p in pat.payloads
            ):
                # Nested-variant arms with guards are a separate
                # restructure (the outer eager-extract has to land
                # AHEAD of the predicate, not inside the body). Not
                # used by any demo today; raise a precise error
                # rather than silently producing wrong code.
                if arm.guard is not None:
                    raise WasmEmissionError(
                        "nested variant pattern with arm guard "
                        "not yet supported in the Wasm backend; "
                        "rewrite as two nested matches or move "
                        "the guard condition outside"
                    )
                # No guard: emit the nested arm via the same flat
                # contract by inlining its predicate + bind here.
                self._emit_nested_variant_arm_guarded(
                    arm, scrut_local, tag_local, sum_layout,
                    done_label,
                )
                continue
            if isinstance(pat, PatOr):
                def push_predicate(p=pat):
                    self._emit_sum_or_predicate(p, tag_local, sum_layout)

                if self._or_pattern_binds(pat):
                    def bind_payloads(p=pat):
                        self._emit_sum_or_pattern_binds(
                            p, tag_local, scrut_local, sum_layout,
                        )
                else:
                    def bind_payloads():
                        return  # binding-free alternatives
            elif isinstance(pat, PatVariant):
                tag, payload_layouts = sum_layout["variants"][pat.name]

                def push_predicate(t=tag):
                    self._write(f"local.get ${tag_local}")
                    self._write(f"i32.const {t}")
                    self._write("i32.eq")

                def bind_payloads(
                    p=pat, layouts=tuple(payload_layouts),
                ):
                    self._emit_variant_payload_binds(
                        p, layouts, scrut_local,
                    )
            elif isinstance(pat, PatWildcard):
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads():
                    return
            elif isinstance(pat, PatIdent):
                # Catch-all that binds the scrutinee pointer.
                def push_predicate():
                    self._write("i32.const 1")

                def bind_payloads(p=pat):
                    self._write(f"local.get ${scrut_local}")
                    self._write(f"local.set ${p.name}")
            else:
                raise WasmEmissionError(
                    f"Sum match (guarded): pattern "
                    f"{type(pat).__name__} not supported "
                    f"(PatVariant / PatWildcard / PatIdent only)"
                )
            self._emit_guarded_arm(
                arm, push_predicate, bind_payloads, done_label,
            )
        self._close_match_done_block()

    def _emit_variant_payload_binds(
        self, pat: PatVariant, payload_layouts: tuple,
        scrut_local: str,
    ) -> None:
        """Bind a PatVariant's sub-patterns from the scrutinee
        record. Factored out of ``_emit_match_arm`` so the
        guard-present path can call it from inside the inner-if
        without dragging in the cascade-opening boilerplate."""
        for sub_pat, (offset, size, _ty) in zip(
            pat.payloads, payload_layouts,
        ):
            if isinstance(sub_pat, PatIdent):
                self._bind_variant_payload(
                    sub_pat, offset, size, _ty,
                    scrut_local_name=scrut_local,
                )
            elif isinstance(sub_pat, PatWildcard):
                continue
            else:
                raise WasmEmissionError(
                    f"Sum match (guarded): nested pattern "
                    f"{type(sub_pat).__name__} inside variant "
                    f"payload not yet supported"
                )

    def _emit_nested_variant_arm_guarded(
        self, arm: MatchArm, scrut_local: str, tag_local: str,
        sum_layout: dict, done_label: str,
    ) -> None:
        """Flat-block emission for a nested-variant arm (no guard).
        Mirrors ``_emit_nested_variant_arm`` but exits via ``br
        $match_done<N>`` instead of cascading into an else block.
        Guards on nested-variant arms are rejected at the caller."""
        pat = arm.pattern
        outer_tag, outer_payloads = sum_layout["variants"][pat.name]
        nested_idx, nested_pat = next(
            (i, p) for i, p in enumerate(pat.payloads)
            if isinstance(p, PatVariant)
        )
        outer_offset, _outer_size, _outer_payload_ty = outer_payloads[nested_idx]
        inner_sum_name = self._variant_to_sum.get(nested_pat.name)
        if inner_sum_name is None:
            raise WasmEmissionError(
                f"nested variant {nested_pat.name!r} has no known "
                f"parent sum; was the type declared in module.types?"
            )
        inner_sum_layout = self._sum_layouts[inner_sum_name]
        inner_tag, inner_payloads = inner_sum_layout["variants"][nested_pat.name]

        # Eager extract of the outer's inner-ptr payload into the
        # scratch local; must happen BEFORE the predicate so the
        # inner tag load can read from $_m_scrut_inner. This is the
        # only side effect that has to escape the if; it's safe
        # because the scratch only persists across the predicate
        # and either gets overwritten by the next arm's nested
        # extract or goes unused.
        self._write(f"local.get ${scrut_local}")
        self._write(f"i64.load offset={outer_offset}")
        self._write("i32.wrap_i64")
        self._write("local.set $_m_scrut_inner")

        def push_predicate():
            self._write(f"local.get ${tag_local}")
            self._write(f"i32.const {outer_tag}")
            self._write("i32.eq")
            self._write("local.get $_m_scrut_inner")
            self._write("i32.load")
            self._write(f"i32.const {inner_tag}")
            self._write("i32.eq")
            self._write("i32.and")

        def bind_payloads():
            for sub_pat, (offset, size, _ty) in zip(
                nested_pat.payloads, inner_payloads,
            ):
                if isinstance(sub_pat, PatIdent):
                    self._bind_variant_payload(
                        sub_pat, offset, size, _ty,
                        scrut_local_name="_m_scrut_inner",
                    )
                elif isinstance(sub_pat, PatWildcard):
                    continue
                else:
                    raise WasmEmissionError(
                        f"Phase 6J: triple-nested pattern "
                        f"{type(sub_pat).__name__} inside "
                        f"{nested_pat.name!r}'s payload not yet "
                        f"supported (max nesting depth is 2)"
                    )

        self._emit_guarded_arm(
            arm, push_predicate, bind_payloads, done_label,
        )
