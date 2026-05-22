"""Match-expression emission mixin.

Owns the lowering of ``match`` against sum types (the only scrutinee
kind currently supported) into a nested if-else cascade in Wasm.
The arm emitter handles variant-payload binding, including the
String packed-i64 unpack into ``${name}_ptr`` / ``${name}_len``
locals and the pointer-shaped-payload unwrap.

Depends on ``_RuntimeHelpersMixin`` and the layout/value-push
plumbing in the main ``WasmEmitter``: ``_sum_layouts``,
``_struct_layouts``, ``_current_fn``, ``_push_value``,
``_emit_instr``, ``_write``, ``_indent``.
"""

from __future__ import annotations

from .._nodes import (
    Match, MatchArm, PatVariant, PatIdent, PatLiteral, PatWildcard,
)
from ._layout import WasmEmissionError, _load_op_for_size


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
        scrut_ty = instr.scrutinee.ty
        if scrut_ty == "Bool":
            self._emit_bool_match(instr)
            return
        if scrut_ty == "String":
            self._emit_string_match(instr)
            return
        # Sum-layout lookups strip generic args: ``Option<Int>`` ->
        # ``Option``. The built-in Option / Result and user-defined
        # sums are all keyed by the bare type name.
        sum_layout = self._sum_layouts.get(scrut_ty.split("<", 1)[0])
        if sum_layout is None:
            raise WasmEmissionError(
                f"Match on scrutinee of type {scrut_ty!r}: only sum "
                f"types and Bool are supported in Phase 6C. Int / "
                f"String match lands in a later phase (or stays "
                f"statement-form via if/elif)."
            )
        scrut_local = "_m_scrut"
        tag_local = "_m_tag"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        self._write(f"local.get ${scrut_local}")
        self._write("i32.load")
        self._write(f"local.set ${tag_local}")
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
        nested if/else just like the sum-type path."""
        scrut_local = "_m_scrut"
        self._push_value(instr.scrutinee)
        self._write(f"local.set ${scrut_local}")
        opened = 0
        for arm in instr.arms:
            pat = arm.pattern
            if isinstance(pat, PatLiteral) and pat.kind == "bool":
                self._write(f"local.get ${scrut_local}")
                if not pat.value:
                    self._write("i32.eqz")
                self._write("if")
                self._indent += 1
                for sub in arm.body:
                    self._emit_instr(sub)
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
                for sub in arm.body:
                    self._emit_instr(sub)
                break
            if isinstance(pat, PatWildcard):
                for sub in arm.body:
                    self._emit_instr(sub)
                break
            raise WasmEmissionError(
                f"Bool match: pattern {type(pat).__name__} not "
                f"supported (PatLiteral / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

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
                for sub in arm.body:
                    self._emit_instr(sub)
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
                for sub in arm.body:
                    self._emit_instr(sub)
                break
            if isinstance(pat, PatWildcard):
                for sub in arm.body:
                    self._emit_instr(sub)
                break
            raise WasmEmissionError(
                f"String match: pattern {type(pat).__name__} not "
                f"supported (PatLiteral / PatIdent / PatWildcard only)"
            )
        for _ in range(opened):
            self._indent -= 1
            self._write("end")

    def _emit_match_arm(
        self, arm: MatchArm, scrut_local: str, tag_local: str,
        sum_layout: dict,
    ) -> int:
        """Emit one arm. Returns the number of new ``if`` blocks
        opened (0 for a wildcard, 1 for a variant arm). The caller
        emits matching ``end`` instructions after all arms are
        processed."""
        pat = arm.pattern
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
                        self._write(f"local.tee $_alloc_tmp_i64")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}_ptr")
                        self._write("local.get $_alloc_tmp_i64")
                        self._write("i64.const 32")
                        self._write("i64.shr_u")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}_len")
                    elif size == 8 and (
                        bind_ty.split("<", 1)[0] in self._struct_layouts
                        or bind_ty.split("<", 1)[0] in self._sum_layouts
                        or bind_ty.startswith(("List", "Map", "Set"))
                    ):
                        # Pointer-shaped payload (struct / sum /
                        # collection) stored in the uniform 8-byte
                        # slot via i64.extend; unpack with
                        # i32.wrap_i64.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"i64.load offset={offset}")
                        self._write("i32.wrap_i64")
                        self._write(f"local.set ${sub_pat.name}")
                    elif bind_ty == "Float":
                        # Float payload stored as f64 in the slot.
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"f64.load offset={offset}")
                        self._write(f"local.set ${sub_pat.name}")
                    else:
                        self._write(f"local.get ${scrut_local}")
                        self._write(f"{_load_op_for_size(size)} offset={offset}")
                        self._write(f"local.set ${sub_pat.name}")
                elif isinstance(sub_pat, PatWildcard):
                    continue
                else:
                    raise WasmEmissionError(
                        f"Phase 6C: nested pattern "
                        f"{type(sub_pat).__name__} inside variant "
                        f"payload not yet supported"
                    )
            for sub in arm.body:
                self._emit_instr(sub)
            # Cascade into the else block where the next arm lives.
            self._indent -= 1
            self._write("else")
            self._indent += 1
            return 1
        if isinstance(pat, PatWildcard):
            # Catch-all: body emits inside the current cascade
            # (which is the open ``else`` of the previous arm).
            for sub in arm.body:
                self._emit_instr(sub)
            return 0
        raise WasmEmissionError(
            f"Phase 6C: match arm pattern {type(pat).__name__} not "
            f"supported (PatVariant + PatWildcard are the current set)"
        )
