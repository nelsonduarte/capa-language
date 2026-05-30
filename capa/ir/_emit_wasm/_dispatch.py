"""Per-instruction dispatcher for the Wasm emitter.

``_emit_instr`` is the central isinstance-on-IR-Instr ladder
that routes each CIR instruction to the appropriate
``_emit_*`` helper. The body grew large enough (~190 lines)
that keeping it in ``__init__.py`` alongside the class
declaration crowded both. Audit P1 split: dispatcher is its
own mixin so the orchestrator can stay slim.

The mixin assumes ``self`` has the WasmEmitter state set up by
``WasmEmitter.__init__`` plus all the per-instruction emitters
imported through the other mixins (binop, unaryop, user_call,
try_unwrap, variant_construction, make_struct, field_access,
etc.).
"""

from __future__ import annotations

from .._capa_types import BUILTIN_CAPS
from .._nodes import (
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return, TryUnwrap,
    MakeStruct, MakeList, MakeMap, MakeRange, MakeSet, MakeTuple,
    FieldAccess, Index, For,
    FormatStr, MakeLambda, Match,
)
from ._layout import WasmEmissionError


class _InstrDispatchMixin:
    def _emit_instr(self, instr: Instr) -> None:
        if isinstance(instr, AssignConst):
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in BUILTIN_CAPS:
                # Capability locals are erased at the Wasm level,
                # EXCEPT Fs / Net / Db / Proc / Env / Clock
                # (slices 25.2 - 25.6) which carry i32 handles so a
                # restricted cap survives crossing function
                # boundaries.
                if dst_ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    self._push_value(instr.src)
                    self._write(f"local.set ${instr.dst}")
                return
            if dst_ty == "String":
                self._emit_string_assign(instr.dst, instr.src)
                return
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, Reassign):
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty in BUILTIN_CAPS:
                if dst_ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    self._push_value(instr.src)
                    self._write(f"local.set ${instr.dst}")
                return
            if dst_ty == "String":
                self._emit_string_assign(instr.dst, instr.src)
                return
            self._push_value(instr.src)
            self._write(f"local.set ${instr.dst}")
            return
        if isinstance(instr, MethodCall):
            # Built-in cap dispatch: prefer instr.cap_used (set by
            # the analyzer for direct calls), but fall back to the
            # receiver type for impl-method-internal calls where
            # the analyzer doesn't propagate cap_used through.
            # Receiver type itself may be Unknown when the IR
            # Value was captured at lowering time before the
            # analyzer's type info reached it; fall back to the
            # fn.locals entry which the emitter populates for
            # impl-method ``self`` and pattern binders.
            recv_ty_pre = self._effective_value_ty(instr.receiver)
            if instr.cap_used:
                self._emit_cap_method_call(instr)
                return
            if recv_ty_pre in BUILTIN_CAPS:
                # Synthesise cap_used from the receiver type. Mutate
                # a copy so the IR module stays untouched.
                import dataclasses
                synth = dataclasses.replace(instr, cap_used=recv_ty_pre)
                self._emit_cap_method_call(synth)
                return
            # Use the effective type for downstream receiver-shape
            # dispatch so impl-method self.method() resolves cleanly.
            recv_ty = recv_ty_pre or ""
            if recv_ty.startswith("List"):
                self._emit_list_method_call(instr)
                return
            if recv_ty.startswith("Map"):
                self._emit_map_method_call(instr)
                return
            if recv_ty.startswith("Set"):
                self._emit_set_method_call(instr)
                return
            if recv_ty == "String":
                self._emit_string_method_call(instr)
                return
            if recv_ty == "JsonValue":
                self._emit_jsonvalue_method_call(instr)
                return
            if recv_ty.startswith("Option") or recv_ty.startswith("Result"):
                self._emit_option_method_call(instr)
                return
            recv_head = recv_ty.split("<", 1)[0]
            if (recv_head, instr.method) in self._method_table:
                self._emit_trait_method_call(instr)
                return
            raise WasmEmissionError(
                f"MethodCall on receiver of type {recv_ty!r} "
                f"(method {instr.method!r}) is not supported by the "
                f"Wasm backend"
            )
        if isinstance(instr, MakeStruct):
            self._emit_make_struct(instr)
            return
        if isinstance(instr, MakeList):
            self._emit_make_list(instr)
            return
        if isinstance(instr, MakeMap):
            self._emit_make_map(instr)
            return
        if isinstance(instr, MakeSet):
            self._emit_make_set(instr)
            return
        if isinstance(instr, MakeTuple):
            self._emit_make_tuple(instr)
            return
        if isinstance(instr, MakeRange):
            self._emit_make_range(instr)
            return
        if isinstance(instr, MakeLambda):
            self._emit_make_lambda(instr)
            return
        if isinstance(instr, FieldAccess):
            self._emit_field_access(instr)
            return
        if isinstance(instr, Index):
            # Tuple receivers go through the type-aware tuple
            # emitter. List receivers use the size-dispatched
            # path in _lists.
            recv_ty = self._effective_value_ty(instr.receiver)
            if self._is_tuple_ty(recv_ty):
                self._emit_tuple_index(instr)
                return
            self._emit_index(instr)
            return
        if isinstance(instr, For):
            self._emit_for(instr)
            return
        if isinstance(instr, Match):
            self._emit_match(instr)
            return
        if isinstance(instr, FormatStr):
            self._emit_format_str(instr)
            return
        if isinstance(instr, BinOp):
            self._emit_binop(instr)
            return
        if isinstance(instr, UnaryOp):
            self._emit_unaryop(instr)
            return
        if isinstance(instr, If):
            self._push_value(instr.cond)
            self._write("if")
            self._indent += 1
            for sub in instr.then_body:
                self._emit_instr(sub)
            self._indent -= 1
            if instr.else_body:
                self._write("else")
                self._indent += 1
                for sub in instr.else_body:
                    self._emit_instr(sub)
                self._indent -= 1
            self._write("end")
            return
        if isinstance(instr, While):
            # Wasm has no native while-loop; ``loop`` branches to its
            # own start, ``block`` branches to its own end. The
            # canonical encoding wraps a ``loop`` inside a ``block``:
            # ``break`` -> ``br $exit_block``; ``continue`` ->
            # ``br $loop_start``; the cond test at the top of the
            # loop dispatches falsy -> br to exit, truthy -> body.
            self._block_counter += 1
            loop_label = f"$L{self._block_counter}_loop"
            exit_label = f"$L{self._block_counter}_exit"
            self._loop_labels.append((loop_label, exit_label))
            self._write(f"block {exit_label}")
            self._indent += 1
            self._write(f"loop {loop_label}")
            self._indent += 1
            # Recompute the condition each iteration; same pattern as
            # the Python emitter's ``while True / cond_setup / break``.
            for sub in instr.cond_setup:
                self._emit_instr(sub)
            self._push_value(instr.cond)
            self._write("i32.eqz")
            self._write(f"br_if {exit_label}")
            for sub in instr.body:
                self._emit_instr(sub)
            self._write(f"br {loop_label}")
            self._indent -= 1
            self._write("end")
            self._indent -= 1
            self._write("end")
            self._loop_labels.pop()
            return
        if isinstance(instr, Break):
            if not self._loop_labels:
                raise WasmEmissionError("break outside of a loop")
            _, exit_label = self._loop_labels[-1]
            self._write(f"br {exit_label}")
            return
        if isinstance(instr, Continue):
            if not self._loop_labels:
                raise WasmEmissionError("continue outside of a loop")
            loop_label, _ = self._loop_labels[-1]
            self._write(f"br {loop_label}")
            return
        if isinstance(instr, Return):
            if instr.value is not None:
                # String returns push (ptr, len) as a pair so the
                # multi-value ``(result i32 i32)`` signature is
                # satisfied; other types push a single value.
                if instr.value.ty == "String":
                    self._push_string_value_as_ptr_len(instr.value)
                else:
                    self._push_value(instr.value)
            self._write("return")
            return
        if isinstance(instr, Call):
            self._emit_user_call(instr)
            return
        if isinstance(instr, TryUnwrap):
            self._emit_try_unwrap(instr)
            return
        raise WasmEmissionError(
            f"Phase 6A: instruction {type(instr).__name__} not supported"
        )

