"""Typed foreign-component call emission (feature #4, F2a).

A ``Bureau.submit(net, x)`` call lowered to a :class:`ForeignCall`
crosses into a sandboxed external Wasm Component Model artifact. On the
core ``--wasm`` path it becomes a single host import call:

    (import "capa:foreign/<component>" "<method>"
        (func $foreign_<component>_<method> (param ...) (result ...)))

The parent guest pushes each capability argument's i32 handle plus each
scalar argument and calls the import. The host closure (see
``capa.runtime._wasm_host`` + ``capa.runtime._foreign``) resolves the
handles to the caller's pre-attenuated caps, instantiates the child
component with a RESTRICTED linker that binds ONLY those caps, calls the
child's scalar export, and marshals the scalar result back.

F2a was SCALAR-only. F2b (this increment) adds the STRING crossing type
reusing the same canonical-ABI machinery the WASI cap methods already
use: a String ARGUMENT crosses as a (ptr, len) i32 pair pushed straight
from the value's linear-memory bytes; a String RESULT crosses through an
8-byte indirect return area the host writes (ptr, len) into via
``$alloc``, then the parent materialises a Capa String from it (the
shared ``string`` materialiser). A capability param still crosses as its
i32 handle. An AGGREGATE crossing type still needs a general host-side
Capa-heap reader/writer that does not yet exist and is rejected earlier
(the CLI's aggregate guard), so nothing here handles records / lists.
"""

from __future__ import annotations

from .._nodes import ForeignCall, Module
from .._walk import walk_module
from ...foreign import SCALAR_CROSSING_WASM, is_string_crossing_type
from ._layout import WasmEmissionError


# Scalar / String roots the foreign-call return handling recognises. Any
# other non-Unit return type is a FLAT scalar-leaf AGGREGATE (feature #4
# F2c-1): a struct name, ``List<...>``, a tuple ``(...)``, ``Option<...>``
# or ``Result<...>``. Those cross the return leg through an indirect
# ret-area pointer (the host writes the Capa heap record and stores its
# pointer into the area, like F2b's String return).
_SCALAR_OR_STRING_ROOTS = frozenset({"Int", "Bool", "Float", "String"})


def _is_aggregate_crossing(return_type: str) -> bool:
    """True when a foreign-call ``return_type`` is a FLAT scalar-leaf
    aggregate (F2c-1) rather than Unit / a scalar / String."""
    return return_type not in ("Unit",) and return_type not in _SCALAR_OR_STRING_ROOTS


def _foreign_param_wasm_types(kind: str, root: str) -> list[str]:
    """The core-wasm value type(s) for one foreign-call parameter: a
    capability crosses as an i32 handle; a scalar crosses as its single
    wasm type (i64 / i32 / f64); a String crosses as a (ptr, len) i32
    pair (F2b); a FLAT aggregate crosses as a single i32 heap pointer
    (F2c-1)."""
    if kind == "cap":
        return ["i32"]
    if kind == "aggregate":
        return ["i32"]
    if is_string_crossing_type(root):
        return ["i32", "i32"]
    wt = SCALAR_CROSSING_WASM.get(root)
    if wt is None:
        # Defensive: the CLI's F2c-2 guard rejects a nested aggregate
        # crossing type before codegen, so this should be unreachable.
        raise WasmEmissionError(
            f"foreign call crosses a non-marshallable type {root!r}; "
            f"nested aggregate crossing types are a further sub-phase (F2c-2)"
        )
    return [wt]


class _ForeignCallEmissionMixin:
    def _discover_foreign_calls(self, module: Module) -> None:
        """Collect the unique ``(component, method)`` foreign boundaries
        the module invokes, keyed for import emission. Each entry records
        the parameter wasm types and the result shape so the import
        declaration matches the call-site push order exactly.

        A String result forces the canonical-ABI indirect-return shape:
        the import takes a trailing i32 return-area pointer and returns
        no core result (the host writes (ptr, len) into the area)."""
        self._foreign_imports: dict[tuple[str, str], dict] = {}
        for _fn, instr in walk_module(module):
            if not isinstance(instr, ForeignCall):
                continue
            key = (instr.component, instr.method)
            if key in self._foreign_imports:
                continue
            params: list[str] = []
            for (kind, root) in instr.param_kinds:
                params.extend(_foreign_param_wasm_types(kind, root))
            result = None
            string_return = is_string_crossing_type(instr.return_type)
            aggregate_return = _is_aggregate_crossing(instr.return_type)
            if string_return or aggregate_return:
                # Indirect return: trailing i32 ret-area pointer, void. For
                # a String the area holds (ptr, len); for a FLAT aggregate
                # it holds the Capa heap-record pointer the host wrote.
                params.append("i32")
            elif instr.return_type != "Unit":
                result = SCALAR_CROSSING_WASM.get(instr.return_type)
                if result is None:
                    raise WasmEmissionError(
                        f"foreign call {instr.component}.{instr.method} "
                        f"returns a non-marshallable type "
                        f"{instr.return_type!r}; nested aggregate returns "
                        f"are a further sub-phase (F2c-2)"
                    )
            self._foreign_imports[key] = {
                "params": params,
                "result": result,
                "artifact": instr.artifact,
            }

    def _emit_foreign_imports(self) -> None:
        """Emit one ``(import "capa:foreign/<comp>" "<method>" ...)`` per
        discovered foreign boundary. The host defines the matching import
        before instantiating this core module (see
        ``WasmHost.register_foreign_methods``)."""
        for (comp, method), info in sorted(
            getattr(self, "_foreign_imports", {}).items()
        ):
            params_str = " ".join(f"(param {t})" for t in info["params"])
            result_str = (
                f" (result {info['result']})" if info["result"] else ""
            )
            head = params_str + result_str
            self._write(
                f'(import "capa:foreign/{comp}" "{method}" '
                f'(func $foreign_{comp}_{method}'
                f'{(" " + head) if head else ""}))'
            )

    def _emit_foreign_call(self, instr: ForeignCall) -> None:
        """Push each argument in declared order and call the foreign
        import, binding the result. A capability argument's operand is
        the guest's i32 cap handle (a ``local.get`` of the cap param); a
        scalar pushes its single value; a String pushes its (ptr, len)
        pair straight from linear memory (F2b, via ``_push_string_arg``).
        The host closure resolves the handles on the caller's table and
        IGNORES whatever the child later passes, so nothing crosses that
        the child could forge or widen.

        A String result uses the canonical-ABI indirect return: allocate
        an 8-byte return area, pass its pointer as the trailing arg, call
        the (void) import, then materialise a Capa String from the
        (ptr, len) the host wrote (the shared ``string`` materialiser)."""
        string_return = is_string_crossing_type(instr.return_type)
        aggregate_return = _is_aggregate_crossing(instr.return_type)
        # Push arguments, expanding a String arg to (ptr, len). A cap arg
        # and a FLAT aggregate arg each push a single i32 (the cap handle /
        # the Capa heap-record pointer). Zip with param_kinds (same
        # declared order) so each operand pushes with the right shape.
        for arg, (kind, root) in zip(instr.args, instr.param_kinds):
            if kind not in ("cap", "aggregate") and is_string_crossing_type(root):
                self._push_string_arg(arg)
            else:
                self._push_value(arg)
        if string_return:
            # Allocate the 8-byte indirect return area (ptr@0, len@4),
            # stash it in $_ret_area, push as the trailing import arg,
            # call (void), then materialise the Capa String.
            self._write("i32.const 8")
            self._write("call $alloc")
            self._write("local.tee $_ret_area")
            self._write(f"call $foreign_{instr.component}_{instr.method}")
            self._emit_cap_indirect_materialise("string", instr.dst)
            return
        if aggregate_return:
            # Allocate a 4-byte indirect return area holding the Capa
            # heap-record pointer the host writes, push it as the trailing
            # import arg, call (void), then load the pointer into dst.
            self._write("i32.const 4")
            self._write("call $alloc")
            self._write("local.tee $_ret_area")
            self._write(f"call $foreign_{instr.component}_{instr.method}")
            self._emit_cap_indirect_materialise("aggregate_ptr", instr.dst)
            return
        self._write(f"call $foreign_{instr.component}_{instr.method}")
        if instr.return_type == "Unit":
            # No result on the stack; nothing to bind or drop.
            return
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")
        else:
            # Scalar result evaluated purely for effect: drop it.
            self._write("drop")
