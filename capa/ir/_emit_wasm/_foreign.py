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

F2a is SCALAR-only: a capability param crosses as its i32 handle, and an
ordinary crossing param / the return is Int (i64) / Bool (i32) / Float
(f64). String and aggregate crossing types need the linear-memory
canonical ABI at the parent-import boundary and are rejected earlier
(the CLI's F2b guard), so nothing here has to touch ``$alloc`` / a
return area.
"""

from __future__ import annotations

from .._nodes import ForeignCall, Module
from .._walk import walk_module
from ...foreign import SCALAR_CROSSING_WASM
from ._layout import WasmEmissionError


def _foreign_wasm_param_type(kind: str, root: str) -> str:
    """The core-wasm value type for one foreign-call parameter: a
    capability crosses as an i32 handle; a scalar crosses as its wasm
    type (i64 / i32 / f64)."""
    if kind == "cap":
        return "i32"
    wt = SCALAR_CROSSING_WASM.get(root)
    if wt is None:
        # Defensive: the CLI's F2b guard rejects a non-scalar crossing
        # type before codegen, so this should be unreachable.
        raise WasmEmissionError(
            f"foreign call crosses a non-scalar type {root!r}; "
            f"aggregate/String crossing types are feature #4 F2b"
        )
    return wt


class _ForeignCallEmissionMixin:
    def _discover_foreign_calls(self, module: Module) -> None:
        """Collect the unique ``(component, method)`` foreign boundaries
        the module invokes, keyed for import emission. Each entry records
        the parameter wasm types and the result type so the import
        declaration matches the call-site push order exactly."""
        self._foreign_imports: dict[tuple[str, str], dict] = {}
        for _fn, instr in walk_module(module):
            if not isinstance(instr, ForeignCall):
                continue
            key = (instr.component, instr.method)
            if key in self._foreign_imports:
                continue
            params = [
                _foreign_wasm_param_type(kind, root)
                for (kind, root) in instr.param_kinds
            ]
            result = None
            if instr.return_type != "Unit":
                result = SCALAR_CROSSING_WASM.get(instr.return_type)
                if result is None:
                    raise WasmEmissionError(
                        f"foreign call {instr.component}.{instr.method} "
                        f"returns a non-scalar type {instr.return_type!r}; "
                        f"aggregate/String returns are feature #4 F2b"
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
        """Push each argument (capability handle i32 or scalar) in
        declared order and call the foreign import, binding the scalar
        result. A capability argument's operand is the guest's i32 cap
        handle (a ``local.get`` of the cap param); the host closure
        resolves it on the caller's handle table and IGNORES whatever the
        child later passes, so nothing crosses that the child could forge
        or widen."""
        for arg in instr.args:
            self._push_value(arg)
        self._write(f"call $foreign_{instr.component}_{instr.method}")
        if instr.return_type == "Unit":
            # No result on the stack; nothing to bind or drop.
            return
        if instr.dst is not None:
            self._write(f"local.set ${instr.dst}")
        else:
            # Scalar result evaluated purely for effect: drop it.
            self._write("drop")
