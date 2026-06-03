"""User-defined trait + capability dispatch.

Handles ``impl Trait for Type`` and ``impl Type`` (inherent) blocks
by emitting each method as a top-level Wasm function named
``<TypeName>_<method_name>``, and routing MethodCalls on
trait-typed receivers to the matching impl method.

Phase 6J scope is **monomorphic dispatch**: a trait is dispatched
only when exactly one impl exists for it in the module. Multi-impl
traits raise a precise error at dispatch time; vtable / dynamic
dispatch is a separate phase that needs a packed (struct_ptr,
vtable_ptr) value layout. The single-impl case covers every demo
program in this repo plus the three downstream demos (each uses
``capa_log``'s ``Logger`` trait with a single ``StdioLogger``
impl).

Inherent impls (no trait) are handled identically: the methods
are emitted with the mangled name and ordinary call sites that
already produce ``Call(callee_name="<Type>_<method>", ...)`` route
to them via the standard user-call path. The trait dispatch only
fires when the receiver carries the trait type rather than the
concrete struct type.

Self typing: impl methods carry ``self`` as a param with
``ty="Unknown"`` from the lowerer (the analyzer doesn't propagate
the impl's owning type into the method's signature shape). The
emitter substitutes ``self.ty = impl.type_name`` on a synthesised
Function before calling the standard emission path; this also
populates fn.locals["self"] so downstream field-access / method-
dispatch consumers see the concrete struct type.
"""

from __future__ import annotations

from .._nodes import Function, MethodCall
from .._capa_types import BUILTIN_CAPS
from ._layout import WasmEmissionError


def _impl_method_name(type_name: str, method_name: str) -> str:
    """Mangled Wasm function name for an impl method. Matches the
    convention used everywhere in the trait module (centralised so a
    future rename only touches this helper)."""
    return f"{type_name}_{method_name}"


class _TraitEmissionMixin:
    def _setup_trait_dispatch(self, module) -> None:
        """Build the impl method dispatch tables from
        ``module.impls``. Two views over the same data:

        - ``_method_table[(receiver_type, method_name)] = mangled``
          lets the MethodCall emitter route any call (whether the
          receiver is the concrete impl type or the trait it
          implements) in one lookup.
        - ``_trait_to_impl[trait_name] = impl`` is kept as a
          back-compat view used by ``_wasm_type`` to decide that a
          trait-typed value is sized as an i32 pointer.

        Trait entries land only when the trait has exactly one
        impl in the module. Multi-impl traits leave their
        ``(Trait, method)`` entries empty; calls on a Trait
        receiver in that case raise at dispatch time. Concrete-
        type entries (``(StdioLogger, info)``) always land,
        regardless of impl-count for the trait, so direct
        self-method calls inside impl bodies dispatch
        unambiguously."""
        self._trait_to_impl: dict[str, object] = {}
        self._method_table: dict[tuple[str, str], str] = {}
        by_trait: dict[str, list] = {}
        for impl in module.impls:
            for method in impl.methods:
                mangled = _impl_method_name(impl.type_name, method.name)
                # Concrete-type entry: always populated.
                self._method_table[(impl.type_name, method.name)] = mangled
            if impl.trait_name:
                by_trait.setdefault(impl.trait_name, []).append(impl)
        for trait_name, impls in by_trait.items():
            if len(impls) == 1:
                self._trait_to_impl[trait_name] = impls[0]
                for method in impls[0].methods:
                    mangled = _impl_method_name(impls[0].type_name, method.name)
                    # Trait entry: only when impl is unique.
                    self._method_table[(trait_name, method.name)] = mangled

    def _emit_impl_methods(self, module) -> None:
        """Emit every impl block's methods as top-level Wasm
        functions. Mangled name: ``<TypeName>_<method_name>``. Each
        method's ``self`` param is retyped to the impl's owning
        struct type before emission so signature generation and
        field-access lookups see the concrete type rather than
        ``Unknown``."""
        for impl in module.impls:
            for method in impl.methods:
                self._emit_one_impl_method(impl, method)

    def _emit_one_impl_method(self, impl, method: Function) -> None:
        """Synthesise a Function with the mangled name and the
        ``self`` param retyped, then call the standard
        ``_emit_function``. We don't mutate the original method
        object so re-running emit on the same Module is
        idempotent."""
        mangled_name = _impl_method_name(impl.type_name, method.name)
        # Clone params so we don't mutate the IR module.
        new_params = []
        for p in method.params:
            if p.name == "self" and p.ty in ("", "Unknown", "?"):
                new_params.append(type(p)(
                    name=p.name,
                    ty=impl.type_name,
                    is_capability=False,
                ))
            else:
                new_params.append(p)
        # Clone locals + populate self's concrete type. The locals
        # dict is consulted by emitters that need to look up the
        # receiver type of a self.method() / self.field call.
        new_locals = dict(method.locals)
        new_locals["self"] = impl.type_name
        synth_fn = Function(
            name=mangled_name,
            params=new_params,
            return_type=method.return_type or "Unit",
            declared_caps=method.declared_caps,
            body=method.body,
            locals=new_locals,
        )
        self._emit_function(synth_fn)

    def _emit_trait_method_call(self, instr: MethodCall) -> None:
        """Route a MethodCall whose receiver is either a user-
        defined trait type (unique-impl case) or a concrete impl
        struct type. The receiver Value's runtime form is the impl
        struct's pointer (i32); we push that + each non-capability
        arg + ``call $<mangled>``. Result handling mirrors
        ``_emit_user_call`` so String multi-value returns land in
        the dst's ``_ptr`` / ``_len`` pair.

        Uses the effective receiver type (consulting fn.locals
        when v.ty is Unknown) so impl-method ``self.method()``
        calls resolve to the right concrete-type entry in the
        method table."""
        recv_ty = self._effective_value_ty(instr.receiver).split("<", 1)[0].split("[", 1)[0]
        target = self._method_table.get((recv_ty, instr.method))
        if target is None:
            # Trait with multiple impls (or no impl at all): the
            # _method_table only carries unique-impl trait entries.
            raise WasmEmissionError(
                f"MethodCall on receiver type {recv_ty!r} method "
                f"{instr.method!r}: no impl method found in this "
                f"module. If {recv_ty} is a trait with multiple "
                f"impls, vtable dispatch is not yet supported."
            )
        # Push receiver (self) -- always an i32 pointer.
        self._push_value(instr.receiver)
        # Push remaining args; capability args are erased (other
        # than Fs / Net / Db / Proc / Env / Clock, slices 25.2 -
        # 25.6 - they now carry i32 handles so a restricted cap
        # survives crossing function boundaries), String args expand
        # to (ptr, len), other args go through the regular push
        # path.
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
        self._write(f"call ${target}")
        if instr.dst is not None:
            dst_ty = self._dst_capa_ty(instr.dst)
            if dst_ty == "String":
                # Multi-value (i32 i32) return -> dst pair.
                self._write(f"local.set ${instr.dst}_len")
                self._write(f"local.set ${instr.dst}_ptr")
            elif dst_ty in (
                "Fs", "Net", "Db", "Proc", "Env", "Clock",
            ):
                # Slices 25.2 - 25.6: Fs / Net / Db / Proc / Env /
                # Clock return the handle as i32.
                self._write(f"local.set ${instr.dst}")
            elif dst_ty and dst_ty not in BUILTIN_CAPS and dst_ty != "Unit":
                self._write(f"local.set ${instr.dst}")
