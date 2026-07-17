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
from ._layout import (
    WasmEmissionError, _strip_type_qualifiers, _TYPE_ID_OFFSET,
)


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
        # Declared return type per ``(receiver_type, method_name)``,
        # keyed identically to ``_method_table``. A value-discarded
        # method call consults this to drop the exact number of result
        # slots the callee pushed (see ``_store_trait_call_result``).
        self._method_return_ty: dict[tuple[str, str], str] = {}
        # Multi-impl traits are dispatched dynamically via a type-id
        # tag stored at a UNIFORM offset (``_TYPE_ID_OFFSET`` = 4) of
        # every participating value -- struct OR sum (a small per-
        # concrete-type integer). A method call on a multi-impl-trait-
        # typed receiver loads that tag and dispatches to the matching
        # concrete impl method through an if-chain. Offset 4 is chosen
        # so the same dispatcher works for both: a sum keeps its variant
        # tag at offset 0 and payloads at offset 8, leaving offset 4
        # free, and a participating struct reserves an 8-byte header
        # whose offset-4 word is also free (fields stay at offset 8).
        # The tables below carry the data that dispatch needs:
        #
        # - ``_multi_impl_traits``: the set of trait names with >1 impl.
        # - ``_type_ids[type_name]``: the stable integer tag written at
        #   offset 4 of a participating value, used to discriminate the
        #   receiver's dynamic type at the call site.
        # - ``_header_struct_types``: concrete struct types that must
        #   reserve an 8-byte header for the type-id (they implement at
        #   least one multi-impl trait). ``compute_struct_layout`` reads
        #   this so the struct's fields start after the header.
        # - ``_header_sum_types``: concrete sum types whose constructor
        #   must additionally write the type-id at offset 4. A sum needs
        #   no layout change (offset 4 is free padding already), so this
        #   only drives the construction emitter, not the layout pass.
        # - ``_multi_impl_candidates[(trait, method)]``: the ordered
        #   list of ``(type_id, mangled_method)`` candidates the
        #   if-chain compares the loaded tag against.
        self._multi_impl_traits: set[str] = set()
        # Union of every trait name that can hold a value (single-impl
        # AND multi-impl). A trait-typed value lowers to a single i32
        # heap pointer (a concrete struct or sum), so the pointer-shape
        # predicate must treat a trait head as pointer-shaped; without
        # it the uniform-8-byte slot encoders (Option/Result payload,
        # Map value, List element, tuple component, struct field) skip
        # the i32<->i64 extend/wrap and the slot read-back type-mismatches.
        # Populated below as the single- and multi-impl tables are built.
        self._trait_value_types: set[str] = set()
        self._type_ids: dict[str, int] = {}
        self._header_struct_types: set[str] = set()
        self._header_sum_types: set[str] = set()
        self._multi_impl_candidates: dict[tuple[str, str], list] = {}
        # Per-trait structural-equality dispatch table, consumed by the
        # ``$eq_<Trait>`` helper in the equality mixin. Maps a trait name
        # to an ordered list of ``(type_id, concrete_type)`` candidates:
        #
        # - Single-impl trait: one candidate with ``type_id`` = ``None``
        #   (a single-impl concrete value carries NO type-id header, and
        #   the only possible dynamic type is that one concrete type, so
        #   the dispatcher calls its ``$eq_<Concrete>`` helper directly
        #   without a tag check).
        # - Multi-impl trait: one candidate per impl target, each with
        #   the stable ``type_id`` written at ``_TYPE_ID_OFFSET`` of a
        #   participating value, so the dispatcher can compare a's and
        #   b's tags and route to the matching concrete helper.
        self._trait_eq_candidates: dict[str, list] = {}
        by_trait: dict[str, list] = {}
        for impl in module.impls:
            for method in impl.methods:
                mangled = _impl_method_name(impl.type_name, method.name)
                # Concrete-type entry: always populated.
                self._method_table[(impl.type_name, method.name)] = mangled
                self._method_return_ty[(impl.type_name, method.name)] = (
                    method.return_type or "Unit"
                )
            if impl.trait_name:
                by_trait.setdefault(impl.trait_name, []).append(impl)
        # Assign stable per-concrete-type ids. A type that implements a
        # multi-impl trait gets a small positive integer; the ordering
        # is the impl-declaration order, which is deterministic for a
        # given module so the tag a struct is built with always matches
        # the tag the dispatcher compares against.
        next_id = 1
        for trait_name, impls in by_trait.items():
            # Every trait with at least one impl can hold a value.
            self._trait_value_types.add(trait_name)
            if len(impls) == 1:
                self._trait_to_impl[trait_name] = impls[0]
                for method in impls[0].methods:
                    mangled = _impl_method_name(impls[0].type_name, method.name)
                    # Trait entry: only when impl is unique.
                    self._method_table[(trait_name, method.name)] = mangled
                    self._method_return_ty[(trait_name, method.name)] = (
                        method.return_type or "Unit"
                    )
                # Single-impl eq dispatch: one concrete type, no type-id.
                self._trait_eq_candidates[trait_name] = [
                    (None, impls[0].type_name)
                ]
                continue
            # Multi-impl trait: register dynamic-dispatch metadata.
            self._multi_impl_traits.add(trait_name)
            # Determine the methods this trait declares (every impl
            # must supply all of them; use the first impl's method list
            # as the canonical set).
            method_names = [m.name for m in impls[0].methods]
            for method in impls[0].methods:
                self._method_return_ty[(trait_name, method.name)] = (
                    method.return_type or "Unit"
                )
            for method_name in method_names:
                self._multi_impl_candidates[(trait_name, method_name)] = []
            sum_names = self._sum_layout_names(module)
            for impl in impls:
                target_head = _strip_type_qualifiers(impl.type_name)
                # Both struct AND sum impl targets are supported: the
                # type-id lives at the uniform ``_TYPE_ID_OFFSET`` (4),
                # which is free padding in either layout (a sum keeps
                # offset 0 for its variant tag and offset 8 for
                # payloads; a struct keeps offset 8 for fields). A sum
                # participant needs no layout change, only a type-id
                # write in its constructor, so it is recorded in the
                # sum-header set rather than the struct-header set.
                is_sum = target_head in sum_names
                if impl.type_name not in self._type_ids:
                    self._type_ids[impl.type_name] = next_id
                    next_id += 1
                if is_sum:
                    self._header_sum_types.add(impl.type_name)
                else:
                    self._header_struct_types.add(impl.type_name)
                tid = self._type_ids[impl.type_name]
                for method_name in method_names:
                    mangled = _impl_method_name(impl.type_name, method_name)
                    self._multi_impl_candidates[
                        (trait_name, method_name)
                    ].append((tid, mangled))
                # Multi-impl eq dispatch: one (type_id, concrete) per
                # impl target so ``$eq_<Trait>`` can tag-dispatch.
                self._trait_eq_candidates.setdefault(trait_name, []).append(
                    (tid, impl.type_name)
                )

    @staticmethod
    def _sum_layout_names(module) -> set[str]:
        """Names of sum types declared in ``module`` (used to detect a
        sum impl target). Built-in sums (Option / Result / JsonValue)
        are never user impl targets, so the module's own SumDecls are
        the only ones that matter here."""
        from .._nodes import SumDecl
        return {t.name for t in module.types if isinstance(t, SumDecl)}

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
        """Emit one impl method through the standard
        ``_emit_function`` path, via the synthesised emission view
        (mangled name, ``self`` retyped)."""
        self._emit_function(self._impl_method_view(impl, method))

    def _impl_method_view(self, impl, method: Function) -> Function:
        """Synthesise the emission view of an impl method: a
        Function with the mangled name and the ``self`` param
        retyped to the impl's owning type (signature generation
        and field-access lookups need the concrete type, not
        ``Unknown``). The original method object is never mutated
        so re-running emit on the same Module is idempotent.

        The lambda-lift discovery (``_discover_lambdas``) consumes
        the same view so a ``MakeLambda`` inside a method body is
        registered under the SAME parent name the emit site will
        look up (``self._current_fn.name`` is the mangled name when
        the method body is being emitted)."""
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
        return Function(
            name=mangled_name,
            params=new_params,
            return_type=method.return_type or "Unit",
            declared_caps=method.declared_caps,
            body=method.body,
            locals=new_locals,
        )

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
        recv_ty = _strip_type_qualifiers(self._effective_value_ty(instr.receiver))
        candidates = self._multi_impl_candidates.get((recv_ty, instr.method))
        if candidates:
            # Multi-impl trait receiver: dynamic dispatch by type-id.
            self._emit_multi_impl_dispatch(instr, candidates)
            return
        target = self._method_table.get((recv_ty, instr.method))
        if target is None:
            # Trait with no impl (or an unresolved receiver type): the
            # _method_table only carries unique-impl trait entries and
            # concrete-type entries.
            raise WasmEmissionError(
                f"MethodCall on receiver type {recv_ty!r} method "
                f"{instr.method!r}: no impl method found in this "
                f"module."
            )
        # Push receiver (self) -- always an i32 pointer -- then the
        # remaining args via the shared call ABI helper.
        self._push_value(instr.receiver)
        self._push_call_args(instr.args)
        self._write(f"call ${target}")
        self._store_trait_call_result(instr)

    def _emit_multi_impl_dispatch(self, instr: MethodCall, candidates: list) -> None:
        """Emit dynamic dispatch for a method call on a multi-impl-
        trait-typed receiver. The receiver is a single i32 pointer to a
        participating value (struct or sum) whose offset-4 word holds
        the concrete type-id (the uniform ``_TYPE_ID_OFFSET``, free in
        both layouts). Load that tag once, then walk an if-chain
        comparing it
        against each candidate ``(type_id, mangled)``; the matching arm
        pushes the receiver + args and calls the concrete impl method,
        storing the result in the same calling shape the single-impl
        path uses (String as (ptr, len), caps / scalars as one value).
        A tag matching no candidate is unreachable for a well-typed
        program; the trailing ``unreachable`` keeps the chain well-typed
        and traps loudly if it is ever hit.

        The args / receiver are re-pushed inside each arm rather than
        once before the chain so the operand-stack shape stays a clean
        per-call sequence (Wasm ``if`` blocks cannot leave the operand
        stack in differing shapes across arms when they carry a result;
        re-pushing per arm sidesteps that entirely)."""
        # Stash the receiver pointer in a scratch local so the tag load
        # and every arm's receiver push read the same value once.
        self._push_value(instr.receiver)
        self._write("local.set $_trait_recv")
        # Load the type-id tag from the uniform offset 4 of the receiver
        # record (free in both struct and sum layouts).
        self._write("local.get $_trait_recv")
        self._write(f"i32.load offset={_TYPE_ID_OFFSET}")
        self._write("local.set $_trait_tag")
        for tid, mangled in candidates:
            self._write("local.get $_trait_tag")
            self._write(f"i32.const {tid}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            self._write("local.get $_trait_recv")
            self._push_call_args(instr.args)
            self._write(f"call ${mangled}")
            self._store_trait_call_result(instr)
            self._indent -= 1
            self._write("else")
            self._indent += 1
        # Innermost else: no candidate matched (unreachable for a well-
        # typed program). Trap.
        self._write("unreachable")
        # Close every else arm opened above.
        for _ in candidates:
            self._indent -= 1
            self._write("end")

    def _store_trait_call_result(self, instr: MethodCall) -> None:
        """Store a trait/impl method call's result in the dst's calling
        shape. Shared by the single-impl and multi-impl dispatch paths
        so the two never drift. The result (if any) is already on the
        operand stack from the preceding ``call``."""
        if instr.dst is None:
            # Value-discarded method call: drop exactly the slots the
            # method's return type pushed so the operand stack stays
            # balanced. The absent dst carries no type, so recover the
            # return type from the method table (keyed identically),
            # consulting the effective receiver type so self.method()
            # and trait-typed receivers both resolve.
            recv_ty = _strip_type_qualifiers(
                self._effective_value_ty(instr.receiver)
            )
            key = (recv_ty, instr.method)
            if key not in self._method_return_ty:
                # Unreachable for a well-formed module: the table is
                # populated in lockstep with ``_method_table``, and both
                # dispatch paths that reach here have already resolved
                # the method against one of those tables. Fail loud
                # rather than default to "drop nothing", which would
                # silently leave the pushed result on the stack and
                # surface much later as an opaque validator error.
                raise WasmEmissionError(
                    f"no recorded return type for discarded method call "
                    f"{recv_ty}.{instr.method!r}; cannot determine how "
                    f"many result slots to drop"
                )
            self._drop_call_result(self._method_return_ty[key])
            return
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
