"""Pre-emit discovery + classification passes for the Wasm backend.

The Wasm emitter does two pre-emit walks of every IR module:

- ``_discover`` populates ``self._used_caps``, the canonical set of
  capability methods the module reaches. Imports are emitted from
  this set; the WIT side derives the same set independently via
  ``capa.ir._emit_wit.collect_used_capabilities``, and the two
  must agree.
- ``_refine_pattern_binder_types`` is a one-shot backfill pass: the
  analyzer occasionally leaves a variant-payload binder typed
  ``Unknown`` (the sum layouts carry the real type but the
  pattern-side type inference does not). Walking the IR once and
  writing the precise type back into ``fn.locals`` lets the local
  declarations pick the right Wasm shape on emit.

Plus a handful of ``_uses_*`` predicates that answer "does this
module need helper X?" for the runtime emitter. Each one walks
all instructions; the cost is dwarfed by the per-instruction emit
work. Kept here so each predicate sits next to the others and
the per-instr dispatch in ``__init__`` stays focused on emission.

Extracted from ``__init__.py`` in May 2026 alongside ``_caps.py``
and ``_locals.py`` so the top-level file stays focused on
orchestration + per-instruction dispatch.
"""

from __future__ import annotations

from .._nodes import (
    Module, Instr, Value, Function,
    Call, MethodCall, For, FormatStr, If, While, Match,
    MakeList, MakeMap, MakeSet, MakeLambda,
    PatIdent, PatLiteral, PatTuple, PatVariant,
)
from .._emit_wit import _WIT_SIGNATURES
from ._layout import _BUILTIN_CAPS, _element_type_of_list, WasmEmissionError


class _DiscoveryMixin:
    def _uses_heap_alloc(self, module: Module) -> bool:
        """Detect whether any function body contains an instruction
        that allocates on the heap. Used to decide whether the
        module needs the ``$alloc`` helper and the ``$heap_top``
        global."""
        # Method names that allocate when called.
        _ALLOC_METHODS_LIST = {"push"}
        _ALLOC_METHODS_STRING = {"substring", "to_upper", "to_lower"}

        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, (MakeList, MakeMap, MakeSet, FormatStr, MakeLambda)):
                    return True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("List") and instr.method in _ALLOC_METHODS_LIST:
                        return True
                    if recv_ty == "String" and instr.method in _ALLOC_METHODS_STRING:
                        return True
                    if recv_ty.startswith("Map") and instr.method in ("set", "get"):
                        return True
                    if recv_ty.startswith("List") and instr.method in ("map", "filter", "fold"):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _refine_pattern_binder_types(
        self, fn: Function, instrs: list[Instr],
    ) -> None:
        """Walk every Match in ``instrs`` and update ``fn.locals``
        for PatVariant payload binders whose recorded type is
        Unknown / missing. The variant's payload layout owns the
        authoritative type."""
        for instr in instrs:
            if isinstance(instr, Match):
                scrut_head = (instr.scrutinee.ty or "").split("<", 1)[0]
                sum_layout = self._sum_layouts.get(scrut_head)
                if sum_layout is not None:
                    for arm in instr.arms:
                        if not isinstance(arm.pattern, PatVariant):
                            continue
                        entry = sum_layout["variants"].get(arm.pattern.name)
                        if entry is None:
                            continue
                        _tag, payload_layouts = entry
                        for sub_pat, (_off, _sz, payload_ty) in zip(
                            arm.pattern.payloads, payload_layouts,
                        ):
                            if not isinstance(sub_pat, PatIdent):
                                continue
                            cur = fn.locals.get(sub_pat.name, "")
                            if (cur in ("", "Unknown", "?", "Any")
                                    or cur.startswith("?")):
                                if payload_ty and payload_ty != "Any":
                                    fn.locals[sub_pat.name] = payload_ty
                # String-scrutinee match: PatIdent arm binds the
                # whole scrutinee value. The emitter routes binds
                # to ${name}_ptr / ${name}_len, so fn.locals must
                # record "String" for the local-decl sweep to
                # allocate the pair.
                if (instr.scrutinee.ty or "") == "String":
                    for arm in instr.arms:
                        if isinstance(arm.pattern, PatIdent):
                            cur = fn.locals.get(arm.pattern.name, "")
                            if (cur in ("", "Unknown", "?")
                                    or cur.startswith("?")):
                                fn.locals[arm.pattern.name] = "String"
                for arm in instr.arms:
                    self._refine_pattern_binder_types(fn, arm.body)
            elif isinstance(instr, If):
                self._refine_pattern_binder_types(fn, instr.then_body)
                self._refine_pattern_binder_types(fn, instr.else_body)
            elif isinstance(instr, While):
                self._refine_pattern_binder_types(fn, instr.cond_setup)
                self._refine_pattern_binder_types(fn, instr.body)
            elif isinstance(instr, For):
                self._refine_pattern_binder_types(fn, instr.body)

    def _uses_float_format(self, module: Module) -> bool:
        """True if any ``FormatStr`` instruction has a Float value
        part, which is what gates emission of the ``$ftoa`` helper.

        Consults each function's ``locals`` dict as a fallback when
        a value's ``ty`` is unresolved -- the match emitter refines
        pattern-binder types into ``fn.locals`` after the analyzer
        leaves them as Unknown, and the FormatStr dispatcher uses
        the same fallback at emit time."""
        def _eff_ty(p: Value, fn: Function) -> str:
            if p.ty and p.ty not in ("?", "Unknown", "Any"):
                return p.ty
            if p.kind in ("local", "param") and p.name in fn.locals:
                return fn.locals[p.name]
            return p.ty or ""
        for fn in module.functions:
            def visit(instrs: list[Instr], fn=fn) -> bool:
                for instr in instrs:
                    if isinstance(instr, FormatStr):
                        for p in instr.parts:
                            if isinstance(p, Value) and _eff_ty(p, fn) == "Float":
                                return True
                    if isinstance(instr, MakeLambda):
                        # Recurse into the lambda body so a Float-
                        # interpolation inside a closure still
                        # triggers $ftoa emission.
                        if visit(instr.body):
                            return True
                    if isinstance(instr, If):
                        if visit(instr.then_body) or visit(instr.else_body):
                            return True
                    if isinstance(instr, While):
                        if visit(instr.cond_setup) or visit(instr.body):
                            return True
                    if isinstance(instr, For):
                        if visit(instr.body):
                            return True
                    if isinstance(instr, Match):
                        for arm in instr.arms:
                            if visit(arm.body):
                                return True
                return False
            if visit(fn.body):
                return True
        return False

    def _uses_parse_int(self, module: Module) -> bool:
        return self._uses_builtin_free_fn(module, "parse_int")

    def _uses_parse_float(self, module: Module) -> bool:
        return self._uses_builtin_free_fn(module, "parse_float")

    def _uses_builtin_free_fn(self, module: Module, name: str) -> bool:
        """True if any function or impl-method body Calls
        ``name``. Used to gate emission of optional runtime
        helpers like ``$parse_int`` / ``$parse_float``."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, Call) and instr.callee_name == name:
                    return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        for impl in module.impls:
            for method in impl.methods:
                if visit(method.body):
                    return True
        return False

    def _uses_format_str(self, module: Module) -> bool:
        """True if any function body contains a ``FormatStr``
        instruction. Drives the emission of the ``$itoa`` helper
        (and pre-interning of ``"true"`` / ``"false"`` for Bool
        parts). Recurses into ``MakeLambda`` bodies so a format
        string nested inside a lambda still triggers the helper
        emission (otherwise the lifted lambda's body references
        ``$itoa`` that the module never defined)."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, FormatStr):
                    return True
                if isinstance(instr, MakeLambda):
                    if visit(instr.body):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    def _uses_map_ops(self, module: Module) -> bool:
        """True if the module touches a Map or a String method that
        relies on byte-string equality (contains / starts_with /
        ends_with). Drives whether the ``$str_eq`` helper is
        emitted."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, MakeMap):
                    return True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        return True
                    if recv_ty == "String" and instr.method in (
                        "contains", "starts_with", "ends_with",
                    ):
                        return True
                    # List<String>.contains compares the needle to
                    # each element via $str_eq.
                    if (recv_ty.startswith("List")
                            and instr.method == "contains"
                            and _element_type_of_list(recv_ty) == "String"):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    # String-scrutinee match calls $str_eq per arm.
                    if (instr.scrutinee.ty or "") == "String":
                        return True
                    # Tuple-scrutinee match with a String literal
                    # sub-pattern: the per-slot equality check calls
                    # $str_eq to compare the slot against the interned
                    # literal. Without this branch a program like
                    # ``match (s, n) ; ("yes", x) -> ...`` would emit
                    # a $str_eq call into a module that never imported
                    # the helper, and wasm-tools parse would refuse
                    # with "unknown func: failed to find name $str_eq".
                    for arm in instr.arms:
                        if isinstance(arm.pattern, PatTuple):
                            for sub in arm.pattern.elements:
                                if (isinstance(sub, PatLiteral)
                                        and sub.kind == "str"):
                                    return True
                        if visit(arm.body):
                            return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        return False

    # ----- discovery pass ---------------------------------------

    def _discover(self, module: Module) -> None:
        """Walk all functions and collect string literals + used
        capability methods. The discovered set drives import
        declarations and the data segment layout; encountering
        anything outside the supported set is a fatal error so the
        emitted Wasm never references something the host did not
        provide.

        Also walks every impl method body so the cap calls inside
        impl methods (e.g. ``self.stdio.println(...)`` in
        ``impl Logger for StdioLogger``) contribute their imports
        to the module just like top-level function bodies."""
        for fn in module.functions:
            self._discover_instrs(fn.body)
        for impl in module.impls:
            for method in impl.methods:
                self._discover_instrs(method.body)

    def _discover_instrs(self, instrs: list[Instr]) -> None:
        for instr in instrs:
            # Cap dispatch: prefer instr.cap_used, fall back to the
            # receiver type for impl-method-internal calls where
            # the analyzer doesn't propagate cap_used through. The
            # emit-side dispatch in _emit_instr mirrors this rule.
            cap_from_recv = None
            if isinstance(instr, MethodCall) and not instr.cap_used:
                rty = (instr.receiver.ty or "")
                if rty in _BUILTIN_CAPS:
                    cap_from_recv = rty
            if isinstance(instr, MethodCall) and (instr.cap_used or cap_from_recv):
                cap = instr.cap_used or cap_from_recv
                if cap not in _BUILTIN_CAPS:
                    raise WasmEmissionError(
                        f"Phase 6B: capability {cap!r} not in the "
                        f"built-in set; user-defined capabilities "
                        f"land in a later phase"
                    )
                key = (cap, instr.method)
                if (cap, instr.method) not in _WIT_SIGNATURES:
                    raise WasmEmissionError(
                        f"Phase 6B: capability method {cap}.{instr.method} "
                        f"has no WIT/Wasm encoding yet; widen the "
                        f"signature tables in capa.ir._emit_wit and "
                        f"capa.ir._emit_wasm together"
                    )
                self._used_caps.add(key)
            # parse_json / to_json used to route through a synthetic
            # ``Json`` host capability with canonical-ABI imports.
            # They now compile to ``call $__capa_parse_json`` /
            # ``call $__capa_to_json`` into the bundled Capa-source
            # parser injected by ``_builtin_json.inject_into``; no
            # host import is produced for either function.
            # Walk every Value-bearing slot of every instruction for
            # ``lit_str`` literals; the data segment must cover any
            # literal the emitter will reference at use site, not
            # just those that flow into capability calls.
            for v in self._values_of(instr):
                if v.kind == "lit_str":
                    self._intern_string(v.literal)
            # FormatStr's literal parts are bare Python strings, not
            # Values; intern them here so they share the data
            # segment with everything else.
            if isinstance(instr, FormatStr):
                for part in instr.parts:
                    if isinstance(part, str) and part:
                        self._intern_string(part)
            if isinstance(instr, If):
                self._discover_instrs(instr.then_body)
                self._discover_instrs(instr.else_body)
            elif isinstance(instr, While):
                self._discover_instrs(instr.cond_setup)
                self._discover_instrs(instr.body)
            elif isinstance(instr, For):
                self._discover_instrs(instr.body)
            elif isinstance(instr, Match):
                for arm in instr.arms:
                    self._discover_instrs(arm.body)

    @staticmethod
    def _values_of(instr: Instr) -> list[Value]:
        """Return every Value-typed slot on ``instr`` so the
        discovery pass can intern string literals reachable from
        anywhere in the function body, not just the few sites the
        previous pass enumerated by hand."""
        out: list[Value] = []
        for attr in (
            "src", "value", "left", "right",
            "operand", "receiver", "iter", "cond", "index",
        ):
            v = getattr(instr, attr, None)
            if isinstance(v, Value):
                out.append(v)
        for v in getattr(instr, "args", []) or []:
            if isinstance(v, Value):
                out.append(v)
        for fname_v in getattr(instr, "fields", []) or []:
            if isinstance(fname_v, tuple) and len(fname_v) == 2:
                v = fname_v[1]
                if isinstance(v, Value):
                    out.append(v)
        for v in getattr(instr, "elements", []) or []:
            if isinstance(v, Value):
                out.append(v)
        for part in getattr(instr, "parts", []) or []:
            if isinstance(part, Value):
                out.append(part)
        return out
