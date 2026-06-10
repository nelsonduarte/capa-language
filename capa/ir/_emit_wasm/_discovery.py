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
    BinOp, Call, MethodCall, For, FormatStr, If, While, Match,
    MakeList, MakeMap, MakeSet, MakeLambda,
    PatIdent, PatLiteral, PatTuple, PatVariant,
)
from .._capa_types import BUILTIN_CAPS
from .._emit_wit import _WIT_SIGNATURES
from ._layout import (
    _element_type_of_list, _element_type_of_set, _map_key_type,
    WasmEmissionError,
)


def _variant_pattern_has_str_literal(pat) -> bool:
    """True iff ``pat`` is a variant pattern carrying a String
    literal anywhere in its payload tree (flat ``Ok("yes")`` or
    nested ``Some(Ok("yes"))``). The per-slot equality check for
    such a literal calls ``$str_eq``, so the helper must be
    registered in the module."""
    if not isinstance(pat, PatVariant):
        return False
    for sub in pat.payloads:
        if isinstance(sub, PatLiteral) and sub.kind == "str":
            return True
        if _variant_pattern_has_str_literal(sub):
            return True
    return False


class _DiscoveryMixin:
    def _uses_heap_alloc(self, module: Module) -> bool:
        """Detect whether any function body contains an instruction
        that allocates on the heap. Used to decide whether the
        module needs the ``$alloc`` helper and the ``$heap_top``
        global."""
        # Method names that allocate when called.
        _ALLOC_METHODS_LIST = {
            "push", "first", "last", "find", "find_index", "sorted_by",
        }
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
                    # Set.add grows / appends, Set.to_list allocates a
                    # fresh List<T>; both need the heap.
                    if recv_ty.startswith("Set") and instr.method in ("add", "to_list"):
                        return True
                    # Range.to_list materialises a fresh List<Int>.
                    if recv_ty.startswith("Range") and instr.method == "to_list":
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
        # A user-defined ``parse_int`` shadows the builtin: emit the
        # user function instead of the runtime helper (matches the
        # Python backend, where the user's function wins).
        if any(fn.name == "parse_int" for fn in module.functions):
            return False
        return self._uses_builtin_free_fn(module, "parse_int")

    def _uses_parse_float(self, module: Module) -> bool:
        if any(fn.name == "parse_float" for fn in module.functions):
            return False
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
        """True if any function OR impl-method body contains a
        ``FormatStr`` instruction. Drives the emission of the
        ``$itoa`` helper (and pre-interning of ``"true"`` /
        ``"false"`` for Bool parts). Recurses into ``MakeLambda``
        bodies so a format string nested inside a lambda still
        triggers the helper emission (otherwise the lifted lambda's
        body references ``$itoa`` that the module never defined).

        Impl-method bodies are walked alongside top-level functions
        (mirroring ``_uses_string_codepoint_index`` / the Random /
        cap discovery walks): a format string that appears ONLY
        inside an impl method - e.g. ``Beat(n) -> "beat ${n}"`` in
        an ``impl Token for Note`` - must still emit ``$itoa``, or
        the impl method's body references a helper the module never
        defined."""
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
        for impl in module.impls:
            for method in impl.methods:
                if visit(method.body):
                    return True
        return False

    def _uses_string_codepoint_index(self, module: Module) -> bool:
        """True when any function in the module calls a String
        method whose Wasm emission now goes through the
        codepoint-counting / cp-to-byte-offset helpers. Slice 17
        (2026-05-29) switched ``length`` and ``substring`` from
        byte-indexing to code-point-indexing to match the Python
        runtime; the inline emit calls ``$str_codepoint_count`` /
        ``$str_cp_to_byte_offset``, which must therefore be
        present in the module when these methods appear.

        Recurses into ``MakeLambda.body`` so a closure-body call
        like ``names.filter(fun (n) -> Bool => n.length() > 3)``
        also triggers the gate (lambda-lift happens after
        discovery; the body is in the MakeLambda Instr at this
        point)."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty == "String" and instr.method in (
                        "length", "substring",
                    ):
                        return True
                if isinstance(instr, If):
                    if visit(instr.then_body) or visit(instr.else_body):
                        return True
                if isinstance(instr, While):
                    if visit(instr.cond_setup) or visit(instr.body):
                        return True
                if isinstance(instr, For):
                    # ``for c in s`` walks the receiver's UTF-8 code
                    # points; the for-string emit path itself does the
                    # leading-byte classification inline, but a body
                    # that calls length / substring still needs the
                    # helpers, so recurse either way. The String-iter
                    # walk does not call $str_codepoint_count /
                    # $str_cp_to_byte_offset directly (it inlines the
                    # classification), so no extra gate is required for
                    # the loop itself.
                    if visit(instr.body):
                        return True
                if isinstance(instr, Match):
                    for arm in instr.arms:
                        # Match arm guards lower to a prelude of
                        # ANF instructions + a Value; a guard like
                        # ``x if x.length() > 0`` puts the
                        # ``length()`` call in the guard prelude.
                        if visit(getattr(arm, "guard_setup", []) or []):
                            return True
                        if visit(arm.body):
                            return True
                if isinstance(instr, MakeLambda):
                    if visit(instr.body):
                        return True
            return False
        for fn in module.functions:
            if visit(fn.body):
                return True
        for impl in module.impls:
            for m in impl.methods:
                if visit(m.body):
                    return True
        return False

    def _uses_random(self, module: Module) -> bool:
        """True if the module needs the SplitMix64 helpers + the
        ``$rand_state`` global. Triggered by either a ``Random()``
        constructor call (``Call(callee_name="Random")``) or a
        ``MethodCall`` on a Random-typed receiver (``with_seed``,
        ``int_range``, ``float_unit``). Walks every function body
        plus impl-method bodies so a Random use inside an impl
        method still flips the gate.

        Mirrors the WIT-side rule in
        ``capa.ir._emit_wit.collect_used_capabilities``: any Random
        touch-point pulls in the ``system-seed`` host import via
        the lazy-init path."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                if isinstance(instr, Call) and instr.callee_name == "Random":
                    return True
                if isinstance(instr, MethodCall):
                    cap = instr.cap_used
                    if cap is None:
                        rty = instr.receiver.ty or ""
                        if rty in BUILTIN_CAPS:
                            cap = rty
                    if cap == "Random":
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
            for m in impl.methods:
                if visit(m.body):
                    return True
        return False

    def _uses_attenuation_check(
        self, module: Module,
    ) -> tuple[bool, bool]:
        """Walk the module for ``cap.allows(arg)`` MethodCalls on
        Fs / Env / Db / Proc with a tracked attenuation chain.
        Only ``.allows()`` queries still emit an inline runtime
        check; the privileged ops (Fs.read / Net.get / ...) moved
        to the host handle table in slice 25 (2026-05-30), so this
        helper no longer needs to scan them.

        Returns ``(needs_starts_with, needs_proc_allows)``:
        - ``needs_starts_with``: Fs.allows / Db.allows requires
          the prefix-component check via ``$str_starts_with``.
        - ``needs_proc_allows``: Proc.allows requires the basename
          + suffix-boundary check via ``$proc_allows``.

        Env.allows uses ``$str_eq`` (already emitted via the
        Map / String-method discovery branches; no separate flag
        is needed)."""
        needs_starts_with = False
        needs_proc_allows = False

        def visit(instrs: list[Instr]) -> None:
            nonlocal needs_starts_with, needs_proc_allows
            for instr in instrs:
                if isinstance(instr, MethodCall) and instr.attenuations:
                    cap = instr.cap_used or ""
                    # Conservatively flag the helper whenever
                    # ``.allows()`` exists with a tracked
                    # attenuation chain: the literal-arg fast-path
                    # collapses to a const without the helper, the
                    # dynamic-arg path needs it. Deciding which is
                    # which lives at emit time; over-emitting one
                    # unused helper adds <100 bytes to the WAT.
                    if (cap in ("Fs", "Db")
                            and instr.method == "allows"):
                        needs_starts_with = True
                    if cap == "Proc" and instr.method == "allows":
                        needs_proc_allows = True
                if isinstance(instr, If):
                    visit(instr.then_body)
                    visit(instr.else_body)
                elif isinstance(instr, While):
                    visit(instr.cond_setup)
                    visit(instr.body)
                elif isinstance(instr, For):
                    visit(instr.body)
                elif isinstance(instr, Match):
                    for arm in instr.arms:
                        visit(arm.body)
        for fn in module.functions:
            visit(fn.body)
        for impl in module.impls:
            for m in impl.methods:
                visit(m.body)
        return needs_starts_with, needs_proc_allows

    def _uses_map_ops(self, module: Module) -> bool:
        """True if the module needs the ``$str_eq`` helper. After
        the M4 key generalisation, the Map gate is restricted to
        Map<String, V>: Int/Bool key maps compare with native
        ``i64.eq`` / ``i32.eq`` and never call ``$str_eq``. The
        helper is still emitted for any String-method that relies
        on byte-string equality (contains / starts_with /
        ends_with) and for List<String>.contains /
        Set<String>.{add,contains,remove}."""
        def visit(instrs: list[Instr]) -> bool:
            for instr in instrs:
                # MakeMap alone never calls ``$str_eq`` (the allocator
                # just zero-initialises the header and data array);
                # the per-key compare emitted by ``_emit_map_*``
                # method handlers is what may need it. So the gate
                # is keyed off the MethodCall recv type below: a
                # String-key receiver triggers, an Int / Bool key
                # never does. Constructing an empty Map<Int, V> and
                # never calling .set / .get on it is therefore zero-
                # helper-emit, matching the locked design.
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    # Net.allows with a dynamic (non-literal) arg emits
                    # ``$str_eq`` for the exact host comparison against
                    # each restricted host. Literal-arg Net.allows
                    # collapses to a const and needs no helper, but
                    # over-emitting $str_eq for the literal case is
                    # harmless (a few unused bytes).
                    if ((instr.cap_used == "Net"
                         or recv_ty == "Net")
                            and instr.method == "allows"
                            and getattr(instr, "attenuations", None)):
                        return True
                    if recv_ty.startswith("Map"):
                        if _map_key_type(recv_ty) == "String":
                            return True
                    if recv_ty == "String" and instr.method in (
                        "contains", "starts_with", "ends_with",
                        "index_of", "replace",
                    ):
                        return True
                    # List<String>.contains compares the needle to
                    # each element via $str_eq.
                    if (recv_ty.startswith("List")
                            and instr.method == "contains"
                            and _element_type_of_list(recv_ty) == "String"):
                        return True
                    # Set<String> add / contains / remove compare the
                    # needle to each element via $str_eq.
                    if (recv_ty.startswith("Set")
                            and instr.method in ("add", "contains", "remove")
                            and _element_type_of_set(recv_ty) == "String"):
                        return True
                if isinstance(instr, BinOp) and instr.op in ("==", "!="):
                    # BinOp ``==`` / ``!=`` on String operands lowers
                    # to a ``call $str_eq`` (see __init__.py's
                    # ``_emit_binop`` String branch). Without this
                    # check a function whose only String comparison
                    # lives in a lifted lambda (e.g. an Option.map
                    # closure body doing ``s == "retry"``) would
                    # emit a $str_eq call into a module that never
                    # registered the helper.
                    if (instr.left.ty == "String"
                            or instr.right.ty == "String"):
                        return True
                if isinstance(instr, MakeLambda):
                    # Lambdas are lifted into top-level Wasm
                    # functions before emission, but the lift
                    # happens AFTER discovery; at this point the
                    # lambda body still lives inside ``MakeLambda``.
                    # Recursing into it catches String comparisons
                    # (BinOp ``==``) and similar str_eq-needing
                    # patterns that only appear in closure bodies
                    # (e.g. ``some.map(fun (e: String) -> Bool =>
                    # e == "retry")``).
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
                        # Variant-payload String literal (flat
                        # ``Ok("yes")`` or nested ``Some(Ok("y"))``):
                        # the arm predicate compares the payload slot
                        # against the interned literal via $str_eq.
                        if _variant_pattern_has_str_literal(arm.pattern):
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
        to the module just like top-level function bodies.

        Slice 7 (D5, 2026-05): scans every function signature for
        an ``Unsafe`` capability parameter and rejects with an
        actionable diagnostic. Unsafe is intentionally Python-only
        (it gives a program raw pointer / FFI / mmap-class
        primitives that have no sandboxed Wasm equivalent). Pre-
        slice-7 the rejection happened later, deep in cap-method
        dispatch (``capability method Unsafe.alloc has no
        WIT/Wasm encoding yet; widen the signature tables``)
        which read as "this is a backlog item" rather than the
        permanent stance it actually is. The single early raise
        is more honest and points the user at the correct
        workaround (Python backend or refactor the call site)."""
        self._reject_unsafe_signatures(module)
        for fn in module.functions:
            self._discover_instrs(fn.body)
        for impl in module.impls:
            for method in impl.methods:
                self._discover_instrs(method.body)

    def _reject_unsafe_signatures(self, module: Module) -> None:
        """Surface ``Unsafe``-typed parameters at discovery time
        with a diagnostic that names the function, the parameter,
        and the only two valid responses (run on the Python
        backend, or remove the Unsafe argument). Scans both
        top-level functions and impl methods."""
        offenders: list[str] = []
        for fn in module.functions:
            for p in fn.params:
                if p.ty == "Unsafe":
                    offenders.append(f"{fn.name}({p.name}: Unsafe)")
        for impl in module.impls:
            impl_label = (
                f"impl {impl.trait_name} for {impl.type_name}"
                if impl.trait_name else f"impl {impl.type_name}"
            )
            for method in impl.methods:
                for p in method.params:
                    if p.ty == "Unsafe":
                        offenders.append(
                            f"{impl_label}::{method.name}"
                            f"({p.name}: Unsafe)"
                        )
        if not offenders:
            return
        sites = "\n  - ".join(offenders)
        raise WasmEmissionError(
            "the Unsafe capability is intentionally not supported "
            "on the Wasm backend (it grants raw pointer / FFI / "
            "memory-map primitives that have no sandboxed Wasm "
            "equivalent). Use the Python backend for these "
            "functions, or refactor to remove the Unsafe "
            "parameter.\n  - "
            f"{sites}"
        )

    def _discover_instrs(self, instrs: list[Instr]) -> None:
        for instr in instrs:
            # Cap dispatch: prefer instr.cap_used, fall back to the
            # receiver type for impl-method-internal calls where
            # the analyzer doesn't propagate cap_used through. The
            # emit-side dispatch in _emit_instr mirrors this rule.
            cap_from_recv = None
            if isinstance(instr, MethodCall) and not instr.cap_used:
                rty = (instr.receiver.ty or "")
                if rty in BUILTIN_CAPS:
                    cap_from_recv = rty
            if isinstance(instr, MethodCall) and (instr.cap_used or cap_from_recv):
                cap = instr.cap_used or cap_from_recv
                if cap not in BUILTIN_CAPS:
                    raise WasmEmissionError(
                        f"Phase 6B: capability {cap!r} not in the "
                        f"built-in set; user-defined capabilities "
                        f"land in a later phase"
                    )
                # Attenuator methods (``restrict_to`` /
                # ``restrict_to_keys`` / ``restrict_to_after``) are
                # elided at emit time (the audit C2 inline check on
                # the privileged op is what enforces the discipline).
                # Skip importing them so the host doesn't need to
                # define a matching no-op stub.
                #
                # Slices 25.2 - 25.6 exception (2026-05-30):
                # ``Fs.restrict_to`` / ``Net.restrict_to`` /
                # ``Db.restrict_to`` / ``Proc.restrict_to`` /
                # ``Env.restrict_to_keys`` /
                # ``Clock.restrict_to_after`` are no longer no-ops -
                # they cross the host bridge with the parent handle
                # and return a fresh i32 handle bound to a narrower
                # restriction. Register the imports so the linker
                # resolves the host callbacks.
                if (cap in ("Fs", "Net", "Db", "Proc")
                        and instr.method == "restrict_to"):
                    self._used_caps.add((cap, "restrict_to"))
                elif (cap == "Env"
                        and instr.method == "restrict_to_keys"):
                    self._used_caps.add((cap, "restrict_to_keys"))
                elif (cap == "Clock"
                        and instr.method == "restrict_to_after"):
                    self._used_caps.add((cap, "restrict_to_after"))
                elif instr.method in (
                    "restrict_to", "restrict_to_keys", "restrict_to_after",
                ):
                    pass
                elif (cap in ("Fs", "Env", "Db", "Proc", "Net")
                      and instr.method == "allows"):
                    # Fs.allows / Env.allows / Db.allows / Proc.allows
                    # lower to inline-attenuation checks at emit time
                    # (D4 Option B): no host import, no WIT signature
                    # needed. ``Clock.allows`` is the exception
                    # (no string arg, needs the live wall clock)
                    # and still uses the host bridge.
                    #
                    # Pre-intern every string the dynamic-arg emit
                    # path will reference. The literal-arg path
                    # collapses to a const so it needs nothing here,
                    # but the dynamic-arg path
                    # (``_emit_atten_allows_runtime``) interns the
                    # boundary-aware prefix forms while emitting the
                    # function body -- AFTER the data segment has
                    # been written. An offset interned that late
                    # points at uninitialised memory. The classic
                    # symptom (audit C2): a no-trailing-slash prefix
                    # like ``restrict_to("/home/data")`` needs the
                    # slash-suffixed ``"/home/data/"`` for the
                    # ``starts_with`` arm, but that string never
                    # appears as a literal Value so discovery never
                    # sees it. Mirror the exact strings the emit
                    # path will reference so they land in the data
                    # segment.
                    self._discover_attenuation_strings(cap, instr)
                elif cap == "Random" and instr.method in (
                    "with_seed", "int_range", "float_unit",
                ):
                    # SplitMix64 runs entirely guest-side; no WIT
                    # signature, no host import for the user-facing
                    # methods. The lazy ``system-seed`` import is
                    # registered separately below so the host bridge
                    # is reachable for unseeded ``Random()``.
                    self._used_caps.add(("Random", "system_seed"))
                else:
                    key = (cap, instr.method)
                    if (cap, instr.method) not in _WIT_SIGNATURES:
                        raise WasmEmissionError(
                            f"Phase 6B: capability method {cap}.{instr.method} "
                            f"has no WIT/Wasm encoding yet; widen the "
                            f"signature tables in capa.ir._emit_wit and "
                            f"capa.ir._emit_wasm together"
                        )
                    self._used_caps.add(key)
            # ``Random()`` constructor: source uses it as a Call
            # (``let r = Random()``). It carries no runtime value at
            # the Wasm level but still pulls the SplitMix64 helpers
            # in via _uses_random, and the lazy host-seed import via
            # the Random use here. Register ``system_seed`` so the
            # core wasm import survives the discovery pass even when
            # the program only ever constructs Random without
            # calling a method on it.
            if (isinstance(instr, Call)
                    and instr.callee_name == "Random"):
                self._used_caps.add(("Random", "system_seed"))
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

    def _discover_attenuation_strings(
        self, cap: str, instr: MethodCall,
    ) -> None:
        """Pre-intern the data-segment strings the dynamic-arg
        ``.allows()`` emit path will reference, so they land in the
        data segment that is written before any function body.

        Mirrors ``_emit_atten_allows_runtime`` /
        ``_emit_one_attenuation`` exactly:
        - Fs / Db: each ``restrict_to`` prefix needs both the
          exact-match form and the boundary-aware slash-suffixed
          form (``prefix + '/'``) for the ``starts_with`` arm.
        - Proc: each ``restrict_to`` prefix is interned verbatim
          (the ``$proc_allows`` basename check reads it directly).
        - Env: each key in every ``restrict_to_keys`` list.

        Only the dynamic-arg shape reaches the runtime emit path;
        the literal-arg shape collapses to a const and needs no
        interned strings. Pre-interning the dynamic strings even
        for a literal-arg call is harmless (the data segment just
        carries an extra unused string), so we do not special-case
        the arg kind here.
        """
        from ._caps import (
            _unquote_attenuation_arg, _parse_attenuation_key_list,
        )
        attenuations = getattr(instr, "attenuations", None) or []
        for att in attenuations:
            if cap in ("Fs", "Db"):
                if att.get("method") != "restrict_to":
                    continue
                args = att.get("args", [])
                if not args:
                    continue
                try:
                    prefix = _unquote_attenuation_arg(args[0])
                except WasmEmissionError:
                    continue
                self._intern_string(prefix)
                slash = prefix if prefix.endswith("/") else prefix + "/"
                self._intern_string(slash)
            elif cap == "Proc":
                if att.get("method") != "restrict_to":
                    continue
                args = att.get("args", [])
                if not args:
                    continue
                try:
                    prefix = _unquote_attenuation_arg(args[0])
                except WasmEmissionError:
                    continue
                self._intern_string(prefix)
            elif cap == "Net":
                # Net.allows is exact host equality (``host in
                # self._allowed``), so each restrict_to host is interned
                # verbatim for the dynamic-arg ``$str_eq`` compare.
                if att.get("method") != "restrict_to":
                    continue
                args = att.get("args", [])
                if not args:
                    continue
                try:
                    host = _unquote_attenuation_arg(args[0])
                except WasmEmissionError:
                    continue
                self._intern_string(host)
            elif cap == "Env":
                if att.get("method") != "restrict_to_keys":
                    continue
                for key in _parse_attenuation_key_list(att.get("args", [])):
                    self._intern_string(key)

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
