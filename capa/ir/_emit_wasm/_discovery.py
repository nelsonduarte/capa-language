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
module need helper X?" for the runtime emitter. Every predicate
consumes the shared traversal in ``capa.ir._walk`` (top-level
functions + impl methods + lambda bodies + every nested
instruction list, match-arm guard preludes included) so a feature
used only inside an impl method or a closure body still flips its
gate; pre-2026-06-11 each predicate hand-rolled its own walk and
several missed those bodies, emitting calls to helpers the module
never defined ("unknown func" at wasm-tools parse time).

Extracted from ``__init__.py`` in May 2026 alongside ``_caps.py``
and ``_locals.py`` so the top-level file stays focused on
orchestration + per-instruction dispatch.
"""

from __future__ import annotations


from .._nodes import (
    Module, Instr, Value, Function,
    BinOp, Call, MethodCall, FormatStr, Match,
    MakeList, MakeMap, MakeSet, MakeLambda,
    PatIdent, PatLiteral, PatTuple, PatVariant,
)
from .._lower_pattern import PatStruct, PatOr
from .._free_vars import values_of
from .._capa_types import BUILTIN_CAPS
from .._cap_discovery import classify_cap_method
from .._python_only_caps import find_rejection
from .._emit_wit import _WIT_SIGNATURES
from .._walk import iter_functions, walk_instrs, walk_module
from ._layout import (
    _element_type_of_list, _element_type_of_set, _map_key_type,
    WasmEmissionError,
)



def _pattern_has_str_literal(pat) -> bool:
    """True iff ``pat`` carries a String literal anywhere in its
    sub-pattern tree: a variant payload (``Ok("yes")`` / nested
    ``Some(Ok("yes"))``), a tuple element (``("yes", n)``), or a
    struct field (``P { name: "bob" }``), including any composition
    of the three. The per-slot equality check for such a literal
    calls ``$str_eq``, so the helper must be registered in the
    module or wasm-tools parse fails with "unknown func: failed to
    find name $str_eq"."""
    if isinstance(pat, PatLiteral):
        return pat.kind == "str"
    if isinstance(pat, PatVariant):
        return any(_pattern_has_str_literal(s) for s in pat.payloads)
    if isinstance(pat, PatTuple):
        return any(_pattern_has_str_literal(s) for s in pat.elements)
    if isinstance(pat, PatStruct):
        return any(_pattern_has_str_literal(s) for _f, s in pat.fields)
    if isinstance(pat, PatOr):
        return any(_pattern_has_str_literal(s) for s in pat.alternatives)
    return False


def _pattern_str_literals(pat):
    """Yield every String literal carried anywhere in ``pat``'s
    sub-pattern tree, mirroring ``_pattern_has_str_literal``'s
    recursion but returning the values rather than a bool. The Wasm
    emitter compares each such slot against an interned copy via
    ``$str_eq`` at match-emit time, which runs AFTER the data segment
    is frozen; so every one must be interned during discovery. A
    literal that appears nowhere else in the module (the scrutinee is
    heap-built and the bytes surface only in the pattern) would
    otherwise be first seen past the frozen ``heap_start``, get an
    offset with no backing ``(data ...)`` block, and read dangling
    memory -- a silent wrong branch or a spurious match (C-F2)."""
    if isinstance(pat, PatLiteral):
        if pat.kind == "str":
            yield pat.value
    elif isinstance(pat, PatVariant):
        for s in pat.payloads:
            yield from _pattern_str_literals(s)
    elif isinstance(pat, PatTuple):
        for s in pat.elements:
            yield from _pattern_str_literals(s)
    elif isinstance(pat, PatStruct):
        for _f, s in pat.fields:
            yield from _pattern_str_literals(s)
    elif isinstance(pat, PatOr):
        for s in pat.alternatives:
            yield from _pattern_str_literals(s)


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

        for _fn, instr in walk_module(module):
            if isinstance(instr, (MakeList, MakeMap, MakeSet,
                                  FormatStr, MakeLambda)):
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
                # fresh List<T>, and union / intersection / difference
                # each allocate a fresh result Set<T>; all need the heap.
                if recv_ty.startswith("Set") and instr.method in (
                    "add", "to_list",
                    "union", "intersection", "difference",
                ):
                    return True
                # Range.to_list materialises a fresh List<Int>.
                if recv_ty.startswith("Range") and instr.method == "to_list":
                    return True
        return False

    def _refine_pattern_binder_types(
        self, fn: Function, instrs: list[Instr],
    ) -> None:
        """Walk every Match reachable from ``instrs`` (including
        inside lambda bodies -- the lowerer's flat ``fn.locals``
        map covers those locals too) and update ``fn.locals`` for
        PatVariant payload binders whose recorded type is Unknown /
        missing. The variant's payload layout owns the
        authoritative type."""
        for instr in walk_instrs(instrs):
            if not isinstance(instr, Match):
                continue
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
        for fn, instr in walk_module(module):
            if isinstance(instr, FormatStr):
                for p in instr.parts:
                    if isinstance(p, Value) and _eff_ty(p, fn) == "Float":
                        return True
        return False

    def _format_str_formats_ioerror(self, module: Module) -> bool:
        """True if any ``FormatStr`` instruction has an IoError value
        part. The FormatStr emitter's IoError branch renders
        ``message: cause`` when the cause is non-empty, which calls
        the ``$str_concat`` runtime helper -- so the helper must be
        emitted whenever a program CAN format an IoError, even when
        no String ``+`` appears anywhere in the source. This includes
        IoErrors the program never constructs itself: an ``Err(e)``
        binder from a failed host fs/net call carries the same record
        shape and reaches the same branch.

        Consults each function's ``locals`` dict as a fallback when
        a value's ``ty`` is unresolved, exactly like
        ``_uses_float_format`` above -- the match emitter refines
        pattern-binder types (the ``Err(e) -> "${e}"`` case) into
        ``fn.locals``, and the FormatStr dispatcher uses the same
        fallback at emit time."""
        def _eff_ty(p: Value, fn: Function) -> str:
            if p.ty and p.ty not in ("?", "Unknown", "Any"):
                return p.ty
            if p.kind in ("local", "param") and p.name in fn.locals:
                return fn.locals[p.name]
            return p.ty or ""
        for fn, instr in walk_module(module):
            if isinstance(instr, FormatStr):
                for p in instr.parts:
                    if isinstance(p, Value) and _eff_ty(p, fn) == "IoError":
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

    def _uses_capa_chr(self, module: Module) -> bool:
        """Gates emission of the ``$chr`` runtime helper backing the
        internal ``_capa_chr`` builtin (used by the bundled JSON
        parser to decode ``\\uXXXX`` escapes). The discovery walk
        runs after ``_builtin_json.inject_into`` splices the parser
        functions in, so the call inside ``__cj_parse_string`` is
        visible here."""
        if any(fn.name == "_capa_chr" for fn in module.functions):
            return False
        return self._uses_builtin_free_fn(module, "_capa_chr")

    def _uses_str_span(self, module: Module) -> bool:
        """Gates emission of the ``$str_span`` runtime helper backing
        the internal ``_capa_str_span`` builtin (used by the bundled
        JSON parser to extract string / number values and object keys
        as O(1) views into the input buffer). The discovery walk runs
        after ``_builtin_json.inject_into`` splices the parser
        functions in, so the calls inside ``__cj_parse_string`` /
        ``__cj_finish_number`` are visible here."""
        if any(fn.name == "_capa_str_span" for fn in module.functions):
            return False
        return self._uses_builtin_free_fn(module, "_capa_str_span")

    def _uses_panic(self, module: Module) -> bool:
        """Gates the ``capa:host/panic`` import emission. A
        user-defined ``panic`` shadows the builtin (the user
        function is emitted and called instead), matching the
        Python backend and the parse_int rule above.

        Besides a direct ``panic(...)`` call, an Option / Result
        ``unwrap`` / ``expect`` reaches ``$panic`` on its value-less
        arm, so the import must also be emitted when one is present.
        Shadowing a user ``panic`` still wins (it has no host import)."""
        if any(fn.name == "panic" for fn in module.functions):
            return False
        if self._uses_builtin_free_fn(module, "panic"):
            return True
        from ._option import methodcall_may_panic
        return any(
            methodcall_may_panic(instr)
            for _fn, instr in walk_module(module)
        )

    def _uses_builtin_free_fn(self, module: Module, name: str) -> bool:
        """True if any function / impl-method / lambda body Calls
        ``name``. Used to gate emission of optional runtime
        helpers like ``$parse_int`` / ``$parse_float``."""
        return any(
            isinstance(instr, Call) and instr.callee_name == name
            for _fn, instr in walk_module(module)
        )

    def _uses_format_str(self, module: Module) -> bool:
        """True if any function / impl-method / lambda body contains
        a ``FormatStr`` instruction. Drives the emission of the
        ``$itoa`` helper (and pre-interning of ``"true"`` /
        ``"false"`` for Bool parts)."""
        return any(
            isinstance(instr, FormatStr)
            for _fn, instr in walk_module(module)
        )

    def _uses_string_codepoint_index(self, module: Module) -> bool:
        """True when any function in the module calls a String
        method whose Wasm emission now goes through the
        codepoint-counting / cp-to-byte-offset helpers. Slice 17
        (2026-05-29) switched ``length`` and ``substring`` from
        byte-indexing to code-point-indexing to match the Python
        runtime; the inline emit calls ``$str_codepoint_count`` /
        ``$str_cp_to_byte_offset``, which must therefore be
        present in the module when these methods appear.

        ``for c in s`` walks the receiver's UTF-8 code points but
        inlines the leading-byte classification, so the loop itself
        never needs these helpers -- only ``length`` / ``substring``
        calls do, wherever they appear (match-arm guard preludes
        included: a guard like ``x if x.length() > 0`` puts the
        ``length()`` call in the guard's ANF prelude)."""
        for _fn, instr in walk_module(module):
            if isinstance(instr, MethodCall):
                recv_ty = instr.receiver.ty or ""
                if recv_ty == "String" and instr.method in (
                    "length", "substring",
                ):
                    return True
        return False

    def _uses_random(self, module: Module) -> bool:
        """True if the module needs the SplitMix64 helpers + the
        ``$rand_state`` global. Triggered by either a ``Random()``
        constructor call (``Call(callee_name="Random")``) or a
        ``MethodCall`` on a Random-typed receiver (``with_seed``,
        ``int_range``, ``float_unit``).

        Mirrors the WIT-side rule in
        ``capa.ir._emit_wit.collect_used_capabilities``: any Random
        touch-point pulls in the ``system-seed`` host import via
        the lazy-init path."""
        for _fn, instr in walk_module(module):
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
        return False

    def _uses_map_ops(self, module: Module) -> bool:
        """True if the module needs the ``$str_eq`` helper. After
        the M4 key generalisation, the Map gate is restricted to
        Map<String, V>: Int/Bool key maps compare with native
        ``i64.eq`` / ``i32.eq`` and never call ``$str_eq``. The
        helper is still emitted for any String-method that relies
        on byte-string equality (contains / starts_with / ends_with /
        index_of / replace / split) and for List<String>.contains /
        Set<String>.{add,contains,remove}."""
        for _fn, instr in walk_module(module):
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
                    "index_of", "replace", "split",
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
                # ``_emit_binop`` String branch). The shared walk
                # reaches the comparison wherever it lives --
                # impl-method body, lifted-lambda body (e.g. an
                # Option.map closure doing ``s == "retry"``), or a
                # match-arm guard prelude.
                if (instr.left.ty == "String"
                        or instr.right.ty == "String"):
                    return True
            if isinstance(instr, Match):
                # String-scrutinee match calls $str_eq per arm.
                if (instr.scrutinee.ty or "") == "String":
                    return True
                # Any arm pattern carrying a String literal sub-pattern
                # compares that slot against the interned literal via
                # $str_eq: a tuple element (``("yes", x)``), a variant
                # payload (flat ``Ok("yes")`` / nested
                # ``Some(Ok("y"))``), a struct field (``P { name:
                # "bob" }``), or any composition. Without this the
                # module would emit a $str_eq call it never imported
                # and wasm-tools parse would refuse with "unknown func:
                # failed to find name $str_eq".
                for arm in instr.arms:
                    if _pattern_has_str_literal(arm.pattern):
                        return True
        return False

    def _uses_string_order_cmp(self, module: Module) -> bool:
        """True if any ``<`` / ``>`` / ``<=`` / ``>=`` BinOp has a
        String operand (Bug #2). These lower to a ``call $str_cmp``,
        so the helper must be emitted whenever the gate fires -- in
        any function body, lifted-lambda body (a ``sorted_by``
        comparator closure is the common case), or match-arm guard
        prelude that the shared module walk reaches."""
        for _fn, instr in walk_module(module):
            if (isinstance(instr, BinOp)
                    and instr.op in ("<", ">", "<=", ">=")
                    and (instr.left.ty == "String"
                         or instr.right.ty == "String")):
                return True
        return False

    def _uses_string_concat(self, module: Module) -> bool:
        """True if any ``+`` BinOp has a String operand. These lower
        to a ``call $str_concat`` (see ``_emit_string_concat``), so
        the runtime helper must be present in the module whenever the
        gate fires -- in any function body, lifted-lambda body, or
        match-arm guard prelude the shared module walk reaches."""
        for _fn, instr in walk_module(module):
            if (isinstance(instr, BinOp)
                    and instr.op == "+"
                    and (instr.left.ty == "String"
                         or instr.right.ty == "String")):
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

        Covers every impl-method body and every ``MakeLambda``
        body via the shared module walk, so the cap calls inside
        impl methods (e.g. ``self.stdio.println(...)`` in
        ``impl Logger for StdioLogger``) and inside closures
        contribute their imports + string literals to the module
        just like top-level function bodies.

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
        workaround (Python backend or refactor the call site).

        2026-07: the same scan now covers every member of
        ``PYTHON_ONLY_CAPS``, so ``Serve`` gets the identical early,
        site-listing rejection."""
        self._reject_python_only_cap_signatures(module)
        for fn in iter_functions(module):
            self._discover_instrs(fn.body)

    def _reject_python_only_cap_signatures(self, module: Module) -> None:
        """Reject a program whose signatures reach a member of
        ``PYTHON_ONLY_CAPS`` (``Unsafe``, ``Serve``), naming the
        capability, why it can never work here, what to do instead,
        and the offending sites.

        The scan itself lives in
        [`_python_only_caps.py`](../_python_only_caps.py) because WIT
        generation needs exactly the same predicate and is reachable
        on its own (``capa --wit`` never runs this discovery pass).
        Two copies of a security-relevant reachability check would
        drift silently, so there is one.

        Raising early matters: pre-2026-05 the rejection happened deep
        in cap-method dispatch ("capability method Unsafe.alloc has no
        WIT/Wasm encoding yet; widen the signature tables"), which read
        as a backlog item rather than the permanent stance it is.
        """
        found = find_rejection(module)
        if found is not None:
            _cap, message = found
            raise WasmEmissionError(message)

    def _discover_instrs(self, instrs: list[Instr]) -> None:
        for instr in walk_instrs(instrs):
            # Capability classification is single-sourced with the WIT
            # collector in ``capa.ir._cap_discovery.classify_cap_method``:
            # it resolves the receiver cap (``cap_used`` else a built-in
            # receiver type) and drops the attenuators elided at emit
            # time -- ``restrict_to`` / ``restrict_to_keys`` /
            # ``restrict_to_after`` that did NOT graduate to a real host
            # call (audit slices 25.2 - 25.6). What is left is projected
            # here to the core-wasm host-import set.
            classified = classify_cap_method(instr)
            if classified is not None:
                cap, method = classified
                if cap not in BUILTIN_CAPS:
                    raise WasmEmissionError(
                        f"Phase 6B: capability {cap!r} not in the "
                        f"built-in set; user-defined capabilities "
                        f"land in a later phase"
                    )
                # SplitMix64 runs entirely guest-side; the user-facing
                # Random methods (``with_seed`` / ``int_range`` /
                # ``float_unit``) have no WIT signature and no host
                # import, they only pull the lazy ``system-seed`` import
                # (also registered below for an unseeded ``Random()``).
                if cap == "Random" and method in (
                    "with_seed", "int_range", "float_unit",
                ):
                    self._used_caps.add(("Random", "system_seed"))
                else:
                    # Every other kept method (the graduated attenuators
                    # and the GAP-2b ``allows`` host route included) must
                    # have a matching WIT/Wasm signature, or the module
                    # would import a host function nobody defines.
                    key = (cap, method)
                    if key not in _WIT_SIGNATURES:
                        raise WasmEmissionError(
                            f"Phase 6B: capability method {cap}.{method} "
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
            # Match-arm pattern literals: a String literal inside an
            # arm pattern is compared against its interned copy via
            # $str_eq at match-emit time, which happens AFTER the data
            # segment is frozen. ``walk_instrs`` descends into an arm's
            # guard prelude and body but never ``arm.pattern``, and
            # ``_values_of`` enumerates no pattern slot (a
            # ``PatLiteral.value`` is a bare str, not a Value), so the
            # loops above miss these. Intern each here -- at any nesting
            # depth (variant payload / tuple element / struct field /
            # or-alternative) -- so the literal always has a backing
            # ``(data ...)`` block. Without this a pattern-only literal
            # (the scrutinee is heap-built and the bytes appear nowhere
            # else) gets an offset past ``heap_start`` and reads
            # dangling memory: a silent wrong branch or a spurious match
            # (C-F2).
            if isinstance(instr, Match):
                for arm in instr.arms:
                    for text in _pattern_str_literals(arm.pattern):
                        self._intern_string(text)

    @staticmethod
    def _values_of(instr: Instr) -> list[Value]:
        """Return every Value-typed slot on ``instr`` so the
        discovery pass can intern string literals reachable from
        anywhere in the function body, not just the few sites the
        previous pass enumerated by hand.

        Delegates to the shared ``_free_vars.values_of`` so the string-
        interning walk and the free-variable walk enumerate an
        instruction's value operands from one source."""
        return values_of(instr)
