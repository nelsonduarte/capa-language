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

import re

from .._nodes import (
    Module, Instr, Value, Function,
    BinOp, Call, MethodCall, FormatStr, Match,
    MakeList, MakeMap, MakeSet, MakeLambda,
    PatIdent, PatLiteral, PatTuple, PatVariant,
)
from .._capa_types import BUILTIN_CAPS
from .._emit_wit import _WIT_SIGNATURES
from .._walk import iter_functions, walk_instrs, walk_module
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
                # fresh List<T>; both need the heap.
                if recv_ty.startswith("Set") and instr.method in ("add", "to_list"):
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

    def _uses_panic(self, module: Module) -> bool:
        """Gates the ``capa:host/panic`` import emission. A
        user-defined ``panic`` shadows the builtin (the user
        function is emitted and called instead), matching the
        Python backend and the parse_int rule above."""
        if any(fn.name == "panic" for fn in module.functions):
            return False
        return self._uses_builtin_free_fn(module, "panic")

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
        on byte-string equality (contains / starts_with /
        ends_with) and for List<String>.contains /
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
        workaround (Python backend or refactor the call site)."""
        self._reject_unsafe_signatures(module)
        for fn in iter_functions(module):
            self._discover_instrs(fn.body)

    @staticmethod
    def _type_name_tokens(ty: str) -> set[str]:
        """Every type-name identifier appearing in a CIR type
        string, including generic args and tuple elements. A simple
        word scan is sound for the Unsafe reachability check: the
        only false positives would be a user type whose name happens
        to be a substring of another, which the ``\\b`` boundaries
        rule out."""
        if not ty:
            return set()
        return set(re.findall(r"[A-Za-z_]\w*", ty))

    def _unsafe_bearing_type_names(self, module: Module) -> set[str]:
        """Fixpoint set of struct / sum type names that
        transitively reach ``Unsafe`` through a field or variant
        payload, so a parameter of such a type is rejected even
        when ``Unsafe`` never appears literally in the signature
        (audit 2026-06-17 C5(b))."""
        field_tys: dict[str, list[str]] = {}
        for decl in module.types:
            fields = getattr(decl, "fields", None)
            if fields is not None:
                field_tys[decl.name] = [f.ty for f in fields]
                continue
            variants = getattr(decl, "variants", None)
            if variants is not None:
                field_tys[decl.name] = [
                    pty for v in variants for pty in v.payload_tys
                ]
        bearing: set[str] = set()
        changed = True
        while changed:
            changed = False
            for name, tys in field_tys.items():
                if name in bearing:
                    continue
                for ty in tys:
                    toks = self._type_name_tokens(ty)
                    if "Unsafe" in toks or toks & bearing:
                        bearing.add(name)
                        changed = True
                        break
        return bearing

    def _reject_unsafe_signatures(self, module: Module) -> None:
        """Surface ``Unsafe``-reaching parameters at discovery time
        with a diagnostic that names the function, the parameter,
        and the only two valid responses (run on the Python
        backend, or remove the Unsafe argument). Scans both
        top-level functions and impl methods.

        Audit 2026-06-17 C5(b): the check walks each param type
        RECURSIVELY through named struct fields, sum-variant
        payloads, and generic arguments, so a param of a type that
        merely *contains* Unsafe (``type Wrapper { u: Unsafe }``)
        is rejected loud rather than slipping through to emit an
        invalid ``call $py_import``. Mirrors the manifest's
        reachability traversal: Unsafe is detected wherever it is
        reachable through the type, not only as a literal head."""
        unsafe_bearing = self._unsafe_bearing_type_names(module)

        def reaches_unsafe(ty: str) -> bool:
            for name in self._type_name_tokens(ty):
                if name == "Unsafe" or name in unsafe_bearing:
                    return True
            return False

        offenders: list[str] = []
        for fn in module.functions:
            for p in fn.params:
                if reaches_unsafe(p.ty):
                    offenders.append(f"{fn.name}({p.name}: {p.ty})")
        for impl in module.impls:
            impl_label = (
                f"impl {impl.trait_name} for {impl.type_name}"
                if impl.trait_name else f"impl {impl.type_name}"
            )
            for method in impl.methods:
                for p in method.params:
                    if reaches_unsafe(p.ty):
                        offenders.append(
                            f"{impl_label}::{method.name}"
                            f"({p.name}: {p.ty})"
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
        for instr in walk_instrs(instrs):
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
                    # GAP-2b (2026-06-21): Fs.allows / Env.allows /
                    # Db.allows / Proc.allows / Net.allows route
                    # through the authoritative host function
                    # ``$<Cap>_allows(handle, arg) -> bool`` (the same
                    # host-route ``Clock.allows`` already used).
                    # Register the host import so the linker resolves
                    # the callback. No string pre-interning is needed
                    # anymore: the arg travels guest->host as a normal
                    # ``(ptr, len)`` string, so the host-route embeds
                    # nothing statically (this is what fixes the
                    # dynamic-prefix gap and the silent Env divergence).
                    self._used_caps.add((cap, "allows"))
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
