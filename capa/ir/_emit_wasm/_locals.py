"""Per-function local-variable discovery for the Wasm backend.

The Wasm spec requires every local to be declared up-front at the
top of a function, before any body instruction. ``_collect_locals``
walks the IR of a single function and infers the full local set:
- ANF temporaries from ``Instr.dst`` slots,
- iteration / accumulation scratch the various emitters need
  (``$_m_scrut``, ``$_f_list_N``, ``$_str_a_*``, ``$_alloc_tmp``,
  ``$_ret_area``, ...),
- pattern-binder renames the lowerer introduced (``c__s17``).

Each branch carries a short comment on why a given scratch is
declared; together they document the cross-mixin coupling.

Extracted from ``__init__.py`` in May 2026 because
``_collect_locals`` was the single largest method in the file and
its concern (declaring locals) is wholly distinct from the
per-instruction emit dispatch that lives in ``__init__``.
"""

from __future__ import annotations

from .._nodes import (
    Function, Instr, Value,
    BinOp, Call, MethodCall, TryUnwrap, For, FormatStr,
    If, While, Match, Index,
    MakeLambda, MakeList, MakeMap, MakeTuple,
    PatIdent, PatVariant,
)
from .._capa_types import BUILTIN_CAPS
from ._layout import _element_type_of_list, WasmEmissionError
from ._caps import _CANONICAL_INDIRECT_RETURN


class _LocalsCollectionMixin:
    def _collect_locals(
        self, fn: Function, param_names: set[str],
    ) -> dict[str, str]:
        """Walk every instruction in the function body and gather
        the set of local names (with their Wasm types) that need
        to be declared at the top of the function. Param names are
        excluded because Wasm treats params as locals already.

        Also reserves the match-helper locals ``$_m_scrut`` and
        ``$_m_tag`` if any Match instruction appears in the body;
        emitted Match code reuses these without per-instance unique
        names (sequential and nested matches do not overlap their
        live ranges of these locals)."""
        out: dict[str, str] = {}
        has_match = False
        has_variant_ctor = False
        has_list = False
        has_for = False
        has_list_contains_i64 = False
        has_map = False
        has_string_method = False
        has_format_str = False
        has_make_lambda = False
        has_list_hof = False
        has_json_method = False
        has_json_parse = False
        has_list_string = False
        has_optres_method = False
        has_list_method = False
        has_tuple = False
        # Set when any capability method in this function uses
        # canonical-ABI indirect return; drives the ``$_ret_area``
        # scratch local declaration.
        has_indirect_cap_call = False
        # Set when any MethodCall carries a non-empty ``attenuations``
        # list (audit C2). Drives declaration of the
        # ``$_atten_*`` scratch locals the inline check needs.
        # Tracked separately from ``has_indirect_cap_call`` because
        # the Env attenuation check fires on Env.get whose ret_area
        # is option_string (12 bytes), not the 20-byte
        # result_string_io_error layout.
        has_attenuation_check = False
        has_attenuation_env_check = False
        has_atten_fs_write_check = False
        # Maximum nesting depth of For instructions. Nested for-loops
        # need distinct iteration scratch (``$_f_list_N`` /
        # ``$_f_idx_N``) so an inner loop doesn't clobber the outer
        # loop's state. ``cur_for_depth`` is the live depth during the
        # walk; ``max_for_depth`` is the watermark we declare for.
        cur_for_depth = 0
        max_for_depth = 0

        def value_uses_variant_ctor(v: Value) -> bool:
            return v is not None and v.kind == "variant_ctor"

        def visit(instrs: list[Instr]) -> None:
            nonlocal has_match, has_variant_ctor, has_list, has_for
            nonlocal has_list_contains_i64, has_map, has_string_method
            nonlocal has_format_str, has_make_lambda, has_list_hof
            nonlocal has_json_method, has_json_parse
            nonlocal has_list_string, has_optres_method
            nonlocal has_list_method, has_tuple
            nonlocal cur_for_depth, max_for_depth
            nonlocal has_indirect_cap_call
            nonlocal has_attenuation_check, has_attenuation_env_check
            nonlocal has_atten_fs_write_check
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    # String-scrutinee match emits $str_eq calls and
                    # reuses the String-method scratch (_str_a_*).
                    if (instr.scrutinee.ty or "") == "String":
                        has_string_method = True
                    # Refine binder types from the variant's payload
                    # layout. The analyzer's pattern-side type
                    # inference is incomplete for builtin sum types
                    # (JsonValue / Option / Result with non-Int
                    # payloads), leaving the binder as Unknown. The
                    # sum layout always knows the payload type, so
                    # use it to fix fn.locals before any local-decl
                    # emission consumes the (wrong) Unknown type.
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
                                if (cur in ("", "Unknown", "?")
                                        or cur.startswith("?")
                                        or cur == "Any"):
                                    if payload_ty and payload_ty != "Any":
                                        fn.locals[sub_pat.name] = payload_ty
                    # String-scrutinee match: PatIdent arm binds the
                    # whole scrutinee to a String local. The emitter
                    # writes to ${name}_ptr / ${name}_len; refine
                    # fn.locals so the local-decl sweep allocates the
                    # pair instead of a default-i64 ``$name``.
                    if (instr.scrutinee.ty or "") == "String":
                        for arm in instr.arms:
                            if isinstance(arm.pattern, PatIdent):
                                cur = fn.locals.get(arm.pattern.name, "")
                                if (cur in ("", "Unknown", "?")
                                        or cur.startswith("?")):
                                    fn.locals[arm.pattern.name] = "String"
                    # Tuple-scrutinee match: a PatTuple arm with
                    # PatIdent sub-patterns binds each tuple slot;
                    # refine fn.locals with the per-position element
                    # type so the local-decl sweep picks the right
                    # Wasm shape (i64 for Int, f64 for Float, String
                    # _ptr/_len pair, pointer-shape i32, ...).
                    s_ty = instr.scrutinee.ty or ""
                    if (s_ty.startswith("(") and s_ty.endswith(")")
                            and s_ty != "()"):
                        from ._tuples import _tuple_elem_types
                        elem_tys = _tuple_elem_types(s_ty)
                        for arm in instr.arms:
                            if not hasattr(arm.pattern, "elements"):
                                continue
                            for idx, sub in enumerate(arm.pattern.elements):
                                if not isinstance(sub, PatIdent):
                                    continue
                                ety = (elem_tys[idx]
                                       if idx < len(elem_tys)
                                       else "Unknown")
                                cur = fn.locals.get(sub.name, "")
                                if (cur in ("", "Unknown", "?")
                                        or cur.startswith("?")):
                                    if ety and ety != "Unknown":
                                        fn.locals[sub.name] = ety
                        # Tuple match unpacks String slots via the
                        # packed-i64 dance; ensure the i64 scratch
                        # is declared even if the function has no
                        # other String-producing instruction.
                        has_tuple = True
                    for arm in instr.arms:
                        visit(arm.body)
                if isinstance(instr, MakeTuple):
                    # MakeTuple's String-element path packs (ptr,
                    # len) into i64 via _alloc_tmp_i64; Index over
                    # a tuple's String slot unpacks via the same
                    # scratch.
                    has_tuple = True
                if isinstance(instr, MakeList):
                    has_list = True
                    # MakeList over String elements needs the i64
                    # scratch for the (ptr, len) -> packed-i64 dance.
                    dst_ty = fn.locals.get(instr.dst, "") if instr.dst else ""
                    if _element_type_of_list(dst_ty) == "String":
                        has_list_string = True
                if isinstance(instr, Index):
                    # Index over List<String> unpacks a packed i64
                    # via _alloc_tmp_i64. Same goes for tuple
                    # indices when the slot type is String.
                    recv_ty = instr.receiver.ty or ""
                    if (recv_ty.startswith("List")
                            and _element_type_of_list(recv_ty) == "String"):
                        has_list_string = True
                    if recv_ty.startswith("(") and recv_ty.endswith(")"):
                        has_tuple = True
                if isinstance(instr, MakeMap):
                    has_map = True
                if isinstance(instr, MakeLambda):
                    has_make_lambda = True
                if isinstance(instr, For):
                    has_for = True
                    cur_for_depth += 1
                    if cur_for_depth > max_for_depth:
                        max_for_depth = cur_for_depth
                    visit(instr.body)
                    cur_for_depth -= 1
                if isinstance(instr, FormatStr):
                    has_format_str = True
                if isinstance(instr, TryUnwrap):
                    # The `?` lowering stashes the receiver in
                    # $_m_scrut and the packed-i64 in $_alloc_tmp_i64
                    # for String payload unpacking. Both locals are
                    # declared via has_match + the i64-scratch group.
                    has_match = True
                if isinstance(instr, BinOp) and instr.op == "+":
                    # String concatenation reuses the same _str_*
                    # scratch locals as the String methods. The
                    # operand type tells us; both operands have
                    # type String when concat applies.
                    if (instr.left.ty == "String"
                            or instr.right.ty == "String"):
                        has_string_method = True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        has_map = True
                    if recv_ty == "String":
                        has_string_method = True
                    if instr.cap_used and (
                        (instr.cap_used, instr.method)
                        in _CANONICAL_INDIRECT_RETURN
                    ):
                        has_indirect_cap_call = True
                    # Capability attenuation check (audit C2):
                    # MethodCall with non-empty ``attenuations`` and
                    # a privileged op on Fs / Net / Env triggers
                    # ``_atten_*`` scratch local declarations.
                    if getattr(instr, "attenuations", None):
                        cap = instr.cap_used or ""
                        m = instr.method
                        if (cap == "Fs" and m in ("read", "write")) \
                                or (cap == "Net" and m in ("get", "post")) \
                                or (cap == "Env" and m == "get"):
                            has_attenuation_check = True
                            has_indirect_cap_call = True
                            if cap == "Env":
                                has_attenuation_env_check = True
                            if cap == "Fs" and m == "write":
                                has_atten_fs_write_check = True
                    if recv_ty.startswith("List"):
                        # List method calls (push / contains / get
                        # / length / is_empty / ...) reuse $_m_scrut
                        # and $_m_tag as their list-pointer and
                        # length scratch.
                        has_list_method = True
                    if instr.method == "contains" and recv_ty.startswith("List"):
                        elem_ty = _element_type_of_list(recv_ty)
                        if self._size_of(elem_ty) == 8:
                            has_list_contains_i64 = True
                        if elem_ty == "String":
                            # List<String>.contains needs the
                            # ``$str_eq`` byte-compare helper and
                            # the ``_str_a_*`` / ``_str_b_*``
                            # scratch pairs that the String
                            # methods already share.
                            has_string_method = True
                    if recv_ty.startswith("List") and instr.method in (
                        "map", "filter", "fold",
                    ):
                        has_list_hof = True
                    if recv_ty == "JsonValue":
                        has_json_method = True
                    if (recv_ty.startswith("Option")
                            or recv_ty.startswith("Result")):
                        has_optres_method = True
                    if instr.method == "split" and recv_ty == "String":
                        # split returns List<String>; uses _alloc_tmp_i64
                        # for the per-chunk packing dance.
                        has_list_string = True
                    if (instr.method == "push"
                            and recv_ty.startswith("List")
                            and _element_type_of_list(recv_ty) == "String"):
                        # List<String>.push packs (ptr, len) via
                        # _alloc_tmp_i64.
                        has_list_string = True
                    if (instr.method == "get"
                            and recv_ty.startswith("List")):
                        # List.get builds an Option<T> result and
                        # reuses _m_scrut / _m_tag / _alloc_tmp_result.
                        has_optres_method = True
                        has_list = True
                if isinstance(instr, Call):
                    if instr.callee_name == "parse_json":
                        # parse_json / to_json land as Capa-source
                        # function calls (``$__capa_parse_json`` /
                        # ``$__capa_to_json``); no host import, no
                        # extra scratch beyond what the parser
                        # bodies already declare via the normal
                        # variant / List / Map paths.
                        pass
                    elif instr.callee_name == "to_json":
                        pass
                    elif instr.callee_name in self._variant_to_sum:
                        # Variant-construction Call with payloads. The
                        # String payload path packs (ptr, len) via
                        # _alloc_tmp_i64; treat any payload-bearing
                        # variant call as variant_ctor for scratch-
                        # local purposes.
                        has_variant_ctor = True
                # Detect Values of kind variant_ctor anywhere; they
                # require the ``$_alloc_tmp`` local at emit time.
                for attr in ("src", "value", "left", "right",
                             "operand", "receiver", "iter", "cond"):
                    v = getattr(instr, attr, None)
                    if isinstance(v, Value) and value_uses_variant_ctor(v):
                        has_variant_ctor = True
                for v in getattr(instr, "args", []) or []:
                    if isinstance(v, Value) and value_uses_variant_ctor(v):
                        has_variant_ctor = True
                dst = getattr(instr, "dst", None)
                if dst and dst not in param_names and dst not in out:
                    # Look up the Capa type of this local from the
                    # function's locals map; fall back to Int if
                    # unknown (Phase 6A only sees Int / Bool, so
                    # this default is safe within the supported
                    # subset).
                    capa_ty = fn.locals.get(dst, "Int")
                    # Capability locals (``let other = stdio``)
                    # carry no Wasm value; skip declaration.
                    if capa_ty in BUILTIN_CAPS:
                        continue
                    # String locals expand to a (ptr, len) pair so
                    # the function can carry the value forward. The
                    # convention: ``$name_ptr`` + ``$name_len``, both
                    # i32. ``_push_string_local`` / ``_set_string_local``
                    # emit operations against the pair.
                    if capa_ty == "String":
                        out[f"{dst}_ptr"] = "i32"
                        out[f"{dst}_len"] = "i32"
                        continue
                    wasm_ty = self._wasm_type(capa_ty) or "i64"
                    out[dst] = wasm_ty
                # Recurse into nested instruction lists.
                if isinstance(instr, If):
                    visit(instr.then_body)
                    visit(instr.else_body)
                elif isinstance(instr, While):
                    visit(instr.cond_setup)
                    visit(instr.body)

        visit(fn.body)
        # Pattern-bound identifiers (Circle(r) -> binds r) and other
        # locals introduced by the lowerer but not visible as
        # ``Instr.dst`` (loop iter names, for-iter binds, etc.) live
        # in ``fn.locals``. Sweep them up so the Wasm function
        # declares everything it references.
        for name, capa_ty in fn.locals.items():
            if name in param_names or name in out:
                continue
            if capa_ty in BUILTIN_CAPS or capa_ty == "Unit":
                continue
            if capa_ty == "String":
                ptr_name = f"{name}_ptr"
                if ptr_name not in out:
                    out[ptr_name] = "i32"
                len_name = f"{name}_len"
                if len_name not in out:
                    out[len_name] = "i32"
                continue
            try:
                wasm_ty = self._wasm_type(capa_ty) or "i64"
            except WasmEmissionError as e:
                # Capa types that lack a Wasm encoding (commonly
                # unresolved type variables like ``T`` from a
                # generic user function) used to silently fall
                # back to ``i64``, which produced wasm that the
                # validator rejected with a confusing i32/i64
                # mismatch at runtime. Re-raise with a clearer
                # message so the user knows the actual gap.
                raise WasmEmissionError(
                    f"local {name!r} has type {capa_ty!r}, which the "
                    f"Wasm backend cannot encode. This is typically a "
                    f"generic / type-parameter case (e.g. ``fun "
                    f"first<T>(...)``); the Wasm backend does not yet "
                    f"monomorphise user-defined generic functions. "
                    f"Workarounds: use the Python backend "
                    f"(``capa --run``), or specialise the function "
                    f"to a concrete type. Original: {e}"
                ) from e
            out[name] = wasm_ty
        # ``_m_scrut`` / ``_m_tag`` are used by both Match and For
        # loops (they double as iter-pointer and index registers).
        # ``_alloc_tmp`` is used by variant-ctor pushes and by
        # MakeList for the data-array base pointer.
        if has_match or has_for or has_list_method:
            out["_m_scrut"] = "i32"
            out["_m_tag"] = "i32"
        if has_for:
            # For-loop owns its own scratch locals so a match in
            # the body can't clobber the iteration state. Nested
            # for-loops each need their own pair so the inner loop
            # doesn't overwrite the outer's list pointer / index;
            # we declare one pair per nesting depth observed in
            # the function body.
            for d in range(max_for_depth):
                out[f"_f_list_{d}"] = "i32"
                out[f"_f_idx_{d}"] = "i32"
        if has_match:
            # Nested PatVariant arms (depth 1) stash the inner
            # scrutinee pointer here; flat arms never touch it.
            out["_m_scrut_inner"] = "i32"
        if has_variant_ctor or has_list or has_map or has_indirect_cap_call:
            out["_alloc_tmp"] = "i32"
        if has_indirect_cap_call:
            # The canonical-ABI lowering for capability calls with
            # composite return types allocates a per-call return
            # area; the materialiser reads flat fields from it. One
            # local serves every call site (calls do not overlap).
            out["_ret_area"] = "i32"
        if (has_list_contains_i64 or has_map or has_match or has_for
                or has_variant_ctor or has_json_method or has_list_string
                or has_optres_method or has_tuple):
            # The i64 scratch is shared by: List.contains for i64
            # elements, Map scan (value packing), match-arm String
            # unpacking, for-iter over List<String> (packed i64
            # slot), variant-construction (String payload packing),
            # JsonValue as_X projection, and List<String>
            # construction / indexing / split (per-element packing).
            out["_alloc_tmp_i64"] = "i64"
        if has_map:
            # Match/For scratch locals double as Map scan helpers
            # (map_local, idx_local). Plus map-specific scratch.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out["_alloc_tmp_key_len"] = "i32"
            out["_alloc_tmp_pair"] = "i32"
            out["_alloc_tmp_newcap"] = "i32"
            out["_alloc_tmp_new_data"] = "i32"
            out["_alloc_tmp_result"] = "i32"
        if has_json_method:
            # JsonValue method emit reuses the match scrut local for
            # the receiver pointer and needs an Option-result alloc
            # slot. _alloc_tmp_i64 is needed for the as_int /
            # as_X paths. _alloc_tmp_f64 holds the f64 payload of a
            # JNum while ``as_int`` checks whether it is integer-
            # valued before constructing Some.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_alloc_tmp_result", "i32")
            out.setdefault("_alloc_tmp_i64", "i64")
            out.setdefault("_alloc_tmp_f64", "f64")
        if has_format_str:
            # FormatStr scratch: per-value (ptr, len) stashes plus
            # total-length / buffer / position registers.
            for i in range(8):
                out.setdefault(f"_fs_p{i}", "i32")
                out.setdefault(f"_fs_l{i}", "i32")
            out["_fs_total_len"] = "i32"
            out["_fs_buf"] = "i32"
            out["_fs_pos"] = "i32"
        if has_make_lambda:
            # MakeLambda emission uses ``$_lam_env_tmp`` as scratch
            # for the freshly-allocated env pointer (or 0 for no
            # captures).
            out["_lam_env_tmp"] = "i32"
        if has_list_hof:
            # List HOFs (map/filter/fold) need: a stash for the
            # closure value (i64), an iteration index, plus the
            # filter-path grow scratch. Non-Int element types also
            # need: a Float reinterpret slot ($_alloc_tmp_f64), and
            # the (ptr, len) String-unpack pair ($_str_a_ptr /
            # $_str_a_len) for List<String> map / filter / fold.
            # We over-declare here unconditionally rather than
            # second-pass detect the elem types -- the cost is two
            # i32 locals + one f64 per function that uses any HOF,
            # which is negligible.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp", "i32")
            out["_lam_fn_tmp"] = "i64"
            out["_lam_idx"] = "i32"
            out["_lam_grow_len"] = "i32"
            out["_lam_grow_cap"] = "i32"
            out["_lam_new_data"] = "i32"
            out.setdefault("_alloc_tmp_i64", "i64")
            out.setdefault("_alloc_tmp_f64", "f64")
            out.setdefault("_str_a_ptr", "i32")
            out.setdefault("_str_a_len", "i32")
        if has_string_method:
            # Scratch locals for the String method handlers. All i32:
            # one pair of (ptr, len) for the receiver, one for the
            # second operand (needle / prefix / suffix), plus index,
            # start, end, new_ptr, new_len, byte registers.
            for name in (
                "_str_a_ptr", "_str_a_len",
                "_str_b_ptr", "_str_b_len",
                "_str_i", "_str_start", "_str_end",
                "_str_new_ptr", "_str_new_len",
                "_str_byte",
            ):
                out.setdefault(name, "i32")
        if has_list_string:
            # split() reuses the match-helper $_m_tag as its chunk
            # counter; MakeList<String> and Index<List<String>>
            # rely on $_alloc_tmp + $_alloc_tmp_i64 already declared
            # by the variant_ctor / for-loop branches above.
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp", "i32")
        if has_attenuation_check:
            # Capability attenuation check (audit C2). Three i32
            # pairs: path/url/name (always), content (Fs.write only).
            # ``_atten_ok`` is the predicate accumulator; ``_atten_match``
            # is the per-Env-restrict_to_keys OR-chain scratch.
            out["_atten_path_ptr"] = "i32"
            out["_atten_path_len"] = "i32"
            out["_atten_ok"] = "i32"
            if has_atten_fs_write_check:
                out["_atten_content_ptr"] = "i32"
                out["_atten_content_len"] = "i32"
            if has_attenuation_env_check:
                out["_atten_match"] = "i32"
        if has_optres_method:
            # Option/Result method dispatch stashes the receiver
            # pointer in $_m_scrut so the tag check + payload load
            # can both read it. List.get also reuses this flag to
            # build its Option<T> result via $_alloc_tmp_result.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp_result", "i32")
        return out
