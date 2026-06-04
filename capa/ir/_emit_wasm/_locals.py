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
    MakeLambda, MakeList, MakeMap, MakeRange, MakeSet, MakeTuple,
    PatIdent, PatVariant,
)
from .._lower_pattern import PatStruct
from .._capa_types import BUILTIN_CAPS
from ._layout import (
    _element_type_of_list, _element_type_of_set, _map_key_type,
    WasmEmissionError,
)
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
        has_range = False
        has_list_contains_i64 = False
        # List<Float>.contains stashes the f64 needle in
        # ``$_alloc_tmp_f64`` and compares with ``f64.eq`` (mirrors
        # the Set<Float> membership path); the i64 scratch would
        # type-mismatch the f64 needle and bit-eq the wrong NaN.
        has_list_contains_f64 = False
        has_map = False
        # Map with a pointer-shape key (struct / sum / tuple) needs
        # the dedicated $_alloc_tmp_key_ptr scratch so the linear
        # scan can stash the canonical i32 key pointer without
        # clobbering the value-packing $_alloc_tmp_i64 or the
        # generic $_alloc_tmp slot the data-array initialisation
        # already consumes.
        has_map_pointer_key = False
        has_string_method = False
        has_format_str = False
        has_make_lambda = False
        has_list_hof = False
        has_json_method = False
        has_json_parse = False
        has_list_string = False
        has_optres_method = False
        has_list_method = False
        has_set_method = False
        # Set whose element type lowers to an i32 heap pointer
        # (struct / sum / tuple / nested collection): add / contains
        # / remove scan via the element's $eq_* helper, stashing the
        # needle pointer in $_alloc_tmp.
        has_set_string = False
        has_set_pointer = False
        has_tuple = False
        # Set when any Match in this function has an Int scrutinee.
        # Int values are i64, so the i32 ``$_m_scrut`` cannot hold
        # them; the Int match path stashes the scrutinee in a
        # dedicated i64 local instead.
        has_int_match = False
        # Set when any Match in this function has a Float scrutinee.
        # Float values are f64, so neither the i32 ``$_m_scrut`` nor
        # the i64 ``$_m_scrut_i64`` can hold them; the Float match
        # path stashes the scrutinee in a dedicated f64 local.
        has_float_match = False
        # Set when any Int ``a % b`` BinOp appears. The Wasm emitter
        # corrects ``i64.rem_s`` to Python's floored modulo via a
        # scratch ``$_alloc_tmp_i64`` slot; declare it on demand.
        has_int_modulo = False
        # Set when any Int ``a + b`` / ``a - b`` / ``a * b`` BinOp
        # appears. The Wasm emitter's overflow-detecting variant
        # (audit fix C2) stashes both operands and the candidate
        # result in three dedicated i64 scratch locals; declare them
        # on demand so functions without arithmetic stay slim.
        has_int_overflow_check = False
        # Set when any capability method in this function uses
        # canonical-ABI indirect return; drives the ``$_ret_area``
        # scratch local declaration.
        has_indirect_cap_call = False
        # Set when any MethodCall is a ``.allows(dynamic_arg)`` on
        # Fs / Env / Db / Proc with a non-empty ``attenuations``
        # list. Drives declaration of the ``$_atten_path_*`` and
        # ``$_atten_ok`` scratch locals the dynamic-arg runtime
        # check needs (literal-arg ``.allows()`` collapses to a
        # const at emit time and needs no locals). Privileged ops
        # moved to the host handle table in slice 25; their
        # emit-time inline check is gone, so the ``$_atten_*``
        # locals are only declared on demand for the still-inline
        # ``.allows()`` dynamic-arg path.
        has_attenuation_check = False
        # ``$_atten_match`` is the per-Env-restrict_to_keys
        # OR-chain scratch; declared only when an Env attenuation
        # surface is present.
        has_attenuation_env_check = False
        # Audit fix C1: List indexing emits an inline ``i32.ge_u``
        # bounds-check trap; the wrapped-i32 idx is stashed in
        # ``$_bounds_idx`` so the check and the subsequent address
        # compute can both read it without re-evaluating the IR
        # Value. String.substring emits an equivalent guard against
        # ``start > end`` / ``end > recv.len`` / negative bounds
        # (the latter via the unsigned compare). No extra scratch is
        # needed for substring beyond what _str_start / _str_end
        # already provide.
        has_list_index_bounds = False
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
            nonlocal has_match, has_variant_ctor, has_list, has_for, has_range
            nonlocal has_list_contains_i64, has_list_contains_f64
            nonlocal has_map, has_string_method
            nonlocal has_format_str, has_make_lambda, has_list_hof
            nonlocal has_json_method, has_json_parse
            nonlocal has_list_string, has_optres_method
            nonlocal has_list_method, has_set_method
            nonlocal has_set_string, has_set_pointer
            nonlocal has_tuple, has_int_match, has_float_match, has_int_modulo
            nonlocal has_int_overflow_check
            nonlocal cur_for_depth, max_for_depth
            nonlocal has_indirect_cap_call
            nonlocal has_attenuation_check, has_attenuation_env_check
            nonlocal has_list_index_bounds
            nonlocal has_map_pointer_key
            for instr in instrs:
                if isinstance(instr, Match):
                    has_match = True
                    # String-scrutinee match emits $str_eq calls and
                    # reuses the String-method scratch (_str_a_*).
                    if (instr.scrutinee.ty or "") == "String":
                        has_string_method = True
                    # Int-scrutinee match stashes the i64 scrutinee in
                    # ``$_m_scrut_i64`` (the i32 ``$_m_scrut`` cannot
                    # hold an i64).
                    if (instr.scrutinee.ty or "") == "Int":
                        has_int_match = True
                    # Float-scrutinee match stashes the f64 scrutinee
                    # in ``$_m_scrut_f64``.
                    if (instr.scrutinee.ty or "") == "Float":
                        has_float_match = True
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
                    # Struct-scrutinee match: a PatStruct arm binds
                    # named fields; refine fn.locals with each field's
                    # declared type (from the struct layout) so the
                    # local-decl sweep allocates the right Wasm shape
                    # (i64 for Int, f64 for Float, i32 for Bool /
                    # pointer-shape, String _ptr/_len pair). Recurses
                    # into nested struct fields.
                    struct_head = (instr.scrutinee.ty or "").split("<", 1)[0]
                    struct_head = struct_head.split("[", 1)[0]
                    struct_layout = self._struct_layouts.get(struct_head)
                    if struct_layout is not None:
                        for arm in instr.arms:
                            self._refine_struct_pat_binds(
                                arm.pattern, struct_layout, fn,
                            )
                    for arm in instr.arms:
                        # Guard preludes can introduce BinOps too
                        # (audit fix C2 lowers Int +/-/* through the
                        # overflow-detecting variant which needs
                        # ``$_ovf_*`` scratch locals); the guard runs
                        # before the arm body so its instructions must
                        # be swept along with the body.
                        if getattr(arm, "guard_setup", None):
                            visit(arm.guard_setup)
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
                    if recv_ty.startswith("List"):
                        # Audit fix C1: List indexing emits an inline
                        # bounds check before the address compute; the
                        # wrapped i32 idx is stashed in $_bounds_idx so
                        # the check and the address compute can both
                        # read it without re-evaluating the IR Value.
                        has_list_index_bounds = True
                if isinstance(instr, MakeMap):
                    has_map = True
                if isinstance(instr, MakeSet):
                    # MakeSet allocates a header + element data array;
                    # the data-array base pointer is stashed in
                    # $_alloc_tmp during init (same as MakeList /
                    # MakeMap).
                    has_set_method = True
                if isinstance(instr, MakeLambda):
                    has_make_lambda = True
                if isinstance(instr, For):
                    has_for = True
                    # for x in someList<String> / someSet<String>
                    # unpacks each packed-i64 element into the bind's
                    # (ptr, len) pair via $_alloc_tmp_i64.
                    iter_ty = instr.iter.ty or ""
                    iter_elem = ""
                    if iter_ty.startswith("List"):
                        iter_elem = _element_type_of_list(iter_ty)
                    elif iter_ty.startswith("Set"):
                        iter_elem = _element_type_of_set(iter_ty)
                    elif iter_ty.startswith("Range"):
                        # Range iter's bind is the induction var,
                        # always Int; declare the per-loop scratch
                        # locals once via the has_range flag below.
                        iter_elem = "Int"
                        has_range = True
                    if iter_elem == "String":
                        has_list_string = True
                    # Refine the for-binder's type from the iter's
                    # element type when the analyzer left it Unknown.
                    # The analyzer types List for-binders precisely but
                    # leaves Set for-binders Unknown; the iter element
                    # type is authoritative, so use it to fix fn.locals
                    # before the local-decl sweep allocates the wrong
                    # Wasm shape (e.g. a bare $name i64 instead of the
                    # $name_ptr / $name_len String pair).
                    if iter_elem and iter_elem not in ("Unknown", "?"):
                        cur = fn.locals.get(instr.name, "")
                        if (cur in ("", "Unknown", "?", "Any")
                                or cur.startswith("?")):
                            fn.locals[instr.name] = iter_elem
                    cur_for_depth += 1
                    if cur_for_depth > max_for_depth:
                        max_for_depth = cur_for_depth
                    visit(instr.body)
                    cur_for_depth -= 1
                if isinstance(instr, MakeRange):
                    # The Range record is allocated through ``$alloc``;
                    # no per-instruction scratch beyond $_alloc_tmp.
                    has_range = True
                if isinstance(instr, FormatStr):
                    has_format_str = True
                if isinstance(instr, TryUnwrap):
                    # The `?` lowering stashes the receiver in
                    # $_m_scrut and the packed-i64 in $_alloc_tmp_i64
                    # for String payload unpacking. Both locals are
                    # declared via has_match + the i64-scratch group.
                    has_match = True
                if isinstance(instr, BinOp) and instr.op in ("%", "/"):
                    # Int ``%`` lowers to a floored-modulo correction
                    # (``i64.rem_s`` then sign-adjust against the
                    # divisor), and Int ``/`` lowers to a floored-
                    # division correction (``i64.div_s`` then subtract 1
                    # against the divisor); both need ``$_alloc_tmp_i64``
                    # as scratch. Skip when either operand is Float (the
                    # Float ``/`` path emits a bare ``f64.div`` and the
                    # Float ``%`` path uses the f64.floor formula, neither
                    # of which touches the i64 stash).
                    lt = (instr.left.ty or "")
                    rt = (instr.right.ty or "")
                    if lt != "Float" and rt != "Float":
                        has_int_modulo = True
                if isinstance(instr, BinOp) and instr.op == "+":
                    # String concatenation reuses the same _str_*
                    # scratch locals as the String methods. The
                    # operand type tells us; both operands have
                    # type String when concat applies.
                    if (instr.left.ty == "String"
                            or instr.right.ty == "String"):
                        has_string_method = True
                if isinstance(instr, BinOp) and instr.op in ("+", "-", "*"):
                    # Int +/-/* lower through the overflow-detecting
                    # variant (audit fix C2), which needs three i64
                    # scratch locals ($_ovf_a / $_ovf_b / $_ovf_r).
                    # Float arithmetic stays on the plain f64 path
                    # without the check; String + is detected above.
                    lt = (instr.left.ty or "")
                    rt = (instr.right.ty or "")
                    if (lt != "Float" and rt != "Float"
                            and lt != "String" and rt != "String"):
                        has_int_overflow_check = True
                if isinstance(instr, MethodCall):
                    recv_ty = instr.receiver.ty or ""
                    if recv_ty.startswith("Map"):
                        has_map = True
                        # Pointer-shape key (struct / sum / tuple)
                        # uses $_alloc_tmp_key_ptr as the canonical
                        # i32 key stash. Mirrors the $_alloc_tmp_key_i64
                        # gate for Int keys: declared only when needed
                        # so scalar-key Map programs stay slim.
                        key_ty = _map_key_type(recv_ty)
                        if key_ty and self._is_pointer_shape_ty(key_ty):
                            has_map_pointer_key = True
                    if recv_ty == "String":
                        has_string_method = True
                    if instr.cap_used and (
                        (instr.cap_used, instr.method)
                        in _CANONICAL_INDIRECT_RETURN
                    ):
                        has_indirect_cap_call = True
                    # Capability attenuation check: the privileged
                    # ops (Fs.read / Net.get / ...) moved to the
                    # host handle table in slice 25 and no longer
                    # need any emit-time inline check or scratch
                    # locals. Only the dynamic-arg path of
                    # ``cap.allows(path)`` on Fs / Env / Db / Proc
                    # still emits an inline runtime check (the
                    # literal-arg path collapses to a const), so
                    # the ``$_atten_path_*`` / ``$_atten_ok``
                    # scratch is declared only when that pattern
                    # appears. Env attenuations additionally use
                    # ``$_atten_match`` for the per-restrict_to_keys
                    # OR-chain.
                    if getattr(instr, "attenuations", None):
                        cap = instr.cap_used or ""
                        m = instr.method
                        if (cap in ("Fs", "Env", "Db", "Proc")
                                and m == "allows"
                                and instr.args
                                and instr.args[0].kind != "lit_str"):
                            has_attenuation_check = True
                            if cap == "Env":
                                has_attenuation_env_check = True
                    if recv_ty.startswith("List"):
                        # List method calls (push / contains / get
                        # / length / is_empty / ...) reuse $_m_scrut
                        # and $_m_tag as their list-pointer and
                        # length scratch.
                        has_list_method = True
                    if recv_ty.startswith("Set"):
                        # Set method calls (add / remove / contains /
                        # length / is_empty / to_list) reuse $_m_scrut
                        # (set pointer) and $_m_tag (scan index), and
                        # the grow / shift paths use $_alloc_tmp +
                        # $_alloc_tmp_newcap.
                        has_set_method = True
                        elem_ty = _element_type_of_set(recv_ty)
                        if elem_ty == "String":
                            # Set<String> add / contains / remove
                            # compare via $str_eq using the shared
                            # $_str_a_* / $_str_b_* scratch pairs.
                            has_set_string = True
                            has_string_method = True
                        elif self._is_pointer_shape_ty(elem_ty):
                            # Set<pointer-shape> stashes the needle
                            # pointer in $_alloc_tmp and compares via
                            # the element's $eq_* helper.
                            has_set_pointer = True
                        if elem_ty == "String" or self._size_of(elem_ty) == 8:
                            # String packs into i64; Int needles stash
                            # in $_alloc_tmp_i64.
                            has_list_contains_i64 = True
                        if instr.method == "to_list":
                            # to_list allocates a List<T>; ensure the
                            # list-method scratch group is declared.
                            has_list_method = True
                    if instr.method == "contains" and recv_ty.startswith("List"):
                        elem_ty = _element_type_of_list(recv_ty)
                        if elem_ty == "Float":
                            # f64 needle scratch + f64.eq path.
                            has_list_contains_f64 = True
                        elif self._size_of(elem_ty) == 8:
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
                        # Slice 6 (2026-05): map / and_then / filter /
                        # or_else / map_err invoke a closure. The
                        # emitter stashes the closure value in
                        # $_lam_fn_tmp and the per-T payload in the
                        # _str_a_* / _alloc_tmp_i64 / _alloc_tmp_f64
                        # scratch locals (same wire shape as
                        # List.map). Re-uses the has_list_hof
                        # declarations rather than carving a parallel
                        # set; the scratch lives in stack scope
                        # anyway so two HOFs in one function don't
                        # collide.
                        if instr.method in (
                            "map", "and_then", "filter",
                            "or_else", "map_err",
                        ):
                            has_list_hof = True
                    if instr.method == "split" and recv_ty == "String":
                        # split returns List<String>; uses _alloc_tmp_i64
                        # for the per-chunk packing dance.
                        has_list_string = True
                    if (instr.method in ("index_of", "char_at")
                            and recv_ty == "String"):
                        # D3 slice 4 (2026-05): index_of returns
                        # Option<Int> and char_at returns Option<String>.
                        # Both allocate a fresh 16-byte Option record
                        # in $_alloc_tmp_result; char_at additionally
                        # packs the (ptr, len) payload via the same
                        # $_alloc_tmp_i64 dance List<String> uses.
                        has_optres_method = True
                        if instr.method == "char_at":
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
                        # Post-slice-15 (2026-05-29): the bounds
                        # check is at i64 width, so the same
                        # ``$_bounds_idx_i64`` scratch the trap-
                        # style Index path uses also gets declared
                        # here.
                        has_optres_method = True
                        has_list = True
                        has_list_index_bounds = True
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
                    # carry no Wasm value; skip declaration EXCEPT
                    # for Fs / Net / Db / Proc / Env / Clock
                    # (slices 25.2 - 25.6) which are i32 handles
                    # so a restricted cap survives crossing function
                    # boundaries.
                    if capa_ty in BUILTIN_CAPS:
                        if capa_ty in (
                            "Fs", "Net", "Db", "Proc", "Env", "Clock",
                        ):
                            out[dst] = "i32"
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
                # Slices 25.2 - 25.6 (2026-05-30): Fs / Net / Db /
                # Proc / Env / Clock are un-erased; every other cap
                # stays as a no-Wasm-value.
                if capa_ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    out[name] = "i32"
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
        if has_match or has_for or has_list_method or has_set_method:
            out["_m_scrut"] = "i32"
            out["_m_tag"] = "i32"
        if has_set_method:
            # Set scan / append / shift reuse $_m_scrut (set pointer)
            # and $_m_tag (scan index). add's grow path doubles the
            # data array via $_alloc_tmp (new data ptr) and
            # $_alloc_tmp_newcap (new capacity); remove's tail-shift
            # uses the same address-math scratch. Pointer-shape /
            # scalar needles also stash in $_alloc_tmp. Set<Float>
            # additionally stashes the f64 needle in
            # $_alloc_tmp_f64 (audit fix 2026-05-29 post-slice-15;
            # pre-fix the f64 needle was set into the i64 slot
            # which crashed the wasm verifier on the first use).
            out["_alloc_tmp"] = "i32"
            out.setdefault("_alloc_tmp_newcap", "i32")
            out.setdefault("_alloc_tmp_f64", "f64")
        if has_set_string:
            # Set<String> compares via $str_eq, stashing the needle
            # pair in $_str_b_* and the scanned element in $_str_a_*.
            for name in (
                "_str_a_ptr", "_str_a_len",
                "_str_b_ptr", "_str_b_len",
            ):
                out.setdefault(name, "i32")
        if has_set_pointer:
            # Set<pointer-shape> stashes the needle pointer in
            # $_alloc_tmp (declared above via has_set_method).
            out.setdefault("_alloc_tmp", "i32")
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
        if has_range:
            # Range iter / MakeRange: scratch for the for-loop's
            # exit-compare (loaded once at loop top) and for the
            # MakeRange allocation. The induction variable itself
            # lives in the bind name's own i64 local (declared by
            # the analyzer / lowerer's locals map). Depth-indexed
            # so nested ``for o in 1..=3 { for p in 0..o { ... } }``
            # doesn't have the inner loop's end-compare clobber
            # the outer's (manifested as the outer loop running
            # only its first iteration's worth of inner work).
            depth = max(max_for_depth, 1)
            for d in range(depth):
                out[f"_range_end_i64_{d}"] = "i64"
                out[f"_range_incl_i32_{d}"] = "i32"
            # MakeRange uses $alloc; declare $_alloc_tmp so the
            # struct allocation has somewhere to stash the result
            # ptr alongside other linear-memory writes.
            out.setdefault("_alloc_tmp", "i32")
        if has_match:
            # Nested PatVariant arms (depth 1) stash the inner
            # scrutinee pointer here; flat arms never touch it.
            out["_m_scrut_inner"] = "i32"
        if has_int_match:
            # Int-scrutinee match: the scrutinee is an i64 and cannot
            # live in the i32 ``$_m_scrut``, so it gets a dedicated
            # i64 stash local.
            out["_m_scrut_i64"] = "i64"
        if has_float_match:
            # Float-scrutinee match: the scrutinee is an f64 and
            # cannot live in either the i32 ``$_m_scrut`` or the i64
            # ``$_m_scrut_i64``; it gets a dedicated f64 stash local.
            out["_m_scrut_f64"] = "f64"
        if (has_variant_ctor or has_list or has_map or has_indirect_cap_call
                or has_list_method):
            # ``has_list_method`` (any List method call: push / contains /
            # get / ...) is gated here too because the push grow path and
            # the contains scan stash the new-data / needle pointer in
            # ``$_alloc_tmp``. Previously this only fired via ``has_list``
            # (a ``MakeList`` in the body), so a function that received a
            # ``List`` as a parameter and merely pushed to it never got
            # ``$_alloc_tmp`` declared and the WAT referenced an unknown
            # local. The String / i64 element variants pull in the i64
            # scratch via ``has_list_string`` / ``has_list_contains_i64``,
            # which are element-type driven and fire for parameters too.
            out["_alloc_tmp"] = "i32"
        if has_indirect_cap_call:
            # The canonical-ABI lowering for capability calls with
            # composite return types allocates a per-call return
            # area; the materialiser reads flat fields from it. One
            # local serves every call site (calls do not overlap).
            out["_ret_area"] = "i32"
        if has_int_overflow_check:
            # Audit fix C2: the overflow-detecting +/-/* path stashes
            # both operands and the candidate result in three
            # dedicated i64 scratch locals so the predicate
            # (((a^r) & (b^r)) < 0 etc.) can be evaluated purely
            # against locals while the stack stays well-formed.
            out["_ovf_a"] = "i64"
            out["_ovf_b"] = "i64"
            out["_ovf_r"] = "i64"
        if (has_list_contains_i64 or has_map or has_match or has_for
                or has_variant_ctor or has_json_method or has_list_string
                or has_optres_method or has_tuple or has_int_modulo):
            # The i64 scratch is shared by: List.contains for i64
            # elements, Map scan (value packing), match-arm String
            # unpacking, for-iter over List<String> (packed i64
            # slot), variant-construction (String payload packing),
            # JsonValue as_X projection, and List<String>
            # construction / indexing / split (per-element packing).
            out["_alloc_tmp_i64"] = "i64"
        if has_list_contains_f64:
            # List<Float>.contains stashes the f64 needle here and
            # compares each f64-loaded element with ``f64.eq``
            # (Python-matching NaN semantics: NaN != NaN).
            out.setdefault("_alloc_tmp_f64", "f64")
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
            # Map.set's value stash. The key generalisation lets Int
            # keys live in $_alloc_tmp_key_i64, so the value cannot
            # share $_alloc_tmp_i64 (the String-value packing dance
            # consumes that slot). A dedicated i64 local keeps the
            # (key, value) pair co-resident across the linear scan.
            out["_alloc_tmp_set_value"] = "i64"
            # Dedicated Int-key canonical stash. Distinct from
            # $_alloc_tmp_i64 so a Map<Int, String> set / get
            # operation can pack the String value without clobbering
            # the key before the scan compare.
            out["_alloc_tmp_key_i64"] = "i64"
        if has_map_pointer_key:
            # Dedicated pointer-key canonical stash. The pointer-
            # shape key path (Map<Point, V> / Map<(Int, Int), V> /
            # Map<Option<Int>, V>) writes the i32 key pointer into
            # $_alloc_tmp_key_ptr so the linear-scan $eq_* helper
            # can read the same operand from a stable local without
            # clobbering $_alloc_tmp (data-array base pointer) or
            # $_alloc_tmp_set_value (the packed-i64 value stash).
            out["_alloc_tmp_key_ptr"] = "i32"
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
            # captures). String captures additionally route through
            # the ``$_str_a_*`` pair to flip operand-stack order
            # between ``_push_string_value_as_ptr_len`` (leaves ptr
            # then len) and the per-field stores (need ptr first
            # then len at offset+4, both alongside env_tmp).
            out["_lam_env_tmp"] = "i32"
            out.setdefault("_str_a_ptr", "i32")
            out.setdefault("_str_a_len", "i32")
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
            # second operand (needle / prefix / suffix), one for a
            # third operand (replace's ``new`` argument), plus index,
            # start, end, new_ptr, new_len, byte, and count registers.
            for name in (
                "_str_a_ptr", "_str_a_len",
                "_str_b_ptr", "_str_b_len",
                "_str_c_ptr", "_str_c_len",
                "_str_i", "_str_start", "_str_end",
                "_str_new_ptr", "_str_new_len",
                "_str_byte", "_str_count",
                # Slice 17 (2026-05-29): String.substring stashes
                # the code-point count once for the bounds check
                # so we don't walk the string a third time.
                "_str_cp_count",
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
            # Dynamic-arg ``.allows()`` check stashes the path/
            # name in ``$_atten_path_*`` and accumulates the
            # predicate into ``$_atten_ok``. Env-specific OR-chain
            # against the key list uses ``$_atten_match``.
            out["_atten_path_ptr"] = "i32"
            out["_atten_path_len"] = "i32"
            out["_atten_ok"] = "i32"
            if has_attenuation_env_check:
                out["_atten_match"] = "i32"
        if has_list_index_bounds:
            # Audit fix C1: ``$_bounds_idx`` holds the wrapped-i32
            # index for the inline bounds check in ``_emit_index``.
            # Stashing lets the check (``i32.ge_u`` against len) and
            # the address compute (``data_ptr + idx * elem_size``)
            # both consume the same wrapped value without
            # re-evaluating the IR ``Value`` for the index.
            #
            # Post-slice-15 (2026-05-29): the bounds check now
            # validates the i64 idx against ``0 <= i < len``
            # BEFORE wrapping, so negative i64s whose low 32 bits
            # land in-bounds (e.g. ``-2**32``) trap instead of
            # silently returning ``xs[0]``. ``$_bounds_idx_i64``
            # is the i64 scratch the check reads.
            out["_bounds_idx"] = "i32"
            out["_bounds_idx_i64"] = "i64"
        if has_optres_method:
            # Option/Result method dispatch stashes the receiver
            # pointer in $_m_scrut so the tag check + payload load
            # can both read it. List.get also reuses this flag to
            # build its Option<T> result via $_alloc_tmp_result.
            out.setdefault("_m_scrut", "i32")
            out.setdefault("_m_tag", "i32")
            out.setdefault("_alloc_tmp_result", "i32")
        return out

    def _refine_struct_pat_binds(
        self, pattern, struct_layout: dict, fn: Function,
    ) -> None:
        """Thread a struct pattern's field types into ``fn.locals`` so
        the local-decl sweep allocates the right Wasm shape for each
        bound field. Shorthand ``{ y }`` and explicit ``{ y: y }``
        both arrive as a PatIdent sub-pattern named after the binder;
        nested ``{ at: Point { x } }`` recurses with the nested
        struct's layout. Literal / wildcard fields bind nothing."""
        if not isinstance(pattern, PatStruct):
            return
        for fname, sub in pattern.fields:
            f_info = struct_layout["fields"].get(fname)
            if f_info is None:
                continue
            _off, _sz, field_ty = f_info
            if isinstance(sub, PatIdent):
                cur = fn.locals.get(sub.name, "")
                if (cur in ("", "Unknown", "?", "Any")
                        or cur.startswith("?")):
                    if field_ty and field_ty not in ("Unknown", "Any"):
                        fn.locals[sub.name] = field_ty
            elif isinstance(sub, PatStruct):
                nested = self._struct_layouts.get(
                    field_ty.split("<", 1)[0].split("[", 1)[0],
                )
                if nested is not None:
                    self._refine_struct_pat_binds(sub, nested, fn)
