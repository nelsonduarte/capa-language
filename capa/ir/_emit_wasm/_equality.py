"""Structural equality (``==`` / ``!=``) for compound types.

The Python backend gives deep, by-value equality for compound values:
structs and sum variants are dataclasses (field-wise ``__eq__``), tuples
and lists compare element-wise, all recursively. The Wasm backend must
match that. Scalars (Int/Float/Bool) and String already compare by value
in ``_emit_binop`` (``i64.eq`` / ``f64.eq`` / ``i32.eq`` / ``$str_eq``);
this mixin adds the compound cases.

Strategy: generate one helper ``$eq_<key>(a i32, b i32) -> i32`` per
compound type that appears (transitively) under a ``==`` / ``!=`` or a
pointer-shape ``List.contains``. Each helper compares the two heap
records by value and returns 1 / 0. Helpers may call each other for
nested compound fields; WAT resolves ``call $name`` across the whole
module regardless of emission order, so no topological sorting is needed,
and Capa values are immutable + acyclic so the recursion terminates.

Leaf comparisons go through :meth:`_emit_leaf_compare`, which assumes the
two operands are already on the stack in canonical form (scalars: a, b;
String: a_ptr, a_len, b_ptr, b_len; pointer-shape: a_ptr, b_ptr) and
emits the comparing op. Each container kind is responsible for the LOAD
that puts operands in that canonical form, because the in-memory encoding
of, say, a String differs between a struct field (two adjacent i32s) and
a sum payload / tuple / list slot (packed i64).
"""

from __future__ import annotations

from .._nodes import BinOp, MethodCall, If, While, For, Match
from ._layout import (
    WasmEmissionError,
    _LIST_LEN_OFFSET, _LIST_DATA_OFFSET,
    _MAP_LEN_OFFSET, _MAP_DATA_OFFSET, _MAP_PAIR_SIZE,
    _MAP_PAIR_KEY_PTR_OFFSET, _MAP_PAIR_KEY_LEN_OFFSET,
    _MAP_PAIR_VALUE_OFFSET,
    _SET_LEN_OFFSET, _SET_DATA_OFFSET,
    _map_key_type, _map_value_type,
)


def _eq_key(ty: str) -> str:
    """Sanitise a Capa type string into a WAT-identifier-safe key.

    ``Point`` -> ``Point``; ``Option<Int>`` -> ``Option_Int``;
    ``List<Point>`` -> ``List_Point``; ``(Int, String)`` ->
    ``T_Int_String``. The mapping is injective enough for distinct
    concrete types to get distinct helper names."""
    out = []
    if ty.startswith("(") and ty.endswith(")"):
        out.append("T")
    for ch in ty:
        if ch.isalnum() or ch == "_":
            out.append(ch)
        elif ch in "<>(), ":
            out.append("_")
    # Collapse runs of underscores and strip the ends.
    key = "".join(out)
    while "__" in key:
        key = key.replace("__", "_")
    return key.strip("_")


class _EqualityMixin:
    def _is_tuple_ty(self, ty: str) -> bool:
        return ty.startswith("(") and ty.endswith(")") and ty != "()"

    def _normalize_eq_ty(self, ty: str) -> str:
        """Map a bare variant-name type to its owning sum type.

        A payloadless variant constructor (``let a = Red``) is typed
        by the analyzer as the variant name (``Red``) rather than the
        enclosing sum (``Color``); the structural-equality machinery
        keys everything off the sum type, so resolve the variant to
        its owner here. Non-variant types pass through unchanged."""
        head = ty.split("<", 1)[0]
        if head not in self._sum_layouts and head in self._variant_to_sum:
            return self._variant_to_sum[head]
        return ty

    def _is_compound_eq_ty(self, ty: str) -> bool:
        """True iff ``==`` on this type needs a generated structural
        helper (struct / sum / tuple / List / Map / Set). Scalars
        and String are handled inline in ``_emit_binop``.

        Map and Set go through generated helpers like List does: the
        helper iterates one operand and looks each key / element up
        in the other, so equality is order-independent in line with
        the Python backend (``dict`` equality is set-of-pairs and
        ``CapaSet.__eq__`` compares the backing dicts)."""
        head = ty.split("<", 1)[0]
        return (
            head in self._struct_layouts
            or head in self._sum_layouts
            or self._is_tuple_ty(ty)
            or head in ("List", "Map", "Set")
        )

    # ----- discovery -------------------------------------------------

    def _collect_eq_types(self, module) -> list[str]:
        """Return the concrete compound types needing an ``$eq_*``
        helper: every type used under a compound ``==`` / ``!=`` or a
        pointer-shape ``List.contains``, transitively closed over
        field / payload / element types."""
        seen: set[str] = set()
        order: list[str] = []

        def add(ty: str) -> None:
            if not self._is_compound_eq_ty(ty) or ty in seen:
                return
            seen.add(ty)
            order.append(ty)
            for sub in self._eq_subtypes(ty):
                add(sub)

        def visit(instrs) -> None:
            for instr in instrs:
                if isinstance(instr, BinOp) and instr.op in ("==", "!="):
                    lt = self._normalize_eq_ty(instr.left.ty or "")
                    rt = self._normalize_eq_ty(instr.right.ty or "")
                    cand = lt if self._is_compound_eq_ty(lt) else rt
                    if self._is_compound_eq_ty(cand):
                        add(cand)
                elif isinstance(instr, MethodCall) and instr.method == "contains":
                    elem = self._list_elem_ty(instr.receiver.ty or "")
                    if elem and self._is_pointer_shape_ty(elem):
                        add(elem)
                elif (isinstance(instr, MethodCall)
                        and instr.method in ("add", "contains", "remove")
                        and (instr.receiver.ty or "").startswith("Set")):
                    # Set<pointer-shape> dedup / membership / removal
                    # scans compare elements via the element's $eq_*
                    # helper, so pull it into the discovery set just
                    # like List.contains does.
                    elem = self._set_elem_ty(instr.receiver.ty or "")
                    if elem and self._is_pointer_shape_ty(elem):
                        add(elem)
                elif (isinstance(instr, MethodCall)
                        and instr.method in ("get", "set", "contains_key")
                        and (instr.receiver.ty or "").startswith("Map")):
                    # Map<pointer-shape, V> set / get / contains_key
                    # compares keys via the key's $eq_* helper, so
                    # pull it into the discovery set just like Set's
                    # add / contains / remove branch above. Scalar
                    # (String / Int / Bool) keys never need a helper.
                    key_ty = _map_key_type(instr.receiver.ty or "")
                    if key_ty and self._is_pointer_shape_ty(key_ty):
                        add(key_ty)
                # Recurse into nested instruction bodies (mirrors the
                # traversal in _discovery / _locals).
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
        return order

    def _eq_subtypes(self, ty: str) -> list[str]:
        """Compound types referenced one level down from ``ty`` (so
        discovery can transitively pull in the helpers they need).

        Struct fields, sum variant payloads (concrete, generics
        resolved), tuple elements, and List elements are all walked
        here; the return filters to compound types so scalars / String
        drop out."""
        head = ty.split("<", 1)[0]
        subs: list[str] = []
        if head in self._struct_layouts:
            for _name, (_off, _sz, fty) in self._struct_layouts[head]["fields"].items():
                subs.append(fty)
        elif head in self._sum_layouts:
            # Walk every variant's concrete payload types so nested
            # compound payloads (a Some(Point), an Ok(List<Int>))
            # transitively pull in their own helpers.
            layout = self._sum_layouts[head]
            for vname, (_tag, payloads) in layout["variants"].items():
                for i, (_off, _sz, _pty) in enumerate(payloads):
                    subs.append(self._resolve_sum_payload_ty(ty, vname, i))
        elif self._is_tuple_ty(ty):
            from ._tuples import _tuple_elem_types
            subs.extend(_tuple_elem_types(ty))
        elif head == "List":
            subs.append(self._list_elem_ty(ty))
        elif head == "Map":
            # ``$eq_Map_*`` compares keys via the canonical pair-key
            # compare (which calls ``$eq_<K>`` for pointer-shape K)
            # and values via the leaf compare (which calls
            # ``$eq_<V>`` for pointer-shape V). Both need to be
            # transitively reachable from the discovery walk so
            # their helpers are emitted before this one is called.
            subs.append(_map_key_type(ty))
            subs.append(_map_value_type(ty))
        elif head == "Set":
            # ``$eq_Set_*`` compares elements via the leaf compare,
            # which calls ``$eq_<elem>`` for pointer-shape elements.
            subs.append(self._set_elem_ty(ty))
        return [s for s in subs if self._is_compound_eq_ty(s)]

    def _list_elem_ty(self, ty: str) -> str:
        if ty.startswith("List<") and ty.endswith(">"):
            return ty[5:-1].strip()
        return ""

    def _set_elem_ty(self, ty: str) -> str:
        if ty.startswith("Set<") and ty.endswith(">"):
            return ty[4:-1].strip()
        return ""

    def _generic_args(self, ty: str) -> list[str]:
        """Split the generic arguments of ``ty`` at the top level.
        ``Option<Int>`` -> ``['Int']``; ``Result<Int, String>`` ->
        ``['Int', 'String']``; ``Map<String, List<Int>>`` ->
        ``['String', 'List<Int>']``. Returns [] when ``ty`` has no
        ``<...>`` args."""
        lt = ty.find("<")
        if lt < 0 or not ty.endswith(">"):
            return []
        inner = ty[lt + 1:-1].strip()
        if not inner:
            return []
        out: list[str] = []
        buf = ""
        depth = 0
        for ch in inner:
            if ch in "(<":
                depth += 1
            elif ch in ")>":
                depth -= 1
            if ch == "," and depth == 0:
                out.append(buf.strip())
                buf = ""
                continue
            buf += ch
        if buf.strip():
            out.append(buf.strip())
        return out

    def _resolve_sum_payload_ty(
        self, ty: str, variant: str, payload_idx: int,
    ) -> str:
        """Resolve the CONCRETE Capa type of a sum variant's payload.

        The sum layout stores the declared payload type, but built-in
        ``Option<T>`` / ``Result<T, E>`` use a uniform "Any" slot, so
        the concrete type has to come from ``ty``'s generic arguments
        (``Option<Int>`` -> Some's payload is ``Int``;
        ``Result<Int, String>`` -> Ok is ``Int``, Err is ``String``).
        User sums carry concrete payload types in the layout already,
        so we return those verbatim. A payload that genuinely cannot
        be resolved (an "Any" we can't map to a generic arg) raises
        rather than guessing."""
        head = ty.split("<", 1)[0]
        layout = self._sum_layouts[head]
        _tag, payloads = layout["variants"][variant]
        declared = payloads[payload_idx][2]
        if declared != "Any":
            return declared
        # Built-in Option / Result: map the variant + payload index to
        # a generic-argument position. Option<T>.Some -> arg 0;
        # Result<T, E>.Ok -> arg 0, Result<...>.Err -> arg 1.
        args = self._generic_args(ty)
        if head == "Option" and variant == "Some" and len(args) >= 1:
            return args[0]
        if head == "Result" and variant == "Ok" and len(args) >= 1:
            return args[0]
        if head == "Result" and variant == "Err" and len(args) >= 2:
            return args[1]
        raise WasmEmissionError(
            f"structural equality cannot resolve the concrete payload "
            f"type of {variant!r} (index {payload_idx}) in {ty!r}: the "
            f"layout slot is 'Any' and the generic arguments do not "
            f"supply it. Annotate the value's type so the Wasm backend "
            f"can pick the right leaf comparison."
        )

    def _eq_needs_str_eq(self, module) -> bool:
        """Whether any generated equality helper will compare a String
        leaf, so the caller knows to emit the shared ``$str_eq`` helper
        even when nothing else in the module uses it. Covers struct
        fields, sum variant payloads (generics resolved), tuple
        elements, and List elements."""
        for ty in self._collect_eq_types(module):
            head = ty.split("<", 1)[0]
            if head in self._struct_layouts:
                for _n, (_o, _s, fty) in self._struct_layouts[head]["fields"].items():
                    if fty == "String":
                        return True
            elif head in self._sum_layouts:
                layout = self._sum_layouts[head]
                for vname, (_tag, payloads) in layout["variants"].items():
                    for i in range(len(payloads)):
                        if self._resolve_sum_payload_ty(ty, vname, i) == "String":
                            return True
            elif self._is_tuple_ty(ty):
                from ._tuples import _tuple_elem_types
                if "String" in _tuple_elem_types(ty):
                    return True
            elif head == "List":
                if self._list_elem_ty(ty) == "String":
                    return True
            elif head == "Map":
                # Map<String, _> compares keys via ``$str_eq``;
                # Map<_, String> compares values via ``$str_eq``.
                if (_map_key_type(ty) == "String"
                        or _map_value_type(ty) == "String"):
                    return True
            elif head == "Set":
                # Set<String> compares elements via ``$str_eq``.
                if self._set_elem_ty(ty) == "String":
                    return True
        return False

    # ----- emission --------------------------------------------------

    def _emit_equality_helpers(self, module) -> None:
        """Emit every ``$eq_*`` helper this module needs. Called from
        the runtime-helper block, before user functions."""
        for ty in self._collect_eq_types(module):
            self._emit_eq_helper(ty)

    def _emit_eq_helper(self, ty: str) -> None:
        head = ty.split("<", 1)[0]
        if head in self._struct_layouts:
            self._emit_struct_eq(ty)
        elif head in self._sum_layouts:
            self._emit_sum_eq(ty)
        elif self._is_tuple_ty(ty):
            self._emit_tuple_eq(ty)
        elif head == "List":
            self._emit_list_eq(ty)
        elif head == "Map":
            self._emit_map_eq(ty)
        elif head == "Set":
            self._emit_set_eq(ty)
        else:
            raise WasmEmissionError(
                f"structural equality for {ty!r} is not supported"
            )

    def _emit_struct_eq(self, ty: str) -> None:
        """``$eq_<Struct>(a, b) -> i32``: AND of per-field compares,
        short-circuiting to 0 on the first mismatch."""
        name = _eq_key(ty)
        layout = self._struct_layouts[ty.split("<", 1)[0]]
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        self._write("block $eq_done (result i32)")
        self._indent += 1
        from .._capa_types import BUILTIN_CAPS
        for _fname, (offset, size, fty) in layout["fields"].items():
            if fty in BUILTIN_CAPS:
                # Capability fields are erased at the Wasm level and
                # carry no value to compare.
                continue
            self._emit_struct_field_eq(offset, size, fty)
            # Stack now holds the field's i32 0/1 result.
            self._write("i32.eqz")
            self._write("if")
            self._indent += 1
            self._write("i32.const 0")
            self._write("br $eq_done")
            self._indent -= 1
            self._write("end")
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_struct_field_eq(self, offset: int, size: int, fty: str) -> None:
        """Push ``a``'s and ``b``'s field at ``offset`` in canonical
        operand form, then emit the leaf compare (leaves i32 0/1)."""
        if fty == "String":
            # Struct String fields are two adjacent i32s: ptr@offset,
            # len@offset+4 (see _emit_make_struct / _emit_field_access).
            self._write("local.get $a")
            self._write(f"i32.load offset={offset}")
            self._write("local.get $a")
            self._write(f"i32.load offset={offset + 4}")
            self._write("local.get $b")
            self._write(f"i32.load offset={offset}")
            self._write("local.get $b")
            self._write(f"i32.load offset={offset + 4}")
            self._emit_leaf_compare("String")
            return
        if fty == "Float":
            self._write("local.get $a")
            self._write(f"f64.load offset={offset}")
            self._write("local.get $b")
            self._write(f"f64.load offset={offset}")
            self._emit_leaf_compare("Float")
            return
        # Int (i64, size 8), Bool (i32, size 4), and pointer-shape
        # (i32 pointer, size 4) all load with the size-appropriate op;
        # the leaf compare picks the right comparison.
        load = "i64.load" if size == 8 else "i32.load"
        self._write("local.get $a")
        self._write(f"{load} offset={offset}")
        self._write("local.get $b")
        self._write(f"{load} offset={offset}")
        self._emit_leaf_compare(fty)

    def _emit_leaf_compare(self, ty: str) -> None:
        """Emit the comparison op for two operands already on the
        stack in canonical form (scalars: a, b; String: a_ptr a_len
        b_ptr b_len; pointer-shape: a_ptr b_ptr). Leaves i32 0/1."""
        head = ty.split("<", 1)[0]
        if ty in ("Int", "Unknown", "") or ty.startswith("?"):
            self._write("i64.eq")
            return
        if ty == "Bool":
            self._write("i32.eq")
            return
        if ty == "Float":
            self._write("f64.eq")
            return
        if ty == "String":
            self._write("call $str_eq")
            return
        if self._is_compound_eq_ty(ty):
            # All compound leaves (struct / sum / tuple / List /
            # Map / Set) route through their generated ``$eq_*``
            # helper. The dispatch in ``_emit_eq_helper`` produces
            # the helper; the discovery walk in ``_eq_subtypes``
            # transitively pulls in nested compound types (e.g.
            # a Map<K, V> with a pointer-shape V) so the helper
            # call always resolves.
            self._write(f"call $eq_{_eq_key(ty)}")
            return
        raise WasmEmissionError(
            f"structural equality leaf for type {ty!r} is not supported"
        )

    # ----- dispatch from _emit_binop ---------------------------------

    def _emit_compound_eq(self, instr: BinOp, op: str, ty: str) -> None:
        """Handle ``a == b`` / ``a != b`` for a compound operand type
        (``ty``, already resolved by the caller): push both pointers,
        call the type's ``$eq_*`` helper, negate for ``!=``, bind the
        i32 result."""
        self._push_value(instr.left)
        self._push_value(instr.right)
        self._write(f"call $eq_{_eq_key(ty)}")
        if op == "!=":
            self._write("i32.eqz")
        self._write(f"local.set ${instr.dst}")

    # ----- sum / tuple / List helpers --------------------------------

    def _emit_sum_eq(self, ty: str) -> None:
        """``$eq_<key>(a, b) -> i32``: compare tags, then (if they
        match) compare the matched variant's payloads field-wise.

        The two records carry their discriminant at offset 0; a tag
        mismatch is an immediate 0. When the tags agree we dispatch on
        the tag value via an if/elif chain (one ``if tag == T`` per
        variant) and AND-short-circuit the variant's payload compares.
        A payloadless variant is equal once the tags match.

        Payload slots are the uniform 8-byte sum slot (mirrors
        ``_bind_variant_payload`` in _match.py): String is a packed
        i64 (low 32 = ptr, high 32 = len), pointer-shape is an
        i64-extended pointer narrowed with ``i32.wrap_i64``, Bool is
        an i64-extended i32, Float is an f64, Int is a raw i64."""
        name = _eq_key(ty)
        head = ty.split("<", 1)[0]
        layout = self._sum_layouts[head]
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        # Scratch for unpacking packed-i64 String payloads. Module-
        # level helpers must declare every local they reference; the
        # struct helper needs none because struct Strings are two
        # adjacent i32s, but sum payloads are packed i64s.
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("block $eq_done (result i32)")
        self._indent += 1
        # Tag mismatch is an instant non-match.
        self._write("local.get $a")
        self._write("i32.load")
        self._write("local.get $b")
        self._write("i32.load")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Tags are equal; dispatch on a's tag to the matching variant
        # and compare its payloads. A variant with no payloads needs
        # no body (tags matching already proves equality).
        for vname, (tag, payloads) in layout["variants"].items():
            if not payloads:
                continue
            self._write("local.get $a")
            self._write("i32.load")
            self._write(f"i32.const {tag}")
            self._write("i32.eq")
            self._write("if")
            self._indent += 1
            for i, (offset, _size, _pty) in enumerate(payloads):
                pty = self._resolve_sum_payload_ty(ty, vname, i)
                self._emit_sum_payload_eq(offset, pty)
                self._write("i32.eqz")
                self._write("if")
                self._indent += 1
                self._write("i32.const 0")
                self._write("br $eq_done")
                self._indent -= 1
                self._write("end")
            self._indent -= 1
            self._write("end")
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_sum_payload_eq(self, offset: int, pty: str) -> None:
        """Push ``a``'s and ``b``'s payload at ``offset`` in canonical
        operand form for ``_emit_leaf_compare``. The slot is the
        uniform 8-byte sum payload (see ``_bind_variant_payload``)."""
        if pty == "String":
            # Packed i64 (low 32 = ptr, high 32 = len); unpack each
            # operand into a (ptr, len) pair on the stack. Done
            # inline rather than via the unpack helper because we
            # need the four operands in stack order a_ptr a_len
            # b_ptr b_len, not stashed in locals.
            self._emit_unpack_sum_string_operand("$a", offset)
            self._emit_unpack_sum_string_operand("$b", offset)
            self._emit_leaf_compare("String")
            return
        if pty == "Float":
            self._write("local.get $a")
            self._write(f"f64.load offset={offset}")
            self._write("local.get $b")
            self._write(f"f64.load offset={offset}")
            self._emit_leaf_compare("Float")
            return
        if pty == "Bool" or self._is_pointer_shape_ty(pty):
            # Bool and pointer-shape both live i64-extended in the
            # uniform slot; narrow back to i32 so the leaf compare
            # (i32.eq for Bool, call $eq_* for pointer-shape) gets
            # i32 operands.
            self._write("local.get $a")
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._write("local.get $b")
            self._write(f"i64.load offset={offset}")
            self._write("i32.wrap_i64")
            self._emit_leaf_compare(pty)
            return
        # Int (and Unknown defaulting to Int): raw i64 in the slot.
        self._write("local.get $a")
        self._write(f"i64.load offset={offset}")
        self._write("local.get $b")
        self._write(f"i64.load offset={offset}")
        self._emit_leaf_compare(pty)

    def _emit_unpack_sum_string_operand(self, local: str, offset: int) -> None:
        """Push (ptr, len) for the packed-i64 String payload of
        ``local`` ($a / $b) at ``offset``. Leaves two i32s on the
        stack: ptr (low 32), then len (high 32). Uses
        ``$_alloc_tmp_i64`` as scratch."""
        self._write(f"local.get {local}")
        self._write(f"i64.load offset={offset}")
        self._write("local.tee $_alloc_tmp_i64")
        self._write("i32.wrap_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")

    def _emit_tuple_eq(self, ty: str) -> None:
        """``$eq_<key>(a, b) -> i32``: AND of per-element compares,
        short-circuiting to 0 on the first mismatch. Element slots are
        the tuple's uniform 8-byte slots at offset ``i * 8`` (mirrors
        ``_emit_tuple_index`` in _tuples.py)."""
        from ._tuples import _tuple_elem_types
        name = _eq_key(ty)
        elem_tys = _tuple_elem_types(ty)
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        # Scratch for unpacking packed-i64 String elements (tuple
        # slots share the sum-payload packed encoding).
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("block $eq_done (result i32)")
        self._indent += 1
        for idx, ety in enumerate(elem_tys):
            self._emit_tuple_elem_eq(idx * 8, ety)
            self._write("i32.eqz")
            self._write("if")
            self._indent += 1
            self._write("i32.const 0")
            self._write("br $eq_done")
            self._indent -= 1
            self._write("end")
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_tuple_elem_eq(self, offset: int, ety: str) -> None:
        """Push ``a``'s and ``b``'s tuple element at ``offset`` in
        canonical operand form, then the leaf compare. Tuple slots
        use the same packed encoding as sum payloads, so the loads
        are identical."""
        # The packed encoding is byte-for-byte the sum payload slot,
        # so reuse the sum payload load idiom.
        self._emit_sum_payload_eq(offset, ety)

    def _emit_list_eq(self, ty: str) -> None:
        """``$eq_<key>(a, b) -> i32``: compare lengths, then walk
        both data arrays element-wise. A length mismatch is an
        instant 0; otherwise we loop ``i`` over ``[0, len)`` loading
        ``a[i]`` and ``b[i]`` (stride ``_size_of(elem)``) and
        comparing each via ``_emit_leaf_compare``. The first mismatch
        returns 0; surviving the loop returns 1.

        Element slots follow ``_emit_index`` in _lists.py: String is
        a packed i64, pointer-shape / Bool live in 4-byte i32 slots,
        Int / Float in 8-byte slots."""
        name = _eq_key(ty)
        elem_ty = self._list_elem_ty(ty)
        elem_size = self._size_of(elem_ty)
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        # Module-level helper locals: the loop index and the
        # packed-i64 String unpack scratch. Data pointers are
        # re-read from each header per element to avoid burning
        # extra named locals.
        self._write("(local $_eq_list_i i32)")
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("block $eq_done (result i32)")
        self._indent += 1
        # Length mismatch -> 0.
        self._write("local.get $a")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("local.get $b")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Loop i in [0, len): compare a[i] vs b[i].
        self._write("i32.const 0")
        self._write("local.set $_eq_list_i")
        self._block_counter += 1
        loop_label = f"$EQL{self._block_counter}_loop"
        self._write(f"loop {loop_label}")
        self._indent += 1
        # Continue only while i < len(a) (lengths are equal here).
        self._write("local.get $_eq_list_i")
        self._write("local.get $a")
        self._write(f"i32.load offset={_LIST_LEN_OFFSET}")
        self._write("i32.lt_s")
        self._write("if")
        self._indent += 1
        self._emit_list_elem_eq(elem_ty, elem_size)
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # i += 1; back-branch.
        self._write("local.get $_eq_list_i")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_eq_list_i")
        self._write(f"br {loop_label}")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write("end")
        # Walked every element without a mismatch.
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")
        self._indent -= 1
        self._write(")")

    def _emit_list_elem_eq(self, elem_ty: str, elem_size: int) -> None:
        """Push ``a[i]`` and ``b[i]`` in canonical operand form (the
        index lives in ``$_eq_list_i``), then the leaf compare. The
        element address is ``data_ptr + i * elem_size``; ``data_ptr``
        is re-read from each list header per call."""
        if elem_ty == "String":
            # Packed i64 element; unpack each into (ptr, len).
            self._emit_unpack_list_string_operand("$a", elem_size)
            self._emit_unpack_list_string_operand("$b", elem_size)
            self._emit_leaf_compare("String")
            return
        if elem_ty == "Float":
            self._emit_push_list_elem_addr("$a", elem_size)
            self._write("f64.load")
            self._emit_push_list_elem_addr("$b", elem_size)
            self._write("f64.load")
            self._emit_leaf_compare("Float")
            return
        # Int (8-byte i64), Bool (4-byte i32), pointer-shape (4-byte
        # i32 pointer). The size-dispatched load yields the canonical
        # operand directly: i64 for Int, i32 for Bool / pointer-shape.
        load_op = "i64.load" if elem_size == 8 else "i32.load"
        self._emit_push_list_elem_addr("$a", elem_size)
        self._write(load_op)
        self._emit_push_list_elem_addr("$b", elem_size)
        self._write(load_op)
        self._emit_leaf_compare(elem_ty)

    def _emit_push_list_elem_addr(self, local: str, elem_size: int) -> None:
        """Push the address of element ``$_eq_list_i`` of the list in
        ``local`` ($a / $b): ``data_ptr + i * elem_size``."""
        self._write(f"local.get {local}")
        self._write(f"i32.load offset={_LIST_DATA_OFFSET}")
        self._write("local.get $_eq_list_i")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")

    def _emit_unpack_list_string_operand(self, local: str, elem_size: int) -> None:
        """Push (ptr, len) for the packed-i64 String element at
        ``$_eq_list_i`` of the list in ``local``. Leaves ptr then len
        (two i32s) on the stack; uses ``$_alloc_tmp_i64`` as scratch."""
        self._emit_push_list_elem_addr(local, elem_size)
        self._write("i64.load")
        self._write("local.tee $_alloc_tmp_i64")
        self._write("i32.wrap_i64")
        self._write("local.get $_alloc_tmp_i64")
        self._write("i64.const 32")
        self._write("i64.shr_u")
        self._write("i32.wrap_i64")

    # ----- Map / Set equality ----------------------------------------

    def _emit_map_eq(self, ty: str) -> None:
        """``$eq_<key>(a, b) -> i32`` for ``Map<K, V>``: order-
        independent equality. A length mismatch is an instant 0.
        Otherwise walk ``a``'s pairs in insertion order; for each
        ``pair_a`` stash its key in the canonical key-scratch slots
        (so the existing ``_emit_compare_pair_key_to`` helper from
        ``_maps`` can compare it against any pair in ``b``), then
        inner-loop over ``b``'s pairs looking for a matching key.
        On match, compare values via ``_emit_map_pair_value_compare``;
        a value mismatch is an instant 0. Falling off the inner loop
        without finding the key is an instant 0. Surviving the outer
        loop is 1.

        Map values are uniform 8-byte slots at
        ``_MAP_PAIR_VALUE_OFFSET``; the value decoder loads both
        pair-slot i64s, decodes them per V (bit-reinterpret to f64
        for Float, wrap to i32 for Bool / pointer-shape, unpack to
        (ptr, len) for String), and routes through
        ``_emit_leaf_compare``."""
        name = _eq_key(ty)
        key_ty = _map_key_type(ty)
        value_ty = _map_value_type(ty)
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        # Outer / inner indices and pair-base scratch (i32). Plus the
        # i64 scratch used by the value-decode dance (Float / String).
        # The canonical-key scratch slots ($_alloc_tmp_key_i64 etc.)
        # are declared so this helper is self-contained even when the
        # enclosing function has no other Map / Set use.
        self._write("(local $_eq_map_i_a i32)")
        self._write("(local $_eq_map_i_b i32)")
        self._write("(local $_eq_map_pair_a i32)")
        self._write("(local $_eq_map_pair_b i32)")
        self._write("(local $_alloc_tmp i32)")
        self._write("(local $_alloc_tmp_key_len i32)")
        self._write("(local $_alloc_tmp_key_ptr i32)")
        self._write("(local $_alloc_tmp_key_i64 i64)")
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("(local $_eq_map_val_a i64)")
        self._write("(local $_eq_map_val_b i64)")
        self._write("block $eq_done (result i32)")
        self._indent += 1
        # Length mismatch -> 0.
        self._write("local.get $a")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("local.get $b")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Outer loop: i_a in [0, len_a).
        self._write("i32.const 0")
        self._write("local.set $_eq_map_i_a")
        self._block_counter += 1
        outer_loop = f"$EQM{self._block_counter}_outer"
        outer_exit = f"$EQM{self._block_counter}_outer_exit"
        inner_loop = f"$EQM{self._block_counter}_inner"
        inner_exit = f"$EQM{self._block_counter}_inner_exit"
        self._write(f"block {outer_exit}")
        self._indent += 1
        self._write(f"loop {outer_loop}")
        self._indent += 1
        # if i_a >= len_a -> outer done.
        self._write("local.get $_eq_map_i_a")
        self._write("local.get $a")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {outer_exit}")
        # pair_a = a.data + i_a * pair_size
        self._write("local.get $a")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write("local.get $_eq_map_i_a")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_eq_map_pair_a")
        # Stash pair_a's key into the canonical key scratch slots so
        # _emit_compare_pair_key_to can dispatch against it.
        self._emit_map_stash_pair_key(key_ty, "_eq_map_pair_a")
        # Inner loop: i_b in [0, len_b). Need a match.
        self._write("i32.const 0")
        self._write("local.set $_eq_map_i_b")
        self._write(f"block {inner_exit}")
        self._indent += 1
        self._write(f"loop {inner_loop}")
        self._indent += 1
        # if i_b >= len_b -> key not found in b -> 0.
        self._write("local.get $_eq_map_i_b")
        self._write("local.get $b")
        self._write(f"i32.load offset={_MAP_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # pair_b = b.data + i_b * pair_size
        self._write("local.get $b")
        self._write(f"i32.load offset={_MAP_DATA_OFFSET}")
        self._write("local.get $_eq_map_i_b")
        self._write(f"i32.const {_MAP_PAIR_SIZE}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write("local.set $_eq_map_pair_b")
        # Compare pair_b's key against the stashed canonical key.
        self._emit_compare_pair_key_to(key_ty, "_eq_map_pair_b")
        self._write("if")
        self._indent += 1
        # Key match. Compare values; mismatch -> 0, match -> break
        # inner loop and advance outer.
        self._emit_map_pair_value_compare(
            value_ty, "_eq_map_pair_a", "_eq_map_pair_b",
        )
        self._write("i32.eqz")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Values matched: leave the inner loop.
        self._write(f"br {inner_exit}")
        self._indent -= 1
        self._write("end")
        # i_b++, continue inner.
        self._write("local.get $_eq_map_i_b")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_eq_map_i_b")
        self._write(f"br {inner_loop}")
        self._indent -= 1
        self._write("end")  # loop inner
        self._indent -= 1
        self._write("end")  # block inner_exit
        # i_a++, continue outer.
        self._write("local.get $_eq_map_i_a")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_eq_map_i_a")
        self._write(f"br {outer_loop}")
        self._indent -= 1
        self._write("end")  # loop outer
        self._indent -= 1
        self._write("end")  # block outer_exit
        # Outer loop completed without mismatch -> 1.
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")  # block eq_done
        self._indent -= 1
        self._write(")")

    def _emit_map_stash_pair_key(
        self, key_ty: str, pair_addr_local: str,
    ) -> None:
        """Stash the key of the pair at ``$pair_addr_local`` into the
        canonical key-scratch slots that ``_emit_compare_pair_key_to``
        reads. This is the pair-address-sourced analogue of
        ``_emit_push_map_key_canonical`` (which sources from a Capa
        ``Value``): same slots, same per-type dispatch, but the
        load issues ``i32.load`` / ``i64.load`` at the pair offset
        rather than evaluating an IR Value.

        - String: ``$_alloc_tmp`` = key_ptr; ``$_alloc_tmp_key_len``
          = key_len (two adjacent i32s at offsets 0 / 4).
        - Int: ``$_alloc_tmp_key_i64`` = key (i64 at offset 0).
        - Bool: ``$_alloc_tmp`` = key (i32 at offset 0).
        - Pointer-shape: ``$_alloc_tmp_key_ptr`` = key pointer (i32
          at offset 0).
        """
        if key_ty == "String":
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_PTR_OFFSET}")
            self._write("local.set $_alloc_tmp")
            self._write(f"local.get ${pair_addr_local}")
            self._write(f"i32.load offset={_MAP_PAIR_KEY_LEN_OFFSET}")
            self._write("local.set $_alloc_tmp_key_len")
            return
        if key_ty == "Int":
            self._write(f"local.get ${pair_addr_local}")
            self._write("i64.load offset=0")
            self._write("local.set $_alloc_tmp_key_i64")
            return
        if key_ty == "Bool":
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("local.set $_alloc_tmp")
            return
        if self._is_pointer_shape_ty(key_ty):
            self._write(f"local.get ${pair_addr_local}")
            self._write("i32.load offset=0")
            self._write("local.set $_alloc_tmp_key_ptr")
            return
        raise WasmEmissionError(
            f"Map key type {key_ty!r} not supported by structural "
            f"equality (supported: String / Int / Bool / struct / "
            f"sum / tuple)"
        )

    def _emit_map_pair_value_compare(
        self, value_ty: str,
        pair_a_local: str, pair_b_local: str,
    ) -> None:
        """Compare the value slots of two pairs and leave an i32 0/1
        on the stack. The slot is uniform 8 bytes at
        ``_MAP_PAIR_VALUE_OFFSET``; the load yields an i64 which we
        decode per V before invoking ``_emit_leaf_compare``:

        - Int: raw i64s -> ``_emit_leaf_compare("Int")`` (i64.eq).
        - Float: ``f64.reinterpret_i64`` twice -> Float compare.
        - Bool: ``i32.wrap_i64`` twice -> Bool compare.
        - String: each packed i64 unpacks to (ptr, len); push the
          four operands in canonical ``$str_eq`` order.
        - Pointer-shape: ``i32.wrap_i64`` twice -> ``$eq_<V>``.

        Uses ``$_eq_map_val_a`` / ``$_eq_map_val_b`` (i64) to stash
        the raw value slots when we need them twice (String unpack).
        """
        # Read both value slots once into scratch i64s; every branch
        # consumes them from there. This avoids re-loading and keeps
        # operand-stack ordering deterministic across kinds.
        self._write(f"local.get ${pair_a_local}")
        self._write(f"i64.load offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write("local.set $_eq_map_val_a")
        self._write(f"local.get ${pair_b_local}")
        self._write(f"i64.load offset={_MAP_PAIR_VALUE_OFFSET}")
        self._write("local.set $_eq_map_val_b")
        if value_ty == "Int":
            self._write("local.get $_eq_map_val_a")
            self._write("local.get $_eq_map_val_b")
            self._emit_leaf_compare("Int")
            return
        if value_ty == "Float":
            # Slot holds the f64 bit pattern (see
            # ``_push_map_value_as_i64``); reinterpret back to f64.
            self._write("local.get $_eq_map_val_a")
            self._write("f64.reinterpret_i64")
            self._write("local.get $_eq_map_val_b")
            self._write("f64.reinterpret_i64")
            self._emit_leaf_compare("Float")
            return
        if value_ty == "Bool":
            self._write("local.get $_eq_map_val_a")
            self._write("i32.wrap_i64")
            self._write("local.get $_eq_map_val_b")
            self._write("i32.wrap_i64")
            self._emit_leaf_compare("Bool")
            return
        if value_ty == "String":
            # Packed-i64 -> (ptr_a, len_a, ptr_b, len_b).
            # ``$_alloc_tmp_i64`` is reused as the shift scratch for
            # each unpack (it is declared in this helper).
            self._write("local.get $_eq_map_val_a")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write("local.get $_eq_map_val_b")
            self._write("local.tee $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._emit_leaf_compare("String")
            return
        if self._is_pointer_shape_ty(value_ty):
            # i64-extended i32 pointer; wrap back to i32 and dispatch
            # to the V-specific structural helper.
            self._write("local.get $_eq_map_val_a")
            self._write("i32.wrap_i64")
            self._write("local.get $_eq_map_val_b")
            self._write("i32.wrap_i64")
            self._emit_leaf_compare(value_ty)
            return
        raise WasmEmissionError(
            f"Map value type {value_ty!r} not supported by structural "
            f"equality on the Wasm backend"
        )

    def _emit_set_eq(self, ty: str) -> None:
        """``$eq_<key>(a, b) -> i32`` for ``Set<T>``: order-
        independent equality. A length mismatch is an instant 0.
        Otherwise walk ``a``'s elements in insertion order; for
        each element stash its needle in the per-kind scratch slots
        (mirroring ``Set.contains`` from ``_sets``) and inner-loop
        over ``b`` looking for a match. A missing element is an
        instant 0; surviving the outer loop is 1.

        Reuses ``_emit_set_compare_at`` and ``_emit_set_stash_element``
        from the Set emission mixin so the per-element-kind unpack /
        compare logic stays in one place."""
        from ._layout import _element_type_of_set
        name = _eq_key(ty)
        elem_ty = _element_type_of_set(ty)
        elem_size = self._size_of(elem_ty)
        self._write(
            f"(func $eq_{name} (param $a i32) (param $b i32) (result i32)"
        )
        self._indent += 1
        # Loop indices, plus the per-kind needle scratch slots so the
        # stash + compare helpers in _sets can dispatch against any
        # element kind without depending on the enclosing function's
        # local declarations.
        self._write("(local $_eq_set_i_a i32)")
        self._write("(local $_eq_set_i_b i32)")
        self._write("(local $_alloc_tmp i32)")
        self._write("(local $_alloc_tmp_i64 i64)")
        self._write("(local $_str_a_ptr i32)")
        self._write("(local $_str_a_len i32)")
        self._write("(local $_str_b_ptr i32)")
        self._write("(local $_str_b_len i32)")
        self._write("block $eq_done (result i32)")
        self._indent += 1
        # Length mismatch -> 0.
        self._write("local.get $a")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("local.get $b")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ne")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Outer loop: i_a in [0, len_a).
        self._write("i32.const 0")
        self._write("local.set $_eq_set_i_a")
        self._block_counter += 1
        outer_loop = f"$EQS{self._block_counter}_outer"
        outer_exit = f"$EQS{self._block_counter}_outer_exit"
        inner_loop = f"$EQS{self._block_counter}_inner"
        inner_exit = f"$EQS{self._block_counter}_inner_exit"
        self._write(f"block {outer_exit}")
        self._indent += 1
        self._write(f"loop {outer_loop}")
        self._indent += 1
        # if i_a >= len_a -> outer done.
        self._write("local.get $_eq_set_i_a")
        self._write("local.get $a")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write(f"br_if {outer_exit}")
        # Stash a[i_a] as the needle.
        needle_scalar = self._emit_set_stash_element_at(
            "$a", "_eq_set_i_a", elem_size, elem_ty,
        )
        # Inner loop: i_b in [0, len_b). Need a match.
        self._write("i32.const 0")
        self._write("local.set $_eq_set_i_b")
        self._write(f"block {inner_exit}")
        self._indent += 1
        self._write(f"loop {inner_loop}")
        self._indent += 1
        # if i_b >= len_b -> not found -> 0.
        self._write("local.get $_eq_set_i_b")
        self._write("local.get $b")
        self._write(f"i32.load offset={_SET_LEN_OFFSET}")
        self._write("i32.ge_s")
        self._write("if")
        self._indent += 1
        self._write("i32.const 0")
        self._write("br $eq_done")
        self._indent -= 1
        self._write("end")
        # Compare b[i_b] vs needle.
        self._emit_set_compare_at(
            "b", "_eq_set_i_b", elem_size, elem_ty, needle_scalar,
        )
        self._write("if")
        self._indent += 1
        # Match: leave inner loop and advance outer.
        self._write(f"br {inner_exit}")
        self._indent -= 1
        self._write("end")
        # i_b++, continue inner.
        self._write("local.get $_eq_set_i_b")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_eq_set_i_b")
        self._write(f"br {inner_loop}")
        self._indent -= 1
        self._write("end")  # loop inner
        self._indent -= 1
        self._write("end")  # block inner_exit
        # i_a++, continue outer.
        self._write("local.get $_eq_set_i_a")
        self._write("i32.const 1")
        self._write("i32.add")
        self._write("local.set $_eq_set_i_a")
        self._write(f"br {outer_loop}")
        self._indent -= 1
        self._write("end")  # loop outer
        self._indent -= 1
        self._write("end")  # block outer_exit
        # Outer loop completed without mismatch -> 1.
        self._write("i32.const 1")
        self._indent -= 1
        self._write("end")  # block eq_done
        self._indent -= 1
        self._write(")")

    def _emit_set_stash_element_at(
        self, set_local: str, idx_local: str,
        elem_size: int, elem_ty: str,
    ) -> str | None:
        """Stash the element at ``$set_local[$idx_local]`` into the
        per-kind needle scratch slots that
        ``_emit_set_compare_at`` consults. Returns the scalar needle
        local name for scalar kinds (so the compare helper can read
        it back) or ``None`` for kinds that use the dedicated
        ``$_str_b_*`` / ``$_alloc_tmp`` slots.

        Mirrors ``_emit_set_stash_needle`` from ``_sets`` but sources
        from a set + index pair (not a Capa Value), so the map / set
        equality helpers can use it on the heap-loaded ``a[i_a]``
        needle without re-evaluating an IR Value.
        """
        # element address: set.data + idx * elem_size
        if elem_ty == "String":
            # Load packed i64, unpack into ($_str_b_ptr, $_str_b_len)
            # so the symmetric compare in _emit_set_compare_at
            # reads from $_str_b_* against the scanned $_str_a_*.
            self._write(f"local.get {set_local}")
            self._write(f"i32.load offset={_SET_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
            self._write("i64.load")
            self._write("local.set $_alloc_tmp_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write("local.set $_str_b_ptr")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write("local.set $_str_b_len")
            return None
        if self._is_pointer_shape_ty(elem_ty):
            # Element slot is an i32 pointer; stash in $_alloc_tmp.
            self._write(f"local.get {set_local}")
            self._write(f"i32.load offset={_SET_DATA_OFFSET}")
            self._write(f"local.get ${idx_local}")
            self._write(f"i32.const {elem_size}")
            self._write("i32.mul")
            self._write("i32.add")
            self._write("i32.load")
            self._write("local.set $_alloc_tmp")
            return None
        # Scalar (Int 8-byte, Bool 4-byte). Load the element and
        # stash in the size-appropriate scratch.
        from ._layout import _load_op_for_size
        load_op = _load_op_for_size(elem_size)
        self._write(f"local.get {set_local}")
        self._write(f"i32.load offset={_SET_DATA_OFFSET}")
        self._write(f"local.get ${idx_local}")
        self._write(f"i32.const {elem_size}")
        self._write("i32.mul")
        self._write("i32.add")
        self._write(load_op)
        if elem_size == 8:
            self._write("local.set $_alloc_tmp_i64")
            return "_alloc_tmp_i64"
        self._write("local.set $_alloc_tmp")
        return "_alloc_tmp"
