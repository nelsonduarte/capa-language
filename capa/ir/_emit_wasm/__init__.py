"""CIR -> WebAssembly text (WAT) emitter (Phase 6A + 6B).

Phase 6A established the core scalar surface (Int / Bool arithmetic,
control flow). Phase 6B adds capability method calls and string
literals so a Capa program like ``stdio.println("hi")`` can lower
end-to-end.

The emitter produces WAT (text) which the caller assembles to binary
``.wasm`` via ``wasm-tools parse``. WAT is preferred over direct
binary because it is human-readable and easy to debug; the binary
form is mechanically derived from it.

Type mapping:

- Capa ``Int`` -> Wasm ``i64`` (signed 64-bit integer)
- Capa ``Bool`` -> Wasm ``i32`` (0 or 1; wasm has no native bool)
- Capa ``Unit`` -> no Wasm result (functions returning Unit omit
  the ``(result ...)`` clause)
- Capa ``String`` (Phase 6B, literal only) -> two i32s (memory ptr,
  byte length). Pushed sequentially when a string is passed as a
  capability method argument.
- Capa capability types (``Stdio``, ``Fs``, ...) have no Wasm
  representation: the methods they expose are imported into the
  module by name (matching the corresponding WIT interface), so a
  capability "value" carries no information at runtime. Capability
  params on Capa functions are dropped from the Wasm signature.

Phase 6B coverage is intentionally narrow: only Stdio methods with
string-literal arguments. Full String semantics (locals, methods,
concatenation) wait for Phase 6D.
"""

from __future__ import annotations

from typing import List, Optional

from .._nodes import (
    Module, Function, Param, Value, Instr,
    AssignConst, Reassign, BinOp, UnaryOp, Call, MethodCall,
    If, While, Break, Continue, Return, TryUnwrap,
    MakeStruct, MakeList, MakeMap, MakeSet, MakeTuple,
    FieldAccess, Index, For,
    FormatStr, MakeLambda,
    Pattern, PatWildcard, PatIdent, PatLiteral, PatVariant, MatchArm, Match,
    StructDecl, SumDecl,
)
# ``_WIT_SIGNATURES`` is consumed in ``_caps.py`` (sig dispatch) and
# ``_discovery.py`` (early validation); not referenced directly
# from this module any more after the mixin extraction.
from .._capa_types import BUILTIN_CAPS
from ._layout import (
    WasmEmissionError,
    _TYPE_SIZE,
    _LIST_HEADER_SIZE, _LIST_LEN_OFFSET, _LIST_CAP_OFFSET, _LIST_DATA_OFFSET,
    _MAP_HEADER_SIZE, _MAP_LEN_OFFSET, _MAP_CAP_OFFSET, _MAP_DATA_OFFSET,
    _MAP_PAIR_SIZE, _MAP_PAIR_KEY_PTR_OFFSET, _MAP_PAIR_KEY_LEN_OFFSET, _MAP_PAIR_VALUE_OFFSET,
    _SET_HEADER_SIZE, _SET_LEN_OFFSET, _SET_CAP_OFFSET, _SET_DATA_OFFSET,
    _OPTION_LAYOUT, _RESULT_LAYOUT, _IOERROR_LAYOUT, _JSONVALUE_LAYOUT,
    _map_value_type, _element_type_of_list, _element_type_of_set,
    _size_of, _store_op_for_size, _load_op_for_size, _align_up,
    compute_struct_layout, compute_sum_layout,
)
from ._runtime import _RuntimeHelpersMixin
from ._grisu import _GrisuEmissionMixin
from ._match import _MatchEmissionMixin
from ._strings import _StringEmissionMixin
from ._maps import _MapEmissionMixin
from ._lists import _ListEmissionMixin
from ._sets import _SetEmissionMixin
from ._closures import _ClosureEmissionMixin
from ._json import _JsonEmissionMixin
from ._option import _OptionEmissionMixin
from ._traits import _TraitEmissionMixin
from ._tuples import _TupleEmissionMixin
from ._caps import _CapDispatchMixin, _CANONICAL_INDIRECT_RETURN  # noqa: F401
from ._encoding import _EncodingMixin
from ._dispatch import _InstrDispatchMixin
from ._structs import _StructEmissionMixin
from ._values import _ValueEmissionMixin
from ._locals import _LocalsCollectionMixin
from ._discovery import _DiscoveryMixin
from ._equality import _EqualityMixin
from ._random import _RandomEmissionMixin


# Comparison ops produce i32 (0 or 1) in Wasm; arithmetic ops
# preserve the operand type (i64 for Int, f64 for Float). The
# emitter dispatches on the operand's Capa type to pick the right
# opcode family.
_INT_BINOP = {
    "+": "i64.add",
    "-": "i64.sub",
    "*": "i64.mul",
    "/": "i64.div_s",
    "%": "i64.rem_s",
    # Bitwise. Signed shift-right (``i64.shr_s``) is the right
    # match for Capa Int because Python's ``>>`` on signed ints is
    # also arithmetic (sign-extending). Shift counts outside the
    # range ``[0, 64)`` trap on both backends (audit fix C3); the
    # ``<<`` / ``>>`` branches in ``_emit_binop`` emit the inline
    # guard before dispatching through this table. ``i64.shl`` /
    # ``i64.shr_s`` would otherwise mask the RHS to the low 6 bits,
    # silently turning ``a << 64`` into ``a << 0``; that masking is
    # a silent-unsafety hole the runtime check closes.
    "&": "i64.and",
    "|": "i64.or",
    "^": "i64.xor",
    "<<": "i64.shl",
    ">>": "i64.shr_s",
}

_FLOAT_BINOP = {
    "+": "f64.add",
    "-": "f64.sub",
    "*": "f64.mul",
    "/": "f64.div",
}

_CMP_BINOP = {
    "==": "i64.eq",
    "!=": "i64.ne",
    "<":  "i64.lt_s",
    "<=": "i64.le_s",
    ">":  "i64.gt_s",
    ">=": "i64.ge_s",
}

_FLOAT_CMP_BINOP = {
    "==": "f64.eq",
    "!=": "f64.ne",
    "<":  "f64.lt",
    "<=": "f64.le",
    ">":  "f64.gt",
    ">=": "f64.ge",
}


# Audit H1 (2026-05): default memory cap on the emitted linear
# memory. 256 pages = 16 MiB. Caps the bump allocator's
# ``memory.grow`` so a runaway program traps predictably rather
# than at a host-dependent OOM point. Override on the CLI with
# ``--wasm-memory-cap <pages>`` (1 page = 64 KiB). The ``$alloc``
# helper's grow-on-failure path already emits ``unreachable``;
# this cap just shrinks the ``memory.grow`` return-(-1) threshold
# to a value the user controls.
MEMORY_CAP_DEFAULT_PAGES = 256

# Audit M4 (2026-05): manifest schema version embedded in the
# ``capa-manifest`` custom section. v1 is ``{name, declared_capabilities}``
# per function plus a top-level ``capa_version``. Consumers should
# refuse a manifest whose ``capa_manifest_version`` they do not
# recognise.
CAPA_MANIFEST_SCHEMA_VERSION = 1
CAPA_MANIFEST_SECTION = "capa-manifest"


class WasmEmitter(
    _RuntimeHelpersMixin,
    _GrisuEmissionMixin,
    _MatchEmissionMixin,
    _StringEmissionMixin,
    _MapEmissionMixin,
    _ListEmissionMixin,
    _SetEmissionMixin,
    _ClosureEmissionMixin,
    _CapDispatchMixin,
    _JsonEmissionMixin,
    _OptionEmissionMixin,
    _TraitEmissionMixin,
    _TupleEmissionMixin,
    _EncodingMixin,
    _InstrDispatchMixin,
    _StructEmissionMixin,
    _ValueEmissionMixin,
    _LocalsCollectionMixin,
    _DiscoveryMixin,
    _EqualityMixin,
    _RandomEmissionMixin,
):
    def __init__(
        self,
        indent_unit: str = "  ",
        *,
        memory_cap_pages: Optional[int] = MEMORY_CAP_DEFAULT_PAGES,
        manifest_json: Optional[str] = None,
    ):
        self._lines: List[str] = []
        self._indent = 0
        self._unit = indent_unit
        # Audit H1 (2026-05): page cap on the emitted ``(memory ...)``
        # declaration. ``None`` skips the cap (host decides); an int
        # bakes ``<max>`` into the memory limits. The bump allocator's
        # ``memory.grow`` then traps deterministically rather than at
        # a host-dependent OOM point.
        self._memory_cap_pages: Optional[int] = memory_cap_pages
        # Audit M4 (2026-05): JSON manifest bytes embedded in a Wasm
        # custom section named ``capa-manifest``. ``None`` skips
        # emission; a string emits ``(@custom "capa-manifest" "...")``
        # at the end of the module. Runtimes ignore custom sections
        # by definition, so this is purely a supply-chain audit aid.
        self._manifest_json: Optional[str] = manifest_json
        # Stack of (loop_label, exit_label) tuples so ``break`` and
        # ``continue`` know which loop they target. Wasm has no
        # implicit "innermost loop" branch; every branch names its
        # target block.
        self._loop_labels: list[tuple[str, str]] = []
        # Per-function counter for unique block labels.
        self._block_counter = 0
        # Module-level string pool: maps a Python string to its
        # (offset, length_in_bytes) in the data segment. Populated
        # by ``_intern_string`` as the emitter walks the function
        # bodies; the data segment itself is emitted after every
        # function so all literals are known.
        self._strings: dict[str, tuple[int, int]] = {}
        self._string_data_offset = 0
        # Set of capability classes the emitter has seen in
        # method-call receivers; drives the ``(import ...)``
        # declarations at the top of the module.
        self._used_caps: set[tuple[str, str]] = set()
        # The function currently being emitted; per-instruction
        # handlers consult ``self._current_fn.locals`` to resolve
        # the Capa type of a local without threading the function
        # through every recursive call.
        self._current_fn: Optional[Function] = None
        # Lifted lambdas: one entry per MakeLambda in the module.
        # Populated during the discover pass and emitted as
        # top-level functions before any user function.
        self._lifted_lambdas: list[dict] = []
        # Map (parent_fn_name, MakeLambda.dst) -> the index into
        # _lifted_lambdas for use at the MakeLambda emit site.
        # Keying by parent name is required because the IR's
        # ``fresh_local`` counter resets per function, so multiple
        # lambdas across different functions share dst names like
        # ``_ir_lambda0``. The emitter resolves the right entry by
        # consulting ``self._current_fn.name`` at MakeLambda time.
        self._lambda_by_dst: dict[tuple[str, str], int] = {}
        # Per-signature dedup table for ``(type $sig_N ...)`` decls.
        # Key: a stable string like "(i32 i64) -> i64"; value: an
        # integer index N.
        self._closure_sig_keys: dict[str, int] = {}
        # When emitting a lifted-lambda body, captures live in
        # this map (name -> (offset, capa_ty)). ``_push_value``
        # and the String pushers consult it.
        self._current_captures: dict[str, tuple[int, str]] = {}
        # Type layouts for structs and sums. Populated from the
        # module's ``types`` list before any function emission so
        # MakeStruct / Call-as-variant / Match / FieldAccess can
        # resolve field offsets and variant tags.
        self._struct_layouts: dict[str, dict] = {}
        self._sum_layouts: dict[str, dict] = {}
        # Reverse index from variant name -> sum type name, so a
        # ``Call(callee_name="Circle", ...)`` resolves to its parent
        # ``Shape`` sum without an enclosing scope hint.
        self._variant_to_sum: dict[str, str] = {}
        # Offset of the Grisu2 cached-powers-of-10 table in linear
        # memory. Reserved by ``emit()`` after string interning and
        # before the heap base when the module uses Float formatting;
        # 0 means "table not present".
        self._cached_powers_offset: int = 0

    # ----- public ------------------------------------------------

    def emit(self, module: Module) -> str:
        # Pre-register Capa's built-in Option<T> and Result<T, E>
        # sum types so the emitter can build / pattern-match them
        # without the user declaring them in source. ``Some``,
        # ``None``, ``Ok``, ``Err`` map to these layouts. User-
        # defined types are added on top, never overriding.
        self._struct_layouts = {"IoError": _IOERROR_LAYOUT}
        self._sum_layouts = {
            "Option": _OPTION_LAYOUT,
            "Result": _RESULT_LAYOUT,
            "JsonValue": _JSONVALUE_LAYOUT,
        }
        self._variant_to_sum = {
            "Some": "Option", "None": "Option",
            "Ok": "Result", "Err": "Result",
            "JNull": "JsonValue", "JBool": "JsonValue", "JNum": "JsonValue",
            "JStr": "JsonValue", "JArr": "JsonValue", "JObj": "JsonValue",
        }
        # Trait dispatch: build trait_name -> impl map for traits
        # with exactly one implementor. Multi-impl traits leave the
        # entry empty; dispatch path raises when it hits one.
        self._setup_trait_dispatch(module)
        # Module-level constants: name -> Value (the RHS literal).
        # Populated below from ``module.consts``. _push_value
        # consults this when it sees Value(kind="global", ...) so
        # use sites inline the literal rather than emitting a
        # global.get. Only literal-RHS consts land here; consts
        # with computed bodies raise at the use site so a future
        # Wasm-global-with-start-fn pass can take over cleanly.
        self._const_values: dict[str, Value] = {}
        for c in module.consts:
            if len(c.body) == 1 and isinstance(c.body[0], AssignConst):
                src = c.body[0].src
                if src.kind in ("lit_int", "lit_float",
                                "lit_bool", "lit_str", "lit_unit"):
                    self._const_values[c.name] = src

        # Pass 0: compute layouts for every struct and sum type so
        # subsequent passes can resolve field offsets and variant
        # tags. Layout of struct fields depends on the size of their
        # field types -- which may themselves be sums or structs.
        # We resolve in two passes: stub all type sizes first (treat
        # forward refs as pointer-sized i32 = 4 bytes), then refine
        # if a struct contains an inlined value type. For Phase 6C
        # all aggregate types are heap-allocated and referenced by
        # pointer, so the first pass is already correct; the second
        # pass is a no-op but kept for clarity if future phases
        # inline small structs.
        for ty in module.types:
            if isinstance(ty, StructDecl):
                self._struct_layouts[ty.name] = compute_struct_layout(
                    ty, self._sum_layouts, self._struct_layouts,
                )
            elif isinstance(ty, SumDecl):
                self._sum_layouts[ty.name] = compute_sum_layout(
                    ty, self._sum_layouts, self._struct_layouts,
                )
                for v in ty.variants:
                    self._variant_to_sum[v.name] = ty.name

        # Refine pattern-binder types from variant payload layouts
        # BEFORE any helper-detection (uses_float_format etc.) reads
        # fn.locals. The analyzer's pattern-side type inference is
        # incomplete for builtin sum types (JsonValue / Option /
        # Result with non-Int payloads), leaving binders as Unknown.
        # The sum layout always knows what each variant carries.
        for fn in module.functions:
            self._refine_pattern_binder_types(fn, fn.body)

        # First pass: walk the module to discover used capability
        # methods and string literals so we can emit imports and
        # the data segment at the top of the module (Wasm requires
        # imports before any function/code section, and we want the
        # data segment in a known location).
        self._used_caps = set()
        self._strings = {}
        self._string_data_offset = 0
        self._lifted_lambdas = []
        self._lambda_by_dst = {}
        self._closure_sig_keys = {}
        # Pre-intern "true" / "false" if any FormatStr might consume
        # a Bool value at runtime; the data-segment offsets are
        # referenced via i32.const in the dispatch.
        if self._uses_format_str(module):
            self._intern_string("true")
            self._intern_string("false")
        # Pre-intern the special-case Float literals returned by
        # ``$ftoa`` directly (NaN / +/- inf / +/-0). These are
        # returned as pointers into the static data segment rather
        # than as fresh allocations, so the offsets must be known
        # at WAT-emission time.
        if self._uses_float_format(module):
            for special in ("nan", "inf", "-inf", "0.0", "-0.0"):
                self._intern_string(special)
        # Pre-intern every String-typed top-level constant. Use
        # sites walk function bodies, never ConstDecl, so a
        # bare ``pub const S: String = "..."`` referenced from
        # any function would otherwise look up an offset of 0
        # (the data segment's start, not the constant's
        # location). Without this the user gets NUL bytes
        # interpolated where they expect the constant's text.
        for name, v in self._const_values.items():
            if v.kind == "lit_str":
                self._intern_string(v.literal)
        self._discover(module)
        self._discover_lambdas(module)

        # Reserve linear-memory space for the Grisu2 cached-powers
        # table when Float formatting is in play. Placed right after
        # the string data segment, before the heap base. The table
        # itself is emitted as a ``(data ...)`` block alongside the
        # string segments below.
        from ._grisu import _CACHED_POWERS_BYTE_SIZE
        if self._uses_float_format(module):
            self._cached_powers_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._cached_powers_offset + _CACHED_POWERS_BYTE_SIZE
            )
        else:
            self._cached_powers_offset = 0

        # Stage 1: emit the (module ... ) header with imports and
        # memory.
        body_lines: list[str] = []
        self._lines = body_lines
        self._write("(module")
        self._indent += 1
        # Imports for each used capability method. The Wasm import
        # name follows the WIT interface convention: module name is
        # the lowercased interface (``capa:stdio`` style) so the
        # host's Linker maps interface -> import in one step.
        for cap, method in sorted(self._used_caps):
            # Component Model convention: import names use the form
            # ``<package>/<interface>``. We emit ``capa:host/<cap>``
            # to match the WIT generated by ``capa.ir.emit_wit`` (the
            # ``capa:host`` package contains one interface per
            # built-in capability, lowercased). WIT identifiers are
            # kebab-case only, so the method-name component of the
            # import must mirror that (``now_secs`` -> ``now-secs``)
            # for ``wasm-tools component embed`` to link the core
            # module to the WIT spec. The local ``$cap_method`` Wasm
            # binding keeps snake_case because it's internal.
            import_module = f"capa:host/{cap.lower()}"
            import_name = method.replace("_", "-")
            params, result = self._cap_method_wasm_sig(cap, method)
            params_str = " ".join(f"(param {t})" for t in params)
            result_str = f" (result {result})" if result else ""
            self._write(
                f'(import "{import_module}" "{import_name}" '
                f'(func ${cap}_{method}{(" " + params_str) if params_str else ""}{result_str}))'
            )
        # Memory + data segment for string literals. Always declare
        # at least one page (64KB) so any string fits without growth
        # logic; the host reads from this memory to materialise
        # string args.
        needs_memory = (
            self._strings
            or self._has_any_caps()
            or self._struct_layouts
            or self._sum_layouts
            or self._uses_heap_alloc(module)
        )
        if needs_memory:
            # Audit H1 (2026-05): bake the per-module memory cap
            # into the limits clause so ``$alloc``'s ``memory.grow``
            # traps at a deterministic page count rather than at
            # whatever the host happens to OOM at. ``None`` skips
            # the cap (host decides). 1 page = 64 KiB; default cap
            # is ``MEMORY_CAP_DEFAULT_PAGES`` (256 pages = 16 MiB).
            if self._memory_cap_pages is not None:
                self._write(
                    f'(memory (export "memory") 1 {self._memory_cap_pages})'
                )
            else:
                self._write('(memory (export "memory") 1)')
            for text, (offset, _len) in sorted(
                self._strings.items(), key=lambda kv: kv[1][0],
            ):
                escaped = self._escape_wat_string(text)
                self._write(f'(data (i32.const {offset}) "{escaped}")')
            # Grisu2 cached-powers-of-10 table, emitted as a raw
            # ``(data ...)`` block at the reserved offset.
            if self._uses_float_format(module):
                self._emit_cached_powers_data()
        # Heap: starts just after the static data segment, aligned
        # to 8 bytes. The ``$alloc`` function below bumps the global
        # forward by the requested size, rounded up to 8.
        if (
            self._struct_layouts
            or self._sum_layouts
            or self._uses_heap_alloc(module)
        ):
            heap_start = _align_up(self._string_data_offset, 8)
            self._write(
                f"(global $heap_top (mut i32) (i32.const {heap_start}))"
            )
            self._emit_alloc_function()
            self._emit_cabi_realloc_function()
            # ``$str_eq`` is only needed when at least one Map
            # operation may run; it compares two (ptr, len) string
            # pairs byte-by-byte. Always emit when a map is in
            # play -- inlining it at every set/get call site would
            # bloat the WAT. Capability attenuation checks
            # (audit C2) for Env.restrict_to_keys also need
            # ``$str_eq`` to compare the requested name against the
            # allow-list, so we emit it unconditionally when any
            # attenuation check is present too.
            needs_starts_with, needs_contains = (
                self._uses_attenuation_check(module)
            )
            needs_str_eq_for_atten = self._uses_env_atten_check(module)
            if (self._uses_map_ops(module)
                    or needs_starts_with
                    or needs_contains
                    or needs_str_eq_for_atten
                    or self._eq_needs_str_eq(module)):
                self._emit_str_eq_function()
            if needs_starts_with:
                self._emit_str_starts_with_function()
            if needs_contains:
                self._emit_str_contains_function()
            if self._uses_format_str(module):
                self._emit_itoa_function()
                if self._uses_float_format(module):
                    # Grisu2 needs four helpers in a fixed order:
                    # pow10 (called by grisu2), mul_high (called by
                    # grisu2), cached_power lookup (called by
                    # grisu2), grisu2 itself, then ftoa which
                    # dispatches to all of the above.
                    self._emit_pow10_i32_function()
                    self._emit_mul_high_u64_function()
                    self._emit_grisu_cached_power_function()
                    self._emit_grisu2_function()
                    self._emit_ftoa_function()
            # parse_int / parse_float are built-in free functions
            # routed to runtime helpers. Emit only when used.
            if self._uses_parse_int(module):
                self._emit_parse_int_function()
            if self._uses_parse_float(module):
                self._emit_parse_float_function()
            # Generated structural-equality helpers ($eq_<Type>) for
            # any compound type compared with == / != (or used as a
            # pointer-shape List.contains element). Emitted here, at
            # module level before user functions, so they can mutually
            # recurse by name.
            self._emit_equality_helpers(module)
        # Random capability: SplitMix64 helpers + the two
        # ``$rand_state`` / ``$rand_state_inited`` globals. Emitted
        # outside the heap conditional because the PRNG runs in pure
        # i64 / f64 ops (no allocator dependency); a Random-only
        # program with no Stdio or compound types would still
        # otherwise miss the helpers. Discovery in ``_uses_random``
        # gates the emission so a Random-free program pays zero cost.
        if self._uses_random(module):
            self._emit_random_globals_and_helpers()
        # Closure infrastructure: function table + (type) decls +
        # each lifted lambda is a top-level function below.
        if self._lifted_lambdas:
            self._emit_closure_types_and_table()
            for lifted in self._lifted_lambdas:
                self._emit_lifted_lambda(lifted)
        # Stage 2: emit each function. Impl methods are emitted as
        # additional top-level functions with mangled names
        # (<TypeName>_<method_name>) so MethodCall dispatch on a
        # trait receiver can route to them via call $<mangled>.
        for fn in module.functions:
            self._emit_function(fn)
        self._emit_impl_methods(module)
        # Audit M4 (2026-05): embed the per-function capability
        # manifest in a Wasm custom section so the discipline travels
        # with the artefact. Runtimes ignore custom sections by
        # definition; ``wasm-tools dump`` and any wasm parser can
        # surface them. Emitted last so it sits at module end where
        # consumers expect optional metadata.
        if self._manifest_json is not None:
            escaped = self._escape_wat_string(self._manifest_json)
            self._write(
                f'(@custom "{CAPA_MANIFEST_SECTION}" "{escaped}")'
            )
        self._indent -= 1
        self._write(")")
        return "\n".join(self._lines) + "\n"

    # Discovery + classification passes (_discover,
    # _refine_pattern_binder_types, _uses_*,
    # _values_of) live in _discovery.py as
    # _DiscoveryMixin (mixed into this class above).

    def _intern_string(self, text: str) -> tuple[int, int]:
        if text in self._strings:
            return self._strings[text]
        encoded = text.encode("utf-8")
        offset = self._string_data_offset
        length = len(encoded)
        self._strings[text] = (offset, length)
        # Align next string on a 1-byte boundary -- no padding needed
        # for UTF-8. Add a 0 byte between strings so a hex dump is
        # readable when debugging.
        self._string_data_offset = offset + length + 1
        return (offset, length)

    def _has_any_caps(self) -> bool:
        return len(self._used_caps) > 0

    # ``_cap_method_wasm_sig``, ``_emit_cap_method_call``, and
    # ``_emit_cap_indirect_materialise`` live in ``_caps.py`` as
    # ``_CapDispatchMixin`` (mixed into this class above).

    @staticmethod
    def _escape_wat_string(s: str) -> str:
        """Escape a Python string for inclusion inside a WAT
        ``(data ... "...")`` literal. WAT data strings use \\HH
        for arbitrary bytes; we go through UTF-8 and escape every
        byte that is not a printable ASCII character (avoiding
        ``"`` and ``\\`` which need special handling)."""
        out = []
        for b in s.encode("utf-8"):
            if 0x20 <= b < 0x7F and b not in (0x22, 0x5C):
                out.append(chr(b))
            else:
                out.append(f"\\{b:02x}")
        return "".join(out)

    # ----- function-level ---------------------------------------

    def _emit_function(self, fn: Function) -> None:
        # Reset per-function state.
        self._block_counter = 0
        self._loop_labels = []
        self._for_depth = 0
        # Cache the current function so per-instruction handlers can
        # look up local / param Capa types without threading ``fn``
        # through every helper.
        self._current_fn = fn

        # Build the function header: params and result. Capability
        # params are dropped from the Wasm signature because their
        # methods are imported into the module by name -- the param
        # carries no runtime value. String params expand to two
        # i32s (ptr, len) named ``${p.name}_ptr`` / ``${p.name}_len``.
        param_clauses = []
        for p in fn.params:
            if p.ty in BUILTIN_CAPS:
                continue
            if p.ty == "String":
                param_clauses.append(f"(param ${p.name}_ptr i32)")
                param_clauses.append(f"(param ${p.name}_len i32)")
                continue
            ty = self._wasm_type(p.ty)
            if not ty:
                raise WasmEmissionError(
                    f"function {fn.name!r}: parameter {p.name!r} has Unit "
                    f"type, which has no Wasm representation"
                )
            param_clauses.append(f"(param ${p.name} {ty})")
        params_str = " ".join(param_clauses)
        # String return -> multi-value (i32 ptr, i32 len). Wasm 2.0
        # supports multi-value, and wasmtime exposes it to Python
        # as a tuple. Other types use the single-value result form.
        if fn.return_type == "String":
            result_str = " (result i32 i32)"
            result_ty = "string"  # any truthy non-empty value
        else:
            result_ty = self._wasm_type(fn.return_type)
            result_str = f" (result {result_ty})" if result_ty else ""
        header = (
            f'(func ${fn.name} (export "{fn.name}")'
            f'{(" " + params_str) if params_str else ""}'
            f'{result_str}'
        )
        self._write(header)
        self._indent += 1

        # Collect every local introduced by the function body so we
        # can declare them up front (Wasm requires this).
        param_names = {p.name for p in fn.params}
        local_decls = self._collect_locals(fn, param_names)
        for name, ty in local_decls.items():
            self._write(f"(local ${name} {ty})")

        # Emit body instructions.
        for instr in fn.body:
            self._emit_instr(instr)

        # Wasm's verifier wants a value on the stack at function
        # exit when the result type is non-empty. Capa's source
        # exhaustiveness analysis can guarantee every code path
        # returns, but the verifier does not see that; emit an
        # ``unreachable`` so the trailing code path is well-typed
        # under "no execution reaches here". For Unit returns the
        # implicit fall-through is fine.
        if result_ty:
            self._write("unreachable")

        self._indent -= 1
        self._write(")")

    # _collect_locals lives in _locals.py as
    # _LocalsCollectionMixin (mixed into this class above).

    # ----- per-instruction --------------------------------------

    def _emit_try_unwrap(self, instr: TryUnwrap) -> None:
        """Lower the ``?`` operator. ``instr.src`` is an i32 pointer
        to a 16-byte sum record (Result<T, E> or Option<T>). If the
        tag at offset 0 is 1 (Err / None), return the original
        pointer from the enclosing function early. Otherwise extract
        the payload at offset 8 into ``instr.dst``.

        Mirrors the sum-type Match arm-extraction logic but elides
        the per-arm cascade since we only care about Ok/Err
        discrimination."""
        src_ty = instr.src.ty
        # Strip generic args: ``Option<Int>`` -> ``Option``.
        head = src_ty.split("<", 1)[0]
        if head not in ("Option", "Result"):
            raise WasmEmissionError(
                f"TryUnwrap on type {src_ty!r}: only Option<T> and "
                f"Result<T, E> are supported"
            )
        self._push_value(instr.src)
        self._write("local.set $_m_scrut")
        # Tag check: 1 = Err / None -> early return.
        self._write("local.get $_m_scrut")
        self._write("i32.load")
        self._write("i32.const 1")
        self._write("i32.eq")
        self._write("if")
        self._indent += 1
        self._write("local.get $_m_scrut")
        self._write("return")
        self._indent -= 1
        self._write("end")
        # Ok / Some path: load payload at offset 8.
        dst_ty = self._dst_capa_ty(instr.dst)
        if dst_ty == "String":
            # Payload packed as i64 (ptr low / len high). Unpack
            # into dst's (ptr, len) locals.
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._write("local.set $_alloc_tmp_i64")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_ptr")
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 32")
            self._write("i64.shr_u")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}_len")
            return
        head_dst = dst_ty.split("<", 1)[0] if dst_ty else ""
        if head_dst in self._struct_layouts or head_dst in self._sum_layouts \
                or (dst_ty and dst_ty.startswith(("List", "Map", "Set"))):
            # Pointer-shaped payload stored as i64.extend; unpack.
            self._write("local.get $_m_scrut")
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
            self._write(f"local.set ${instr.dst}")
            return
        # Scalar (Int / Bool / Float / Unit / Unknown). Dispatch
        # on the dst type rather than wasm_type so Unit doesn't
        # accidentally land on the Bool-narrowing path (Unit has
        # no real value; the Ok payload slot is a placeholder).
        self._write("local.get $_m_scrut")
        if dst_ty == "Float":
            self._write("f64.load offset=8")
        elif dst_ty == "Bool":
            self._write("i64.load offset=8")
            self._write("i32.wrap_i64")
        else:
            # Int / Unit / Unknown all stored as i64 in the slot;
            # the dst local was declared i64 by the locals sweep.
            self._write("i64.load offset=8")
        self._write(f"local.set ${instr.dst}")

    def _emit_binop(self, instr: BinOp) -> None:
        op = instr.op
        # Dispatch on operand type: Float operands use f64.* opcodes,
        # String operands use ``$str_eq`` for equality, everything
        # else stays on the i64 / i32 path.
        is_string = instr.left.ty == "String" or instr.right.ty == "String"
        if is_string and op == "==":
            self._push_string_value_as_ptr_len(instr.left)
            self._push_string_value_as_ptr_len(instr.right)
            self._write("call $str_eq")
            self._write(f"local.set ${instr.dst}")
            return
        if is_string and op == "!=":
            self._push_string_value_as_ptr_len(instr.left)
            self._push_string_value_as_ptr_len(instr.right)
            self._write("call $str_eq")
            self._write("i32.eqz")
            self._write(f"local.set ${instr.dst}")
            return
        if is_string and op == "+":
            # Concatenate two strings. Allocates a fresh buffer of
            # combined length, memory.copies each source.
            self._emit_string_concat(instr)
            return
        if is_string:
            raise WasmEmissionError(
                f"String operator {op!r} not supported at the Wasm level"
            )
        is_float = instr.left.ty == "Float" or instr.right.ty == "Float"
        if op in _INT_BINOP and is_float:
            if op == "%":
                # f64 has no remainder opcode. Emit Python's floored
                # modulo (``a - floor(a/b) * b``) so the sign of the
                # result matches the divisor, matching Python's ``a %
                # b`` for floats. Using ``f64.trunc`` instead would
                # match C semantics (sign of dividend) and diverge for
                # mixed-sign operands.
                # Safety (audit fix C6): trap on ``b == 0`` so the
                # backend mirrors Python's ``ZeroDivisionError`` instead
                # of silently producing NaN through ``0/0 * 0 - a``.
                self._push_value(instr.right)
                self._write("f64.const 0")
                self._write("f64.eq")
                self._write("if")
                self._indent += 1
                self._write("unreachable")
                self._indent -= 1
                self._write("end")
                self._push_value(instr.left)
                self._push_value(instr.left)
                self._push_value(instr.right)
                self._write("f64.div")
                self._write("f64.floor")
                self._push_value(instr.right)
                self._write("f64.mul")
                self._write("f64.sub")
                self._write(f"local.set ${instr.dst}")
                return
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_FLOAT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op == "%" and op in _INT_BINOP and not is_float:
            # Wasm's ``i64.rem_s`` is C-style truncated remainder (the
            # sign of the result follows the dividend), but Python's
            # ``a % b`` for ints is floored (the sign follows the
            # divisor). Emit a correction: compute ``r = a rem_s b``,
            # then add ``b`` to ``r`` iff the signs of ``r`` and ``b``
            # differ (i.e. ``r != 0 and (r ^ b) < 0``). This matches
            # Python and the Python backend on every operand pair,
            # including the previously-divergent mixed-sign cases
            # (``-7 % 3`` was wasm ``-1`` / py ``2``, now both ``2``).
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i64.rem_s")
            self._write("local.set $_alloc_tmp_i64")
            # Predicate: r != 0 AND (r XOR b) < 0.
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 0")
            self._write("i64.ne")
            self._write("local.get $_alloc_tmp_i64")
            self._push_value(instr.right)
            self._write("i64.xor")
            self._write("i64.const 0")
            self._write("i64.lt_s")
            self._write("i32.and")
            self._write("if (result i64)")
            self._indent += 1
            self._write("local.get $_alloc_tmp_i64")
            self._push_value(instr.right)
            self._write("i64.add")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            self._write("local.get $_alloc_tmp_i64")
            self._indent -= 1
            self._write("end")
            self._write(f"local.set ${instr.dst}")
            return
        if op in ("<<", ">>") and op in _INT_BINOP and not is_float:
            # Safety (audit fix C3): trap when the shift count is
            # outside ``[0, 64)``. ``i64.shl`` / ``i64.shr_s`` would
            # otherwise silently mask the RHS to its low 6 bits,
            # so ``a << 64`` becomes ``a << 0`` rather than the
            # OverflowError Python now raises on the same input.
            self._push_value(instr.right)
            self._write("i64.const 64")
            self._write("i64.ge_u")  # unsigned: negative => huge => true
            self._write("if")
            self._indent += 1
            self._write("unreachable")
            self._indent -= 1
            self._write("end")
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_INT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in ("+", "-", "*") and op in _INT_BINOP and not is_float:
            # Safety (audit fix C2): trap on signed 64-bit overflow so
            # the Wasm backend mirrors Python's ``OverflowError`` (raised
            # by the ``_capa_iadd`` / ``_capa_isub`` / ``_capa_imul``
            # runtime helpers) instead of wrapping mod 2^64.
            self._emit_int_overflow_check(instr, op)
            return
        if op in _INT_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_INT_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        if op in _CMP_BINOP and is_float:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_FLOAT_CMP_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        # Bool == / != use the i32 comparison opcodes; the default
        # _CMP_BINOP table is keyed for i64 (Int). Consult effective
        # types so binders typed Unknown route via fn.locals.
        left_ty = self._effective_value_ty(instr.left)
        right_ty = self._effective_value_ty(instr.right)
        # A payloadless variant binder (``let a = Red``) is typed as
        # the variant name; normalise to its owning sum type so the
        # compound-equality dispatch below recognises it as a sum
        # value rather than falling through to the i64 pointer compare.
        left_ty = self._normalize_eq_ty(left_ty)
        right_ty = self._normalize_eq_ty(right_ty)
        if op in _CMP_BINOP and (left_ty == "Bool" or right_ty == "Bool"):
            if op not in ("==", "!="):
                raise WasmEmissionError(
                    f"Bool operands do not support {op!r} (only "
                    f"== and != are defined for Bool comparisons)"
                )
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i32.eq" if op == "==" else "i32.ne")
            self._write(f"local.set ${instr.dst}")
            return
        # Compound == / != : structural (deep, by-value) equality via a
        # generated $eq_<Type> helper, matching the Python backend's
        # dataclass / tuple / list equality. Scalars and String are
        # handled above; struct / sum / tuple / List / Map / Set all
        # reach here and route through ``_emit_compound_eq``. Map /
        # Set equality is order-independent: the helper iterates one
        # operand and looks each key / element up in the other, in
        # line with Python's ``dict`` / ``CapaSet`` semantics.
        if op in ("==", "!="):
            cmp_ty = (
                left_ty if self._is_compound_eq_ty(left_ty)
                else right_ty
            )
            if self._is_compound_eq_ty(cmp_ty):
                self._emit_compound_eq(instr, op, cmp_ty)
                return
        if op in _CMP_BINOP:
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write(_CMP_BINOP[op])
            self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"Phase 6A: binop {op!r} not supported (and/or are "
            f"short-circuited at the IR level and should not reach "
            f"the Wasm emitter)"
        )

    def _emit_int_overflow_check(self, instr: BinOp, op: str) -> None:
        """Emit a signed 64-bit overflow-detecting variant of ``+``,
        ``-`` or ``*`` (audit fix C2).

        Strategy: stash the two operands and the proposed result in
        three i64 scratch locals (``$_ovf_a``, ``$_ovf_b``, ``$_ovf_r``),
        then evaluate the overflow predicate purely against the locals
        so the stack stays well-formed. On overflow, emit
        ``unreachable``; otherwise, push the stashed result and bind
        it to the destination. The Python backend reaches the same
        observable failure mode via ``_capa_iadd`` / ``_capa_isub`` /
        ``_capa_imul`` (see ``capa.runtime._safety``).

        Predicates (signed two's-complement, 64-bit):
        - ``+``: overflow iff ``((a ^ r) & (b ^ r)) < 0``
          (sign of a and b agree, sign of r differs from both).
        - ``-``: overflow iff ``((a ^ b) & (a ^ r)) < 0``
          (sign of a and b differ, and sign of a differs from r).
        - ``*``: overflow iff ``b != 0 AND (r div_s b) != a``.
          The extra divide is the simplest correct check; the
          cheaper Hacker's-Delight form needs i128 to be precise.
        """
        # Stash operands.
        self._push_value(instr.left)
        self._write("local.set $_ovf_a")
        self._push_value(instr.right)
        self._write("local.set $_ovf_b")
        # Compute candidate result.
        self._write("local.get $_ovf_a")
        self._write("local.get $_ovf_b")
        if op == "+":
            self._write("i64.add")
        elif op == "-":
            self._write("i64.sub")
        else:  # op == "*"
            self._write("i64.mul")
        self._write("local.set $_ovf_r")
        # Build the overflow predicate (leaves an i32 on the stack).
        if op == "+":
            # (a ^ r) & (b ^ r) < 0
            self._write("local.get $_ovf_a")
            self._write("local.get $_ovf_r")
            self._write("i64.xor")
            self._write("local.get $_ovf_b")
            self._write("local.get $_ovf_r")
            self._write("i64.xor")
            self._write("i64.and")
            self._write("i64.const 0")
            self._write("i64.lt_s")
        elif op == "-":
            # (a ^ b) & (a ^ r) < 0
            self._write("local.get $_ovf_a")
            self._write("local.get $_ovf_b")
            self._write("i64.xor")
            self._write("local.get $_ovf_a")
            self._write("local.get $_ovf_r")
            self._write("i64.xor")
            self._write("i64.and")
            self._write("i64.const 0")
            self._write("i64.lt_s")
        else:  # op == "*"
            # b != 0 AND (r / b) != a
            self._write("local.get $_ovf_b")
            self._write("i64.const 0")
            self._write("i64.ne")
            self._write("if (result i32)")
            self._indent += 1
            self._write("local.get $_ovf_r")
            self._write("local.get $_ovf_b")
            self._write("i64.div_s")
            self._write("local.get $_ovf_a")
            self._write("i64.ne")
            self._indent -= 1
            self._write("else")
            self._indent += 1
            self._write("i32.const 0")
            self._indent -= 1
            self._write("end")
        # Trap on overflow.
        self._write("if")
        self._indent += 1
        self._write("unreachable")
        self._indent -= 1
        self._write("end")
        # Bind result.
        self._write("local.get $_ovf_r")
        self._write(f"local.set ${instr.dst}")

    def _emit_unaryop(self, instr: UnaryOp) -> None:
        op = instr.op
        if op == "-":
            # Float operand: emit ``f64.neg`` directly. Int operand:
            # Wasm has no ``i64.neg``, so synthesise as ``0 - x``.
            operand_ty = self._effective_value_ty(instr.operand)
            if operand_ty == "Float":
                self._push_value(instr.operand)
                self._write("f64.neg")
                self._write(f"local.set ${instr.dst}")
                return
            self._write("i64.const 0")
            self._push_value(instr.operand)
            self._write("i64.sub")
            self._write(f"local.set ${instr.dst}")
            return
        if op == "not":
            # Boolean negation: i32.eqz turns 0 -> 1, anything else
            # -> 0. Matches Capa's ``not`` semantics on Bool.
            self._push_value(instr.operand)
            self._write("i32.eqz")
            self._write(f"local.set ${instr.dst}")
            return
        raise WasmEmissionError(
            f"Phase 6A: unary op {op!r} not supported"
        )

    # ----- user-function calls ----------------------------------

    def _emit_user_call(self, instr: Call) -> None:
        """Lower a Capa-level function call. Three flavours share this
        path because the IR's lowerer represents them all as ``Call``:

        - **Variant construction** (``Circle(5)`` etc.).
        - **Closure call** (callee is a local or param of Fun(...) type):
          unpack env_ptr + fn_idx from the closure i64 and dispatch
          via ``call_indirect``.
        - **Ordinary function call**: push non-capability args, ``call
          $name``, bind the result.

        Capability-typed args are always skipped (capabilities flow
        through module-level imports, not as values)."""
        if instr.callee_name in self._variant_to_sum:
            self._emit_variant_construction(instr)
            return
        # ``Random()`` source-level constructor. The dst is a Random
        # cap (BUILTIN_CAPS dsts are erased at the Wasm level) so
        # there's no value to bind; the SplitMix64 state lazy-inits
        # on the first ``int_range`` / ``float_unit`` call. Keep
        # this branch above the ordinary-call path so we don't try
        # to ``call $Random`` (no such function exists in the
        # emitted module).
        if instr.callee_name == "Random":
            self._emit_random_constructor(instr)
            return
        # Built-in free functions that route through host bridges.
        # parse_json / to_json take String / JsonValue and would
        # otherwise miss the ``call $<name>`` path because no Capa
        # function declares them.
        if instr.callee_name == "parse_json":
            self._emit_call_host_json_parse(instr)
            return
        if instr.callee_name == "to_json":
            self._emit_call_host_json_to_string(instr)
            return
        # parse_int / parse_float route to runtime helpers
        # ($parse_int / $parse_float). The arg is a String pushed
        # as (ptr, len); the return is an Option<Int> / Option<Float>
        # pointer.
        if instr.callee_name in ("parse_int", "parse_float") \
                and len(instr.args) == 1:
            arg = instr.args[0]
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            else:
                self._push_string_value_as_ptr_len(arg)
            self._write(f"call ${instr.callee_name}")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        # Numeric conversion intrinsics. These lower to one Wasm
        # instruction each; faster (and simpler) than a host bridge.
        if instr.callee_name == "to_float" and len(instr.args) == 1:
            self._push_value(instr.args[0])
            self._write("f64.convert_i64_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        if instr.callee_name == "to_int" and len(instr.args) == 1:
            self._push_value(instr.args[0])
            self._write("i64.trunc_f64_s")
            if instr.dst is not None:
                self._write(f"local.set ${instr.dst}")
            return
        # Closure call: callee is a local / param of Fun type.
        callee_ty = self._lookup_local_or_param_ty(instr.callee_name)
        if callee_ty and callee_ty.startswith("Fun"):
            self._emit_closure_call(instr, callee_ty)
            return
        for arg in instr.args:
            if arg.ty in BUILTIN_CAPS:
                continue
            if arg.ty == "String":
                # Defer to the shared helper, which now handles
                # ``lit_str`` / ``local`` / ``param`` / ``global``
                # uniformly (the previous hand-inlined branch
                # missed ``global`` for top-level
                # ``pub const X: String`` constants).
                self._push_string_value_as_ptr_len(arg)
                continue
            self._push_value(arg)
        self._write(f"call ${instr.callee_name}")
        if instr.dst is not None:
            dst_ty = self._dst_capa_ty(instr.dst)
            # If the callee returns a non-empty value, store it in
            # ``instr.dst``. Capability / Unit dsts have no Wasm
            # representation; String returns are multi-value
            # (i32 i32) and need to land in the dst's _ptr / _len
            # pair (in reverse stack order: len is on top, then ptr).
            if dst_ty == "String":
                self._write(f"local.set ${instr.dst}_len")
                self._write(f"local.set ${instr.dst}_ptr")
            elif dst_ty and dst_ty not in BUILTIN_CAPS and dst_ty != "Unit":
                self._write(f"local.set ${instr.dst}")

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
