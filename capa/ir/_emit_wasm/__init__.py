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
from .._walk import iter_functions, walk_module
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
    _strip_type_qualifiers,
    compute_struct_layout, compute_sum_layout,
)
from ._runtime import _RuntimeHelpersMixin
from ._grisu import _GrisuEmissionMixin
from ._match import _MatchEmissionMixin
from ._strings import _StringEmissionMixin
from ._maps import _MapEmissionMixin
from ._lists import _ListEmissionMixin
from ._sets import _SetEmissionMixin
from ._set_algebra import _SetAlgebraMixin
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
from ._wasi import _WasiEmissionMixin, _WASI_MIGRATED_METHODS


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

# Bug #2: String order comparison folds ``$str_cmp``'s -1/0/1 result
# against zero with the matching i32 signed comparison opcode. The
# helper's sign IS the ordering (``s1 < s2`` -> -1), so ``s1 < s2``
# is ``str_cmp(...) < 0`` and so on.
_STR_CMP_FOLD = {
    "<":  "i32.lt_s",
    "<=": "i32.le_s",
    ">":  "i32.gt_s",
    ">=": "i32.ge_s",
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
    _SetAlgebraMixin,
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
    _WasiEmissionMixin,
):
    def __init__(
        self,
        indent_unit: str = "  ",
        *,
        memory_cap_pages: Optional[int] = MEMORY_CAP_DEFAULT_PAGES,
        manifest_json: Optional[str] = None,
        wasi: bool = False,
        wasi_dynamic_fs: bool = False,
    ):
        # Experimental opt-in (2026-06-27): when True, Random.system_seed
        # and Clock.now_secs / now_monotonic import canonical WASI
        # Preview 2 interfaces (wasi:random / wasi:clocks) instead of
        # the custom ``capa:host`` ones, with the unit conversion done
        # guest-side. Every other capability the program uses stays on
        # ``capa:host`` (hybrid mode). The default (False) path is the
        # untouched all-``capa:host`` behaviour. See
        # ``docs/design/wasi_mode.md``.
        self._wasi: bool = wasi
        # WASI Fs layer b1 (operator preopen, 2026-06-30): True when the
        # operator declared ``--preopen <dir>`` for this run, granting the
        # component filesystem authority over that directory and so
        # UNBLOCKING dynamic (non-literal) Fs paths under ``--wasi``. A
        # dynamic path is resolved at RUNTIME relative to the single
        # operator preopen (the WASI ``--dir`` model, wasmtime's
        # convention), framed honestly as a LEVEL-2 operator-DECLARED
        # grant (see ``docs/design/wasi-attenuation.md``), distinct from
        # the COMPILER-DERIVED preopen ceiling. When False (the default),
        # a dynamic Fs path is REJECTED at compile time exactly as before
        # -- this flag is the ONLY thing that suppresses that rejection.
        #
        # b1 INDEX RULE (emitter <-> host agreement): the operator preopen
        # is the LAST preopen the host registers, AFTER every
        # compiler-derived ceiling preopen, so it never shifts an existing
        # literal call site's index. In the dynamic case the derived
        # ceiling is NOT closed and so contributes NO preopens, leaving
        # the operator preopen at index 0; the dynamic call-site emitter
        # therefore addresses it with the constant
        # ``_wasi_operator_preopen_index`` (0 whenever the ceiling is open,
        # i.e. exactly the dynamic case). The host computes the same index
        # (len(derived preopens)) so the two never disagree.
        self._wasi_dynamic_fs: bool = wasi_dynamic_fs
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
        # The limb-bignum helpers ($bn_*) are shared by the Dragon4
        # float-to-string fallback and the correctly-rounded
        # string-to-float parser; emit them at most once even when both
        # paths are present.
        self._bignum_helpers_emitted = False
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
        # Experimental WASI mode: the statically-computed Fs preopen
        # ceiling (``capa.ir.FsCeiling``) for the program being
        # emitted, or None outside ``--wasi``. Computed in ``emit()``
        # after discovery; consulted by ``_validate_wasi_caps`` (the
        # fail-closed check) and by the Fs metadata call-site emitter
        # (literal-path -> preopen-index + basename resolution).
        self._fs_ceiling = None
        # Set in ``emit()``: True when a migrated Fs metadata op needs
        # the wasi:filesystem preopen machinery (scratch + globals).
        self._wasi_fs_uses_preopens = False
        self._wasi_fs_scratch_offset = 0
        # Experimental WASI mode: the statically-computed Net host
        # ceiling (``capa.ir.NetCeiling``) for the program being emitted,
        # or None outside ``--wasi``. Computed in ``emit()`` after
        # discovery; consulted by the Net.get guest-side host gate
        # (``$Net_host_allowed``, the codegen-enforced ceiling) and by the
        # Net.get call-site emitter (literal-url -> scheme/authority/path).
        self._net_ceiling = None
        # Offset of the Net.get indirect-return scratch (the wasi:http
        # chain's result areas), 0 when Net.get is not used.
        self._wasi_net_scratch_offset = 0

    # ----- WASI operator-preopen (layer b1) ----------------------

    def _wasi_operator_preopen_index(self) -> int:
        """The preopen INDEX the operator ``--preopen`` directory occupies
        on the host, for the dynamic-Fs-path call-site emitter to address.

        b1 index rule: the host registers the operator preopen AFTER every
        compiler-derived ceiling preopen, so its index is the number of
        derived preopens. A dynamic Fs path (the only thing that reaches
        the operator preopen) requires a NOT-CLOSED ceiling, which
        contributes NO derived preopens, so this is 0 in the dynamic case.
        For a fully-literal program (closed ceiling) the operator preopen
        sits at ``len(ceiling.preopens)`` and is unused by the guest (no
        dynamic call site), but still registered + recorded for honesty;
        the constant returned here matches the host's registration order
        either way."""
        ceiling = self._fs_ceiling
        if ceiling is None or not getattr(ceiling, "closed", False):
            return 0
        return len(ceiling.preopens)

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
        # Names of user-defined free functions. Consulted when a
        # builtin free function (e.g. parse_int / parse_float) could
        # be shadowed by a user definition of the same name: the user
        # function wins, matching the Python backend.
        self._user_fn_names = {fn.name for fn in module.functions}
        # Bug #3: map each user function to its declared return type so
        # a call site can tell whether the callee leaves a value on the
        # stack. A Unit-returning function emits no result clause, so a
        # ``let _ = f()`` (or any bound call) must NOT emit a trailing
        # ``local.set`` for a value that was never pushed.
        self._user_fn_return_types = {
            fn.name: (fn.return_type or "") for fn in module.functions
        }
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
                # Structs implementing a multi-impl trait reserve a
                # type-id header at offset 0 for dynamic dispatch
                # (``_setup_trait_dispatch`` populated the set above).
                self._struct_layouts[ty.name] = compute_struct_layout(
                    ty, self._sum_layouts, self._struct_layouts,
                    reserve_header=ty.name in self._header_struct_types,
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
        # Impl-method bodies are refined too (iter_functions yields
        # them after the top-level functions): a match inside a
        # method writes its binder types into the METHOD's locals
        # map, which the emission view clones.
        for fn in iter_functions(module):
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
        # Thunks generated when a top-level function is passed as a
        # ``Fun(...)`` value (e.g. ``xs.map(double_int)``). Each
        # thunk is a tiny Wasm function with the closure ABI
        # ``(env_ptr, args...) -> result`` that ignores ``env_ptr``
        # and delegates to the named top-level function. Keyed by
        # (fn_name, sig_key); the value carries the table slot
        # index assigned to that (fn, sig) combination.
        self._fn_ref_thunks: dict[tuple[str, str], dict] = {}
        # Module reference, used by ``_push_value`` to look up a
        # global function's signature when synthesising a thunk.
        self._module = module
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
        # Pre-intern the fixed panic messages for Option / Result
        # ``unwrap()``. Like every other literal, these must be in the
        # data segment (laid out below) before the function bodies that
        # reference them are emitted; interning at emit time would point
        # the host past the segment's end and print NUL bytes. ``expect``
        # carries a runtime String message (pushed via ptr/len), so only
        # ``unwrap``'s fixed strings need pre-interning here.
        from ._option import (
            _UNWRAP_NONE_MSG, _UNWRAP_ERR_MSG, methodcall_may_panic,
        )
        from .._nodes import MethodCall
        for _fn, instr in walk_module(module):
            if (isinstance(instr, MethodCall)
                    and instr.method == "unwrap"
                    and methodcall_may_panic(instr)):
                head = (instr.receiver.ty or "").split("<", 1)[0]
                self._intern_string(
                    _UNWRAP_NONE_MSG if head == "Option" else _UNWRAP_ERR_MSG
                )
        self._discover(module)
        self._discover_lambdas(module)

        # Experimental WASI mode: compute the static Fs preopen ceiling
        # so ``_validate_wasi_caps`` can fail-closed on a dynamic Fs
        # path and the Fs metadata call-site emitter can resolve each
        # literal path to its (preopen_index, basename). Computed from
        # the same module the emitter walks (the loader already inlined
        # imported functions), mirroring how the host computes it
        # independently for the preopen registration.
        if self._wasi:
            from .._fs_ceiling import (
                compute_fs_ceiling_from_cir, mkdir_prefixes,
                resolve_fs_call,
            )
            self._fs_ceiling = compute_fs_ceiling_from_cir(module)
            # Pre-intern every WASI-Fs string the wrappers / call sites
            # reference, BEFORE the data segment is emitted below. The
            # data segment is written once, up front; a string interned
            # later (at wrapper- or call-site-emission time) would get a
            # valid offset but no ``(data ...)`` block, so its bytes
            # would be undefined at runtime. The two sources of such
            # strings are: (1) the per-call-site relative BASENAME each
            # Fs metadata literal resolves to, and (2) the ``mkdir
            # failed`` Err message the mkdir wrapper writes. Pre-intern
            # both here so they land in the data segment deterministically.
            if self._fs_ceiling.closed:
                from .._nodes import MethodCall
                # Every migrated Fs op that resolves a literal path to a
                # relative BASENAME the wrapper addresses by (ptr, len)
                # must be pre-interned here: exists / is_dir / mkdir AND
                # the stream-bearing read / write. ``write`` was missing
                # from this tuple, so a program whose ONLY Fs op was
                # ``write`` (no read / metadata sharing the same literal)
                # never pre-interned its basename: the string got a valid
                # offset at $Fs_write call-site emission time but no
                # ``(data ...)`` block, so the relative path the guest
                # handed to ``open-at`` was undefined memory and the open
                # failed at runtime (no file written). A co-present
                # ``read`` of the same path masked the bug by interning
                # the shared basename early.
                _fs_meta = (
                    "exists", "is_dir", "mkdir", "read", "write", "list_dir",
                )
                for _fn, instr in walk_module(module):
                    if (isinstance(instr, MethodCall)
                            and (instr.cap_used
                                 or (instr.receiver.ty or "")) == "Fs"
                            and instr.method in _fs_meta
                            and instr.args
                            and instr.args[0].kind == "lit_str"
                            and isinstance(instr.args[0].literal, str)):
                        _idx, _rel = resolve_fs_call(
                            self._fs_ceiling, instr.args[0].literal,
                        )
                        if instr.method == "mkdir":
                            # Recursive mkdir interns EVERY cumulative
                            # prefix segment (matching os.makedirs):
                            # ``a/b/c`` -> ``a``, ``a/b``, ``a/b/c``,
                            # each a create-directory-at target.
                            for _pfx in mkdir_prefixes(_rel):
                                self._intern_string(_pfx)
                        else:
                            # exists / is_dir / read / write / list_dir
                            # all resolve to a single relative path the
                            # wrapper addresses by (ptr, len).
                            self._intern_string(_rel)
                        # FINE ATTENUATION (2026-06-28): every migrated Fs
                        # op now also passes the FULL original literal path
                        # to its guest-side fail-closed gate
                        # (``$Fs_path_allowed``), so the full literal must
                        # be interned here too -- interning it only at
                        # call-site emission time would leave it without a
                        # backing ``(data ...)`` block and the gate would
                        # compare against undefined memory. The relative
                        # path (above) and the full path are usually
                        # distinct strings (the full path carries the
                        # preopen prefix), so both must be pre-interned.
                        self._intern_string(instr.args[0].literal)
                # FINE ATTENUATION (2026-06-28): a literal ``restrict_to``
                # prefix and a literal ``allows`` path also reach the data
                # segment (the prefix is stored verbatim in the allow-list
                # the guest builds; the allows path is compared against it).
                # Dynamic (local / param) args travel as a runtime
                # ``(ptr, len)`` and need no static interning. Pre-intern
                # the literal ones for the same backing-data reason.
                for _fn, instr in walk_module(module):
                    if (isinstance(instr, MethodCall)
                            and (instr.cap_used
                                 or (instr.receiver.ty or "")) == "Fs"
                            and instr.method in ("restrict_to", "allows")
                            and instr.args
                            and instr.args[0].kind == "lit_str"
                            and isinstance(instr.args[0].literal, str)):
                        self._intern_string(instr.args[0].literal)
                if any(
                    cap == "Fs" and m == "mkdir"
                    for (cap, m) in self._used_caps
                ):
                    self._intern_string("mkdir failed")
                if any(
                    cap == "Fs" and m == "read"
                    for (cap, m) in self._used_caps
                ):
                    # The fixed Err message $Fs_read writes on an open /
                    # read-via-stream / last-operation-failed failure.
                    self._intern_string("failed to read file")
                if any(
                    cap == "Fs" and m == "write"
                    for (cap, m) in self._used_caps
                ):
                    # The fixed Err message $Fs_write writes on an open /
                    # write-via-stream / last-operation-failed failure.
                    # Pre-interned for the same reason as the read message:
                    # interning it only at $Fs_write emission time would
                    # leave it without a backing data segment.
                    self._intern_string("failed to write file")
                if any(
                    cap == "Fs" and m == "list_dir"
                    for (cap, m) in self._used_caps
                ):
                    # The fixed Err message $Fs_list_dir writes on an
                    # open / read-directory / read-directory-entry
                    # failure. Pre-interned for the same reason as the
                    # read / write messages: interning it only at
                    # $Fs_list_dir emission time would leave it without a
                    # backing data segment.
                    self._intern_string("failed to list directory")

        # Experimental WASI mode: Stdio output (Phase 1, 2026-06-29).
        # ``println`` / ``eprintln`` append a trailing ``"\n"`` byte by
        # writing the interned newline string as a second chunk through
        # the same output-stream. Pre-intern it HERE, before the data
        # segment is emitted below, for the same write-only-parity reason
        # as the Fs / Net strings: a string interned later (at
        # wrapper-emission time) gets a valid offset but no backing
        # ``(data ...)`` block, so its byte would be undefined memory at
        # runtime (the symptom that surfaced as a stray NUL printed in
        # place of the newline). ``print`` writes no newline, so it does
        # not pull the string in.
        if self._wasi and any(
            cap == "Stdio" and method in ("println", "eprintln")
            for (cap, method) in self._used_caps
        ):
            self._intern_string("\n")

        # Experimental WASI mode: Stdio.read_line (Phase 2, 2026-06-29).
        # ``read_line`` returns ``Err(IoError("end of input"))`` at EOF
        # (input fully consumed). The wrapper writes that fixed message
        # into the Err arm, so it must be pre-interned HERE -- before the
        # data segment is emitted below -- for the same write-only-parity
        # reason the Fs / Net Err strings follow: a string interned later
        # (at $Stdio_read_line emission time) gets a valid offset but no
        # backing ``(data ...)`` block, so its bytes would be undefined
        # memory at runtime. The message matches the Python oracle's
        # ``Err(IoError("end of input"))`` (capa/runtime/_capabilities.py
        # read_line) byte-for-byte.
        if self._wasi and ("Stdio", "read_line") in self._used_caps:
            self._intern_string("end of input")

        # Experimental WASI mode: compute the static Net host ceiling so
        # the Net.get guest-side host gate (``$Net_host_allowed``) can
        # refuse any host the program does not name as a literal url
        # (codegen-enforced, the honest guest-side ceiling -- wasmtime's
        # wasi:http C-API is allow-all, so there is no host-side Net
        # ceiling to map onto, unlike Fs preopens / Env env-set). Computed
        # from the same module the emitter walks (the loader inlined
        # imports), mirroring how the host gates linking wasi:http on Net
        # being used at all.
        if self._wasi and (
            ("Net", "get") in self._used_caps
            or ("Net", "post") in self._used_caps
        ):
            from .._net_ceiling import compute_net_ceiling_from_cir, url_host
            self._net_ceiling = compute_net_ceiling_from_cir(module)
            # Pre-intern every WASI-Net string the wrappers / call sites
            # reference, BEFORE the data segment is emitted below (the same
            # write-only-parity discipline the Fs strings follow: a string
            # interned later gets a valid offset but no ``(data ...)``
            # block, so its bytes are undefined at runtime). Sources:
            #   (1) each literal url's HOST (the ceiling membership keys the
            #       gate scans, AND the per-call authority host the wrapper
            #       sends) -- for BOTH get and post, whose first arg is the
            #       url,
            #   (2) the per-call AUTHORITY (host:port) and PATH-with-query
            #       resolved from each literal url,
            #   (3) the fixed ``HTTP GET failed`` / ``HTTP POST failed`` Err
            #       messages.
            # No method-name string is interned for POST: the wasi:http
            # ``method`` variant encodes POST as the discriminant 2 (no
            # payload), so the wrapper never references a "POST" literal.
            from ._net import split_net_url
            for _fn, instr in walk_module(module):
                if (isinstance(instr, MethodCall)
                        and (instr.cap_used
                             or (instr.receiver.ty or "")) == "Net"
                        and instr.method in ("get", "post")
                        and instr.args
                        and instr.args[0].kind == "lit_str"
                        and isinstance(instr.args[0].literal, str)):
                    host, _https, authority, path = split_net_url(
                        instr.args[0].literal,
                    )
                    self._intern_string(host)
                    self._intern_string(authority)
                    self._intern_string(path)
            # Every ceiling host (membership keys) -- usually a subset of
            # the per-call hosts above, but interned explicitly so the
            # gate's data is complete even if a host appears only via a
            # url whose host extraction differs (defensive; url_host
            # lowercases).
            for h in self._net_ceiling.hosts:
                self._intern_string(h)
            if ("Net", "get") in self._used_caps:
                self._intern_string("HTTP GET failed")
            if ("Net", "post") in self._used_caps:
                self._intern_string("HTTP POST failed")

        # Experimental WASI mode, Net FINE ATTENUATION (2026-06-29,
        # Phase 3): a literal ``Net.restrict_to`` host and a literal
        # ``Net.allows`` host also reach the data segment (the restrict_to
        # host is stored VERBATIM in the guest's allow-list List<String>;
        # the allows host is compared byte-exact against it via $str_eq).
        # Pre-intern the literal ones here, BEFORE the data segment is
        # emitted, for the same write-only-parity reason the Fs / Net.get
        # strings follow (a string interned at call-site emission time gets
        # a valid offset but no backing ``(data ...)`` block, so its bytes
        # would be undefined at runtime). Dynamic (local / param) args
        # travel as a runtime ``(ptr, len)`` and need no static interning.
        # Gated independently of the Net ceiling above: a program may
        # narrow / query a Net it received from a caller without ever
        # naming a literal url to get / post.
        if self._wasi and (
            ("Net", "restrict_to") in self._used_caps
            or ("Net", "allows") in self._used_caps
        ):
            from .._nodes import MethodCall
            for _fn, instr in walk_module(module):
                if (isinstance(instr, MethodCall)
                        and (instr.cap_used
                             or (instr.receiver.ty or "")) == "Net"
                        and instr.method in ("restrict_to", "allows")
                        and instr.args
                        and instr.args[0].kind == "lit_str"
                        and isinstance(instr.args[0].literal, str)):
                    self._intern_string(instr.args[0].literal)

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

        # Experimental WASI mode: reserve a 16-byte scratch slot for the
        # ``wasi:clocks/wall-clock.now`` indirect return (datetime
        # record: u64 seconds @0, u32 nanoseconds @8). Placed in the
        # static data region just like the Grisu table so the wrapper
        # never has to depend on ``$alloc`` being emitted (a Clock-only
        # program may touch no heap otherwise). 0 means "not reserved".
        self._wasi_walltime_scratch_offset = 0
        if self._wasi and ("Clock", "now_secs") in self._used_caps:
            self._wasi_walltime_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_walltime_scratch_offset + 16
            )

        # Experimental WASI mode: reserve an 8-byte scratch slot for
        # the ``wasi:cli/environment`` ``get-environment`` /
        # ``get-arguments`` indirect returns (both lower to a
        # list header: data_ptr @0, len @4). The two readers never run
        # concurrently within a single host call, so one shared slot is
        # sufficient. Placed in the static data region like the Grisu
        # table and the walltime scratch so the wrappers never depend on
        # ``$alloc`` being emitted for their own bookkeeping (the
        # materialiser still allocates the Capa-side records via
        # ``$alloc``, which a program reaching Env always pulls in).
        # 0 means "not reserved".
        self._wasi_env_scratch_offset = 0
        if self._wasi and (
            ("Env", "get") in self._used_caps
            or ("Env", "args") in self._used_caps
        ):
            self._wasi_env_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_env_scratch_offset + 8
            )

        # Experimental WASI mode: Fs metadata via wasi:filesystem
        # (2026-06-27). Two reservations, both gated on a migrated Fs
        # metadata op (exists / is_dir / mkdir) being present:
        #
        # - ``_wasi_fs_scratch_offset``: a 104-byte, 8-aligned scratch
        #   for the descriptor.stat-at / create-directory-at indirect
        #   returns (the result<...> discriminant @0, plus the
        #   descriptor-stat Ok payload whose first field %type sits at
        #   offset 8 under u64 alignment). 104 bytes is the canonical
        #   ABI size of ``result<descriptor-stat, error-code>`` (the
        #   stat-at return): an 8-byte discriminant prefix plus the
        #   96-byte ``descriptor-stat`` record (type @8, link-count @8,
        #   size @16, then three 24-byte ``option<datetime>`` fields at
        #   @24 / @48 / @72). stat-at writes the WHOLE record, so the
        #   slot must hold all of it; a 16-byte slot overflowed by ~88
        #   bytes into the adjacent get-directories list buffer and
        #   corrupted the cached preopen descriptors after the second
        #   stat. ``create-directory-at`` (mkdir) returns the smaller
        #   ``result<_, error-code>`` (8 bytes) and the get-directories
        #   header is 8 bytes, so 104 covers every Fs indirect return.
        #   The metadata calls never overlap within one wrapper
        #   invocation, so one shared slot suffices. Placed in the
        #   static data region like the other WASI scratch slots so the
        #   wrappers do not depend on ``$alloc`` for their own
        #   bookkeeping (mkdir still allocates its 20-byte Capa-side
        #   result area via ``$alloc`` at the call site, a dependency a
        #   program reaching Result always pulls in).
        #
        # - ``_wasi_fs_uses_preopens``: drives the two module globals
        #   (``$__wasi_fs_pre_data`` / ``$__wasi_fs_pre_inited``) that
        #   cache ``preopens.get-directories`` across all metadata
        #   calls (the descriptors are the preopen roots, live for the
        #   component's lifetime, never dropped).
        self._wasi_fs_scratch_offset = 0
        self._wasi_fs_uses_preopens = self._wasi and any(
            cap == "Fs"
            and method in (
                "exists", "is_dir", "mkdir", "read", "write", "list_dir",
            )
            for (cap, method) in self._used_caps
        )
        if self._wasi_fs_uses_preopens:
            self._wasi_fs_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_fs_scratch_offset + 104
            )

        # Experimental WASI mode: Fs.read (2026-06-28). A 32-byte,
        # 8-aligned scratch holding the THREE indirect returns of the
        # read sequence, packed at distinct sub-offsets so they never
        # overlap each other:
        #   open-at         result<descriptor, error-code>     @ +0  (8B)
        #   read-via-stream result<input-stream, error-code>   @ +8  (8B)
        #   blocking-read   result<list<u8>, stream-error>     @ +16 (12B)
        # This region is SEPARATE from the 104-byte metadata scratch
        # (``_wasi_fs_scratch_offset``, used by stat-at /
        # create-directory-at) and from the cached get-directories list
        # buffer the host writes (addressed via the preopen globals), so
        # a read interleaved with metadata ops cannot corrupt either.
        # The blocking-read DATA buffer is NOT here: the host writes the
        # chunk bytes into its own canonical-ABI-allocated memory
        # (cabi_realloc / $alloc), and the wrapper copies them into a
        # geometrically-grown heap accumulation buffer via $alloc +
        # memory.copy. 0 means "not reserved".
        self._wasi_fs_read_scratch_offset = 0
        if self._wasi and ("Fs", "read") in self._used_caps:
            self._wasi_fs_read_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_fs_read_scratch_offset + 32
            )

        # Experimental WASI mode: Fs.write (2026-06-28). A 32-byte,
        # 8-aligned scratch holding the TWO indirect returns of the
        # write sequence, packed at distinct sub-offsets so they never
        # overlap each other:
        #   write-via-stream result<output-stream, error-code>  @ +0  (8B)
        #   blocking-write-and-flush / blocking-flush
        #       result<_, stream-error>                         @ +8  (12B)
        # This region is SEPARATE from the 104-byte metadata scratch
        # (``_wasi_fs_scratch_offset``), the 32-byte read scratch
        # (``_wasi_fs_read_scratch_offset``), and the cached
        # get-directories list buffer the host writes (addressed via the
        # preopen globals), so a write interleaved with read / metadata
        # ops cannot corrupt either. The content bytes are NOT here: they
        # already live in linear memory (the String ``content`` argument)
        # and are handed to blocking-write-and-flush as ``(ptr, len)``
        # chunks straight through, no copy. 0 means "not reserved".
        self._wasi_fs_write_scratch_offset = 0
        if self._wasi and ("Fs", "write") in self._used_caps:
            self._wasi_fs_write_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_fs_write_scratch_offset + 32
            )

        # Experimental WASI mode: Fs.list_dir (2026-06-28). A 32-byte,
        # 8-aligned scratch holding the TWO indirect returns of the
        # directory-enumeration sequence, packed at distinct sub-offsets:
        #   read-directory        result<dir-entry-stream, error-code>  @ +0  (8B)
        #   read-directory-entry  result<option<dir-entry>, error-code> @ +8  (20B)
        # The read-directory slot @+0 also holds open-at's
        # result<descriptor, error-code> first (the two never overlap in
        # time: read-directory runs only after open's result is consumed
        # into $desc). This region is SEPARATE from the 104-byte metadata
        # scratch, the 32-byte read scratch, the 32-byte write scratch,
        # and the cached get-directories list buffer the host writes, so a
        # list_dir interleaved with read / write / metadata ops corrupts
        # none of them. The entry NAME bytes are NOT here: the host writes
        # them into its own canonical-ABI-allocated memory (cabi_realloc),
        # and the wrapper accumulates only (ptr, len) pairs into a
        # geometrically-grown heap buffer via $alloc + memory.copy.
        # 0 means "not reserved".
        self._wasi_fs_list_dir_scratch_offset = 0
        if self._wasi and ("Fs", "list_dir") in self._used_caps:
            self._wasi_fs_list_dir_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_fs_list_dir_scratch_offset + 32
            )

        # Experimental WASI mode: Net.get (2026-06-28, Phase 1) / Net.post
        # (2026-06-28, Phase 2). A 192-byte, 8-aligned scratch SHARED by
        # both request ops (they never interleave within one wrapper
        # invocation), holding the indirect returns of the wasi:http chain
        # at distinct sub-offsets so no two overlap in time-and-space (the
        # offsets are also recorded in the ``$Net_get`` / ``$Net_post``
        # docstrings; validated by the oracle spike):
        #   outgoing-request.body       result<own<outgoing-body>, _>   @ +0  (8B,  value @+4)
        #   outgoing-body.finish        result<_, error-code>           @ +8  (8B)
        #   outgoing-handler.handle     result<own<future>, error-code> @ +16 (16B, value @+8 -- error-code forces 8-align)
        #   future-incoming-response.get  option<result<result<own<resp>, ec>>> @ +32 (32B, option disc @+0, outer @+8, inner @+16, own<resp> @+24)
        #   incoming-response.consume   result<own<incoming-body>, _>   @ +64 (8B,  value @+4)
        #   incoming-body.stream        result<own<input-stream>, _>    @ +72 (8B,  value @+4)
        #   input-stream.blocking-read  result<list<u8>, stream-error>  @ +80 (12B, Ok data_ptr @+4 len @+8; Err stream-error disc @+4, error @+8)
        # Net.post ADDS three slots (unused by get) for the FLOW-CONTROLLED
        # REQUEST-body write path, all reached BEFORE the read loop, so they
        # cannot collide with the read scratch in time:
        #   output-stream write/flush  result<_, stream-error>          @ +96  (12B)
        #   outgoing-body.write        result<own<output-stream>, _>    @ +112 (8B,  value @+4)
        #   output-stream.check-write  result<u64, stream-error>        @ +128 (16B, disc @+0, budget u64 @+8)
        # The blocking-read DATA bytes / blocking-write SOURCE bytes are NOT
        # here: the host writes read chunks into its own canonical-ABI
        # memory (the wrapper copies into a geometrically-grown heap buffer
        # via $alloc + memory.copy, like Fs.read), and the post request body
        # is handed to blocking-write-and-flush straight from linear memory
        # as ``(ptr, len)`` chunks, no copy (like Fs.write). This region is
        # SEPARATE from every Fs / Env / Clock scratch (disjoint offsets are
        # belt-and-braces). 0 means "not reserved".
        self._wasi_net_scratch_offset = 0
        if self._wasi and (
            ("Net", "get") in self._used_caps
            or ("Net", "post") in self._used_caps
        ):
            self._wasi_net_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_net_scratch_offset + 192
            )

        # Experimental WASI mode: Stdio output (Phase 1, 2026-06-29). A
        # 16-byte, 8-aligned scratch holding the single indirect return of
        # output-stream.blocking-write-and-flush:
        #   blocking-write-and-flush  result<_, stream-error>  @ +0  (12B)
        # Each chunk write reuses this one slot (the writes are
        # sequential, never overlapping). The text bytes are NOT here:
        # they already live in linear memory (the String ``msg`` argument,
        # or the interned "\n" for println / eprintln) and are handed to
        # blocking-write-and-flush as ``(ptr, len)`` chunks straight
        # through, no copy. This region is SEPARATE from every Fs / Env /
        # Clock / Net scratch (disjoint offsets are belt-and-braces).
        # Placed in the static data region like the other WASI scratch
        # slots so the wrappers never depend on ``$alloc`` (a Stdio-only
        # program touches no heap otherwise). 0 means "not reserved".
        self._wasi_stdio_scratch_offset = 0
        if self._wasi and any(
            cap == "Stdio" and method in ("print", "println", "eprintln")
            for (cap, method) in self._used_caps
        ):
            self._wasi_stdio_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_stdio_scratch_offset + 16
            )

        # Experimental WASI mode: Stdio.read_line (Phase 2, 2026-06-29). A
        # 16-byte, 8-aligned scratch holding the single indirect return of
        # input-stream.blocking-read:
        #   blocking-read  result<list<u8>, stream-error>  @ +0  (12B)
        # Each 1-byte read reuses this one slot (the reads are sequential,
        # never overlapping). The byte the host yields lands in its own
        # canonical-ABI-allocated memory (cabi_realloc / $alloc); the
        # wrapper copies it into a geometrically-grown heap accumulation
        # buffer via $alloc + memory.copy, exactly like Fs.read. This
        # region is SEPARATE from every Fs / Env / Clock / Net / Stdio-out
        # scratch (disjoint offsets are belt-and-braces). 0 means "not
        # reserved".
        self._wasi_stdin_scratch_offset = 0
        if self._wasi and ("Stdio", "read_line") in self._used_caps:
            self._wasi_stdin_scratch_offset = _align_up(
                self._string_data_offset, 8,
            )
            self._string_data_offset = (
                self._wasi_stdin_scratch_offset + 16
            )

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
        # Experimental WASI mode (2026-06-27): the migrated cap methods
        # import canonical wasi:* interfaces and get a thin wrapper that
        # adapts the WASI shape to the ``$Cap_method`` binding the call
        # sites already use (drop the unused handle param, convert the
        # WASI time units to f64 seconds). Validated + emitted here so
        # the rest of the import loop and every call-site emitter stay
        # untouched.
        if self._wasi:
            self._validate_wasi_caps()
        for cap, method in sorted(self._used_caps):
            if self._wasi and (cap, method) in _WASI_MIGRATED_METHODS:
                # Skip here; the wasi:* import + adapter wrapper for
                # this method is emitted by ``_emit_wasi_imports`` /
                # ``_emit_wasi_wrappers`` below.
                continue
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
        if self._wasi:
            self._emit_wasi_imports()
        # The ``panic`` builtin is a host import (the message must
        # reach the host's stderr) outside the capability system: it
        # needs no declared cap, mirroring the Python backend where
        # ``panic`` is a plain runtime function. The guest calls it
        # with (ptr, len) of the UTF-8 message and then executes
        # ``unreachable``, so the trap is deterministic and guest-
        # side regardless of host behaviour. A user-defined ``panic``
        # shadows the builtin and suppresses the import.
        if self._uses_panic(module):
            self._write(
                '(import "capa:host/panic" "panic" '
                '(func $panic (param i32) (param i32)))'
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
            # The panic host import reads the message out of linear
            # memory; belt-and-braces (a String message implies
            # interned literals or heap use already).
            or self._uses_panic(module)
        )
        if needs_memory:
            # Initial page count must cover the full static data
            # segment (interned string literals + the Grisu2 table),
            # not a hard-coded single page. Pre-fix (2026-06-10) the
            # declaration was always ``(memory 1 cap)``: any module
            # whose interned literals crossed 64 KiB failed at
            # INSTANTIATION time with "out of bounds memory access"
            # (active data segments are bounds-checked against the
            # initial size, before ``$alloc`` ever runs, which is
            # why ``--wasm-memory-cap`` had no effect). A 70 KiB
            # string literal -- printed, interpolated, or fed to
            # ``parse_json`` -- was enough to trap where the Python
            # backend ran fine.
            initial_pages = max(
                1, (self._string_data_offset + 65535) // 65536,
            )
            # Audit H1 (2026-05): bake the per-module memory cap
            # into the limits clause so ``$alloc``'s ``memory.grow``
            # traps at a deterministic page count rather than at
            # whatever the host happens to OOM at. ``None`` skips
            # the cap (host decides). 1 page = 64 KiB; default cap
            # is ``MEMORY_CAP_DEFAULT_PAGES`` (256 pages = 16 MiB).
            if self._memory_cap_pages is not None:
                if self._memory_cap_pages < initial_pages:
                    raise WasmEmissionError(
                        f"static string data needs {initial_pages} "
                        f"memory page(s) (64 KiB each) but the memory "
                        f"cap is {self._memory_cap_pages} page(s); "
                        f"raise it via --wasm-memory-cap"
                    )
                self._write(
                    f'(memory (export "memory") {initial_pages} '
                    f'{self._memory_cap_pages})'
                )
            else:
                self._write(f'(memory (export "memory") {initial_pages})')
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
            or self._wasi_env_uses_get_or_args()
            or self._wasi_net_uses_attenuation()
            or self._wasi_fs_uses_preopens
            or (self._wasi and ("Stdio", "read_line") in self._used_caps)
        ):
            heap_start = _align_up(self._string_data_offset, 8)
            self._write(
                f"(global $heap_top (mut i32) (i32.const {heap_start}))"
            )
            # WASI Fs metadata (2026-06-27): cache the
            # ``preopens.get-directories`` list pointer across all
            # metadata calls. ``$__wasi_fs_pre_inited`` flips to 1 on
            # the first call; ``$__wasi_fs_pre_data`` then holds the
            # list data pointer (each 12-byte element: descriptor
            # handle @0, str_ptr @4, str_len @8). The descriptors are
            # the preopen roots, live for the component's lifetime.
            if self._wasi_fs_uses_preopens:
                self._write(
                    "(global $__wasi_fs_pre_data (mut i32) (i32.const 0))"
                )
                self._write(
                    "(global $__wasi_fs_pre_inited (mut i32) (i32.const 0))"
                )
            self._emit_alloc_function()
            self._emit_cabi_realloc_function()
            # ``$str_eq`` is only needed when at least one Map
            # operation may run; it compares two (ptr, len) string
            # pairs byte-by-byte. Always emit when a map is in
            # play -- inlining it at every set/get call site would
            # bloat the WAT.
            # GAP-2b (2026-06-21): ``cap.allows(arg)`` queries no
            # longer emit any guest-side attenuation helper - they
            # route through the ``$<Cap>_allows`` host import - so
            # the old ``$str_starts_with`` / ``$proc_allows`` /
            # ``$str_has_slash`` gate is gone.
            if (self._uses_map_ops(module)
                    or self._eq_needs_str_eq(module)
                    or self._set_algebra_needs_str_eq(module)
                    or self._wasi_env_get_needs_str_eq()
                    or self._wasi_net_needs_str_eq()):
                self._emit_str_eq_function()
            if self._uses_string_concat(module):
                # String ``+`` lowers to ``call $str_concat`` (see
                # _emit_binop's String branch). The helper grows the
                # last bump allocation in place so ``out = out + x``
                # in a loop is O(n) amortised rather than O(n^2).
                self._emit_str_concat_function()
            if (self._uses_string_order_cmp(module)
                    or self._wasi_fs_list_dir_needs_str_cmp()):
                # Bug #2: String ``<`` / ``>`` / ``<=`` / ``>=`` lower
                # to ``call $str_cmp`` (byte-by-byte UTF-8 ordering ==
                # Python's code-point ordering). Independent of $str_eq.
                # WASI Fs.list_dir also calls ``$str_cmp`` to sort the
                # directory entry names into the oracle's
                # ``sorted(os.listdir(path))`` order, so the helper must
                # be present even when the program uses no String ``<``.
                self._emit_str_cmp_function()
            if self._uses_string_codepoint_index(module):
                # Slice 17 (2026-05-29): String.length and
                # String.substring switched from byte-indexing to
                # code-point-indexing to match Python. The two
                # helpers walk the UTF-8 byte stream skipping
                # continuation bytes.
                self._emit_str_codepoint_count_function()
                self._emit_str_cp_to_byte_offset_function()
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
                    self._emit_grisu_round_weed_function()
                    self._emit_grisu2_function()
                    # Dragon4 exact fallback (limb bignum) for the
                    # ~0.5% of values where Grisu cannot prove the
                    # shortest digit string. Emitted before $ftoa,
                    # which dispatches to it on the Grisu3 failure flag.
                    self._emit_dragon4_functions()
                    self._emit_ftoa_function()
            # parse_int / parse_float are built-in free functions
            # routed to runtime helpers. Emit only when used.
            if self._uses_parse_int(module):
                self._emit_parse_int_function()
            if self._uses_parse_float(module):
                # The correctly-rounded string->float parser needs the
                # limb-bignum helpers for its hard-rounding slow path
                # (the same family Dragon4 uses); emit them if the
                # float-format path above did not already.
                self._emit_bignum_helpers()
                self._emit_parse_float_function()
            # _capa_chr (internal): one-codepoint String from an Int
            # code point; backs \uXXXX decoding in the bundled JSON
            # parser. Emit only when used.
            if self._uses_capa_chr(module):
                self._emit_chr_function()
            # _capa_str_span (internal): O(1) String view over code
            # points [a, b) of the parser's per-character List<String>;
            # backs value / key extraction in the bundled JSON parser
            # (linear instead of substring's per-extraction re-walk).
            # Emit only when used.
            if self._uses_str_span(module):
                self._emit_str_span_function()
            # Generated structural-equality helpers ($eq_<Type>) for
            # any compound type compared with == / != (or used as a
            # pointer-shape List.contains element). Emitted here, at
            # module level before user functions, so they can mutually
            # recurse by name.
            self._emit_equality_helpers(module)
            # Set algebra helpers ($set_union_* / $set_intersection_* /
            # $set_difference_* / $set_is_subset_*). Emitted after the
            # $eq_* helpers because a pointer-shape Set element's
            # membership scan calls the element's $eq_<elem> helper;
            # WAT resolves calls by name across the module so order is
            # not strictly required, but keeping them adjacent reads
            # cleanly.
            self._emit_set_algebra_helpers(module)
        # Random capability: SplitMix64 helpers + the two
        # ``$rand_state`` / ``$rand_state_inited`` globals. Emitted
        # outside the heap conditional because the PRNG runs in pure
        # i64 / f64 ops (no allocator dependency); a Random-only
        # program with no Stdio or compound types would still
        # otherwise miss the helpers. Discovery in ``_uses_random``
        # gates the emission so a Random-free program pays zero cost.
        if self._uses_random(module):
            self._emit_random_globals_and_helpers()
        # Experimental WASI mode: emit the adapter wrappers that bridge
        # the ``$Cap_method`` bindings the call sites use to the raw
        # wasi:* imports declared above. Random's ``$Random_system_seed``
        # binding is consumed by ``$rand_state_init_if_needed`` (emitted
        # just above), so the wrapper must exist by module-link time;
        # WAT resolves calls by name across the whole module, so the
        # textual order here only needs to be inside the module body.
        if self._wasi:
            self._emit_wasi_wrappers()
        # Pre-register thunks for any top-level function used as a
        # ``Fun(...)`` value (e.g. ``xs.map(double_int)`` where the
        # closure arg is a global function reference rather than an
        # inline lambda). The thunk has the same shape as a lifted
        # lambda's wasm sig: it takes ``(env_ptr, args...)`` and
        # delegates to the original function dropping the env. By
        # registering them here, before the closure table is
        # emitted, the fn_idx values are stable for ``_push_value``
        # to use when it encounters a global ``Fun`` value in a
        # call argument.
        self._register_fn_ref_thunks(module)
        # Closure infrastructure: function table + (type) decls +
        # each lifted lambda is a top-level function below. Thunks
        # appended to the table after the lambdas so existing fn_idx
        # values stay stable.
        if self._lifted_lambdas or self._fn_ref_thunks:
            self._emit_closure_types_and_table()
            for lifted in self._lifted_lambdas:
                self._emit_lifted_lambda(lifted)
            for thunk in self._fn_ref_thunks.values():
                self._emit_fn_ref_thunk(thunk)
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
        # params other than Fs are dropped from the Wasm signature
        # because their methods are imported into the module by name
        # and the param carries no runtime value. String params expand
        # to two i32s (ptr, len) named ``${p.name}_ptr`` /
        # ``${p.name}_len``.
        #
        # Slices 25.2 - 25.6 (2026-05-30): Fs / Net / Db / Proc /
        # Env / Clock are un-erased and lowered as i32 handles so a
        # restricted cap carries its restriction across function
        # boundaries (audit slice 25 F1: the previous erased-cap
        # design relied on inline emit-time checks that dropped the
        # restriction the moment the cap crossed a function
        # boundary). Random / Unsafe / Stdio stay erased (no
        # attenuation surface to wire).
        param_clauses = []
        for p in fn.params:
            if p.ty in BUILTIN_CAPS:
                if p.ty in (
                    "Fs", "Net", "Db", "Proc", "Env", "Clock",
                ):
                    param_clauses.append(f"(param ${p.name} i32)")
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
        self._emit_body(fn.body)

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

    # ----- tail-call optimisation (roadmap P4) ------------------

    # Free-function names that ``_emit_user_call`` routes to a
    # non-``call $name`` path (intrinsics / host bridges / source-level
    # constructors). A tail call must reuse the *ordinary* user-call
    # shape, so these are excluded from the peephole and fall back to
    # the normal call + return.
    _TAIL_CALL_INTRINSICS = frozenset({
        "Random", "parse_json", "to_json",
        "parse_int", "parse_float", "to_float", "to_int",
        "_capa_chr", "_capa_str_span", "panic",
    })

    def _emit_body(self, instrs: list) -> None:
        """Emit a straight-line instruction sequence, applying the
        tail-call peephole (roadmap P4): a ``Call`` whose result is
        immediately returned (``return f(x)``) becomes a Wasm
        ``return_call``, so accumulator-style recursion runs in
        constant stack space instead of overflowing.

        The pair ``Call(dst=t)`` then ``Return(value=t)`` is the canonical
        CIR shape the lowerer produces for ``return f(...)``. ``return_call``
        is type-valid here for free: the returned value *is* the call's
        result, so the callee's result type equals the enclosing
        function's, which is exactly what the proposal requires.

        Used for every block body (function top level, ``if`` / ``else``
        arms, ``while`` body, ``match`` arms) so a tail call in any
        position is optimised.

        Known limitation (documented in CHANGELOG / docs/reference.md): a
        call in *expression*-position ``match`` / ``if`` (``return match
        n { ... }``) is NOT optimised, because the lowerer binds the
        match result to a temporary and the ``Return`` reads that
        temporary *after* the ``Match`` instruction, so the
        ``Call`` / ``Return`` pair is not adjacent here. The
        statement-form (``_ -> return f(...)``) is optimised. Lifting
        this needs a CIR-level tail-position marker set by the lowerer
        (so both backends share it), which is a separate change; the
        fallback for the unoptimised case is an ordinary call + return,
        which is correct, just not constant-stack."""
        n = len(instrs)
        i = 0
        while i < n:
            instr = instrs[i]
            nxt = instrs[i + 1] if i + 1 < n else None
            if (
                isinstance(instr, Call)
                and instr.dst is not None
                and isinstance(nxt, Return)
                and nxt.value is not None
                and nxt.value.kind in ("local", "param")
                and nxt.value.name == instr.dst
                and self._is_tail_callable(instr)
            ):
                self._emit_tail_call(instr)
                i += 2
                continue
            self._emit_instr(instr)
            i += 1

    def _is_tail_callable(self, instr: Call) -> bool:
        """True if ``instr`` is an ordinary user-function call (the only
        flavour the tail-call peephole handles). Variant constructors,
        intrinsics / host bridges, and closure calls keep their normal
        call + return lowering."""
        name = instr.callee_name
        if name in self._variant_to_sum:
            return False
        if name in self._TAIL_CALL_INTRINSICS:
            return False
        callee_ty = self._lookup_local_or_param_ty(name)
        if callee_ty and callee_ty.startswith("Fun"):
            return False
        return True

    def _push_call_args(self, args: list) -> None:
        """Push a call's arguments in the shared call ABI: capability
        args are erased except the handle-carrying ones (Fs / Net / Db /
        Proc / Env / Clock, slices 25.2-25.6, which cross function
        boundaries as i32 handles so a restricted cap keeps its
        restriction); String args expand to (ptr, len); everything else
        goes through the regular push path. Single source of truth for
        the ordinary call (``_emit_user_call``), the tail call
        (``_emit_tail_call``), and the trait/impl-method call
        (``_emit_trait_method_call``) so the three never drift."""
        for arg in args:
            if arg.ty in BUILTIN_CAPS:
                if arg.ty in ("Fs", "Net", "Db", "Proc", "Env", "Clock"):
                    self._push_value(arg)
                continue
            if arg.ty == "String":
                self._push_string_value_as_ptr_len(arg)
                continue
            self._push_value(arg)

    def _emit_tail_call(self, instr: Call) -> None:
        """Emit ``return_call $name`` for a call in tail position. The
        result is not bound and no separate ``return`` follows, because
        ``return_call`` transfers control to the callee directly."""
        self._push_call_args(instr.args)
        self._write(f"return_call ${instr.callee_name}")

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
        if is_string and op in ("<", ">", "<=", ">="):
            # Order comparison (Bug #2): the Python backend compares
            # strings lexicographically. ``$str_cmp`` returns -1 / 0 / 1
            # for the byte-by-byte UTF-8 ordering (== Python's code-point
            # ordering for well-formed UTF-8); fold its result into the
            # requested boolean with the matching i32 comparison against
            # zero.
            self._push_string_value_as_ptr_len(instr.left)
            self._push_string_value_as_ptr_len(instr.right)
            self._write("call $str_cmp")
            self._write("i32.const 0")
            self._write(_STR_CMP_FOLD[op])
            self._write(f"local.set ${instr.dst}")
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
            if op == "/":
                # Safety (Bug #4): ``f64.div`` yields ``inf`` on a zero
                # divisor, but the Python backend raises
                # ``ZeroDivisionError`` on ``1.5 / 0.0``. Mirror the
                # float-``%`` zero guard above: trap when the divisor is
                # zero. Non-zero division is left to IEEE-754.
                self._push_value(instr.right)
                self._write("f64.const 0")
                self._write("f64.eq")
                self._write("if")
                self._indent += 1
                self._write("unreachable")
                self._indent -= 1
                self._write("end")
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
        if op == "/" and op in _INT_BINOP and not is_float:
            # Safety + parity (Bug #1): ``i64.div_s`` truncates toward
            # zero (``-7 / 2 == -3``), but Capa Int division is floored
            # (``-7 / 2 == -4``), matching the Python backend's ``//``.
            # Compute ``q = a div_s b`` first - this preserves
            # wasmtime's native traps on ``b == 0`` and ``MIN / -1`` -
            # then apply the same floor correction the ``%`` path above
            # uses: subtract 1 from ``q`` iff ``(a rem_s b) != 0 and
            # (a XOR b) < 0`` (a non-zero remainder with operands of
            # differing sign). Mirrors ``_capa_idiv`` on the Python
            # side; both backends trap on ``/0`` and ``MIN / -1``.
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i64.div_s")
            self._write("local.set $_alloc_tmp_i64")
            # Predicate: (a rem_s b) != 0 AND (a XOR b) < 0.
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i64.rem_s")
            self._write("i64.const 0")
            self._write("i64.ne")
            self._push_value(instr.left)
            self._push_value(instr.right)
            self._write("i64.xor")
            self._write("i64.const 0")
            self._write("i64.lt_s")
            self._write("i32.and")
            self._write("if (result i64)")
            self._indent += 1
            self._write("local.get $_alloc_tmp_i64")
            self._write("i64.const 1")
            self._write("i64.sub")
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
            if op == "<<":
                # Safety + parity (Bug #1): ``i64.shl`` silently discards
                # the bits that leave the signed 64-bit window, so
                # ``1 << 63`` wraps to i64::MIN instead of raising. The
                # Python backend's ``_capa_shl`` traps whenever the
                # shifted value loses significant (or sign) bits. Detect
                # the same loss here: arithmetic-shift the result back
                # right by the count; if it does not recover the original
                # operand, high bits were dropped. This is bit-identical
                # to ``_capa_shl``'s masked-compare for every (a, b) in
                # the legal count range (verified by oracle). The result
                # of ``i64.shl`` is still on the stack; stash it, run the
                # check against the stash, then bind it.
                self._write("local.set $_alloc_tmp_i64")
                self._write("local.get $_alloc_tmp_i64")
                self._push_value(instr.right)
                self._write("i64.shr_s")
                self._push_value(instr.left)
                self._write("i64.ne")
                self._write("if")
                self._indent += 1
                self._write("unreachable")
                self._indent -= 1
                self._write("end")
                self._write("local.get $_alloc_tmp_i64")
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
            # A trait-typed operand is a single i32 pointer whose dynamic
            # type is only known at runtime (the offset-4 type-id). The
            # Python backend gives STRUCTURAL equality of the underlying
            # concrete value (``Beat(1) == Beat(1)`` is True even through
            # a ``Token`` binding), and returns False - not an error -
            # for two different dynamic types. The ``$eq_<Trait>``
            # dispatcher reproduces exactly that: it compares the two
            # type-ids (different -> 0) and routes a matching pair to the
            # concrete type's structural helper. Pick whichever side
            # names a trait.
            trait_ty = (
                _strip_type_qualifiers(left_ty)
                if self._is_trait_eq_ty(_strip_type_qualifiers(left_ty))
                else _strip_type_qualifiers(right_ty)
            )
            if self._is_trait_eq_ty(trait_ty):
                self._emit_compound_eq(instr, op, trait_ty)
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
            # Safety (Bug #6): Wasm has no ``i64.neg``; synthesise as
            # ``0 - x``. But ``0 - i64::MIN`` wraps back to MIN (the
            # only i64 value whose negation overflows), so guard it:
            # trap when ``x == i64::MIN`` to match the Python backend's
            # ``_capa_isub(0, x)`` ``OverflowError``. All other values
            # negate normally (``-5 -> -5``, ``-(-5) -> 5``).
            self._push_value(instr.operand)
            self._write("i64.const -9223372036854775808")  # i64::MIN
            self._write("i64.eq")
            self._write("if")
            self._indent += 1
            self._write("unreachable")
            self._indent -= 1
            self._write("end")
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
                and len(instr.args) == 1 \
                and instr.callee_name not in self._user_fn_names:
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
        # panic (builtin): write the message to the host's stderr via
        # the ``capa:host/panic`` import, then trap. The ``unreachable``
        # is guest-side so the abort is deterministic; everything after
        # it in this block is dead and validates under Wasm's
        # unreachable-mode typing.
        if instr.callee_name == "panic" \
                and len(instr.args) == 1 \
                and instr.callee_name not in self._user_fn_names:
            arg = instr.args[0]
            if arg.kind == "lit_str":
                offset, length = self._intern_string(arg.literal)
                self._write(f"i32.const {offset}")
                self._write(f"i32.const {length}")
            else:
                self._push_string_value_as_ptr_len(arg)
            self._write("call $panic")
            self._write("unreachable")
            return
        # _capa_chr (internal builtin): Int code point -> one-codepoint
        # String, via the $chr runtime helper (multi-value ptr/len).
        if instr.callee_name == "_capa_chr" \
                and len(instr.args) == 1 \
                and instr.callee_name not in self._user_fn_names:
            self._push_value(instr.args[0])
            self._write("call $chr")
            if instr.dst is not None:
                self._set_string_dst(instr.dst)
            else:
                self._write("drop")
                self._write("drop")
            return
        # _capa_str_span (internal builtin): (List<String> chars, Int a,
        # Int b) -> String, an O(1) (ptr, len) view spanning code points
        # [a, b) of the per-character list, via the $str_span helper.
        if instr.callee_name == "_capa_str_span" \
                and len(instr.args) == 3 \
                and instr.callee_name not in self._user_fn_names:
            self._push_value(instr.args[0])  # chars: List pointer (i32)
            self._push_value(instr.args[1])  # a: i64
            self._push_value(instr.args[2])  # b: i64
            self._write("call $str_span")
            if instr.dst is not None:
                self._set_string_dst(instr.dst)
            else:
                self._write("drop")
                self._write("drop")
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
        self._push_call_args(instr.args)
        self._write(f"call ${instr.callee_name}")
        if instr.dst is not None:
            # Bug #3: a Unit-returning callee leaves nothing on the
            # stack (its header has no result clause), so binding the
            # result -- ``let _ = void_fn()`` -- must emit no
            # ``local.set``; otherwise the validator reports "expected
            # i64 but nothing on stack". The dst temp's own type can be
            # a stale i64 default, so consult the callee's declared
            # return type, which is the source of truth for what the
            # call actually pushes.
            ret_ty = self._user_fn_return_types.get(instr.callee_name)
            if ret_ty is not None:
                head = _strip_type_qualifiers(ret_ty)
                if head in ("Unit", "") or ret_ty == "()":
                    return
            dst_ty = self._dst_capa_ty(instr.dst)
            # If the callee returns a non-empty value, store it in
            # ``instr.dst``. Capability / Unit dsts have no Wasm
            # representation; String returns are multi-value
            # (i32 i32) and need to land in the dst's _ptr / _len
            # pair (in reverse stack order: len is on top, then ptr).
            if dst_ty == "String":
                self._write(f"local.set ${instr.dst}_len")
                self._write(f"local.set ${instr.dst}_ptr")
            elif dst_ty in (
                "Fs", "Net", "Db", "Proc", "Env", "Clock",
            ):
                # Slices 25.2 - 25.6: Fs / Net / Db / Proc / Env /
                # Clock return values carry the handle as i32.
                self._write(f"local.set ${instr.dst}")
            elif dst_ty and dst_ty not in BUILTIN_CAPS and dst_ty != "Unit":
                self._write(f"local.set ${instr.dst}")

    def _write(self, line: str) -> None:
        if line == "":
            self._lines.append("")
        else:
            self._lines.append(self._unit * self._indent + line)
