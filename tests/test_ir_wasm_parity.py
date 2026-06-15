# pyright: reportCallIssue=none
"""Python<->Wasm output parity harness for examples/wasm/.

The README's claim that the Wasm backend produces output
bit-identical to the Python reference path lacked an in-tree
verification: every Wasm execution test in
``tests/test_ir_wasm.py`` checks the Wasm output against a
hand-rolled expected string, never against the same program's
Python output. This file closes that gap for the parity-clean
subset of ``examples/wasm/`` -- those programs that:

- use only ``Stdio`` (no ``Clock`` / ``Env`` / ``Fs`` to keep the
  runs deterministic across backends without fixtures);
- avoid ``Float`` interpolation (the Wasm ``$ftoa`` helper
  prints fixed-6-decimal truncated values while Python's
  ``str(float)`` is variable-width; that divergence is
  documented under TODO.md as a separate task).

For each parity-compatible example the harness compiles + runs
both backends in-process, captures stdout, and asserts the two
buffers match exactly. Audit 2026-05-25 (item #4).
"""

from __future__ import annotations

import io
import shutil
import sys
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm, lower


_EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "wasm"


# Stdio-only programs that produce bit-identical output across
# both backends. Float interpolation now goes through a Grisu2
# port in the Wasm runtime, so JNum-bearing programs are parity-
# clean too.
_PARITY_PROGRAMS: list[str] = [
    "hello.capa",
    "typestate_door.capa",
    "typestate_socket.capa",
    "typestate_methods.capa",
    "fizzbuzz.capa",
    "shape_area.capa",
    "strings.capa",
    "word_count.capa",
    "closures.capa",
    "json_demo.capa",
    "generic_accumulator.capa",
    "list_struct_basics.capa",
    "list_struct_map_identity.capa",
    "list_struct_map.capa",
    "list_struct_filter.capa",
    "list_struct_fold.capa",
    "list_scalar_to_struct.capa",
    "map_struct.capa",
    "map_string_int.capa",
    "map_int_int.capa",
    "map_int_string.capa",
    "map_int_struct.capa",
    "map_int_update.capa",
    "map_bool_int.capa",
    "map_point_key.capa",
    "map_tuple_key.capa",
    "map_option_key.capa",
    "map_nested_struct_key.capa",
    "list_nested.capa",
    "int_match.capa",
    "struct_eq.capa",
    "tuple_eq.capa",
    "sum_eq.capa",
    "list_eq.capa",
    "list_contains_struct.capa",
    "list_contains_float.capa",
    "nested_eq.capa",
    "set_basics.capa",
    "set_string.capa",
    "set_struct.capa",
    "map_eq.capa",
    "set_eq.capa",
    "numeric_parity.capa",
    "bitwise.capa",
    "safety_traps.capa",
    "allows_inline.capa",
    "random_seeded.capa",
    "net_get.capa",
    "net_restrict.capa",
    "string_replace.capa",
    "string_char_at.capa",
    "string_index_of.capa",
    # Slice (2026-06-13): String.bytes() returns the receiver's UTF-8
    # bytes as a List<Int> (each 0..255). The Wasm backend stores
    # strings as their raw UTF-8 byte slice so it copies the bytes
    # straight through; the Python backend encodes via
    # ``str.encode('utf-8', 'surrogatepass')``. Covers ASCII,
    # multi-byte BMP (2-/3-byte), astral (4-byte emoji), the empty
    # string, the code-point-count vs byte-count relationship for a
    # mixed string, and a lone surrogate (from a JSON \uD800 escape)
    # whose 3-byte WTF-8 form is byte-identical on both backends.
    "string_bytes.capa",
    "tuple_arity_n.capa",
    # Slice (2026-06-03): nested tuple indexing. Pre-fix the Wasm
    # emitter stored a raw i64 into the i32 tuple local for a
    # nested-tuple element (a dst type like (Int, Int) matched no
    # pointer-shaped branch), producing invalid Wasm. A nested
    # tuple element is an i32 pointer in the slot, so it now decodes
    # like a struct / list element.
    "tuple_nested_index.capa",
    "map_keys_values.capa",
    "range_iter.capa",
    "option_result_hofs.capa",
    "fn_ref_as_closure.capa",
    "net_post.capa",
    # ``fs_demo`` and ``env_demo`` were both flagged as deferred
    # ("needs a fixture") in earlier slices, but inspection shows
    # they are parity-clean by construction: ``fs_demo`` writes to
    # / reads from a single constant ``/tmp/`` path and prints only
    # the constant strings around it; ``env_demo`` queries the
    # *same* ``os.environ`` from both backends within one Python
    # process, so back-to-back runs see identical values. Promoted
    # to the parity list 2026-05-29.
    "fs_demo.capa",
    "env_demo.capa",
    # Slice 11 (2026-05): Db v1 (SQLite-backed) with path-prefix
    # attenuation. db_demo writes to a fresh ``/tmp/`` sqlite file
    # and exercises exec + query + restrict_to; both backends route
    # through ``sqlite3`` (Python directly; Wasm via host bridge).
    "db_demo.capa",
    # Slice 12 (2026-05-29): regression net for the audit findings
    # that Fs.{exists,is_dir,mkdir,list_dir} bypassed attenuation
    # on the Wasm backend, and that the path-prefix check admitted
    # ``/tmproot`` lookalikes when restricted to ``/tmp``.
    "fs_attenuation_audit.capa",
    # Slice 13 (2026-05-29): close the two audit findings deferred
    # from slice 12 - Clock.sleep on a restrict_to_after(future)
    # cap silently no-ops on both backends now; Db.exec blocks
    # ATTACH/DETACH at the SQLite parser level on both backends.
    "clock_sleep_attenuation.capa",
    "db_attach_blocked.capa",
    # Slice 14 (2026-05-29): lift the literal-only restriction on
    # Fs/Env/Db.allows so programs can pass a runtime String
    # argument and get the cap-mediated answer on both backends.
    "allows_dynamic.capa",
    # Slice 15 (2026-05): Proc v1 (sandboxed subprocess) with
    # basename + suffix-boundary attenuation. proc_demo shells
    # out to ``python`` (present on every CI matrix entry) with
    # a fixed string so the captured stdout is deterministic;
    # both backends run subprocess.run(argv, capture_output=True,
    # timeout=30, shell=False) and decode UTF-8 with
    # errors='replace'.
    "proc_demo.capa",
    # Slice 16 (2026-05-29): regression net for three older-code
    # audit findings - Float captures in lifted lambdas crashed
    # the wasm verifier, Set<Float> needle stash + NaN equality
    # was bit-eq (NaN compared equal), and negative-i64 list
    # indices whose low 32 bits wrapped in-bounds silently
    # returned xs[0] instead of trapping.
    "audit_float_and_index.capa",
    # Slice 17 (2026-05-29): String.length + String.substring on
    # the Wasm backend switched from byte-indexed to code-point-
    # indexed to match the Python runtime. Pre-fix Wasm
    # ``"abcé".length()`` returned 5 (byte count) while Python
    # returned 4 (code-point count); substring returned partial
    # UTF-8 mid-codepoint on Wasm.
    "string_unicode.capa",
    # Slice 19 (2026-05-29): for-loop lambda capture parity.
    # Pre-fix Python emit captured loop vars by reference
    # (lambda: i), Wasm captured by value at MakeLambda time.
    # Both wrong on their own, no parity test exercised the
    # shape. Now Python emits ``lambda i=i: ...`` to bind by
    # value, matching Wasm.
    "closure_loop_capture.capa",
    # Slice 24 (2026-05-30): block-body lambda implicit-result
    # tail parity. Pre-fix the CIR lowerer's Block branch fell
    # through with no Return, so a non-Unit lambda like
    # ``fun (x) -> Int => { let y = x*2; y + 1 }`` returned
    # None on Python (silent wrong answer) and trapped on Wasm
    # ('unreachable' executed). Both fixed: CIR side mirrors
    # the implicit-result rule already used by ``_lower_match_expr``;
    # transpiler side wraps the tail in ``return`` for the
    # legacy Python path.
    "lambda_block_implicit_result.capa",
    # Slice 25.2 (2026-05-30): cross-function attenuation on Wasm.
    # Pre-slice the Wasm backend lost a Fs cap's restriction the
    # moment the cap was passed to another function (audit slice
    # 25 F1); the program below let a helper read a file outside
    # the parent's narrow prefix. Post-slice the host-side handle
    # table holds the restriction and enforces ``fs.allows(path)``
    # on every privileged op, so both backends print the same
    # ``ok: helper read denied`` line. If this test fails the
    # regression is back.
    "fs_cross_function_attenuation.capa",
    # Slice 25.3 (2026-05-30): same audit-slice-25 cross-function
    # attenuation bug but for Net (F1), plus the substring-attack
    # bug the inline ``$str_contains`` check introduced (F2). Both
    # programs print exactly one ``ok:`` line on both backends; a
    # ``BUG:`` line means the regression came back.
    "net_cross_function_attenuation.capa",
    "net_substring_attack.capa",
    # Slices 25.4 / 25.5 / 25.6 (2026-05-30): same audit-slice-25 F1
    # cross-function attenuation regression net for the remaining
    # un-erased caps - Db / Proc (slice 25.4), Env (slice 25.5),
    # Clock (slice 25.6). Each program narrows a root cap, hands it
    # to a helper, and asserts the helper's privileged op is denied.
    # The Python backend has always passed; the Wasm backend now
    # matches via the handle-table routing.
    "db_cross_function_attenuation.capa",
    "proc_cross_function_attenuation.capa",
    "env_cross_function_attenuation.capa",
    "clock_cross_function_attenuation.capa",
    # Roadmap P4 (tail-call optimisation): tail calls in if/else,
    # statement-match arms, and mutual recursion lower to Wasm
    # ``return_call``. At this moderate depth (300) both backends agree;
    # the constant-stack property at large depth is a separate Wasm-only
    # test (the Python reference would hit its recursion limit).
    "tail_recursion.capa",
    # Match-pattern parity slice (2026-06-03): patterns that already
    # worked on the Python backend but the Wasm CIR path rejected at
    # compile time. ``match_ident_sum`` is a bare-identifier catch-all
    # in a sum match; ``match_float_lit`` is Float-literal arms
    # (f64.eq); ``match_or_pattern`` is binding-free or-patterns
    # (variant + Int/Float literal alternatives); ``match_struct_pattern``
    # destructures struct scrutinees (literal / wildcard fields,
    # shorthand binds, nested struct sub-patterns).
    "match_ident_sum.capa",
    "match_float_lit.capa",
    "match_or_pattern.capa",
    "match_struct_pattern.capa",
    # Bound or-pattern slice (2026-06-04): or-patterns whose
    # alternatives are different variants each binding the SAME name(s)
    # (e.g. ``Pos(n) | Neg(n) -> n``). Pre-fix the Wasm CIR lowerer
    # rejected any binding alternative ("or-pattern with bindings not
    # supported on the Wasm backend yet"); the Python backend already
    # handled them via native ``a | b`` match. The Wasm emitter now ORs
    # the alternative tag predicates and, after the predicate gates
    # entry, re-checks each variant alternative's tag to load the
    # matched alternative's payload into the shared binder. Covers a
    # single shared bind, two shared binds, a bound or-pattern under a
    # guard, statement- and expression-position match, payload types
    # Int / String / Char / Bool / Float / struct / list, and a
    # binding-free or-pattern regression.
    "match_or_bind.capa",
    # Char slice (2026-06-03): a Capa ``Char`` is a single-codepoint
    # String; the Wasm path normalizes the type token ``Char`` ->
    # ``String`` before emit so the existing String machinery carries
    # it. ``char_basics`` covers value / param / return / equality /
    # tuple / list / struct-field / multibyte; ``match_char_lit``
    # covers char-literal match patterns (one-char string compare via
    # ``$str_eq``). Pre-fix both errored with "Capa type 'Char' has
    # no Wasm encoding yet".
    "char_basics.capa",
    "match_char_lit.capa",
    # Generic-struct slice (2026-06-03): a generic struct's field,
    # read across a function boundary, must decode identically on
    # both backends for any concrete T. Pre-fix the Wasm path left
    # ``Pair<T>`` un-monomorphised, so the field ``a: T`` was sized /
    # decoded as the bare type variable (no Wasm encoding) and a
    # ``Pair<Char>`` returned from one function and read in another
    # mis-decoded ("unknown local $_ir_t0" / "type mismatch i32 vs
    # i64"). The monomorphiser now specialises generic struct / sum
    # types per concrete instantiation (``Pair<Char>`` ->
    # ``Pair__Char`` with ``a: Char``) so the layout machinery sizes
    # every field from its real type. Covers T = Int / String / Char
    # / Bool / Float, a compound generic field (List / nested struct),
    # the same-function read, and the non-generic regression case.
    "generic_struct_field.capa",
    # Generic FUNCTION over a user SUM type slice (2026-06-06): a generic
    # function whose parameter / return type is a user-defined sum
    # parameterised by the function's type variable (``unwrap<T>(o:
    # Opt<T>, fallback: T) -> T``) type-checked and ran on Python but
    # miscompiled on Wasm once instantiated at more than one concrete
    # type. The monomorphiser already specialised both the sum decl and
    # the function, but the emitter routed a variant constructor to a sum
    # via a table keyed by the bare variant name; two monomorphic clones
    # sharing a variant name (``Opt__Char`` / ``Opt__Point`` both declare
    # ``Just``) collapsed that table to the last-declared clone, so a
    # ``Just('z')`` typed ``Opt__Char`` was laid out with the wrong
    # clone's payload sizes ("type mismatch: expected i32, found i64" at
    # Wasm validation). The emitter now resolves a constructor's sum from
    # the dst local's concrete monomorphised type. Covers T = Int /
    # String / Char, the fallback (Nothing) arm, a generic fn that
    # returns a constructed sum, a compound payload (struct + list), the
    # same generic fn at several concrete types, and a second generic sum.
    "generic_fn_sum.capa",
    # Generic-impl-method slice (2026-06-07): methods on a generic type's
    # ``impl`` block must dispatch once the type is monomorphised. The
    # monomorphiser specialised the generic struct / sum decls but left
    # ``module.impls`` keyed on the bare generic head with type-variable
    # bodies, so a method call on a monomorphised receiver (``Box__Int``)
    # found no method-table entry on the Wasm backend. The pass now
    # specialises each generic impl per instantiation and re-keys it on
    # the mangled type name. Covers a T-getter, a T-arg method, a
    # String-returning method, a self.method() call, three instantiations
    # of one type, T-typed param / return shapes, a generic value in a
    # list / across a function boundary, and a generic sum's match-self
    # methods.
    "generic_impl_methods.capa",
    # Generic-impl-method defect slice (2026-06-07): three review-found
    # defects in the generic-impl monomorphisation path, each correct on
    # the Python reference but wrong / crashing on Wasm. (1) A generic
    # type with more than one inherent ``impl`` block silently dropped
    # every block after the first (the per-instantiation emit dedup keyed
    # on ``(mangled_type, trait_name)`` collided all inherent blocks onto
    # ``(Cell__Int, None)``); now keyed on the method name too so every
    # method survives, including a never-called method in a later block.
    # (2) A sum-variant construction inside a generic method
    # (``return Some_(x)``) left the dst typed ``Opt<?>`` and crashed
    # ("no Wasm encoding") because partial-type resolution never ran over
    # specialised method bodies; now it does. (3) A nested generic
    # instantiation through a method (``Cell<Cell<Int>>`` with
    # ``.get().get()``) mangled to ``Cell__Cell`` (bare-headed method
    # return) instead of ``Cell__Cell_Int``; the make-struct-site
    # inference now carries nested type arguments at full depth.
    "generic_impl_methods_advanced.capa",
    # Generic-literal-in-control-flow slice (2026-06-07): a generic
    # struct literal whose construction site is INSIDE a control-flow
    # block (if then/else, for, while, match arm) crashed the Wasm
    # backend with a bare-headed "Capa type 'Box' has no Wasm encoding
    # yet". ``_patch_bare_generic_struct_refs`` walked only the flat
    # top-level ``fn.body`` and never recursed into nested instruction
    # bodies, so although the mangled clone was registered (the scan side
    # recurses) the bare ``MakeStruct.type_name`` and dst-local typing
    # inside the nested block were never patched. The patch pass now
    # recurses into nested control-flow bodies with per-branch scoping.
    # Covers a literal built in an if then-body, an if else-body, a for
    # body, a while body, and a match arm; nested control flow (if inside
    # for); two sibling branches building the SAME generic type at
    # DIFFERENT instantiations (Box<Int> vs Box<String>, value-checked so
    # a wrong cross-branch scope entry surfaces); and a method call on a
    # literal built inside a branch.
    "generic_literal_in_control_flow.capa",
    # List-parameter mutation slice (2026-06-04): pushing to a List
    # received as a function PARAMETER (no local list built in the body)
    # crashed the Wasm backend at assembly time with "unknown local
    # $_alloc_tmp". The push grow path and the contains scan stash a
    # scratch pointer in $_alloc_tmp, but _collect_locals only declared
    # that local when the body itself built a list (MakeList / has_list).
    # A list arriving purely as a parameter never tripped that gate, so
    # the emitted WAT referenced an undeclared local. Fix: the
    # $_alloc_tmp declaration gate now also fires on has_list_method (any
    # List method call). Covers push on a parameter for Int / String /
    # Char / Bool / Float / struct / nested-list elements, contains on a
    # parameter, and the by-reference caller-visibility semantics
    # (a push through a parameter is visible to the caller on both
    # backends, including across the grow path).
    "list_param_push.capa",
    # Tuple-destructuring for-pattern slice (2026-06-06): a for-loop
    # whose loop pattern destructures a tuple (``for (a, b) in pairs``)
    # already ran on the Python backend but the Wasm CIR lowerer
    # rejected it ("for-pattern TuplePat"). The lowerer now binds each
    # iteration's element to a fresh temporary carrying the tuple type
    # and destructures it positionally through the same ``Index`` path
    # that powers ``let (a, b) = t`` and ``t[i]``; both backends already
    # emit ``For`` (single name) and tuple ``Index``, so no IR-node or
    # emitter change was needed. Covers arity 2/3/4, component types
    # Int / String / Char / Bool / struct / nested-tuple, a wildcard
    # component, the plain single-identifier regression, and nested
    # for-loops (a tuple-destructure loop inside a plain one and inside
    # another tuple-destructure loop).
    "for_tuple_destructure.capa",
    # String iteration slice (2026-06-06): ``for c in s`` walks the
    # receiver's UTF-8 byte slice one Unicode code point at a time on
    # the Wasm backend, binding the loop variable as a one-codepoint
    # String (a ptr/len view into the original buffer) per iteration.
    # Pre-fix the Wasm CIR emitter rejected it at lowering time ("For-
    # iter over type 'String': only List, Set, and Range iteration are
    # supported") while the Python backend already yielded one-character
    # strings. The analyzer now types the loop variable String (was
    # Unknown) and Char / String are interchangeable for == so a char-
    # literal comparison still type-checks. Covers ASCII, a mix of
    # ASCII / accented / CJK / emoji (astral), the empty string, the
    # element used as a String (interpolate / compare to a one-char
    # string and a char literal / concatenate / collect / pass to a
    # String fn), break / continue / early return, iterating a String
    # from a variable / function return / struct field / literal, and
    # nested loops (String in List, List in String, String in String).
    "for_string_iter.capa",
    # Slice (2026-06-06): struct field-target assignment on the Wasm
    # backend. ``obj.field = value`` lowers to a FieldStore that writes
    # the field slot of the heap record in place (the symmetric write to
    # a field read), mirroring the Python backend's in-place mutation.
    # Covers every field type (Int / String / Char / Bool / Float /
    # nested struct / list), the read-modify-write form (``x = x + 1``
    # and ``+=``), a nested receiver (``outer.inner.n``), and caller-
    # visibility through a function boundary (a callee mutating the
    # caller's struct).
    "struct_field_assign.capa",
    # Slice (2026-06-06): augmented integer division / modulo. ``x /=
    # y`` and ``x %= y`` on an Int target must produce the same floored
    # result as the explicit ``x = x / y`` / ``x = x % y`` form (which
    # the Wasm backend already gets right). The Python backend routed
    # Int ``+= -= *= <<= >>=`` through the floor / overflow helpers but
    # let ``/=`` / ``%=`` fall through to raw Python operators, so ``x
    # /= 4`` was true division (Float, wrong rounding) and ``-7 /= 2``
    # printed ``-3.5`` instead of ``-4``. Covers positive / negative /
    # mixed-sign / zero-result operands as a plain local and as a
    # struct-field read-modify-write, plus the Float ``/=`` (unchanged,
    # stays float division) and the ``+= -= *=`` regression.
    "aug_int_divmod.capa",
    # Slice (2026-06-07): list literal of a sum type with an interleaved
    # payloadless (tag-only) variant element. Pre-fix _emit_make_list
    # cached the data-array base pointer in $_alloc_tmp and reused it for
    # every element store, but a payloadless variant element pushes via
    # the variant_ctor path in _push_value, which does ``call $alloc`` +
    # ``local.tee $_alloc_tmp`` and so overwrote that scratch with the
    # fresh variant pointer. Every element AFTER the first payloadless
    # variant then stored at variant_ptr + offset instead of the data
    # array, reading back as 0 (silent wrong value): ``[Nil, Has(3)]``
    # read element 1 as 0 on Wasm (Python gave 3); ``[Has(5), Nil,
    # Has(7)]`` read element 2 as 0. The .push()-built equivalent was
    # always correct (push re-reads data_ptr from the header each call).
    # Fix: _emit_make_list re-reads data_ptr from the list header for
    # each element store, immune to any element push that clobbers a
    # scratch local. Covers payloadless first / last / middle / multiple
    # consecutive / all-payloadless / all-payload orders, payload types
    # Int / String / struct / list / tuple each with an interleaved
    # payloadless variant, a non-generic AND a monomorphised generic sum,
    # reads by index AND by iterating + matching, and the .push()
    # regression.
    "list_literal_sum_interleaved.capa",
    # Slice (2026-06-07): top-level ``const`` of a non-i64-shaped type
    # used at a value site. Pre-fix the global-const branch of
    # ``_push_value`` recursed every const through the generic literal
    # path, so a ``const S: String`` landed in the packed-i64
    # ``lit_str`` branch (ptr | len<<32) - the encoding the uniform
    # 8-byte slots (tuple / Map / variant payload) need, but the wrong
    # shape for a String value fed where (ptr, len) two-i32s are
    # expected (println, ``+``, ``==``, a String fn arg). Module
    # validation crashed with "type mismatch: expected i32, found i64".
    # Fix: the const branch now dispatches on the stored literal's
    # shape, delegating a String const to ``_push_string_value_as_ptr_len``
    # (two i32s) and keeping the recursion for the scalar consts (Int ->
    # i64, Bool -> i32, Float -> f64). Covers a String const via bare
    # println / interpolation / concat / == / String-fn arg, Int / Bool
    # / Float consts used several ways, and consts read across more than
    # one function.
    "top_level_const.capa",
    # Slice (2026-06-07): a top-level String ``const`` used at every
    # non-i64-shaped value site the global-const fix's reviewer
    # verified by hand. Pre-fix the sibling struct-field-store helpers
    # ``_push_string_field_ptr_only`` / ``_push_string_field_len_only``
    # handled lit_str / local / param but NOT the ``global`` const
    # case, so a String const used as a struct-field initializer
    # (``Box { label: S, n: 5 }``) errored loudly on the Wasm backend
    # ("cannot push string ptr of Value kind 'global'") while Python
    # accepted it - a loud divergence, not a miscompile, but still a
    # case parity must cover. Fix: both helpers gained a global-const
    # branch that resolves the const from ``_const_values`` and re-
    # dispatches on the underlying lit_str literal, mirroring the
    # const branch already present in ``_push_string_value_as_ptr_len``.
    # Covers a String const as a struct field (read back via println +
    # interpolation), a String const AND a String literal as fields in
    # one struct, an empty-string const and a multi-byte-UTF-8 const as
    # fields, and - to lock the whole matrix - a String const as a Map
    # key, Map value, List element, tuple component, and match
    # scrutinee.
    "const_string_sites.capa",
    # Slice (2026-06-07): a method invoked through a trait-typed
    # (user-capability) receiver must give its result the trait
    # method's DECLARED return type, so the Wasm backend stores /
    # reads it in the right calling shape - String as (ptr, len),
    # Bool as i32, Float as f64, Int as i64. A String return read
    # back as a single i64 would trip module validation or silently
    # mis-decode. The single-impl trait routes monomorphically
    # through the impl's mangled method; this program exercises a
    # String return printed / interpolated / concatenated / compared
    # / passed onward to another String consumer, Bool / Float / Int
    # returns used in branch / arithmetic / print, the direct-return
    # ``return g.greet()`` shape, and the let-then-use shape.
    # (A trait with more than one impl needs dynamic dispatch over a
    # packed struct_ptr+vtable layout the backend does not emit yet;
    # that case raises a precise WasmEmissionError rather than
    # miscompiling, so it is not a parity program.)
    "trait_return_shapes.capa",
    # Sibling of trait_return_shapes.capa using the ``trait`` keyword
    # (SymbolKind.TRAIT) instead of ``capability``
    # (SymbolKind.CAPABILITY). The capability flavour already resolved
    # a method's declared return type at the call site; the trait
    # flavour fell through to TyUnknown, which propagated as ``?`` and
    # broke the Wasm backend's calling shape (String return decoded as
    # a single i64). Covers String / Bool / Float / Int returns plus an
    # aggregate (struct + List) return, a struct implementing TWO
    # different single-impl traits, and a trait method returning another
    # trait type.
    "trait_keyword_return_shapes.capa",
    # Group A generics slice (2026-06-07): the three remaining
    # Wasm-backend generics gaps. (A1) A generic FREE FUNCTION whose
    # parameter / return type is itself a generic struct or sum, called
    # at >=2 instantiations: a generic struct literal bound to a local
    # carried only the bare generic head (``bi: Box`` not ``Box<Int>``),
    # so call-site inference could not unify ``Box<T>`` against it and
    # the call missed its clone ("unknown func $unwrap_box"); a pre-pass
    # now annotates each such local with its canonical instantiation
    # before inference. (A2) Generic struct construction / field access
    # in nested / list / generic-field paths, value-checked. (A3) A
    # generic sum's payload of type T matched with a binder, at T = Int /
    # String / a struct payload and through a NESTED generic sum: a sum
    # clone's ``payload_tys`` list escaped the instantiation rewrite
    # (stayed ``Opt<Int>`` not ``Opt__Int``), and the match-binder
    # refinement read stale pre-rewrite decls and never reached an inner
    # match's scrutinee nor a refined binder's Value references ("no Wasm
    # encoding for 'Opt<Int>' / 'T'"); the rewrite now threads
    # ``payload_tys``, the refinement reads the rewritten decls, recovers
    # an inner scrutinee's sum from its refined local, and syncs every
    # refined binder's Value references.
    "generic_fn_struct.capa",
    "generic_struct_construction.capa",
    "generic_sum_payload_binder.capa",
    # Multi-impl trait dynamic dispatch slice (2026-06-07): a trait with
    # MORE THAN ONE impl, called through a trait-typed value, dispatches
    # to the right concrete impl on the Wasm backend. Pre-fix the front-
    # end accepted such programs and they ran on Python, but the Wasm
    # backend raised a precise WasmEmissionError (no vtable / dynamic-
    # dispatch codegen). The fix stores a per-concrete-type type-id at
    # offset 0 of every struct that implements a multi-impl trait (fields
    # shift after an 8-byte header, invisible to field iteration), keeps a
    # trait value as a single i32 struct pointer (no fat pointer, no
    # boundary packing), and at a method call on a trait-typed receiver
    # loads the type-id and dispatches via an if-chain to the matching
    # mangled impl method. Covers every result shape (String / Int / Bool
    # / Float), three impls with different field layouts, the trait value
    # flowing through a let / param / return / struct field / sum-payload
    # match, a List of trait values with mixed concrete types iterated
    # with the method called per element (the headline), a self-method
    # call, and a participating struct used as a plain concrete value
    # (direct call / field read / structural equality) to prove the
    # header does not corrupt those paths.
    "multi_impl_dispatch.capa",
    # Sum-type impl targets of a multi-impl trait (2026-06-07): the
    # type-id moved to a UNIFORM offset 4 (free padding in both struct
    # and sum layouts) so a single dispatcher routes both. A sum keeps
    # its variant tag at offset 0 and payloads at offset 8 unchanged.
    # ``multi_impl_sum_dispatch.capa`` covers two distinct sum impls of
    # one trait (every result shape, let / param / return / field /
    # match hops, a mixed-sum List<Trait>, match self, self-method call,
    # plain-sum match + equality); ``multi_impl_mixed_dispatch.capa``
    # covers ONE trait with BOTH a struct impl AND sum impls (the case
    # the uniform offset exists for) through every hop and a List<Trait>
    # mixing struct + sum concrete types.
    "multi_impl_sum_dispatch.capa",
    "multi_impl_mixed_dispatch.capa",
    # Trait-typed value as a container payload / value (2026-06-08): a
    # trait value lowers to a single i32 heap pointer tagged with a
    # dynamic type-id, but the Wasm pointer-shape predicate did not treat
    # a trait head as pointer-shaped, so the uniform-8-byte slot encoders
    # neither i64-extended on store nor i32-wrapped on read-back. The fix
    # recognises trait heads centrally, repairing every container
    # symmetrically. ``option_result_trait_payload.capa`` covers
    # Option<Trait> (Some + None) and Result<Trait> (Ok + Err) over a
    # single-impl trait and a multi-impl trait at struct AND sum dynamic
    # types, dispatching after extraction; ``map_trait_value.capa`` covers
    # Map<String, Trait> + Map<Int, Trait> with mixed dynamic types,
    # Map.get -> Option<Trait> + dispatch, Map.values iteration, an
    # overwrite and a miss; ``container_trait_payload.capa`` covers
    # List<Trait> (iterate / .get(i) / index), a tuple with a trait
    # component (let + match destructure), and a struct field of trait
    # type.
    "option_result_trait_payload.capa",
    "map_trait_value.capa",
    "container_trait_payload.capa",
    # Trait-typed value structural equality (2026-06-08): == / != on a
    # trait-typed value dispatches at runtime on the offset-4 type-id to
    # the matching concrete type's $eq_<Concrete> helper via a $eq_<Trait>
    # dispatcher. Two trait values are equal IFF same dynamic type AND
    # structurally equal; different dynamic types (incl struct-vs-sum)
    # compare not-equal (matching Python's False, never an error). Pre-fix
    # the Wasm backend raised a precise WasmEmissionError for trait == / !=.
    # ``trait_value_eq.capa`` covers direct == / != for single-impl AND
    # multi-impl traits, struct AND sum dynamic types (sum with payload-
    # bearing + payloadless variants), same-type-equal / same-type-different
    # / different-type cases. ``trait_eq_in_containers.capa`` covers a trait
    # leaf nested in List<Trait>, Option<Trait>, Result<Trait, Int>,
    # Map<String, Trait>, Map<Int, Trait>, a (Trait, Int) tuple, a struct
    # with a trait field, and List<Trait>.contains. (Trait as a Map key /
    # Set element stays a precise loud error: a sum dynamic type is
    # unhashable on the Python backend while a struct one is hashable, so
    # the two backends cannot agree at compile time.)
    "trait_value_eq.capa",
    "trait_eq_in_containers.capa",
    # Audit C1 (2026-06-09) + F2 (2026-06-10): Float interpolation
    # parity. The harness historically EXCLUDED Float interpolation,
    # which hid a silent cross-backend miscompile - the Wasm Grisu2
    # port printed ``14.285714285714287`` for ``100.0 / 7.0`` where
    # Python's repr gives ``...286``, because the WAT omitted Grisu2's
    # RoundWeed last-digit nudge. C1 ported RoundWeed; F2 added the
    # Grisu3 confidence flag plus the exact limb-bignum Dragon4
    # fallback for the sub-1% of values Grisu cannot prove shortest
    # (including arithmetic-reachable ones like 86.0 / 7018.0 that
    # Grisu2 alone rendered as a non-round-tripping decimal). Every
    # computed-float class in this program is now byte-identical with
    # Python repr across both backends, so the file is parity-clean.
    "float_interpolation.capa",
    # Loud-error stdlib gap closure (2026-06-10): three method families
    # that previously raised a clean WasmEmissionError now compile to
    # Wasm with Python parity.
    #   list_query_methods: List.first / last / find / find_index /
    #     sorted_by. Covers empty-list -> None, no-match -> None, match
    #     at index 0 and the last index, and sorted_by stability
    #     (equal-comparing elements keep input order) over Int, struct,
    #     and String element types via a bottom-up STABLE merge sort
    #     (Python's sorted is Timsort = stable; the left-biased merge
    #     reproduces that exactly).
    #   range_methods: Range.length / contains / is_empty / to_list on a
    #     Range used as a value. Half-open [start, stop) with stop =
    #     end + (inclusive ? 1 : 0), matching CapaRange's range(start,
    #     stop). Covers empty (5..5), single, inclusive (a..=b),
    #     contains at the boundaries, and to_list materialisation.
    #   net_allows: Net.allows(host) inlined at emit time (exact host-
    #     set membership, NOT a prefix check), literal + dynamic arg,
    #     allowed / denied / prefix-share boundary, and chained
    #     restrict_to narrowing to the empty set.
    "list_query_methods.capa",
    "range_methods.capa",
    "net_allows.capa",
    # Variant-payload literal slice (2026-06-10): literal patterns
    # nested inside a variant payload (``Some(true)``), found by a
    # downstream capa_cli smoke pass. Pre-fix the Wasm sum-match path
    # raised "Phase 6C: nested pattern PatLiteral inside variant
    # payload not yet supported" while Python ran fine. The literal
    # check now refines the variant tag predicate (short-circuited
    # behind the tag check so a mismatched variant's slot bits are
    # never decoded under the wrong encoding) with fall-through to
    # the next arm on mismatch. Covers Bool (builtin 8-byte "Any"
    # slot AND a declared 4-byte Bool slot), Int, String, and Float
    # literals; several literal arms ending in a binder / wildcard
    # arm; a non-exhaustive literal set with a wildcard fallback; a
    # literal + binder in one payload list; a two-level nested
    # literal (``Some(Ok(0))``); an outer literal sibling next to a
    # nested variant pattern; and literal arms under a guard (the
    # flat-block guarded emission path).
    "match_variant_payload_literal.capa",
    # Nested-variant outer-sibling bind slice (2026-06-10): a match
    # arm whose variant payload mixes a nested variant pattern with
    # OUTER sibling binders (``Pair(n, Some(m))``) silently
    # miscompiled on Wasm - the nested-arm paths bound only the
    # nested variant's own payloads, so the outer binder read its
    # local's default 0 ("pair 0 4" where Python printed "pair 3
    # 4"). The arm now binds every outer non-variant payload from
    # the outer record before the inner binds, in both the cascade
    # and the flat-block guarded paths. The same slice generalised
    # the arm to SEVERAL nested-variant siblings (``Duo(Some(a),
    # Some(b))`` previously tag-checked only the FIRST sibling and
    # took the wrong arm) and lifted the loud "nested variant
    # pattern with arm guard not yet supported" rejection (binds
    # land ahead of the guard, so a guard can read the outer +
    # inner binders). Covers binder before / after / around the
    # nested variant, wildcard + binder siblings, outer literal +
    # outer binder + nested variant in one payload list, String /
    # Float / Bool / Int sibling bind shapes, two nested siblings
    # (all four tag combinations), guards reading outer + inner
    # binders, a guard-free nested arm inside a guarded match,
    # payloadless nested variants (None arms), and expression-form
    # match.
    "match_nested_variant_outer_binds.capa",
    # Wildcard for-pattern slice (2026-06-15): ``for _ in <range/
    # iterable>`` iterates without binding a visible loop variable.
    # Pre-fix the Wasm CIR lowerer's _lower_for accepted only IdentPat
    # and TuplePat and rejected a WildcardPat ("CIR lowering does not
    # yet support: for-pattern WildcardPat"), while the Python backend
    # already mapped it to a ``_`` loop variable. The lowerer now binds
    # a fresh throwaway induction local (the emitter consumes the For's
    # bind name whether or not the body reads it), mirroring the
    # ``let _ = expr`` and tuple ``forelem`` discardable-local patterns.
    # Covers ``for _`` over an exclusive / inclusive Range, over a List
    # (forelem path), a nested wildcard loop, and the named-binder
    # for-loop alongside (regression).
    "for_wildcard.capa",
    # Env.restrict_to_keys non-inline-list-arg slice (2026-06-15): a
    # key list arriving from a function call-result (or any List<String>
    # with no MakeList / list-method in the body) crashed the Wasm
    # emitter with "unknown local $_alloc_tmp" - the restrict_to_keys
    # emit stashed the list-header pointer through $_alloc_tmp, but the
    # locals walker only declares that scratch when a list gate fires.
    # An inline ``["A","B"]`` argument tripped has_list and so worked.
    # The emitter now pushes the header value twice and loads one field
    # from each copy (the IoError-formatter pattern), needing no scratch
    # local. Covers a call-result argument (the failing case), an inline
    # list literal (regression), and a let-bound list local; each scoped
    # Env then denies a key outside its allow-set for a deterministic
    # None on both backends.
    "env_restrict_to_keys_callarg.capa",
    # List-literal trait-annotation slice (2026-06-15): a list literal of
    # mixed trait implementors under a ``List<Shape>`` annotation
    # (``[Sq{...}, Rec{...}]``) was rejected because the analyzer inferred
    # the element type purely from the FIRST element (``List<Sq>``) and
    # never saw the annotation. ``_check_let`` now threads the declared
    # ``List<T>`` element type into the list-literal checker, which checks
    # each element against ``T`` (trait membership) instead of against the
    # first element. Covers a heterogeneous list dispatching the trait
    # method per element (multi-impl), a homogeneous annotated list, and
    # an empty annotated list keeping its declared element type.
    "list_lit_trait_annotation.capa",
    # Number-parser parity slice (2026-06-15): closes the parse_int
    # and to_json-number-formatting cross-backend divergences. Both
    # backends now follow one canonical parse_int grammar (ASCII-ws
    # trim, optional sign, decimal digits, [-2**63, 2**63) including
    # i64::MIN, no PEP-515 underscores / 0x / Unicode digits) and one
    # canonical to_json number form (integer digits only when the
    # shortest repr is non-scientific, else the exponent form). Pre-
    # fix the Wasm parse_int rejected leading/trailing whitespace and
    # i64::MIN, the Python parse_int accepted "1_000", and to_json of
    # an integral float >= 1e16 printed full digits on Python but the
    # exponent form on Wasm. (Float-PARSE precision and scientific-
    # notation parse_float / parse_json are a separate slice and not
    # exercised here.)
    "parse_int_json_number_parity.capa",
]

# Programs deliberately excluded from parity and why; documented
# here so a future contributor doesn't accidentally widen the
# parity list without thinking about the divergence.
_EXCLUDED: dict[str, str] = {
    "clock_demo.capa": (
        "Clock.now_secs / now_monotonic are time-dependent; their "
        "values differ between back-to-back runs even on one backend."
    ),
    "read_line_echo.capa": (
        "Stdio.read_line consumes stdin; covered by the dedicated "
        "test_stdio_read_line / test_stdio_read_line_under_cm methods "
        "which install a stdin fixture per backend run (the auto-list "
        "harness does not feed stdin)."
    ),
}


def _has_wasm_tools() -> bool:
    return shutil.which("wasm-tools") is not None


def _has_wasmtime_py() -> bool:
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


def _parse_and_analyze(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result


def _capture_stdout(thunk) -> str:
    buf = io.StringIO()
    saved = sys.stdout
    sys.stdout = buf
    try:
        thunk()
    finally:
        sys.stdout = saved
    return buf.getvalue()


def _run_python(src: str) -> str:
    """Transpile + exec in-process; capture stdout. Using ``exec``
    rather than ``subprocess.run`` keeps the harness fast enough to
    run on every push. ``capa.runtime.Stdio.println`` writes through
    ``print(...)`` to ``sys.stdout``, which the caller has already
    redirected via :func:`_capture_stdout`."""
    module, result = _parse_and_analyze(src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    exec(compile(code, "<parity>", "exec"), ns)
    return ""  # output already captured by caller's redirect


def _run_wasm(src: str) -> str:
    """Compile to .wasm and run under ``WasmHost``; capture stdout.
    Symmetrically with :func:`_run_python`, the host bridge writes
    through ``sys.stdout``."""
    from capa.runtime._wasm_host import WasmHost
    module, result = _parse_and_analyze(src)
    blob = compile_wasm(module, types=result.types)
    host = WasmHost()
    host.run_main(blob)
    return ""  # output already captured by caller's redirect


def _run_wasm_component(src: str) -> str:
    """Compile to .wasm, wrap via ``wasm-tools component new``, and
    run under ``WasmComponentHost``; capture stdout. Targets the
    full ``--component --run`` shipping path so latent
    canonical-ABI mismatches (e.g. the slice 9 ``option<T>``
    discriminant fix) fail this harness rather than slipping
    through to downstream consumers."""
    from capa.cli import _wrap_as_component
    from capa.ir import compile_wit
    from capa.runtime._wasm_component_host import WasmComponentHost
    module, result = _parse_and_analyze(src)
    core_blob = compile_wasm(module, types=result.types)
    wit = compile_wit(module, types=result.types)
    component_blob = _wrap_as_component(core_blob, wit)
    host = WasmComponentHost()
    host.run_main(component_blob)
    return ""  # output already captured by caller's redirect


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestPythonWasmParity(unittest.TestCase):
    """One test per parity-compatible example in ``examples/wasm/``.

    Failures here mean the Wasm backend has drifted from the
    Python reference (or vice versa). The README's bit-identical
    claim depends on this suite staying green for the listed
    subset.
    """

    def _assert_parity(self, filename: str) -> None:
        path = _EXAMPLES / filename
        src = path.read_text(encoding="utf-8")
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence for {filename}.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )

    def _assert_cm_parity(self, filename: str) -> None:
        """Same shape as :meth:`_assert_parity` but pivots on the
        Component Model path (``WasmComponentHost``) instead of
        the core ``WasmHost``. Used by the CM-host-bridge subset
        below to catch canonical-ABI mismatches that the core
        path would silently fake-match (see slice 9's
        ``option<T>`` discriminant fix)."""
        path = _EXAMPLES / filename
        src = path.read_text(encoding="utf-8")
        py_out = _capture_stdout(lambda: _run_python(src))
        cm_out = _capture_stdout(lambda: _run_wasm_component(src))
        self.assertEqual(
            py_out, cm_out,
            msg=(
                f"Python/Wasm-Component output divergence for "
                f"{filename}.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm-component ---\n{cm_out}"
            ),
        )

    def test_hello(self):
        self._assert_parity("hello.capa")

    def test_fizzbuzz(self):
        self._assert_parity("fizzbuzz.capa")

    def test_shape_area(self):
        self._assert_parity("shape_area.capa")

    def test_strings(self):
        self._assert_parity("strings.capa")

    def test_word_count(self):
        self._assert_parity("word_count.capa")

    def test_closures(self):
        self._assert_parity("closures.capa")

    def test_json_demo(self):
        self._assert_parity("json_demo.capa")

    def test_generic_accumulator(self):
        self._assert_parity("generic_accumulator.capa")

    def test_list_struct_basics(self):
        self._assert_parity("list_struct_basics.capa")

    def test_list_struct_map_identity(self):
        self._assert_parity("list_struct_map_identity.capa")

    def test_list_struct_map(self):
        self._assert_parity("list_struct_map.capa")

    def test_list_struct_filter(self):
        self._assert_parity("list_struct_filter.capa")

    def test_list_struct_fold(self):
        self._assert_parity("list_struct_fold.capa")

    def test_list_scalar_to_struct(self):
        self._assert_parity("list_scalar_to_struct.capa")

    def test_map_struct(self):
        self._assert_parity("map_struct.capa")

    def test_map_string_int(self):
        self._assert_parity("map_string_int.capa")

    def test_map_int_int(self):
        self._assert_parity("map_int_int.capa")

    def test_map_int_string(self):
        self._assert_parity("map_int_string.capa")

    def test_map_int_struct(self):
        self._assert_parity("map_int_struct.capa")

    def test_map_int_update(self):
        self._assert_parity("map_int_update.capa")

    def test_map_bool_int(self):
        self._assert_parity("map_bool_int.capa")

    def test_map_point_key(self):
        self._assert_parity("map_point_key.capa")

    def test_map_tuple_key(self):
        self._assert_parity("map_tuple_key.capa")

    def test_map_option_key(self):
        self._assert_parity("map_option_key.capa")

    def test_map_nested_struct_key(self):
        self._assert_parity("map_nested_struct_key.capa")

    def test_list_nested(self):
        self._assert_parity("list_nested.capa")

    def test_int_match(self):
        self._assert_parity("int_match.capa")

    def test_struct_eq(self):
        self._assert_parity("struct_eq.capa")

    def test_tuple_eq(self):
        self._assert_parity("tuple_eq.capa")

    def test_sum_eq(self):
        self._assert_parity("sum_eq.capa")

    def test_list_eq(self):
        self._assert_parity("list_eq.capa")

    def test_list_contains_struct(self):
        self._assert_parity("list_contains_struct.capa")

    def test_list_contains_float(self):
        self._assert_parity("list_contains_float.capa")

    def test_nested_eq(self):
        self._assert_parity("nested_eq.capa")

    def test_set_basics(self):
        self._assert_parity("set_basics.capa")

    def test_set_string(self):
        self._assert_parity("set_string.capa")

    def test_set_struct(self):
        self._assert_parity("set_struct.capa")

    def test_map_eq(self):
        self._assert_parity("map_eq.capa")

    def test_set_eq(self):
        self._assert_parity("set_eq.capa")

    def test_numeric_parity(self):
        self._assert_parity("numeric_parity.capa")

    def test_bitwise(self):
        self._assert_parity("bitwise.capa")

    def test_allows_inline(self):
        # Capability ``allows`` queries: the Python runtime carries
        # the live attenuation set on the cap value; the Wasm
        # backend inlines the same chain at emit time (D4 Option B).
        # Both backends must agree on every literal-arg case.
        self._assert_parity("allows_inline.capa")

    def test_net_get(self):
        # Slice 3 (2026-05): ``Net.get`` end-to-end. The example
        # writes a deterministic fixture via ``Fs.write`` then
        # reads it back via ``net.get("file:///...")``. Both
        # backends touch the same on-disk bytes through Python's
        # ``urllib.request.urlopen``, so the round-trip is byte-
        # identical without needing an HTTP fixture.
        self._assert_parity("net_get.capa")

    def test_net_restrict(self):
        # Slice 3 (2026-05): ``Net.restrict_to`` attenuation. The
        # allow-set excludes every URL the example fetches, so the
        # Wasm-side inline ``$str_contains`` check (audit C2) and
        # the Python runtime's ``urlparse(url).hostname not in
        # _allowed`` short-circuit fire in lockstep. No network
        # call is made on either backend; the parity is purely on
        # the canonical Err diagnostic shape.
        self._assert_parity("net_restrict.capa")

    def test_random_seeded(self):
        # D1 (2026-05): SplitMix64 PRNG runs guest-side in linear
        # memory on the Wasm side, byte-identical to the Python
        # runtime's ``Random.int_range``. Pinning the parity is the
        # only check that the two i64-arithmetic paths agree to the
        # last bit; if Grisu2 float rendering re-diverges, that's a
        # separate concern handled by other parity tests.
        self._assert_parity("random_seeded.capa")

    def test_safety_traps(self):
        # Audit 2026-05: pin that the five secure-by-default fixes
        # (shift count, UTF-8 host decode, Float % by zero, Int
        # overflow, parse_int overflow) did NOT change the
        # observable output for well-behaved inputs. Negative cases
        # are tested separately so the trap / raise check is direct
        # rather than vacuous-identical.
        self._assert_parity("safety_traps.capa")

    def test_string_replace(self):
        # Slice 4 (2026-05): ``String.replace`` lands on the Wasm
        # backend. Empty-needle policy is "return receiver unchanged"
        # on both backends (Python's native ``"abc".replace("", "X")
        # == "XaXbXcX"`` is suppressed by the Python emitter's
        # lambda guard); see _emit_string_replace.
        self._assert_parity("string_replace.capa")

    def test_string_char_at(self):
        # Slice 4 (2026-05): ``String.char_at`` returns
        # ``Option<String>`` with per-codepoint indexing. The Wasm
        # emitter walks UTF-8 leading bytes (1/2/3/4 byte
        # codepoints) to match Python's per-codepoint ``s[idx]``.
        self._assert_parity("string_char_at.capa")

    def test_string_index_of(self):
        # Slice 4 (2026-05): ``String.index_of`` returns
        # ``Option<Int>``. D3 retired the legacy -1 sentinel; the
        # Python emitter wraps ``.find()`` in a ``Some/None_``
        # lambda, the Wasm emitter writes the Option record directly.
        # Slice 17 (2026-05-29): the index is a CODE-POINT offset,
        # not a byte offset. The example now includes multibyte
        # prefixes (emoji / accented / CJK) where the Wasm backend
        # previously returned the byte offset and diverged from
        # Python's code-point-indexed ``str.find``.
        self._assert_parity("string_index_of.capa")

    def test_string_bytes(self):
        # Slice (2026-06-13): ``String.bytes`` returns the receiver's
        # UTF-8 bytes as a ``List<Int>`` (each 0..255). The Wasm
        # backend copies the raw UTF-8 byte slice straight through;
        # the Python backend encodes via ``surrogatepass``. Covers
        # ASCII, multi-byte BMP, astral, the empty string, the
        # code-point-vs-byte-count relationship, and a lone surrogate
        # (JSON \uD800) whose 3-byte WTF-8 form matches on both backends.
        self._assert_parity("string_bytes.capa")

    def test_tuple_arity_n(self):
        # Slice 5 (2026-05): the 2-arity tuple cap was lifted; the
        # uniform 8-byte slot stride covers arity-3 / arity-4.
        # Co-shipped with the Index lowering type-recovery fix that
        # parses elem types out of the receiver's tuple shape when
        # the analyzer didn't carry a precise type for the slot.
        self._assert_parity("tuple_arity_n.capa")

    def test_tuple_nested_index(self):
        # Slice (2026-06-03): nested tuple indexing. A nested-tuple
        # element is an i32 pointer in the slot; pre-fix the Wasm
        # emitter fell through to a raw i64.load and stored an i64
        # into the i32 tuple local, producing invalid Wasm. Now the
        # pointer-shaped decode branch also covers tuple-typed dsts.
        self._assert_parity("tuple_nested_index.capa")

    def test_map_keys_values(self):
        # Slice 5 (2026-05): ``Map.keys()`` / ``Map.values()`` walk
        # the pair table into a fresh List<K> / List<V> with per-K
        # / per-V slot encoding (mirroring how MakeList writes the
        # respective element shape).
        self._assert_parity("map_keys_values.capa")

    def test_range_iter(self):
        # Slice 5 (2026-05): ``for i in a..b`` / ``for j in a..=b``
        # via a new ``MakeRange`` CIR node + a counted-loop Wasm
        # fast-path that reads start / end / inclusive out of the
        # 24-byte Range record without materialising the integer
        # sequence. Nested range loops use depth-indexed scratch
        # locals so an inner loop's end-compare doesn't clobber the
        # outer's.
        self._assert_parity("range_iter.capa")

    def test_option_result_hofs(self):
        # Slice 6 (2026-05): every Option<T> / Result<T, E> HOF
        # (``map``, ``and_then``, ``or_else``, ``filter``,
        # ``ok_or``, ``map_err``, ``ok``, ``err``) lands on the
        # Wasm backend. Exercises Int / String payloads,
        # payload-type-changing maps, all Result projection
        # directions, and pointer-pass-through on the fallback
        # arm of map / and_then. Closure ABI matches List.map's
        # call_indirect shape; the scratch locals reuse the
        # existing has_list_hof declarations via the locals-
        # collection extension shipped in the same slice.
        self._assert_parity("option_result_hofs.capa")

    def test_fn_ref_as_closure(self):
        # Slice 6.1 (2026-05): top-level functions used as
        # ``Fun(...)`` values (e.g. ``xs.map(double_int)`` where
        # ``double_int`` is a free function, not an inline lambda).
        # Pre-fix the Wasm emitter rejected with "value kind
        # 'global' not supported"; the fix synthesises a per-(fn,
        # sig) thunk that adapts the closure ABI to the
        # underlying function. Same call site shape across both
        # backends; Python passes the Python function object
        # natively, Wasm dispatches via call_indirect through the
        # thunk.
        self._assert_parity("fn_ref_as_closure.capa")

    def test_net_post(self):
        # Slice 8 (2026-05): ``Net.post(url, body)`` lands on the
        # Wasm backend. The parity program exercises only the
        # attenuation-deny path so the harness stays hermetic
        # (both backends short-circuit to Err before the
        # network bridge runs). The happy path uses a loopback
        # http.server fixture and lives in
        # ``test_net_post_round_trip_against_loopback``.
        self._assert_parity("net_post.capa")

    def test_fs_demo(self):
        # Slice 9 (2026-05): ``fs_demo`` exercises Fs.read /
        # Fs.write end-to-end on both backends. Parity-clean by
        # construction: the program writes to a single constant
        # ``/tmp/`` path and prints only that path + the response
        # of the host bridge. Both backends route through Python's
        # ``open(...)`` under the hood (Python directly; Wasm via
        # the host bridge), so back-to-back runs see identical
        # bytes on disk. Previously gated as needing a fixture;
        # inspection shows none was actually required.
        self._assert_parity("fs_demo.capa")

    def test_env_demo(self):
        # Slice 9 (2026-05): ``env_demo`` queries Env.get for
        # several keys. Parity-clean because both backends consult
        # the same ``os.environ`` from within one Python process,
        # and ``os.environ`` doesn't change between two back-to-
        # back calls. Previously gated as needing a fixture;
        # inspection shows none was actually required.
        self._assert_parity("env_demo.capa")

    def test_db_demo(self):
        # Slice 11 (2026-05): Db v1 SQLite-backed capability with
        # path-prefix attenuation. Both backends route through
        # Python's ``sqlite3`` module (Python directly; Wasm via
        # the host bridge) against the same on-disk file, so query
        # output + attenuation-deny diagnostics match.
        # Delete the fixture first so back-to-back runs both see
        # the same starting state (empty database).
        import os
        path = "/tmp/capa_db_demo.db"
        for _ in range(2):  # paranoia: ensure full reset
            if os.path.exists(path):
                os.unlink(path)
        try:
            self._assert_parity("db_demo.capa")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_fs_attenuation_audit(self):
        # Slice 12 (2026-05-29): pin the audit-bug-fix surface.
        # Pre-fix the Wasm Fs host bridges for exists / is_dir /
        # mkdir / list_dir bypassed attenuation entirely (a cap
        # scoped to /tmp/ could fs.mkdir("/etc/foo") on Wasm);
        # the path-prefix check also admitted /tmproot/x when
        # restricted to /tmp. Both holes now closed. This test
        # would fail on the pre-fix Wasm backend.
        self._assert_parity("fs_attenuation_audit.capa")

    def test_clock_sleep_attenuation(self):
        # Slice 13 (2026-05-29): Clock.sleep on a
        # ``restrict_to_after(future)`` cap silently no-ops on
        # both backends now. Pre-fix Python skipped the sleep
        # but Wasm ran the host call; the inline ``if
        # (clock.now_secs() >= deadline) sleep(secs)`` gate
        # mirrors Python.
        self._assert_parity("clock_sleep_attenuation.capa")

    def test_typestate_door(self):
        # Roadmap S3.3: a typestate protocol runs identically on both
        # backends. The typestate value lowers to a zero-field struct
        # (an i32 token on Wasm); construction is a fieldless MakeStruct
        # and become is identity.
        self._assert_parity("typestate_door.capa")

    def test_typestate_socket(self):
        # Roadmap S3.4: a typestate carrying a field (fd) lowers as a
        # struct; construction + field reads + become run identically on
        # both backends.
        self._assert_parity("typestate_socket.capa")

    def test_typestate_methods(self):
        # Roadmap S3.5: state-specific receiver methods (impl Type[State])
        # and transition methods (consume self) run identically on both
        # backends; the state is compile-time-only.
        self._assert_parity("typestate_methods.capa")

    def test_stdio_read_line(self):
        # Slice 1 host-bridge pile: Stdio.read_line parity. Both
        # backends read sys.stdin.readline() and strip the trailing
        # newline; a fresh stdin buffer is installed per backend run
        # because each consumes it.
        stdin_text = "Alice\n42\n"

        def _run_with_stdin(thunk):
            saved = sys.stdin
            sys.stdin = io.StringIO(stdin_text)
            try:
                return _capture_stdout(thunk)
            finally:
                sys.stdin = saved

        src = (_EXAMPLES / "read_line_echo.capa").read_text(encoding="utf-8")
        py_out = _run_with_stdin(lambda: _run_python(src))
        wasm_out = _run_with_stdin(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm read_line divergence.\n"
                f"--- python ---\n{py_out}\n--- wasm ---\n{wasm_out}"
            ),
        )
        self.assertIn("hello, Alice", py_out)
        self.assertIn("you said: 42", py_out)

    def test_db_attach_blocked(self):
        # Slice 13 (2026-05-29): both backends install a
        # ``set_authorizer`` on every sqlite connection that
        # denies ATTACH / DETACH at the SQLite parser level.
        # Closes the documented Db.exec ATTACH-bypass without
        # needing Python 3.11+ ``setlimit`` (the authorizer API
        # is portable to Python 3.10).
        import os
        path = "/tmp/capa_db_attach.db"
        for _ in range(2):  # paranoia: ensure full reset
            if os.path.exists(path):
                os.unlink(path)
        try:
            self._assert_parity("db_attach_blocked.capa")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_allows_dynamic(self):
        # Slice 14 (2026-05-29): the literal-only restriction on
        # Fs/Env/Db.allows is lifted. Pre-slice the program below
        # crashed compile on Wasm with "requires a literal string
        # argument"; now both backends emit the same yes/no per
        # cap-mediated query for a runtime String arg.
        #
        # Audit C2 (2026-06-09): extended with no-trailing-slash
        # prefixes + dynamic args. ``restrict_to("/home/data")``
        # needs the slash-suffixed ``/home/data/`` for the
        # boundary-aware starts-with arm; that string never appears
        # as a source literal, so the discovery pass must pre-intern
        # it or the runtime check reads uninitialised memory and
        # silently DENIES an allowed path (``/home/data/users.csv``)
        # while Python ALLOWS it. The sibling ``/home/database``
        # shares the prefix string but is not under the path - it
        # must be denied on both backends.
        self._assert_parity("allows_dynamic.capa")

    def test_float_interpolation(self):
        # Audit C1 (2026-06-09) + F2 (2026-06-10): computed-float
        # interpolation parity. The pre-fix Wasm Grisu2 port omitted
        # RoundWeed and printed ``14.285714285714287`` for ``100.0 /
        # 7.0`` (one ulp high) while Python's repr gives ``...286``.
        # C1 ported RoundWeed into $grisu2; F2 added the Grisu3
        # confidence flag plus the exact Dragon4 fallback, so the
        # arithmetic-reachable residuals (e.g. 86.0 / 7018.0) that
        # Grisu2 could not name correctly are now repr-exact too.
        # Every sum / ratio / division / average / fallback case in
        # the program is byte-identical across backends. Float interp
        # was excluded from this harness before, which is exactly why
        # the divergence reached audit instead of CI.
        self._assert_parity("float_interpolation.capa")

    def test_list_query_methods(self):
        # Loud-error stdlib gap (2026-06-10): List.first / last / find /
        # find_index / sorted_by, previously a clean WasmEmissionError.
        # sorted_by is a STABLE merge sort matching Python's Timsort, so
        # equal-comparing elements keep input order; the program checks
        # that over Int, struct, and String element shapes. Edge cases:
        # empty -> None, no-match -> None, match at index 0 / last.
        self._assert_parity("list_query_methods.capa")

    def test_range_methods(self):
        # Loud-error stdlib gap (2026-06-10): Range.length / contains /
        # is_empty / to_list on a Range used as a value. Half-open
        # [start, stop) semantics matching CapaRange; covers empty
        # (5..5), single, inclusive (a..=b), and contains boundaries.
        self._assert_parity("range_methods.capa")

    def test_net_allows(self):
        # Loud-error stdlib gap (2026-06-10): Net.allows(host) inlined
        # at emit time (exact host-set membership, NOT a prefix check).
        # Covers literal + dynamic arg, allowed / denied / prefix-share
        # boundary, and chained restrict_to narrowing to the empty set.
        self._assert_parity("net_allows.capa")

    def test_closure_loop_capture(self):
        # Slice 19 (2026-05-29): for-loop lambda captures bind
        # by value at lambda-creation time on both backends.
        # Pre-fix Python's late-binding closure semantics made
        # every lambda in a ``for i in 0..N { ... fun () => i }``
        # loop return the same final value; Wasm captured per-
        # iteration. Real divergence undetected by every prior
        # parity test (none exercised a captured loop var).
        self._assert_parity("closure_loop_capture.capa")

    def test_fs_cross_function_attenuation(self):
        # Slice 25.2 (2026-05-30): Fs cap restriction travels
        # with the value across function boundaries on Wasm.
        # Pre-slice the Wasm emitter erased Fs values and
        # inlined the prefix check at the literal call site;
        # passing a restricted Fs to a helper dropped the
        # restriction and the host bridge happily executed the
        # syscall. The handle-table foundation
        # (capa/runtime/_cap_handles.py) routed Fs through an
        # i32 handle the host looks up to enforce
        # ``fs.allows(path)`` on every privileged op, so both
        # backends now print ``ok: helper read denied``. Closes
        # audit slice 25 finding F1 for Fs (other caps land in
        # slices 25.3-25.7).
        import os
        os.makedirs("/tmp/audit_narrow", exist_ok=True)
        sentinel = "/tmp/other_file_outside_narrow.txt"
        with open(sentinel, "w", encoding="utf-8") as f:
            f.write("outside")
        try:
            self._assert_parity("fs_cross_function_attenuation.capa")
        finally:
            if os.path.exists(sentinel):
                os.unlink(sentinel)

    def test_net_cross_function_attenuation(self):
        # Slice 25.3 (2026-05-30): same audit-slice-25 F1 bug as
        # Fs above, but for Net. Pre-slice the Wasm emitter
        # erased Net values and inlined ``$str_contains(url,
        # host)`` at the literal call site; passing a restricted
        # Net to a helper dropped the restriction and the host
        # bridge happily issued the HTTP fetch. Post-slice the
        # receiver Net carries an i32 handle the host looks up to
        # enforce ``Net.allows(urlparse(url).hostname)`` on every
        # privileged op, so both backends now print
        # ``ok: helper net.get denied``.
        self._assert_parity("net_cross_function_attenuation.capa")

    def test_net_substring_attack(self):
        # Slice 25.3 (2026-05-30): audit-slice-25 F2. The pre-fix
        # inline ``$str_contains(url, host)`` admitted URLs whose
        # hostname is attacker-controlled but whose path / query
        # component contained the allowed host as a substring.
        # Routing through the Python ``Net.get`` (which uses
        # ``urlparse(url).hostname``) is now the single soundness
        # chokepoint, so both backends print
        # ``ok: hostname check rejected lookalike``.
        self._assert_parity("net_substring_attack.capa")

    def test_db_cross_function_attenuation(self):
        # Slice 25.4 (2026-05-30): Db cap restriction travels with
        # the value across function boundaries on Wasm. Pre-slice
        # the Wasm emitter erased Db values and inlined the path-
        # prefix check at the literal call site; passing a
        # restricted Db to a helper dropped the restriction and the
        # host bridge happily opened the SQLite connection. Closes
        # audit slice 25 finding F1 for Db.
        self._assert_parity("db_cross_function_attenuation.capa")

    def test_proc_cross_function_attenuation(self):
        # Slice 25.4 (2026-05-30): Proc cap restriction travels with
        # the value across function boundaries on Wasm. Pre-slice
        # the Wasm emitter erased Proc values and inlined the
        # basename + suffix-boundary check at the literal call site;
        # passing a restricted Proc to a helper dropped the
        # restriction and the host bridge happily spawned the
        # subprocess. Closes audit slice 25 finding F1 for Proc.
        self._assert_parity("proc_cross_function_attenuation.capa")

    def test_env_cross_function_attenuation(self):
        # Slice 25.5 (2026-05-30): Env cap restriction travels with
        # the value across function boundaries on Wasm. Pre-slice
        # the Wasm emitter erased Env values and inlined the
        # allow-list check at the literal call site; passing a
        # restricted Env to a helper dropped the restriction and the
        # host bridge read ``os.environ`` unconditionally. Closes
        # audit slice 25 finding F1 for Env. Both backends now
        # return None (fail-closed-as-absent) for an out-of-allow-
        # list key.
        self._assert_parity("env_cross_function_attenuation.capa")

    def test_clock_cross_function_attenuation(self):
        # Slice 25.6 (2026-05-30): Clock cap restriction travels
        # with the value across function boundaries on Wasm. Pre-
        # slice the Wasm host bridge hard-coded ``allows`` to
        # return ``true`` regardless of the cap's
        # ``restrict_to_after`` deadline, so a narrowed Clock
        # threaded through a helper queried as unrestricted.
        # Closes audit slice 25 finding F1 for Clock. Both backends
        # now consult the cap's real deadline against the wall
        # clock.
        self._assert_parity("clock_cross_function_attenuation.capa")

    def test_lambda_block_implicit_result(self):
        # Slice 24 (2026-05-30): block-body lambdas with an
        # implicit-result tail expression. Pre-fix Python's
        # transpiler emitted the tail as a discarded statement
        # (returning None) and the CIR lowerer for Wasm fell
        # through with no Return (trap). Both fixed: transpiler
        # wraps the tail in ``return``; lowerer mirrors the
        # implicit-result rule from ``_lower_match_expr``.
        self._assert_parity("lambda_block_implicit_result.capa")

    def test_string_unicode(self):
        # Slice 17 (2026-05-29): String.length and substring now
        # use code-point indices on Wasm, matching Python. Covers
        # 2/3/4-byte code points + every substring boundary. Pre-
        # fix this program would have diverged on every length
        # call and every substring on a non-ASCII range.
        self._assert_parity("string_unicode.capa")

    def test_audit_float_and_index(self):
        # Slice 16 (2026-05-29): pins three audit-fix surfaces.
        # Pre-fix the Float-capture program crashed the wasm
        # verifier; the Set<Float> program also crashed; the
        # negative-index path silently returned xs[0] instead of
        # returning None / trapping. All three now produce
        # byte-identical output on both backends.
        self._assert_parity("audit_float_and_index.capa")

    def test_proc_demo(self):
        # Slice 15 (2026-05): Proc v1 sandboxed subprocess
        # capability with basename + suffix-boundary attenuation.
        # Both backends run ``subprocess.run(argv,
        # capture_output=True, timeout=30, shell=False)`` against
        # the same ``python -c "..."`` invocation, so captured
        # stdout + attenuation-deny diagnostics match exactly.
        self._assert_parity("proc_demo.capa")

    def test_tail_recursion(self):
        # Roadmap P4: tail calls lower to ``return_call``. Moderate
        # depth so the Python reference path agrees byte-for-byte.
        self._assert_parity("tail_recursion.capa")

    def test_match_ident_sum(self):
        # Match-pattern slice (2026-06-03): a bare-identifier catch-all
        # arm in a sum-type match binds the scrutinee. Pre-fix the Wasm
        # sum-match path raised "Phase 6C: match arm pattern PatIdent
        # not supported"; the binding now mirrors the Int / Bool /
        # String / tuple paths.
        self._assert_parity("match_ident_sum.capa")

    def test_match_float_lit(self):
        # Match-pattern slice (2026-06-03): Float-literal arms compare
        # the f64 scrutinee via ``f64.eq`` (Python ``==`` semantics).
        # Pre-fix a Float scrutinee was rejected outright.
        self._assert_parity("match_float_lit.capa")

    def test_match_or_pattern(self):
        # Match-pattern slice (2026-06-03): binding-free or-patterns
        # (``A | B -> body``) over payload-less sum variants and
        # Int / Float literals. Each alternative's predicate is ORed;
        # the body runs once. Pre-fix the CIR lowerer raised
        # "match pattern OrPat".
        self._assert_parity("match_or_pattern.capa")

    def test_match_struct_pattern(self):
        # Match-pattern slice (2026-06-03): struct-destructuring
        # patterns test literal / wildcard fields and bind shorthand
        # fields, recursing into nested struct sub-patterns via the
        # struct layout offsets. Pre-fix the CIR lowerer raised
        # "match pattern StructPat".
        self._assert_parity("match_struct_pattern.capa")

    def test_match_variant_payload_literal(self):
        # Variant-payload literal slice (2026-06-10): ``Some(true)``
        # and friends. The literal equality (Int / Bool / String /
        # Float) composes with the variant tag check and falls
        # through to the next arm on mismatch; covers flat, guarded,
        # multi-payload, and two-level nested shapes. Pre-fix the
        # Wasm backend raised "Phase 6C: nested pattern PatLiteral
        # inside variant payload not yet supported".
        self._assert_parity("match_variant_payload_literal.capa")

    def test_match_nested_variant_outer_binds(self):
        # Nested-variant outer-sibling bind slice (2026-06-10):
        # ``Pair(n, Some(m))`` bound ``m`` but never ``n`` on Wasm
        # (read 0; Python gave the real value) - a silent divergence
        # in both nested-arm emission paths. Also locks the
        # two-nested-siblings arm (wrong-arm selection pre-fix) and
        # guards on nested-variant arms (loud rejection pre-fix).
        # See the _PARITY_PROGRAMS entry for the full coverage
        # matrix.
        self._assert_parity("match_nested_variant_outer_binds.capa")

    def test_match_or_bind(self):
        # Bound or-pattern slice (2026-06-04): or-patterns whose
        # alternatives are different variants each binding the SAME
        # name(s) (e.g. ``Pos(n) | Neg(n) -> n``). Pre-fix the Wasm CIR
        # lowerer rejected any binding alternative ("or-pattern with
        # bindings not supported on the Wasm backend yet"); the Python
        # backend already handled them via native ``a | b`` match. The
        # Wasm emitter now ORs the alternative tag predicates and, after
        # the predicate gates entry, re-checks each variant alternative's
        # tag to load the matched alternative's payload into the shared
        # binder. Covers a single shared bind, two shared binds, a bound
        # or-pattern under a guard, statement- and expression-position
        # match, payload types Int / String / Char / Bool / Float /
        # struct / list, and a binding-free or-pattern regression.
        self._assert_parity("match_or_bind.capa")

    def test_for_tuple_destructure(self):
        # Tuple-destructuring for-pattern slice (2026-06-06): a for-loop
        # whose loop pattern destructures a tuple (``for (a, b) in
        # pairs``) already ran on the Python backend but the Wasm CIR
        # lowerer rejected it ("for-pattern TuplePat"). The lowerer now
        # binds each iteration's element to a fresh temporary carrying
        # the tuple type and destructures it positionally through the
        # same ``Index`` path that powers ``let (a, b) = t`` and
        # ``t[i]``. Covers arity 2/3/4, component types Int / String /
        # Char / Bool / struct / nested-tuple, a wildcard component, the
        # plain single-identifier regression, and nested for-loops.
        self._assert_parity("for_tuple_destructure.capa")

    def test_for_string_iter(self):
        # String iteration slice (2026-06-06): ``for c in s`` walks the
        # receiver's UTF-8 byte slice one Unicode code point at a time on
        # the Wasm backend, binding the loop variable as a one-codepoint
        # String per iteration. Pre-fix the Wasm CIR emitter rejected it
        # at lowering time ("For-iter over type 'String': only List, Set,
        # and Range iteration are supported") while the Python backend
        # already yielded one-character strings. Covers ASCII, a mix of
        # ASCII / accented / CJK / emoji (astral), the empty string, the
        # element used as a String several ways, break / continue / early
        # return, iterating a String from a variable / function return /
        # struct field / literal, and nested loops.
        self._assert_parity("for_string_iter.capa")

    def test_char_basics(self):
        # Char slice (2026-06-03): a Capa ``Char`` is a single-
        # codepoint String and is laid out exactly like a String at
        # the Wasm level. The Wasm path normalizes the type token
        # ``Char`` -> ``String`` across every type-string-bearing
        # field before emit, so the String machinery (params, returns,
        # locals, interpolation, equality, tuple / list / struct
        # slots) carries it. Covers a multibyte codepoint too. Pre-fix
        # this errored with "Capa type 'Char' has no Wasm encoding
        # yet".
        self._assert_parity("char_basics.capa")

    def test_match_char_lit(self):
        # Char slice (2026-06-03): char-literal match patterns. After
        # the scrutinee type is normalized ``Char`` -> ``String``, a
        # ``match c { 'a' -> ... }`` routes to the String-scrutinee
        # match path; the char-literal patterns lower as one-char
        # ``PatLiteral(kind="str")`` compared via ``$str_eq``.
        self._assert_parity("match_char_lit.capa")

    def test_generic_struct_field(self):
        # Generic-struct slice (2026-06-03): a generic struct's field,
        # read across a function boundary, must decode identically on
        # both backends for any concrete type parameter T. Pre-fix the
        # Wasm path left ``Pair<T>`` un-monomorphised, so the field
        # ``a: T`` was sized / decoded as the bare type variable and a
        # ``Pair<Char>`` returned from one function and read in another
        # mis-decoded ("unknown local $_ir_t0" / "type mismatch i32 vs
        # i64"). The monomorphiser now specialises generic struct / sum
        # types per concrete instantiation (``Pair<Char>`` ->
        # ``Pair__Char`` with ``a: Char``) so the layout machinery
        # sizes every field from its real type. Covers T = Int / String
        # / Char / Bool / Float, a compound generic field (List / nested
        # struct), the same-function read, and the non-generic
        # regression case.
        self._assert_parity("generic_struct_field.capa")

    def test_generic_fn_sum(self):
        # Generic-function-over-user-sum slice (2026-06-06): a generic
        # function whose parameter / return type is a user-defined sum
        # parameterised by the function's type variable (``unwrap<T>(o:
        # Opt<T>, fallback: T) -> T``) ran on Python but miscompiled on
        # Wasm once instantiated at more than one concrete type. The
        # monomorphiser specialised the sum decl and the function, but
        # the emitter routed variant construction via a table keyed by
        # the bare variant name; two clones of one generic sum that share
        # a variant name (``Opt__Char`` / ``Opt__Point`` both declare
        # ``Just``) collapsed it to the last clone, so a ``Just('z')``
        # typed ``Opt__Char`` (String, 8-byte slot) was laid out with the
        # other clone's payload sizes ("type mismatch: expected i32,
        # found i64"). The emitter now resolves a constructor's sum from
        # the dst local's concrete monomorphised type. Covers T = Int /
        # String / Char, the Nothing fallback arm, a generic fn that
        # returns a constructed sum, a compound payload (struct + list),
        # the same generic fn at several concrete types, and a second
        # generic sum.
        self._assert_parity("generic_fn_sum.capa")

    def test_generic_impl_methods(self):
        # Generic-impl-method slice (2026-06-07): a method declared in an
        # ``impl`` block on a generic type must dispatch on the Wasm
        # backend once the type is monomorphised. Pre-fix the
        # monomorphiser specialised the generic struct / sum decls but
        # never rewrote ``module.impls``: the impl stayed keyed on the
        # bare head ``Box`` with bodies mentioning the type variable
        # ``T``, while the Wasm method-dispatch table is keyed on the
        # monomorphised receiver type, so ``bi.get()`` on a ``Box__Int``
        # found no ``(Box__Int, get)`` entry ("MethodCall ... not
        # supported"). The monomorphiser now specialises each generic
        # impl per instantiation (substitute T, rewrite to the mangled
        # clone, re-key the impl on the mangled type name). Covers a
        # getter returning T, a method taking a T arg, a method returning
        # a different concrete type (String), a self.method() call, the
        # same generic type at three instantiations (Int / String /
        # Bool), a method whose param / return type IS T (String ptr/len
        # vs Int i64), a generic value in a list / passed to / returned
        # from a function, and a generic SUM type with ``match self``
        # methods at two instantiations.
        self._assert_parity("generic_impl_methods.capa")

    def test_generic_impl_methods_advanced(self):
        # Generic-impl-method defect slice (2026-06-07): three review-
        # found defects in the generic-impl monomorphisation path, each
        # correct on Python but wrong / crashing on Wasm. (1) Multiple
        # inherent ``impl`` blocks on one generic type: pre-fix the
        # per-instantiation emit dedup keyed ``(mangled_type, trait_name)``
        # collided every inherent block onto ``(Cell__Int, None)`` and
        # silently dropped all but the first - a SILENT method loss (no
        # error if the dropped method was never called). Now keyed on the
        # method name too. (2) A sum-variant construction inside a generic
        # method (``return Some_(x)``) left the dst typed ``Opt<?>`` and
        # crashed with "no Wasm encoding"; partial-type resolution now runs
        # over specialised method bodies. (3) A nested generic
        # instantiation through a method (``Cell<Cell<Int>>`` /
        # ``Cell<Cell<String>>`` with ``.get().get()``) mangled to a
        # bare-headed ``Cell__Cell`` clone instead of ``Cell__Cell_Int``;
        # make-struct-site inference now carries nested type arguments at
        # full depth. Covers three inherent blocks with a never-called
        # method, variant construction at T = Int / String / struct
        # payload, nested generics two deep, and a generic struct whose
        # field is another generic instantiation, method-accessed.
        self._assert_parity("generic_impl_methods_advanced.capa")

    def test_generic_literal_in_control_flow(self):
        # Generic-literal-in-control-flow slice (2026-06-07): a generic
        # struct literal whose construction site is INSIDE a control-flow
        # block (if then/else, for, while, match arm) crashed the Wasm
        # backend with a bare-headed "Capa type 'Box' has no Wasm
        # encoding yet". ``_patch_bare_generic_struct_refs`` walked only
        # the flat top-level ``fn.body`` and never recursed into nested
        # instruction bodies, so the mangled clone was registered (the
        # scan side recurses) but the bare ``MakeStruct.type_name`` and
        # dst-local typing inside the nested block were left unpatched.
        # The patch pass now recurses into nested control-flow bodies
        # with the same per-branch scoping the scan side uses. Covers a
        # literal built in an if then-body, an if else-body, a for body,
        # a while body, a match arm; nested control flow (if inside for);
        # two sibling branches building the same generic type at
        # different instantiations (Box<Int> vs Box<String>); and a
        # method call on a literal built inside a branch.
        self._assert_parity("generic_literal_in_control_flow.capa")

    def test_list_param_push(self):
        # List-parameter mutation slice (2026-06-04): pushing to a List
        # received as a function PARAMETER (no local list built in the
        # body) crashed the Wasm backend at assembly time with "unknown
        # local $_alloc_tmp" - the push grow path / contains scan stash a
        # scratch pointer there, but the locals pass only declared it when
        # the body itself built a list (MakeList). Covers push on a
        # parameter for Int / String / Char / Bool / Float / struct /
        # nested-list elements, contains on a parameter, and by-reference
        # caller-visibility (a push through a parameter is visible to the
        # caller on both backends, including across the grow path).
        self._assert_parity("list_param_push.capa")

    def test_aug_int_divmod(self):
        # Augmented integer division / modulo slice (2026-06-06): ``x
        # /= y`` and ``x %= y`` on an Int target lower to the same
        # ``_capa_idiv`` / floored-``%`` path as the binary forms.
        # Pre-fix the Python backend let Int ``/=`` fall through to raw
        # Python true division (Float, wrong rounding), so ``24 /= 4``
        # printed ``6.0`` and ``-7 /= 2`` printed ``-3.5`` where the
        # Wasm backend printed ``6`` / ``-4``. Covers plain locals,
        # struct-field RMW, the unaffected Float ``/=``, and the
        # ``+= -= *=`` regression.
        self._assert_parity("aug_int_divmod.capa")

    def test_list_literal_sum_interleaved(self):
        # List-literal sum-element slice (2026-06-07): a list literal of
        # a sum type with an interleaved payloadless (tag-only) variant
        # element silently read back later payload-carrying elements as
        # 0 on the Wasm backend. _emit_make_list cached the data-array
        # base pointer in $_alloc_tmp, but a payloadless variant element
        # pushes via the variant_ctor path in _push_value (``call $alloc``
        # + ``local.tee $_alloc_tmp``), overwriting that scratch with the
        # fresh variant pointer; every element after the first payloadless
        # variant then stored at variant_ptr + offset instead of the data
        # array. The .push()-built equivalent was always correct (push
        # re-reads data_ptr from the header each call). Fix:
        # _emit_make_list re-reads data_ptr from the list header for each
        # element store. Covers payloadless first / last / middle /
        # multiple-consecutive / all-payloadless / all-payload orders,
        # payload types Int / String / struct / list / tuple each with an
        # interleaved payloadless variant, a non-generic AND a
        # monomorphised generic sum, reads by index AND by iterating +
        # matching, and the .push() regression.
        self._assert_parity("list_literal_sum_interleaved.capa")

    def test_top_level_const(self):
        # Slice (2026-06-07): a top-level ``const`` of a non-i64-shaped
        # type used at a value site. Pre-fix the global-const branch of
        # ``_push_value`` recursed a String const into the packed-i64
        # ``lit_str`` path and crashed Wasm module validation the moment
        # the const reached a String sink (println / ``+`` / ``==`` / a
        # String fn arg) with "type mismatch: expected i32, found i64".
        # The fix dispatches the const branch on the stored literal's
        # shape - String consts go through the (ptr, len) helper, scalar
        # consts keep the recursion. Exercises String / Int / Bool /
        # Float consts used several ways, including across functions.
        self._assert_parity("top_level_const.capa")

    def test_const_string_sites(self):
        # Slice (2026-06-07): a top-level String ``const`` used at
        # every non-i64-shaped value site. Pre-fix the struct-field-
        # store helpers ``_push_string_field_ptr_only`` /
        # ``_push_string_field_len_only`` lacked a ``global``-const
        # branch, so a String const used as a struct-field initializer
        # (``Box { label: S, n: 5 }``) errored loudly on Wasm ("cannot
        # push string ptr of Value kind 'global'") while Python
        # accepted it. Both helpers now resolve the const from
        # ``_const_values`` and re-dispatch on the underlying lit_str
        # literal, mirroring ``_push_string_value_as_ptr_len``. Covers
        # struct field (println + interpolation read-back), a const +
        # literal in one struct, an empty-string const and a multi-
        # byte-UTF-8 const as fields, and a String const as a Map key,
        # Map value, List element, tuple component, and match scrutinee.
        self._assert_parity("const_string_sites.capa")

    def test_trait_return_shapes(self):
        # Slice (2026-06-07): a method called through a trait-typed
        # (user-capability) receiver must give its result the trait
        # method's DECLARED return type so the Wasm backend stores /
        # reads it in the right calling shape - String as (ptr, len),
        # Bool as i32, Float as f64, Int as i64. A String return
        # decoded as a single i64 would trip module validation or
        # silently mis-decode. The single-impl trait routes
        # monomorphically through the impl's mangled method. Covers a
        # String return printed / interpolated / concatenated /
        # compared / passed onward to another String consumer, Bool /
        # Float / Int returns used in branch / arithmetic / print, the
        # direct-return ``return g.greet()`` shape, and let-then-use.
        self._assert_parity("trait_return_shapes.capa")

    def test_trait_keyword_return_shapes(self):
        # Slice (2026-06-07): the ``trait`` keyword (SymbolKind.TRAIT)
        # sibling of test_trait_return_shapes (which used the
        # ``capability`` keyword, SymbolKind.CAPABILITY). A method
        # called through a ``trait``-typed receiver must get its
        # DECLARED return type so the Wasm backend stores / reads it in
        # the right calling shape - String as (ptr, len), Bool as i32,
        # Float as f64, Int as i64 (typed Int, not Unknown-aliased),
        # struct / List as an i32 pointer. Before the fix the trait
        # path fell through to TyUnknown and Wasm rejected the module
        # ("type mismatch: expected i64, found i32"). Covers String /
        # Bool / Float / Int returns used five / arithmetic / branch
        # ways, an aggregate (struct field read, then List iteration)
        # return, a struct implementing TWO different single-impl
        # traits, and a trait method returning another trait type.
        self._assert_parity("trait_keyword_return_shapes.capa")

    def test_generic_fn_struct(self):
        # Group A1 (2026-06-07): a generic FREE FUNCTION whose
        # parameter / return type is itself a generic struct or sum,
        # called at two instantiations. Pre-fix a generic struct literal
        # bound to a local carried only the bare generic head
        # (``bi: Box`` not ``Box<Int>``), so the monomorphiser's
        # call-site inference could not unify ``Box<T>`` against it and
        # the call missed its emitted clone ("unknown func
        # $unwrap_box"); a generic fn returning a generic struct was
        # never specialised. A pre-pass now annotates each generic
        # struct-literal local with its canonical instantiation before
        # call inference. Covers a taker, a returner, and a generic fn
        # over a generic SUM, each at Int (i64) and String (ptr/len),
        # result used several ways. Also a nested-sibling pre-pass guard:
        # an if/else building the SAME generic struct at Int (then, taken)
        # vs String (else) - a stale-overwrite in the pre-pass would make
        # the taken Int branch resolve to the String clone and mis-decode.
        self._assert_parity("generic_fn_struct.capa")

    def test_generic_struct_construction(self):
        # Group A2 (2026-06-07): generic struct construction + field
        # access in nested / list / generic-field paths, value-checked.
        # A nested generic literal (``Box<Box<Int>>``), a generic struct
        # built as a list element, and a two-type-param struct with a
        # generic-struct field all flow the per-site make-struct
        # inference at construction sites the earlier slices did not
        # exercise.
        self._assert_parity("generic_struct_construction.capa")

    def test_generic_sum_payload_binder(self):
        # Group A3 (2026-06-07): a generic sum's payload of type T,
        # matched with a binder, decodes as the concrete instantiation
        # at T = Int / String / a struct payload and through a NESTED
        # generic sum (``Opt<Opt<Int>>``). Pre-fix a sum clone's
        # ``payload_tys`` list escaped the instantiation rewrite (stayed
        # ``Opt<Int>``), and the binder refinement read stale decls and
        # never reached an inner match's scrutinee nor a refined binder's
        # Value references (``${k}`` kept ty ``T``), surfacing as "no
        # Wasm encoding for 'Opt<Int>' / 'T'". Also a generic STRUCT whose
        # field is a generic SUM (``Box<Opt<Int>>`` / ``Box<Opt<String>>``)
        # matched on the field ``bo.value`` with the inner payload bound +
        # used (Int and String leaves, plus the field's Nothing arm), and
        # the inner-Nothing arm of a nested sum (``Just(Nothing)`` of
        # ``Opt<Opt<Int>>``) to exercise sizing when the inner payload is
        # absent.
        self._assert_parity("generic_sum_payload_binder.capa")

    def test_multi_impl_dispatch(self):
        # Multi-impl trait dynamic dispatch slice (2026-06-07): a trait
        # with MORE THAN ONE impl, called through a trait-typed value,
        # dispatches to the right concrete impl on the Wasm backend.
        # Pre-fix the front-end accepted such programs (they ran on
        # Python) but the Wasm backend raised a precise
        # WasmEmissionError - no dynamic-dispatch codegen. The fix
        # stores a per-concrete-type type-id at offset 0 of every
        # struct implementing a multi-impl trait (fields shift after an
        # 8-byte header, invisible to field iteration), keeps a trait
        # value as a single i32 struct pointer, and dispatches at the
        # call site by loading the tag and walking an if-chain to the
        # matching mangled impl method. Covers every result shape
        # (String / Int / Bool / Float), three impls with different
        # field layouts, the trait value through a let / param / return
        # / struct field / sum-payload match, a List of mixed concrete
        # types iterated per element, a self-method call, and a
        # participating struct used as a plain concrete value (direct
        # call / field read / equality) so the header does not corrupt
        # those paths.
        self._assert_parity("multi_impl_dispatch.capa")

    def test_multi_impl_sum_dispatch(self):
        # Sum-type impl targets of a multi-impl trait (2026-06-07):
        # pre-fix the Wasm backend raised a precise WasmEmissionError
        # for any sum impl target because the dispatcher read the
        # type-id at struct offset 0 - exactly where a sum stores its
        # variant tag. The fix moves the type-id to a UNIFORM offset 4
        # (free padding in both struct and sum layouts) for every
        # participant: a sum keeps its variant tag at offset 0 and
        # payloads at offset 8 unchanged, so its match / equality /
        # payload extraction are unaffected, while its constructor also
        # writes the type-id at offset 4. Covers two distinct sum impls
        # of one trait, every result shape (String / Int / Bool / Float
        # / Unit), the trait value through a let / param / return /
        # struct field / match-binder hop, a List<Trait> mixing sum
        # concrete types iterated per element, ``match self`` in an impl
        # method, a self-method call, and a participating sum used as a
        # plain sum (match + structural equality, equal and unequal) so
        # the offset-4 type-id does not corrupt those paths.
        self._assert_parity("multi_impl_sum_dispatch.capa")

    def test_multi_impl_mixed_dispatch(self):
        # Mixed struct + sum impls of ONE multi-impl trait (2026-06-07):
        # the case the uniform offset-4 type-id exists for. A struct
        # participant carries fields at offset 8 with the type-id in its
        # reserved header at offset 4; a sum participant carries its
        # variant tag at offset 0, payloads at offset 8, and the type-id
        # at offset 4 - so the one dispatcher reads the type-id from the
        # same offset regardless of the receiver's dynamic type. Covers
        # one trait with a struct impl + two sum impls through every hop
        # (let / param / return / struct field / match-binder) and a
        # List<Trait> mixing struct and both sum concrete types iterated
        # per element, plus each value used as its plain concrete self
        # (struct field + equality, sum match + equality).
        self._assert_parity("multi_impl_mixed_dispatch.capa")

    def test_option_result_trait_payload(self):
        # Trait value as an Option<Trait> / Result<Trait> payload
        # (2026-06-08): pre-fix the Wasm backend rejected
        # Some(traitval) / Ok(traitval) / Err(traitval) with "type
        # mismatch: expected i64, found i32" because a trait head was
        # not recognised as pointer-shaped, so the uniform-8-byte
        # payload slot was neither i64-extended on store nor i32-wrapped
        # on read-back. Covers Option<Trait> Some + None and
        # Result<Trait> Ok + Err over a single-impl trait and a
        # multi-impl trait at BOTH a struct and a sum dynamic type, with
        # method dispatch on the extracted value (the type-id must
        # survive the i64<->i32 slot round-trip).
        self._assert_parity("option_result_trait_payload.capa")

    def test_map_trait_value(self):
        # Trait value as a Map<K, Trait> value (2026-06-08): pre-fix the
        # Wasm backend raised "Map value type 'X' not supported" because
        # the Map value encoder's inline pointer-shape test did not
        # recognise a trait head. Covers K = String and K = Int, several
        # entries with different concrete dynamic types (struct + two
        # sum participants), Map.get returning Option<Trait> then a
        # method call on the value, Map.values iteration with per-value
        # dispatch, an overwrite, and a miss.
        self._assert_parity("map_trait_value.capa")

    def test_container_trait_payload(self):
        # Trait value in the other containers the central pointer-shape
        # predicate now enables (2026-06-08): List<Trait> (iterate /
        # .get(i) -> Option<Trait> / index), a tuple with a trait
        # component (let-destructure + match-destructure), and a struct
        # field of trait type - each read / extracted then dispatched,
        # mixing struct and sum dynamic types.
        self._assert_parity("container_trait_payload.capa")

    def test_trait_value_eq(self):
        # Trait-typed value structural equality (2026-06-08): == / != on
        # a trait-typed value dispatches at runtime on the offset-4
        # type-id to the matching concrete type's $eq_<Concrete> helper
        # via a $eq_<Trait> dispatcher. Two trait values are equal IFF
        # same dynamic type AND structurally equal; different dynamic
        # types (incl struct-vs-sum) compare not-equal (matching Python's
        # False, never an error). Pre-fix the Wasm backend raised a
        # precise WasmEmissionError for trait == / !=. Covers direct == /
        # != for single-impl AND multi-impl traits, struct AND sum
        # dynamic types (sum with payload-bearing + payloadless
        # variants), same-type-equal / same-type-different / different-
        # type cases.
        self._assert_parity("trait_value_eq.capa")

    def test_trait_eq_in_containers(self):
        # Trait-typed value equality inside containers (2026-06-08): a
        # trait leaf nested in List<Trait>, Option<Trait>, Result<Trait,
        # Int>, Map<String, Trait>, Map<Int, Trait>, a (Trait, Int)
        # tuple, a struct with a trait field, and List<Trait>.contains,
        # each compared with == / != and routed through the same offset-4
        # type-id dispatch. (Trait as a Map key / Set element stays a
        # precise loud error: a sum dynamic type is unhashable on the
        # Python backend while a struct one is hashable, so the two
        # backends cannot agree at compile time.)
        self._assert_parity("trait_eq_in_containers.capa")

    def test_struct_field_assign(self):
        # Field-target assignment slice (2026-06-06): ``obj.field =
        # value`` lowers to a FieldStore that writes the field slot of
        # the heap record in place (the symmetric write to a field
        # read). Covers every field type (Int / String / Char / Bool /
        # Float / nested struct / list), the read-modify-write form
        # (``x = x + 1`` and ``+=``), a nested receiver
        # (``outer.inner.n``), and caller-visibility through a function
        # boundary (a callee mutating the caller's struct must be
        # observed identically on both backends).
        self._assert_parity("struct_field_assign.capa")

    def test_tail_call_emits_return_call(self):
        # White-box: confirm the peephole actually fires (a green
        # parity run alone would also pass with a plain ``call``).
        src = (_EXAMPLES / "tail_recursion.capa").read_text(encoding="utf-8")
        module, result = _parse_and_analyze(src)
        from capa.ir import compile_wat
        wat = compile_wat(module, types=result.types)
        # sum_to (if/else), count_down (match arm), is_even, is_odd.
        self.assertEqual(wat.count("return_call"), 4, wat)

    def test_tail_call_runs_in_constant_stack_wasm_only(self):
        # The robustness payoff: a depth that overflows an ordinary
        # call stack returns cleanly under TCO. Wasm-only -- the Python
        # reference would raise RecursionError well before this depth,
        # so it is deliberately not a parity program.
        src = (
            "fun sum_to(n: Int, acc: Int) -> Int\n"
            "    if n == 0\n"
            "        return acc\n"
            "    return sum_to(n - 1, acc + n)\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${sum_to(1000000, 0)}\")\n"
        )
        out = _capture_stdout(lambda: _run_wasm(src))
        # 1_000_000 * 1_000_001 / 2
        self.assertEqual(out, "500000500000\n")

    def test_for_wildcard(self):
        self._assert_parity("for_wildcard.capa")

    def test_env_restrict_to_keys_callarg(self):
        self._assert_parity("env_restrict_to_keys_callarg.capa")

    def test_list_lit_trait_annotation(self):
        self._assert_parity("list_lit_trait_annotation.capa")

    def test_parse_int_json_number_parity(self):
        self._assert_parity("parse_int_json_number_parity.capa")

    def test_inventory_matches_examples_dir(self):
        # Soundness check: every .capa under examples/wasm/ is
        # either in the parity list or in the documented-excluded
        # dict. Forces a future contributor adding a new example
        # to decide which side it lives on rather than letting it
        # silently fall outside parity coverage.
        on_disk = {p.name for p in _EXAMPLES.glob("*.capa")}
        accounted_for = set(_PARITY_PROGRAMS) | set(_EXCLUDED.keys())
        unaccounted = on_disk - accounted_for
        self.assertFalse(
            unaccounted,
            (
                "examples/wasm/ has files not classified by "
                "test_ir_wasm_parity.py: "
                f"{sorted(unaccounted)}. Either add to _PARITY_PROGRAMS "
                "(and a test_ method) or add to _EXCLUDED with a "
                "one-line rationale."
            ),
        )

    def test_every_parity_program_has_executing_test(self):
        # Soundness check (2026-06-08): list membership in
        # ``_PARITY_PROGRAMS`` alone does NOT make a program run --
        # pytest only executes ``test_*`` methods. A program added to
        # the list without a method that actually drives it (e.g. via
        # ``self._assert_parity("foo.capa")``) silently ships
        # un-exercised, and ``test_inventory_matches_examples_dir``
        # passes on membership alone. This gate closes that gap: every
        # parity program must be referenced by an ``_assert_parity``
        # call inside some ``test_*`` method of this class, so a
        # list-only registration can never silently ship again.
        import inspect
        import re

        class_src = inspect.getsource(type(self))
        referenced = set(
            re.findall(r'_assert_parity\(\s*"([^"]+\.capa)"', class_src)
        )
        unwired = [p for p in _PARITY_PROGRAMS if p not in referenced]
        self.assertFalse(
            unwired,
            (
                "parity programs registered in _PARITY_PROGRAMS but not "
                "driven by any test method (pytest will never run them): "
                f"{sorted(unwired)}. Add a test_ method that calls "
                "self._assert_parity(\"<name>.capa\") for each."
            ),
        )


# Programs that exercise a host bridge whose canonical-ABI
# lift / lower can diverge between the core ``WasmHost`` path and
# the Component Model adapter path (the discrepancy that produced
# the slice 9 ``option<T>`` discriminant bug). Each entry here gets
# a CM-pivot parity assertion alongside the existing core-host one
# above. Programs that live entirely in the guest (no host bridge
# data flow beyond ``Stdio.println``) trust the core-host parity
# test and don't need CM coverage -- the CM wrapping doesn't touch
# guest-only WAT.
_CM_HOST_BRIDGE_SUBSET: list[str] = [
    "hello.capa",          # trivial CM sanity (Stdio.println)
    "env_demo.capa",       # option<string> lift (the slice 9 bug shape)
    "fs_demo.capa",        # result<string, io-error> + result<unit, io-error>
    "net_get.capa",        # Fs.write + Net.get duo
    "net_post.capa",       # Net.post two-string-arg variant
    "net_restrict.capa",   # attenuation-deny short-circuit
    "allows_inline.capa",  # Fs.allows / Env.allows / Clock.allows inline
    "db_demo.capa",        # Db.exec / Db.query two-string-arg + attenuation
    # Slice 13 audit-fix surface under CM. The Clock.sleep gate
    # threads through the inline ``clock.now_secs()`` host call,
    # so it exercises CM canonical-ABI lift for f64 returns; the
    # ATTACH block runs through the standard Db host bridge.
    "clock_sleep_attenuation.capa",
    "db_attach_blocked.capa",
    # Slice 15 (2026-05): Proc.exec two-String-arg + attenuation
    # short-circuit under CM, plus the ``$proc_allows`` runtime
    # helper exercised by both Proc.exec's attenuation check and
    # Proc.allows on a scoped cap.
    "proc_demo.capa",
    # Slice 25.8 (2026-05-30): cross-function attenuation parity on
    # the Component Model path. The core wasm host gained handle-
    # threading in slices 25.2 - 25.6; this slice catches the CM
    # host up. Each of these programs narrows a root cap, hands the
    # narrowed handle to a helper across a function boundary, and
    # asserts the helper's privileged op is denied. Pre-slice-25.8
    # the CM wrapper could not even ingest a program whose ``main``
    # took a handle-bearing cap (hard ``wasm-tools component new``
    # failure on the world-vs-core signature mismatch); now the CM
    # host enforces the same restriction as the Python and core-
    # wasm backends. ``net_substring_attack.capa`` is the F2
    # companion (the inline ``$str_contains`` URL check used to
    # admit lookalike URLs).
    "fs_cross_function_attenuation.capa",
    "net_cross_function_attenuation.capa",
    "net_substring_attack.capa",
    "db_cross_function_attenuation.capa",
    "proc_cross_function_attenuation.capa",
    "env_cross_function_attenuation.capa",
    "clock_cross_function_attenuation.capa",
    # Match-emission slice (2026-06-10): guest-only programs, but
    # both carry freshly-written nested-match emitter paths
    # (variant-payload literals; outer sibling binders alongside a
    # nested variant), so they get the full CM shipping pivot as
    # cheap insurance alongside the core-host parity run, the same
    # way hello.capa anchors the trivial guest surface.
    "match_variant_payload_literal.capa",
    "match_nested_variant_outer_binds.capa",
]


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestPythonWasmComponentParity(unittest.TestCase):
    """Companion to :class:`TestPythonWasmParity` that pivots on
    the Component Model path instead of the core ``WasmHost``.

    Wraps each host-bridge-exercising program via ``wasm-tools
    component new`` + runs through ``WasmComponentHost`` (the
    ``capa --wasm --component --run`` shipping path). The slice 9
    ``option<T>`` discriminant fix surfaced a real bug here that
    the core-host pivot had been silently fake-matching; this
    class is the regression net for the next such canonical-ABI
    mismatch."""

    # Slice 25.8 (2026-05-30): the Component Model host now mirrors
    # the core host's cap-handle threading. The WIT generator emits
    # ``export main: func(<cap>: u32, ...)`` for each handle-bearing
    # cap on ``main``'s signature, ``WasmComponentHost`` parses the
    # exported func's WIT param list and dispatches the right root
    # handle into each slot, and every cap host bridge takes a
    # ``handle: u32`` first arg + looks the receiver up in the
    # per-instance handle table before performing the syscall. The
    # tests that were parked here while the CM wrapper still hard-
    # coded ``main: func();`` are now live.

    def _assert_cm_parity(self, filename: str) -> None:
        path = _EXAMPLES / filename
        src = path.read_text(encoding="utf-8")
        py_out = _capture_stdout(lambda: _run_python(src))
        cm_out = _capture_stdout(lambda: _run_wasm_component(src))
        self.assertEqual(
            py_out, cm_out,
            msg=(
                f"Python/Wasm-Component output divergence for "
                f"{filename}.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm-component ---\n{cm_out}"
            ),
        )

    def test_hello_under_cm(self):
        self._assert_cm_parity("hello.capa")

    def test_env_demo_under_cm(self):
        # Slice 9 bug shape: option<T> discriminant convention
        # mismatch between WIT (none=0, some=1) and Capa internal
        # (Some=0, None=1). This test would have failed pre-fix.
        # Slice 25.8 (2026-05-30): unparked once the CM host's
        # cap-handle threading caught up with the core host's.
        self._assert_cm_parity("env_demo.capa")

    def test_fs_demo_under_cm(self):
        self._assert_cm_parity("fs_demo.capa")

    def test_net_get_under_cm(self):
        self._assert_cm_parity("net_get.capa")

    def test_net_post_under_cm(self):
        self._assert_cm_parity("net_post.capa")

    def test_net_restrict_under_cm(self):
        self._assert_cm_parity("net_restrict.capa")

    def test_allows_inline_under_cm(self):
        self._assert_cm_parity("allows_inline.capa")

    def test_db_demo_under_cm(self):
        # Slice 11 (2026-05): Db v1 SQLite-backed capability under
        # the Component Model. Same reset-fixture dance as the
        # core parity test so back-to-back Python + CM runs both
        # see an empty database.
        import os
        path = "/tmp/capa_db_demo.db"
        if os.path.exists(path):
            os.unlink(path)
        try:
            self._assert_cm_parity("db_demo.capa")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_clock_sleep_attenuation_under_cm(self):
        # Slice 13 audit-fix surface under CM. The Clock.sleep
        # gate calls ``clock.now_secs()`` inline; if the WIT
        # generator hadn't been taught to advertise ``now_secs``
        # when ``sleep`` carries attenuations, the component
        # wrap would fail at link time with "import interface
        # is missing function now-secs". Slice 25.8 (2026-05-30):
        # unparked alongside the rest of the cap-on-main CM tests
        # once the CM host learned to thread handles through main.
        self._assert_cm_parity("clock_sleep_attenuation.capa")

    def test_stdio_read_line_under_cm(self):
        # Slice 1 host-bridge pile under the Component Model: the CM
        # host's read-line bridge reads sys.stdin and returns the
        # canonical-ABI result<string, io-error>, matching Python.
        stdin_text = "Alice\n42\n"

        def _run_with_stdin(thunk):
            saved = sys.stdin
            sys.stdin = io.StringIO(stdin_text)
            try:
                return _capture_stdout(thunk)
            finally:
                sys.stdin = saved

        src = (_EXAMPLES / "read_line_echo.capa").read_text(encoding="utf-8")
        py_out = _run_with_stdin(lambda: _run_python(src))
        cm_out = _run_with_stdin(lambda: _run_wasm_component(src))
        self.assertEqual(
            py_out, cm_out,
            msg=(
                f"Python/CM read_line divergence.\n"
                f"--- python ---\n{py_out}\n--- cm ---\n{cm_out}"
            ),
        )

    def test_db_attach_blocked_under_cm(self):
        # Slice 13 audit-fix surface under CM. Confirms the
        # sqlite3 authorizer is installed on the CM host
        # bridge's connections too.
        import os
        path = "/tmp/capa_db_attach.db"
        if os.path.exists(path):
            os.unlink(path)
        try:
            self._assert_cm_parity("db_attach_blocked.capa")
        finally:
            if os.path.exists(path):
                os.unlink(path)

    def test_proc_demo_under_cm(self):
        # Slice 15 (2026-05): Proc v1 sandboxed subprocess
        # capability under the Component Model. Same shape as
        # the core parity test - both backends run
        # ``subprocess.run`` against the same python invocation
        # so captured stdout matches byte-for-byte. The CM
        # canonical-ABI lift for ``result<string, io-error>``
        # already had Db / Fs / Net coverage; this case adds
        # Proc to the matrix. Slice 25.8 (2026-05-30): unparked
        # once the CM host's cap-handle threading reached parity
        # with the core host.
        self._assert_cm_parity("proc_demo.capa")

    # Slice 25.8 (2026-05-30): cross-function attenuation oracles
    # under the Component Model. The core wasm path gained these
    # in slices 25.2 - 25.6; this slice catches the CM path up.
    # Each program narrows a root cap, hands the narrowed handle
    # to a helper across a function boundary, and asserts the
    # helper's privileged op is denied. A regression here means
    # the CM host bridge stopped enforcing attenuation through
    # the handle table on at least one cap.

    def test_fs_cross_function_attenuation_under_cm(self):
        self._assert_cm_parity("fs_cross_function_attenuation.capa")

    def test_net_cross_function_attenuation_under_cm(self):
        self._assert_cm_parity("net_cross_function_attenuation.capa")

    def test_net_substring_attack_under_cm(self):
        # Audit slice 25 F2 under CM: the substring-match URL bug
        # admitted a URL whose hostname was ``attacker.invalid``
        # but whose path contained ``api.example.com``. The
        # handle-routed bridge defers to ``Net.get(url)`` which
        # does the proper ``urlparse(url).hostname`` + ``allows()``
        # check, so the lookalike is denied on both backends.
        self._assert_cm_parity("net_substring_attack.capa")

    def test_db_cross_function_attenuation_under_cm(self):
        # The deny check fires before the SQLite connection is
        # opened (the path-prefix check rejects the helper's call
        # via the host handle table), so no on-disk fixture is
        # required - both backends print exactly the one ``ok:``
        # line regardless of /tmp state.
        self._assert_cm_parity("db_cross_function_attenuation.capa")

    def test_proc_cross_function_attenuation_under_cm(self):
        self._assert_cm_parity("proc_cross_function_attenuation.capa")

    def test_env_cross_function_attenuation_under_cm(self):
        self._assert_cm_parity("env_cross_function_attenuation.capa")

    def test_clock_cross_function_attenuation_under_cm(self):
        self._assert_cm_parity("clock_cross_function_attenuation.capa")

    def test_match_variant_payload_literal_under_cm(self):
        # Match-emission slice (2026-06-10) under the CM pivot:
        # locks the new variant-payload literal-pattern emitter
        # paths through the full --component --run shipping path.
        self._assert_cm_parity("match_variant_payload_literal.capa")

    def test_match_nested_variant_outer_binds_under_cm(self):
        # Match-emission slice (2026-06-10) under the CM pivot:
        # locks the outer-sibling-binder fix (the silent
        # ``Pair(n, Some(m))`` divergence) through the full
        # --component --run shipping path.
        self._assert_cm_parity("match_nested_variant_outer_binds.capa")

    def test_subset_membership(self):
        # Soundness check: every entry in _CM_HOST_BRIDGE_SUBSET
        # must already be in the core parity list (otherwise we'd
        # be silently relaxing standards), and the file must
        # exist on disk.
        on_disk = {p.name for p in _EXAMPLES.glob("*.capa")}
        for name in _CM_HOST_BRIDGE_SUBSET:
            self.assertIn(
                name, _PARITY_PROGRAMS,
                msg=f"CM subset entry {name!r} is not in _PARITY_PROGRAMS",
            )
            self.assertIn(
                name, on_disk,
                msg=f"CM subset entry {name!r} not present on disk",
            )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestJsonAndLargeStringParity(unittest.TestCase):
    """Adversarial-review fixes (2026-06-10): two silent
    cross-backend divergences found through ``parse_json``.

    C1: the bundled Wasm-side JSON parser accepted RAW control
    characters (newline, tab, anything < 0x20) inside JSON strings,
    returning ``Ok`` where Python's ``json.loads`` returns ``Err``
    (RFC 8259 section 7 requires them escaped). It also accepted
    invalid escape introducers (``\\q``) and decoded ``\\b`` /
    ``\\f`` verbatim as ``b`` / ``f``.

    C2: any string over ~64 KiB trapped the Wasm backend with
    "out of bounds memory access" where Python returned ``Ok``.
    Two distinct causes shared the symptom: (a) the module's
    ``(memory ...)`` declaration hard-coded ONE initial page, so a
    static data segment past 64 KiB failed at instantiation (which
    is why ``--wasm-memory-cap`` had no effect, and why even
    *printing* a 70 KiB literal trapped); (b) the bundled parser
    accumulated string contents one character at a time through the
    no-free bump allocator -- O(n^2) bytes -- so even runtime-built
    large inputs blew the 16 MiB cap inside ``$alloc``.

    These tests build their sources inline (a 100 KiB literal has
    no business being a checked-in example file) but assert the
    same property as the file-based harness above: bit-identical
    stdout across the Python and Wasm backends.
    """

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            # Pin the agreed-upon output too: both backends agreeing
            # on the WRONG answer must not pass.
            self.assertEqual(py_out, expect)

    @staticmethod
    def _ok_err_probe(doc_literal: str) -> str:
        """A main() that parses ``doc_literal`` (a Capa string
        literal, escapes included) and prints just Ok / Err."""
        return (
            "fun main(stdio: Stdio)\n"
            f"    let doc = {doc_literal}\n"
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )

    # ----- C1: raw control characters inside JSON strings --------

    def test_raw_newline_in_json_string_is_err(self):
        # The exact reported repro: an object whose string value
        # contains a literal 0x0A. Pre-fix: Python Err, Wasm Ok.
        src = self._ok_err_probe(r'"{\"k\": \"a\nb\"}"')
        self._assert_src_parity(src, expect="Err\n")

    def test_raw_tab_in_json_string_is_err(self):
        src = self._ok_err_probe(r'"{\"k\": \"a\tb\"}"')
        self._assert_src_parity(src, expect="Err\n")

    def test_raw_ctrl_chars_in_json_string_are_err(self):
        # Boundary sweep of the < 0x20 range: 0x00, 0x01, 0x0D,
        # 0x1F raw inside a string value or key are all Err; 0x20
        # (space) is fine.
        for esc in ("\\u{0}", "\\u{1}", "\\u{d}", "\\u{1f}"):
            src = self._ok_err_probe(f'"[\\"a{esc}b\\"]"')
            self._assert_src_parity(src, expect="Err\n")
        src = self._ok_err_probe(r'"{\"a' + "\\u{1}" + r'\": 1}"')
        self._assert_src_parity(src, expect="Err\n")
        src = self._ok_err_probe(r'"[\"a b\"]"')
        self._assert_src_parity(src, expect="Ok\n")

    def test_valid_escapes_round_trip(self):
        # \n \t \r \b \f \" \\ \/ all decode to the same value on
        # both backends; the value is pinned by serialising the
        # parsed tree back out (json.dumps on Python, the bundled
        # serialiser on Wasm).
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "{\\"a\\": \\"x\\\\ny\\\\tz\\", '
            '\\"b\\": \\"q\\\\\\"w\\\\\\\\e\\\\/r\\", '
            '\\"c\\": \\"\\\\b\\\\f\\\\r\\"}"\n'
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )
        self._assert_src_parity(
            src,
            expect='Ok {"a": "x\\ny\\tz", "b": "q\\"w\\\\e/r", '
                   '"c": "\\b\\f\\r"}\n',
        )

    def test_unicode_escape_is_ok_on_both(self):
        # \uXXXX parses Ok on both backends AND decodes to the real
        # code point. (Until 2026-06-10 the Wasm-side parser passed
        # the four hex digits through verbatim; the decoded value is
        # now pinned by TestJsonUnicodeEscapeAndExtraDataParity
        # below; here the historical Ok-ness probe is kept, value
        # strengthened.)
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "\\"a\\\\u0041b\\""\n'
            "    match parse_json(doc)\n"
            "        Ok(jv) ->\n"
            "            match jv.as_string()\n"
            '                Some(v) -> stdio.println("Ok ${v}")\n'
            '                None    -> stdio.println("not a string")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )
        self._assert_src_parity(src, expect="Ok aAb\n")

    def test_invalid_escape_is_err(self):
        # \q is not a JSON escape: Err on both (Python: "Invalid
        # \escape"). Pre-fix Wasm passed it through verbatim as Ok.
        src = self._ok_err_probe(r'"\"a\\qb\""')
        self._assert_src_parity(src, expect="Err\n")

    # ----- C2: large strings ---------------------------------------

    def test_parse_json_100kib_string_literal(self):
        # The exact reported repro shape: a >64 KiB literal handed
        # to parse_json. Pre-fix the module trapped at INSTANTIATION
        # ("out of bounds memory access": the data segment did not
        # fit the hard-coded single initial page). Value-checked:
        # length plus head and tail slices.
        big = "ab" * 51200  # 102400 chars
        src = (
            "fun main(stdio: Stdio)\n"
            f'    let doc = "\\"{big}\\""\n'
            "    match parse_json(doc)\n"
            "        Ok(jv) ->\n"
            "            match jv.as_string()\n"
            '                Some(v) -> stdio.println("Ok ${v.length()} '
            '${v.substring(0, 8)} ${v.substring(102392, 102400)}")\n'
            '                None    -> stdio.println("not a string")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )
        self._assert_src_parity(src, expect="Ok 102400 abababab abababab\n")

    def test_parse_json_runtime_built_100kib_string(self):
        # Same size but built by runtime concatenation, so the data
        # segment stays small: this pins the OTHER trap (quadratic
        # per-character accumulation through the bump allocator that
        # blew the 16 MiB cap inside $alloc).
        src = (
            "fun main(stdio: Stdio)\n"
            '    var body = "0123456789"\n'
            "    while body.length() < 100000\n"
            "        body = body + body\n"
            '    let doc = "\\"" + body + "\\""\n'
            "    match parse_json(doc)\n"
            "        Ok(jv) ->\n"
            "            match jv.as_string()\n"
            '                Some(v) -> stdio.println("Ok ${v.length()}")\n'
            '                None    -> stdio.println("not a string")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )
        self._assert_src_parity(src, expect="Ok 163840\n")

    def test_parse_json_document_over_128kib(self):
        # A >128 KiB DOCUMENT (not just one big string): an array of
        # eight 20 KiB strings plus scalar elements. Checks element
        # count and the summed string lengths so a silently
        # truncated value cannot pass.
        chunk = "z" * 20000
        elems = ", ".join(
            [f'\\"{chunk}{i}\\"' for i in range(8)]
            + ["1", "2.5", "null", "true"]
        )
        src = (
            "fun main(stdio: Stdio)\n"
            f'    let doc = "[{elems}]"\n'
            "    match parse_json(doc)\n"
            "        Ok(jv) ->\n"
            "            match jv.as_array()\n"
            "                Some(xs) ->\n"
            "                    var total = 0\n"
            "                    for x in xs\n"
            "                        match x.as_string()\n"
            "                            Some(v) -> total = total + v.length()\n"
            "                            None    -> total = total + 0\n"
            '                    stdio.println("Ok ${xs.length()} ${total}")\n'
            '                None -> stdio.println("not an array")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )
        self._assert_src_parity(src, expect="Ok 12 160008\n")

    def test_large_string_literal_shared_infra(self):
        # The C2 root cause was NOT parse_json-specific: any module
        # whose interned literals crossed 64 KiB trapped at
        # instantiation. Interpolating + printing a 70 KiB literal
        # pins the general fix (initial pages sized to the data
        # segment).
        big = "x" * 70000
        src = (
            "fun main(stdio: Stdio)\n"
            f'    let s = "{big}"\n'
            '    stdio.println("${s.length()}")\n'
        )
        self._assert_src_parity(src, expect="70000\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestJsonUnicodeEscapeAndExtraDataParity(unittest.TestCase):
    r"""Bundled-JSON-parser hardening (2026-06-10, follow-up to
    TestJsonAndLargeStringParity): two more pre-existing silent
    divergences against the Python ``json`` oracle.

    D1 (\uXXXX escapes): the Wasm-side parser passed the four hex
    digits through VERBATIM ("A" decoded to the five characters
    ``u0041``) where Python decodes the code point. Now decoded for
    real, including surrogate pairs (``\ud83d\ude00`` -> one astral
    code point) and Python's exact unpaired-surrogate semantics:
    ``json.loads('"\ud800"')`` does NOT error -- it returns a string
    holding the lone surrogate, length 1. The Wasm side stores that
    lone surrogate as WTF-8 bytes, which keeps ``length()`` (code
    point count) identical. Note that Python itself cannot PRINT a
    lone surrogate (``UnicodeEncodeError`` at the stdout encoder),
    so the unpaired-surrogate probes pin Ok-ness + length, never the
    raw character.

    D2 (extra data): ``parse_json("1 2")`` returned ``Ok(1)`` on
    Wasm where Python raises "Extra data" -- the wrapper simply
    discarded the trailing position. Any non-whitespace after the
    top-level value is now Err; trailing whitespace stays Ok.
    """

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            # Pin the agreed-upon output too: both backends agreeing
            # on the WRONG answer must not pass.
            self.assertEqual(py_out, expect)

    @staticmethod
    def _ok_err_probe(doc_literal: str) -> str:
        """A main() that parses ``doc_literal`` (a Capa string
        literal, escapes included) and prints just Ok / Err."""
        return (
            "fun main(stdio: Stdio)\n"
            f"    let doc = {doc_literal}\n"
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )

    @staticmethod
    def _string_value_probe(doc_literal: str, body: str) -> str:
        """A main() that parses ``doc_literal``, projects the string
        value ``v`` out, and prints ``body`` (an interpolation over
        ``v`` / ``jv``)."""
        return (
            "fun main(stdio: Stdio)\n"
            f"    let doc = {doc_literal}\n"
            "    match parse_json(doc)\n"
            "        Ok(jv) ->\n"
            "            match jv.as_string()\n"
            f'                Some(v) -> stdio.println("{body}")\n'
            '                None    -> stdio.println("not a string")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )

    # ----- D1: \uXXXX decodes to the real code point ---------------

    def test_unicode_escape_bmp(self):
        # Two-byte (é, U+00E9) and three-byte (中, U+4E2D) BMP code
        # points: decoded value, code point count, and the to_json
        # round-trip (json.dumps with ensure_ascii=False emits the
        # raw characters) all byte-identical.
        src = self._string_value_probe(
            r'"\"caf\\u00e9 \\u4e2d\""',
            "Ok ${v} ${v.length()} ${to_json(jv)}",
        )
        self._assert_src_parity(src, expect='Ok café 中 6 "café 中"\n')

    def test_unicode_escape_control_char(self):
        # \u0001 decodes to the raw control code point U+0001; the
        # round-trip re-escapes it exactly like json.dumps. The
        # value is pinned through to_json rather than printed raw so
        # the expected string stays readable; length pins that ONE
        # code point landed in the value.
        src = self._string_value_probe(
            r'"\"\\u0001\""',
            "Ok ${v.length()} ${to_json(jv)}",
        )
        self._assert_src_parity(src, expect='Ok 1 "\\u0001"\n')

    def test_surrogate_pair_astral(self):
        # \ud83d\ude00 combines into U+1F600 (one emoji code point),
        # printable on both backends, round-trips through to_json.
        src = self._string_value_probe(
            r'"\"\\ud83d\\ude00\""',
            "Ok ${v} ${v.length()} ${to_json(jv)}",
        )
        self._assert_src_parity(src, expect='Ok \U0001f600 1 "\U0001f600"\n')

    def test_surrogate_pair_uppercase_hex(self):
        # Python json accepts upper / mixed-case hex digits.
        src = self._string_value_probe(
            r'"\"\\uD83D\\udE00\""',
            "Ok ${v} ${v.length()}",
        )
        self._assert_src_parity(src, expect="Ok \U0001f600 1\n")

    def test_lone_surrogate_is_ok_like_python(self):
        # Python's exact semantics, replicated: json.loads accepts
        # an UNPAIRED surrogate escape and produces a string holding
        # the lone surrogate code point (length 1). High and low
        # alike. The raw character is deliberately NOT printed:
        # Python cannot encode a lone surrogate to stdout
        # (UnicodeEncodeError), so Ok-ness + code point count is the
        # whole observable surface shared by the two backends.
        for esc in (r"\\ud800", r"\\udc00"):
            src = self._string_value_probe(
                f'"\\"{esc}\\""',
                "Ok ${v.length()}",
            )
            self._assert_src_parity(src, expect="Ok 1\n")

    def test_lone_high_surrogate_then_bmp_escape(self):
        # \ud800 followed by A: Python pairs ONLY a contiguous
        # low-surrogate escape, so this is the lone surrogate plus
        # "A" -- two code points.
        src = self._string_value_probe(
            r'"\"\\ud800\\u0041\""',
            "Ok ${v.length()}",
        )
        self._assert_src_parity(src, expect="Ok 2\n")

    def test_lone_high_surrogate_then_text(self):
        # \ud800 followed by a plain character: lone surrogate + x.
        src = self._string_value_probe(
            r'"\"\\ud800x\""',
            "Ok ${v.length()}",
        )
        self._assert_src_parity(src, expect="Ok 2\n")

    def test_high_surrogate_then_full_pair(self):
        # \ud800 then \ud83d\ude00: the first high surrogate stays lone
        # (the next escape is another HIGH surrogate, not a low
        # one), then the \ud83d\ude00 pair combines. Python: 2 code points.
        src = self._string_value_probe(
            r'"\"\\ud800\\ud83d\\ude00\""',
            "Ok ${v.length()}",
        )
        self._assert_src_parity(src, expect="Ok 2\n")

    def test_escapes_mixed_with_text(self):
        # Escapes interleaved with plain runs: the chunked decode
        # pass must splice runs and decoded code points in order.
        src = self._string_value_probe(
            r'"\"a\\u00e9b \\ud83d\\ude00 c\\u4e2dd\""',
            "Ok ${v} ${v.length()} ${to_json(jv)}",
        )
        self._assert_src_parity(
            src,
            expect='Ok aéb \U0001f600 c中d 9 "aéb \U0001f600 c中d"\n',
        )

    def test_invalid_unicode_escapes_are_err(self):
        # Non-hex digits, truncation by the closing quote, and
        # Python's quirky-but-real rejection of "0x41" are all
        # "Invalid \uXXXX escape" -> Err on both backends.
        for esc in (r"\\uZZZZ", r"\\u00", r"\\u12", r"\\u0x41"):
            src = self._ok_err_probe(f'"\\"{esc}\\""')
            self._assert_src_parity(src, expect="Err\n")

    # ----- D2: extra data after the top-level value -----------------

    def test_extra_data_after_number(self):
        # The exact reported repro: Python Err ("Extra data"),
        # pre-fix Wasm Ok(1).
        src = self._ok_err_probe(r'"1 2"')
        self._assert_src_parity(src, expect="Err\n")

    def test_extra_data_after_object(self):
        src = self._ok_err_probe(r'"{\"a\": 1} {}"')
        self._assert_src_parity(src, expect="Err\n")

    def test_extra_data_after_string(self):
        src = self._ok_err_probe(r'"\"a\" \"b\""')
        self._assert_src_parity(src, expect="Err\n")

    def test_extra_data_after_array(self):
        src = self._ok_err_probe(r'"[1] ,"')
        self._assert_src_parity(src, expect="Err\n")

    def test_trailing_whitespace_is_ok(self):
        # Whitespace (space, tab, newline, CR) after the value is
        # legitimate JSON; only non-whitespace bytes are extra data.
        for doc in (r'"1\n"', r'"  {\"a\": 1}\t \r\n"'):
            src = self._ok_err_probe(doc)
            self._assert_src_parity(src, expect="Ok\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestJsonStrictNumbersDepthAndSignParity(unittest.TestCase):
    r"""Closing round for five pre-existing parse_json / to_json
    cross-backend divergences (2026-06-10, follow-up to
    TestJsonUnicodeEscapeAndExtraDataParity). Oracle: both backends
    identical AND RFC 8259-conformant.

    1. NaN / Infinity / -Infinity: Python's json.loads accepted
       them (allow_nan default) where the Wasm parser never did,
       and to_json(parse_json("Infinity")...) CRASHED the Python
       backend with OverflowError in the int() collapse. Strict
       wins: Err on both, and the collapse is isfinite-guarded.
    2. Number grammar: the Wasm parser accepted 01 / -01 / 1. /
       .5 / +1 that Python rejects; the token shape is now
       validated against the RFC 8259 grammar before conversion.
    3. Nesting cap: __CJ_MAX_DEPTH=100 existed only on Wasm; the
       Python wrapper now enforces the same cap with the same
       message at the same position (probed at 99/100/101).
    4. Negative zero: to_json gave "0" on Python (int() collapse
       drops the sign) and "-0" on Wasm; both now emit "-0.0",
       what json.dumps does with the real -0.0 value, and the
       integer-form "-0" input collapses to 0 like json.loads.
    5. _capa_chr stays internal (analyzer rejection covered in
       tests/test_analyzer.py::TestInternalBuiltinRejection); the
       \uXXXX decode path it backs keeps working on both backends,
       re-pinned here through a round-trip probe.

    Err MESSAGES for malformed numbers / constants are worded per
    backend (Python surfaces json.loads's wording); those probes
    pin Ok/Err only. The depth message is identical on both sides
    and is pinned verbatim.
    """

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            # Pin the agreed-upon output too: both backends agreeing
            # on the WRONG answer must not pass.
            self.assertEqual(py_out, expect)

    @staticmethod
    def _ok_err_probe(doc_literal: str) -> str:
        """A main() that parses ``doc_literal`` (a Capa string
        literal) and prints Ok plus the to_json round-trip, or Err."""
        return (
            "fun main(stdio: Stdio)\n"
            f"    let doc = {doc_literal}\n"
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err")\n'
        )

    # ----- 1: NaN / Infinity constants are Err on both ------------

    def test_nan_and_infinity_constants_are_err(self):
        # Pre-fix: Python Ok (and the Infinity round-trip CRASHED
        # with OverflowError in the int() collapse), Wasm Err.
        for doc in ('"NaN"', '"Infinity"', '"-Infinity"',
                    '"[NaN]"', '"{\\"x\\": Infinity}"'):
            src = self._ok_err_probe(doc)
            self._assert_src_parity(src, expect="Err\n")

    # ----- 2: RFC 8259 number grammar ------------------------------

    def test_malformed_number_tokens_are_err(self):
        # Pre-fix the Wasm side accepted every one of these through
        # its lenient parse_float; Python rejects them all.
        for doc in ('"01"', '"-01"', '"1."', '".5"', '"+1"',
                    '"1e"', '"1e+"', '"--1"', '"1.2.3"', '"-"',
                    '"[01]"'):
            src = self._ok_err_probe(doc)
            self._assert_src_parity(src, expect="Err\n")

    def test_valid_number_tokens_round_trip(self):
        # Grammar-valid numbers keep parsing, with byte-identical
        # round-trips. (Exponent forms are excluded: the Wasm
        # parse_float scientific-notation limitation is documented
        # in TODO.md and out of scope here.)
        for doc, out in (
            ('"0"', "0"),
            ('"10"', "10"),
            ('"-7"', "-7"),
            ('"1.25"', "1.25"),
            ('"-0.5"', "-0.5"),
            ('"[0.0, 12.75]"', "[0, 12.75]"),
        ):
            src = self._ok_err_probe(doc)
            self._assert_src_parity(src, expect=f"Ok {out}\n")

    # ----- 3: nesting depth cap ------------------------------------

    @staticmethod
    def _depth_probe(levels: int) -> str:
        """A main() that builds ``[ * levels + 1 + ] * levels`` at
        runtime, parses it, and prints Ok / the full Err message
        (identical on both backends, position included)."""
        return (
            "fun main(stdio: Stdio)\n"
            '    var doc = "1"\n'
            "    var i = 0\n"
            f"    while i < {levels}\n"
            '        doc = "[" + doc + "]"\n'
            "        i = i + 1\n"
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok")\n'
            '        Err(m) -> stdio.println("Err ${m}")\n'
        )

    def test_depth_99_and_100_are_ok(self):
        for levels in (99, 100):
            self._assert_src_parity(self._depth_probe(levels), expect="Ok\n")

    def test_depth_101_is_err_with_identical_message(self):
        # Pre-fix: Wasm Err, Python Ok (json.loads has no cap below
        # the interpreter recursion limit). The message and position
        # are pinned verbatim: the innermost value sits at code
        # point 101, exactly where __cj_parse_value gives up.
        self._assert_src_parity(
            self._depth_probe(101),
            expect="Err max nesting depth 100 exceeded at 101\n",
        )

    # ----- 4: negative zero ----------------------------------------

    def test_negative_zero_serialises_like_json_dumps(self):
        # to_json(JNum(-0.0)) was "0" on Python (int() collapse) and
        # "-0" on Wasm (strip loses the fraction): three answers for
        # one value. Both now emit "-0.0", which is what json.dumps
        # produces for the real -0.0.
        src = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(to_json(JNum(-0.0)))\n"
            "    stdio.println(to_json(JNum(0.0)))\n"
        )
        self._assert_src_parity(src, expect="-0.0\n0\n")

    def test_negative_zero_parse_round_trips(self):
        # "-0.0" keeps the sign through the round-trip; the
        # integer-form "-0" collapses to 0 exactly like
        # json.loads("-0") (int() drops the sign).
        for doc, out in (
            ('"-0.0"', "-0.0"),
            ('"-0"', "0"),
            ('"[-0.0, 0.0, -0]"', "[-0.0, 0, 0]"),
        ):
            src = self._ok_err_probe(doc)
            self._assert_src_parity(src, expect=f"Ok {out}\n")

    # ----- 5: the \uXXXX path _capa_chr backs still works ----------

    def test_unicode_escape_still_decodes_after_internal_gate(self):
        # _capa_chr is now analyzer-rejected in user code; the
        # bundled parser (analyzed with internal=True) must keep
        # using it. Round-trip re-pin on both backends.
        src = self._ok_err_probe(r'"\"caf\\u00e9 \\ud83d\\ude00\""')
        self._assert_src_parity(src, expect='Ok "café \U0001f600"\n')


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestDiscoveryGateCoverageParity(unittest.TestCase):
    """Shared-traversal slice (2026-06-11): every pre-emit Wasm
    discovery gate now consumes ``capa.ir._walk`` (top-level
    functions + impl methods + MakeLambda bodies + every nested
    instruction list, match-arm guard preludes included).

    Pre-fix each gate hand-rolled its own IR walk and several were
    blind to impl-method bodies and/or lambda bodies, so a feature
    used ONLY in one of those contexts emitted calls to runtime
    helpers the module never defined ("unknown func: failed to
    find name $str_eq / $ftoa / $__capa_parse_json / ..." from
    wasm-tools parse) or aborted emission outright (any lambda in
    an impl method: "MakeLambda ... not registered by the discover
    pass"). One test per previously-blind (gate, context) pair,
    each the minimal program that failed loudly, asserted as
    cross-backend output parity; plus the two match-guard shapes
    that already worked, pinned against regression; plus the
    WIT-side capability collection under the full
    ``--component --run`` path."""

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            # Pin the agreed-upon output too: both backends agreeing
            # on the WRONG answer must not pass.
            self.assertEqual(py_out, expect)

    def _assert_src_cm_parity(self, src: str, expect: str | None = None) -> None:
        """Component Model flavour: the WIT generated for ``src``
        and the core module's imports must agree, or the component
        link fails before anything runs."""
        py_out = _capture_stdout(lambda: _run_python(src))
        cm_out = _capture_stdout(lambda: _run_wasm_component(src))
        self.assertEqual(
            py_out, cm_out,
            msg=(
                f"Python/Wasm-Component output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm-component ---\n{cm_out}"
            ),
        )
        if expect is not None:
            self.assertEqual(py_out, expect)

    # ----- $str_eq (_uses_map_ops) ------------------------------

    def test_str_eq_in_method(self):
        # Pre-fix: "unknown func: failed to find name $str_eq".
        src = (
            "type Box { s: String }\n"
            "impl Box\n"
            "    fun is_hi(self) -> Bool\n"
            '        return self.s == "hi"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let b = Box { s: "hi" }\n'
            "    if b.is_hi()\n"
            '        stdio.println("method str eq")\n'
        )
        self._assert_src_parity(src, expect="method str eq\n")

    def test_str_eq_in_lambda_inside_method(self):
        # The doubly-nested context: a String == that only exists
        # inside a lambda which itself only exists inside an impl
        # method. Pre-fix this aborted at lambda registration
        # before $str_eq even mattered.
        src = (
            "type Box { s: String }\n"
            "impl Box\n"
            "    fun check(self) -> Bool\n"
            "        let f = fun (x: String) -> Bool => x == \"yes\"\n"
            "        return f(self.s)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let b = Box { s: "yes" }\n'
            "    if b.check()\n"
            '        stdio.println("lambda in method str eq")\n'
        )
        self._assert_src_parity(src, expect="lambda in method str eq\n")

    def test_string_match_in_method(self):
        # String-scrutinee match calls $str_eq per arm; the Match
        # branch of _uses_map_ops was blind to impl methods.
        src = (
            "type Tagger { t: String }\n"
            "impl Tagger\n"
            "    fun label(self) -> Int\n"
            "        match self.t\n"
            '            "a" -> return 1\n'
            '            "b" -> return 2\n'
            "            _ -> return 0\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let t = Tagger { t: "b" }\n'
            '    stdio.println("label = ${t.label()}")\n'
        )
        self._assert_src_parity(src, expect="label = 2\n")

    def test_set_and_map_of_string_in_method(self):
        # Set<String>.add/contains and Map<String, _>.set/get both
        # compare keys/elements via $str_eq.
        src = (
            "type Registry { n: Int }\n"
            "impl Registry\n"
            "    fun probe(self, stdio: Stdio)\n"
            "        var tags = new_set()\n"
            '        tags.add("red")\n'
            '        tags.add("red")\n'
            '        stdio.println("set has red: ${tags.contains(\\"red\\")}")\n'
            "        var m = new_map()\n"
            '        m.set("k", 7)\n'
            '        match m.get("k")\n'
            '            Some(v) -> stdio.println("map k = ${v}")\n'
            '            None -> stdio.println("map miss")\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let r = Registry { n: 1 }\n"
            "    r.probe(stdio)\n"
        )
        self._assert_src_parity(
            src, expect="set has red: true\nmap k = 7\n",
        )

    # ----- $eq_* structural helpers (_collect_eq_types) ---------

    def test_list_string_eq_in_method(self):
        # List<String> == needs $eq_List_String AND $str_eq for the
        # element leaves; _collect_eq_types / _eq_needs_str_eq were
        # both blind to impl methods.
        src = (
            "type Holder { n: Int }\n"
            "impl Holder\n"
            "    fun same(self, a: List<String>, b: List<String>) -> Bool\n"
            "        return a == b\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let h = Holder { n: 0 }\n"
            '    let xs = ["a", "b"]\n'
            '    let ys = ["a", "b"]\n'
            '    let zs = ["a", "c"]\n'
            '    stdio.println("xs == ys: ${h.same(xs, ys)}")\n'
            '    stdio.println("xs == zs: ${h.same(xs, zs)}")\n'
        )
        self._assert_src_parity(
            src, expect="xs == ys: true\nxs == zs: false\n",
        )

    def test_list_string_eq_in_toplevel_lambda(self):
        # Same gate, lambda-body context inside a plain function.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let xs = ["a", "b"]\n'
            '    let ys = ["a", "b"]\n'
            "    let same = fun (p: List<String>, q: List<String>) -> Bool => p == q\n"
            '    stdio.println("lambda list eq: ${same(xs, ys)}")\n'
        )
        self._assert_src_parity(src, expect="lambda list eq: true\n")

    # ----- $ftoa (_uses_float_format) ----------------------------

    def test_float_interpolation_in_method(self):
        # Pre-fix: "unknown func: failed to find name $ftoa".
        src = (
            "type Reading { f: Float }\n"
            "impl Reading\n"
            "    fun show(self, stdio: Stdio)\n"
            '        stdio.println("f = ${self.f}")\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let r = Reading { f: 1.5 }\n"
            "    r.show(stdio)\n"
        )
        self._assert_src_parity(src, expect="f = 1.5\n")

    # ----- lambda lift (_discover_lambdas) -----------------------

    def test_lambda_in_method(self):
        # Pre-fix: ANY lambda inside an impl method aborted with
        # "MakeLambda ... not registered by the discover pass".
        src = (
            "type Box { n: Int }\n"
            "impl Box\n"
            "    fun doubled(self) -> Int\n"
            "        let f = fun (x: Int) -> Int => x * 2\n"
            "        return f(self.n)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 21 }\n"
            '    stdio.println("doubled = ${b.doubled()}")\n'
        )
        self._assert_src_parity(src, expect="doubled = 42\n")

    # ----- bundled JSON parser (uses_json_builtins) --------------

    def test_parse_json_in_method(self):
        # Pre-fix: the injector never saw the call, so the emitted
        # "call $__capa_parse_json" had no target function.
        src = (
            "type P { s: String }\n"
            "impl P\n"
            "    fun first_ok(self) -> Bool\n"
            "        match parse_json(self.s)\n"
            "            Ok(j) -> return true\n"
            "            Err(m) -> return false\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let good = P { s: "[1, 2]" }\n'
            '    let bad = P { s: "[1, " }\n'
            '    stdio.println("good: ${good.first_ok()}")\n'
            '    stdio.println("bad: ${bad.first_ok()}")\n'
        )
        self._assert_src_parity(src, expect="good: true\nbad: false\n")

    # ----- SplitMix64 helpers (_uses_random) ---------------------

    def test_random_in_lambda(self):
        # Pre-fix: "unknown global: failed to find name $rand_state".
        # Seeded so both backends draw the identical sequence.
        src = (
            "fun main(stdio: Stdio, rng: Random)\n"
            "    let draw = fun () -> Int => rng.with_seed(42).int_range(0, 100)\n"
            '    stdio.println("draw = ${draw()}")\n'
        )
        self._assert_src_parity(src)

    # ----- match-arm guard preludes (pinned, were already OK) ----

    def test_str_eq_only_in_match_guard(self):
        # The guard_setup walk: a String == whose ONLY occurrence
        # is a match-arm guard. Verified working before the shared
        # traversal landed; pinned so it stays that way.
        src = (
            "fun pick(n: Int, s: String) -> Int\n"
            "    match n\n"
            '        x if s == "go" -> return x * 10\n'
            "        x -> return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("go: ${pick(3, \\"go\\")}")\n'
            '    stdio.println("stop: ${pick(3, \\"stop\\")}")\n'
        )
        self._assert_src_parity(src, expect="go: 30\nstop: 3\n")

    def test_list_eq_only_in_match_guard(self):
        # Same pin for the structural-equality gate: a List<String>
        # == that only exists inside a guard prelude.
        src = (
            "fun pick(n: Int, xs: List<String>, ys: List<String>) -> Int\n"
            "    match n\n"
            "        x if xs == ys -> return x * 10\n"
            "        x -> return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let a = ["a", "b"]\n'
            '    let b = ["a", "b"]\n'
            '    let c = ["a", "c"]\n'
            '    stdio.println("eq: ${pick(3, a, b)}")\n'
            '    stdio.println("ne: ${pick(3, a, c)}")\n'
        )
        self._assert_src_parity(src, expect="eq: 30\nne: 3\n")

    # ----- WIT capability collection under --component --run -----

    def test_cap_only_in_method_under_cm(self):
        # The program's ONLY capability use lives in an impl
        # method. Pre-fix collect_used_capabilities returned an
        # empty WIT while the core module imported
        # capa:host/stdio, so the component link failed loudly.
        src = (
            "type Greeter { n: Int }\n"
            "impl Greeter\n"
            "    fun hello(self, stdio: Stdio)\n"
            '        stdio.println("hi from method ${self.n}")\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let g = Greeter { n: 7 }\n"
            "    g.hello(stdio)\n"
        )
        self._assert_src_cm_parity(src, expect="hi from method 7\n")

    def test_cap_only_in_lambda_under_cm(self):
        # Same mismatch, lambda-body context: the core-wasm side
        # discovered the import (its lambda walk fed
        # _discover_instrs) but the WIT side never saw it.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let say = fun () -> Unit => stdio.println(\"hi from lambda\")\n"
            "    say()\n"
        )
        self._assert_src_cm_parity(src, expect="hi from lambda\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestLambdaMatchResultAndShadowParity(unittest.TestCase):
    """Lambda-body match / shadowing slice (2026-06-11): two loud
    Wasm miscompiles found by the bug-hunt walk, both correct on
    the Python reference.

    (1) A lambda whose block-body TAIL is a match where every arm
    exits via an explicit ``return`` lowers through
    ``_lower_match_expr``; the analyzer types that match ``?`` (no
    arm yields a value), so the lowerer's result temp defaulted to
    the i64 Wasm shape while the (unreachable but still validated)
    trailing ``Return`` had to produce the lambda's declared
    result shape: "type mismatch: expected i32, found i64" at
    wasmtime compile for String / Float / pointer results.
    Practical consequence: ``parse_json`` / ``parse_int`` matched
    inside a lambda broke under ``--wasm``. The lowerer now
    re-types the temp (and any chained nested-match temp) from the
    declared return type.

    (2) A lambda body local shadowing the very variable the
    closure is bound to (``let f = fun ... => { let f = ...; }``;
    ``f()`` after) made the lowerer alpha-rename the OUTER binding
    (the lambda body lowers first and claims the bare name), but
    ``_lower_call`` did not resolve the callee through the alias
    stack, so the Call carried the source name and the Wasm
    emitter fell through to ``return_call $f`` against a function
    that does not exist ("unknown func" at wasm-tools parse). The
    callee now resolves through the same alias stack value
    positions already use; the analyzer keeps permitting the
    shadowing (lambda params shadowing outer locals are documented
    behaviour, and the Python backend always ran this shape
    correctly), so the fix is execution parity, not a new error."""

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            self.assertEqual(py_out, expect)

    # ----- (1) all-arms-return tail match inside a lambda --------

    def test_err_string_binder_return_in_lambda(self):
        # Exact bug-hunt repro (red5). Pre-fix: wasmtime "type
        # mismatch: expected i32, found i64" compiling lambda_0.
        src = (
            "fun helper() -> Result<Int, String>\n"
            "    return Ok(1)\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Ok(_) -> return "ok"\n'
            "            Err(m) -> return m\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="ok\n")

    def test_some_string_binder_return_in_lambda(self):
        # Exact bug-hunt repro (red7), Err-arm taken at runtime in
        # the sibling test above; here the Some payload is the one
        # that flows.
        src = (
            "fun helper() -> Option<String>\n"
            '    return Some("hi")\n'
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            "            Some(m) -> return m\n"
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="hi\n")

    def test_err_arm_taken_at_runtime_in_lambda(self):
        # The String payload actually flows out of the binder (the
        # repros above exercise the Ok/Some arm at runtime).
        src = (
            "fun helper() -> Result<Int, String>\n"
            '    return Err("boom")\n'
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Ok(_) -> return "ok"\n'
            "            Err(m) -> return m\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="boom\n")

    def test_parse_int_some_binder_in_lambda(self):
        # Exact bug-hunt repro (red11).
        src = (
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            '        match parse_int("41")\n'
            '            Some(n) -> return "p=${n + 1}"\n'
            '            None -> return "err"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="p=42\n")

    def test_some_float_binder_return_in_lambda(self):
        src = (
            "fun helper() -> Option<Float>\n"
            "    return Some(2.5)\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(x) -> return "x=${x}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="x=2.5\n")

    def test_some_list_binder_return_in_lambda(self):
        src = (
            "fun helper() -> Option<List<Int>>\n"
            "    return Some([7, 8])\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(xs) -> return "x=${xs[1]}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="x=8\n")

    def test_float_returning_lambda_all_arms_return(self):
        # Non-String result shapes were broken too: the '?' temp
        # defaulted to i64 against the lambda's f64 result.
        src = (
            "fun helper() -> Option<Float>\n"
            "    return Some(2.5)\n"
            "\n"
            "fun feat() -> Float\n"
            "    let f = fun () -> Float =>\n"
            "        match helper()\n"
            "            Some(x) -> return x + 1.0\n"
            "            None -> return 0.0\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("v=${feat()}")\n'
        )
        self._assert_src_parity(src, expect="v=3.5\n")

    def test_err_string_binder_in_method_lambda(self):
        # Same shape, lambda inside an impl method (the lifted
        # lambda is registered against the mangled method name).
        src = (
            "type Box { n: Int }\n"
            "\n"
            "fun helper() -> Result<Int, String>\n"
            '    return Err("nope")\n'
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let f = fun () -> String =>\n"
            "            match helper()\n"
            '                Ok(_) -> return "ok"\n'
            "                Err(m) -> return m\n"
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 10 }\n"
            "    stdio.println(b.describe())\n"
        )
        self._assert_src_parity(src, expect="nope\n")

    def test_parse_int_in_method_lambda(self):
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let base = self.n\n"
            "        let f = fun () -> String =>\n"
            '            match parse_int("7")\n'
            '                Some(k) -> return "k=${k}"\n'
            '                None -> return "err"\n'
            '        return "${f()} n=${base}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 10 }\n"
            "    stdio.println(b.describe())\n"
        )
        self._assert_src_parity(src, expect="k=7 n=10\n")

    def test_parse_json_in_lambda(self):
        # The practical consequence the bug-hunt called out:
        # parse_json matched inside a lambda broke under --wasm.
        src = (
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            '        match parse_json("{\\"a\\": 1}")\n'
            '            Ok(v) -> return "parsed"\n'
            "            Err(e) -> return e\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="parsed\n")

    def test_parse_json_payload_used_in_lambda(self):
        # The JsonValue payload flows through a nested match, all
        # inside the lambda.
        src = (
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            '        match parse_json("\\"hello\\"")\n'
            "            Ok(v) ->\n"
            "                match v.as_string()\n"
            '                    Some(s) -> return "got=${s}"\n'
            '                    None -> return "not a string"\n'
            "            Err(e) -> return e\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="got=hello\n")

    def test_nested_match_in_lambda(self):
        # The inner match's result temp is itself never-typed and
        # feeds the outer's via a dead arm AssignConst; the retype
        # must follow the chain ("cannot bind String dst" pre-fix).
        src = (
            "fun helper() -> Option<Result<Int, String>>\n"
            '    return Some(Err("inner"))\n'
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            "            Some(r) ->\n"
            "                match r\n"
            '                    Ok(_) -> return "ok"\n'
            "                    Err(m) -> return m\n"
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="inner\n")

    def test_yield_arms_lambda_regression(self):
        # Regression pin: arms that YIELD values (no returns) were
        # always typed precisely and must keep working.
        src = (
            "fun helper() -> Option<String>\n"
            '    return Some("hi")\n'
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            "            Some(m) -> m\n"
            '            None -> "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="hi\n")

    # ----- (2) lambda local shadowing the closure variable --------

    def test_lambda_local_shadows_closure_var(self):
        # Exact bug-hunt repro (red10). Pre-fix: "unknown func:
        # failed to find name $f" at wasm-tools parse
        # (return_call against a nonexistent function).
        src = (
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        let f = 1.0 / 8.0\n"
            '        return "v=${f}"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="v=0.125\n")

    def test_lambda_local_shadow_inner_use_regression(self):
        # Regression pin: a lambda body local shadowing an outer
        # name and USED inside the body keeps its own value while
        # the outer call still resolves to the closure.
        src = (
            "fun feat() -> String\n"
            "    let g = fun (x: Int) -> Int =>\n"
            "        let g = x * 2\n"
            "        return g + 1\n"
            '    return "v=${g(5)}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="v=11\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestLambdaGuardedTailMatchParity(unittest.TestCase):
    """Guarded tail-match inside a lambda (2026-06-13 follow-up to
    the 941c12b lambda-tail-match slice).

    941c12b closed the lambda-tail-match miscompile when every arm
    returns, but the same lambda shape with a GUARDED arm
    (``Some(n) if n > 5 -> ...``) still failed wasmtime compile
    with "type mismatch: expected i64, found i32" in lambda_0. Root
    cause: a guard's ANF prelude introduces its own temporary (the
    Bool ``n > 5`` BinOp lands in ``_ir_tN``), but the closure
    lifter's ``collect_defs`` walked only each arm's body and
    pattern, never its ``guard_setup``. The temp was therefore
    absent from the lifted function's body-locals copy, so the
    locals sweep fell back to the default i64 shape while the guard
    comparison produces an i32 -- the validator rejected the
    function. The control proves it is lambda-specific: the same
    guarded match in a TOP-LEVEL function already had parity (its
    locals come straight from the real ``fn.locals`` with the Bool
    type intact), and a lambda with an unguarded tail match (the
    941c12b fix) was already green.

    The lifter now sweeps each arm's ``guard_setup`` into the
    defined-in-body set, so the guard temp inherits its real Bool
    (i32) shape."""

    def _assert_src_parity(self, src: str, expect: str | None = None) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm output divergence.\n"
                f"--- python ---\n{py_out}\n"
                f"--- wasm ---\n{wasm_out}"
            ),
        )
        if expect is not None:
            self.assertEqual(py_out, expect)

    def test_guarded_arm_return_string_result(self):
        # Exact bug-hunt repro (a5_guard). Pre-fix: wasmtime "type
        # mismatch: expected i64, found i32" compiling lambda_0.
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > 5 -> return "big=${n}"\n'
            '            Some(n) -> return "small=${n}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="big=10\n")

    def test_guarded_arm_return_int_result(self):
        # Int result; the guard temp (i32 Bool) still must not get
        # the i64 default. (a5b)
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat() -> Int\n"
            "    let f = fun () -> Int =>\n"
            "        match helper()\n"
            "            Some(n) if n > 5 -> return n + 100\n"
            "            Some(n) -> return n\n"
            "            None -> return 0\n"
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${feat()}")\n'
        )
        self._assert_src_parity(src, expect="110\n")

    def test_guarded_arm_yield_string_result(self):
        # Arms YIELD (no return) + guard: the result temp is LIVE
        # here (each arm assigns into it, the trailing Return reads
        # it back), which is the case the 941c12b docstring premise
        # did not cover. (a5d)
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > 5 -> "big=${n}"\n'
            '            Some(n) -> "small=${n}"\n'
            '            None -> "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="big=10\n")

    def test_guarded_arm_guard_fails_falls_through(self):
        # The guard fails at runtime (n is not > 5), so the
        # fall-through to the next arm is what produces the value;
        # exercises the live guarded path end to end.
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(3)\n"
            "\n"
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > 5 -> return "big=${n}"\n'
            '            Some(n) -> return "small=${n}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="small=3\n")

    def test_guarded_parse_int_in_lambda(self):
        # The practical case from the brief: parse_int with a guard
        # inside a lambda. (a5f)
        src = (
            "fun feat() -> String\n"
            "    let f = fun () -> String =>\n"
            '        match parse_int("41")\n'
            '            Some(n) if n > 0 -> return "pos=${n}"\n'
            '            Some(n) -> return "nonpos=${n}"\n'
            '            None -> return "err"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="pos=41\n")

    def test_guarded_match_top_level_control(self):
        # Control that ALREADY had parity: the same guarded match in
        # a top-level function (no lambda lifting). Pins that the
        # fix does not regress the non-lambda path.
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat() -> String\n"
            "    match helper()\n"
            '        Some(n) if n > 5 -> return "big=${n}"\n'
            '        Some(n) -> return "small=${n}"\n'
            '        None -> return "none"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="big=10\n")

    def test_guard_captures_enclosing_param(self):
        # Symmetric half of cf6740c: the guard reads a name captured
        # from the ENCLOSING function's parameter (``threshold``),
        # used ONLY inside the guard, never in any arm body. Pre-fix
        # the free-var collector skipped ``arm.guard`` /
        # ``arm.guard_setup``, so ``threshold`` never entered the
        # env layout and the lifted body emitted ``local.get`` for an
        # unallocated local (unknown local at Wasm validate time).
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat(threshold: Int) -> String\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > threshold -> return "big=${n}"\n'
            '            Some(n) -> return "small=${n}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat(5))\n"
        )
        self._assert_src_parity(src, expect="big=10\n")

    def test_guard_captures_enclosing_let_local(self):
        # Same shape but the guard captures a let-LOCAL of the
        # enclosing function (``cutoff``) rather than a param. Also
        # guard-only; never referenced in any arm body.
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(10)\n"
            "\n"
            "fun feat() -> String\n"
            "    let cutoff = 5\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > cutoff -> return "big=${n}"\n'
            '            Some(n) -> return "small=${n}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="big=10\n")

    def test_guard_captures_let_local_guard_fails(self):
        # The captured-local guard fails at runtime (n is not >
        # cutoff), proving the captured value is genuinely threaded
        # into the closure body and compared, not just allocated.
        src = (
            "fun helper() -> Option<Int>\n"
            "    return Some(3)\n"
            "\n"
            "fun feat() -> String\n"
            "    let cutoff = 5\n"
            "    let f = fun () -> String =>\n"
            "        match helper()\n"
            '            Some(n) if n > cutoff -> return "big=${n}"\n'
            '            Some(n) -> return "small=${n}"\n'
            '            None -> return "none"\n'
            "    return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(feat())\n"
        )
        self._assert_src_parity(src, expect="small=3\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestSelfCapturedInImplMethodLambda(unittest.TestCase):
    """Known limitation pin (TODO.md "Known limitations"): a lambda
    inside an impl method that captures ``self`` and reads one of
    its fields fails loud on Wasm with "FieldAccess on receiver of
    type 'Unknown': no struct layout known" while the Python backend
    runs it correctly. The receiver's concrete impl type is lost
    when the lambda body is lifted. Marked ``expectedFailure`` so
    this gives a clear signal (an unexpected pass) the day the
    lifter threads ``self``'s owning type through; flip it to a
    normal assertion then."""

    @unittest.expectedFailure
    def test_self_field_access_in_impl_method_lambda(self):
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let f = fun () -> String =>\n"
            '            return "n=${self.n}"\n'
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 5 }\n"
            "    stdio.println(b.describe())\n"
        )
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(py_out, wasm_out)
        self.assertEqual(py_out, "n=5\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestStringBytesParity(unittest.TestCase):
    """``String.bytes() -> List<Int>`` parity (slice 2026-06-13).

    The receiver's UTF-8 bytes, each element 0..255. The Wasm
    backend stores strings as their raw UTF-8 byte slice and copies
    them straight through; the Python backend encodes via
    ``str.encode('utf-8', 'surrogatepass')``. For well-formed text
    both equal the canonical UTF-8 from Python's ``str.encode``;
    a lone surrogate (which the WTF-8 internal representation holds
    as its 3-byte form) is byte-identical across backends rather
    than raising, matching ``surrogatepass``."""

    def _dump_src(self, build_str: str) -> str:
        # Prints the byte list of a String produced by ``build_str``
        # (a Capa expression of type String), one byte per line.
        return (
            "fun main(stdio: Stdio)\n"
            f"    let s = {build_str}\n"
            "    for b in s.bytes()\n"
            "        stdio.println(\"${b}\")\n"
        )

    def _assert_parity(self, src: str, expect: str) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm bytes() divergence.\n"
                f"--- python ---\n{py_out}\n--- wasm ---\n{wasm_out}"
            ),
        )
        self.assertEqual(py_out, expect)

    @staticmethod
    def _expect(text: str) -> str:
        # The Python oracle: strict canonical UTF-8 for well-formed
        # text. One byte per line, matching the dump program.
        return "".join(f"{b}\n" for b in text.encode("utf-8"))

    def test_ascii(self):
        self._assert_parity(self._dump_src('"hello"'), self._expect("hello"))

    def test_bmp_two_byte(self):
        # U+00E9 LATIN SMALL LETTER E WITH ACUTE -> 2 bytes.
        self._assert_parity(self._dump_src('"é"'), self._expect("é"))

    def test_bmp_three_byte(self):
        # U+4E2D CJK -> 3 bytes.
        self._assert_parity(self._dump_src('"中"'), self._expect("中"))

    def test_astral_four_byte(self):
        # U+1F98A FOX FACE -> 4 bytes (astral plane).
        self._assert_parity(self._dump_src('"🦊"'), self._expect("🦊"))

    def test_empty_is_empty_list(self):
        # Empty string -> empty byte list -> no output lines.
        self._assert_parity(self._dump_src('""'), "")

    def test_mixed_length_vs_byte_count(self):
        # 4 code points; 1 + 2 + 3 + 4 = 10 UTF-8 bytes. The oracle
        # below pins the exact byte sequence on both backends.
        mixed = "aé中🦊"
        self._assert_parity(self._dump_src(f'"{mixed}"'), self._expect(mixed))

    def test_length_vs_bytes_counts(self):
        # Pin the code-point count vs byte count relationship: the
        # mixed string has 4 code points but 10 bytes.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let s = "aé中🦊"\n'
            '    stdio.println("cps=${s.length()} bytes=${s.bytes().length()}")\n'
        )
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(py_out, wasm_out)
        self.assertEqual(py_out, "cps=4 bytes=10\n")

    def test_lone_surrogate_wtf8(self):
        # A JSON "\\uD800" escape decodes to an unpaired surrogate
        # code point, kept as its 3-byte WTF-8 form internally. Both
        # backends expose [237, 160, 128] -- equal to Python's
        # ``'\\ud800'.encode('utf-8', 'surrogatepass')``. The JSON
        # source uses \\u{...} escapes (\\u{22}='"', \\u{5c}='\\') so
        # the Capa lexer leaves the literal \\uD800 for the parser.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let json = "\\u{22}\\u{5c}uD800\\u{22}"\n'
            "    match parse_json(json)\n"
            "        Ok(j) ->\n"
            "            match j.as_string()\n"
            "                Some(s) ->\n"
            "                    for b in s.bytes()\n"
            '                        stdio.println("${b}")\n'
            '                None -> stdio.println("not a string")\n'
            '        Err(e) -> stdio.println("parse error")\n'
        )
        expect = "".join(
            f"{b}\n" for b in "\ud800".encode("utf-8", "surrogatepass")
        )
        self._assert_parity(src, expect)
        # Sanity: surrogatepass gives the canonical 3-byte WTF-8 form.
        self.assertEqual(expect, "237\n160\n128\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestContextDrivenMonomorphParity(unittest.TestCase):
    """Generic factories whose type parameter is fixed by the call-
    site context (annotated binding / return type / consuming
    argument), not by any value argument (bug fix 2026-06-14).

    The Python backend never monomorphises, so it accepts these
    programs and runs correctly; the Wasm backend used to infer the
    instantiation from argument types alone and so never emitted the
    specialised clone, failing with ``unknown func`` at parse. Each
    case below must run bit-identically across both backends."""

    def _assert_parity(self, src: str, expect: str) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm monomorph divergence.\n"
                f"--- python ---\n{py_out}\n--- wasm ---\n{wasm_out}"
            ),
        )
        self.assertEqual(py_out, expect)

    def test_annotated_binding(self):
        # The reported repro: zero-value-arg factory, T fixed by the
        # binding's type annotation.
        src = (
            "type Tally<T> { items: List<T> }\n"
            "fun empty_tally<T>() -> Tally<T>\n"
            "    let xs: List<T> = []\n"
            "    return Tally { items: xs }\n"
            "fun main(out: Stdio)\n"
            "    var t: Tally<String> = empty_tally()\n"
            '    t.items.push("hi")\n'
            '    out.println("len=${t.items.length()}")\n'
        )
        self._assert_parity(src, "len=1\n")

    def test_direct_return(self):
        # T fixed by the enclosing function's declared return type.
        src = (
            "type Tally<T> { items: List<T> }\n"
            "fun empty_tally<T>() -> Tally<T>\n"
            "    let xs: List<T> = []\n"
            "    return Tally { items: xs }\n"
            "fun make_string_tally() -> Tally<String>\n"
            "    return empty_tally()\n"
            "fun main(out: Stdio)\n"
            "    var t: Tally<String> = make_string_tally()\n"
            '    t.items.push("hi")\n'
            '    out.println("len=${t.items.length()}")\n'
        )
        self._assert_parity(src, "len=1\n")

    def test_consuming_argument(self):
        # T fixed by the parameter type of a non-generic consuming
        # call (``count(empty_tally())``).
        src = (
            "type Tally<T> { items: List<T> }\n"
            "fun empty_tally<T>() -> Tally<T>\n"
            "    let xs: List<T> = []\n"
            "    return Tally { items: xs }\n"
            "fun count(t: Tally<String>) -> Int\n"
            "    return t.items.length()\n"
            "fun main(out: Stdio)\n"
            "    let n: Int = count(empty_tally())\n"
            '    out.println("n=${n}")\n'
        )
        self._assert_parity(src, "n=0\n")

    def test_nested_generic_factory(self):
        # Generic factory whose result feeds a generic struct literal
        # in another generic factory; T threads through G<G<T>>. The
        # inner call's only concrete anchor is the outer factory's
        # use site.
        src = (
            "type Box<T> { value: List<T> }\n"
            "fun empty_box<T>() -> Box<T>\n"
            "    let xs: List<T> = []\n"
            "    return Box { value: xs }\n"
            "type Wrap<T> { inner: Box<T> }\n"
            "fun empty_wrap<T>() -> Wrap<T>\n"
            "    return Wrap { inner: empty_box() }\n"
            "fun main(out: Stdio)\n"
            "    var w: Wrap<Int> = empty_wrap()\n"
            "    w.inner.value.push(7)\n"
            '    out.println("len=${w.inner.value.length()}")\n'
        )
        self._assert_parity(src, "len=1\n")

    def test_mixed_arg_and_annotation_params(self):
        # Two type params: A pinned by a value argument, B only by the
        # binding annotation. Both must resolve.
        src = (
            "type Pair<A, B> { first: List<A>, second: List<B> }\n"
            "fun seeded<A, B>(a: A) -> Pair<A, B>\n"
            "    let xs: List<A> = []\n"
            "    xs.push(a)\n"
            "    let ys: List<B> = []\n"
            "    return Pair { first: xs, second: ys }\n"
            "fun main(out: Stdio)\n"
            "    var p: Pair<Int, String> = seeded(7)\n"
            '    p.second.push("hi")\n'
            '    out.println("f=${p.first.length()} s=${p.second.length()}")\n'
        )
        self._assert_parity(src, "f=1 s=1\n")

    def test_arg_driven_still_works(self):
        # Regression guard: a factory whose T IS carried by a value
        # argument keeps monomorphising via argument inference, with
        # no call-site context needed.
        src = (
            "type Tally<T> { items: List<T> }\n"
            "fun one_tally<T>(seed: T) -> Tally<T>\n"
            "    let xs: List<T> = []\n"
            "    xs.push(seed)\n"
            "    return Tally { items: xs }\n"
            "fun main(out: Stdio)\n"
            "    let t = one_tally(42)\n"
            '    out.println("len=${t.items.length()}")\n'
        )
        self._assert_parity(src, "len=1\n")


if __name__ == "__main__":
    unittest.main()
