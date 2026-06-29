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
    # Slice (2026-06-18): a lambda inside an impl method that
    # captures ``self`` and reads its fields. The lifted lambda's
    # ``self`` capture carried no concrete type on the FieldAccess
    # receiver Value nor in the synthesised function's locals; the
    # field-access emitter now reads the type the lift's env layout
    # already resolved. Covers single/multiple fields, self+local
    # capture, a doubly-nested lambda, and an Int (non-String) field.
    "self_in_impl_lambda.capa",
    # GAP-2b (2026-06-21): dynamic-prefix ``.allows()`` parity across
    # Fs / Net / Db / Proc / Env (host-route closes the crash + the
    # silent Env divergence + the realpath/traversal query drift).
    "allows_dynamic_prefix_parity.capa",
    "json_demo.capa",
    # perf/wasm-json-span (2026-06-22): parse-side O(1) value / key
    # extraction. Parses large string / number arrays plus a document
    # whose keys / values sit after multibyte prefixes, byte-identical
    # across backends.
    "json_parse_span.capa",
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
    "set_algebra.capa",
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
    # Parity slice: to_upper / to_lower are ASCII-only on both backends
    # (only A-Z <-> a-z fold; accents, Greek, Cyrillic, and emoji pass
    # through). The Python backend routes through _capa_to_upper /
    # _capa_to_lower instead of str.upper()/str.lower() so the two
    # backends are byte-identical on non-ASCII input.
    "string_case_ascii.capa",
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
    # Slice (2026-06-26): Option<T> / Result<T, E> unwrap() + expect(msg)
    # success paths (Some / Ok) across Int and String payloads. The
    # value-less panic paths (None / Err) abort rather than produce
    # comparable stdout, so they live in tests/test_panic.py.
    "option_unwrap_expect.capa",
    "fn_ref_as_closure.capa",
    # Slice (2026-06-27): lambda parameter / return-type inference in
    # higher-order calls. Every lambda in this program omits its
    # parameter and return types; the analyzer infers them from each
    # method's expected Fun(..) type and writes them back into the AST,
    # so the lowered CIR is byte-identical to the hand-annotated form.
    # The dedicated CIR-equality assertion lives in
    # ``test_lambda_inference_cir_matches_annotated`` below; this entry
    # exercises the runtime output parity across both backends.
    "lambda_inference.capa",
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
    # Audit 2026-06-17: guest-side proc.allows / db.allows query
    # parity for the path-identity (a bare-name Proc restriction
    # rejects a planted ``/attacker/git``) and lexical-traversal
    # (a Db literal walking out via ``..`` is denied) cases the
    # pre-fix Wasm collapse answered differently from Python.
    "allows_traversal_parity.capa",
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
    # fix/interp-nested-strings (2026-06-25): a string literal nested
    # inside a ``${...}`` interpolation (``"a is ${m.get("a")...}"``)
    # used to terminate the outer string at the inner quote. The lexer
    # and the parser's matching-``}`` scan now step over nested strings.
    # Covers the headline idiom, a ``}`` inside a nested string,
    # recursive nesting, and the preserved interpolation behaviours,
    # byte-identical across backends.
    "string_interp_nested.capa",
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
    # Bug #2 (2026-06-16): String ordering operators (< > <= >=),
    # previously rejected at Wasm emit, now lowered through $str_cmp
    # (byte-by-byte UTF-8 == Python code-point order). Covers a
    # sorted_by String comparator and Unicode.
    "string_order_cmp.capa",
    # Bug #3 (2026-06-16): a named binder over a Unit payload (Ok(s)
    # on Result<Unit, _>), previously emitting local.set for an
    # undeclared local, now treated as a wildcard; also exercises the
    # ``let _ = unit_returning_fn()`` call-site bind.
    "match_unit_payload.capa",
    # perf/wasm-concat-inplace (2026-06-22): String ``+`` lowers to
    # the ``$str_concat`` runtime helper, which grows the left
    # operand's buffer in place when it is the last bump allocation
    # (``out = out + chunk`` in a loop is now O(n) amortised instead
    # of O(n^2)). The program pins byte-identical output for the loop
    # accumulator AND the grow-only aliasing contract: a snapshot
    # taken before a growing concat keeps the old value, a substring
    # view stays valid across a grow, ``out = out + out`` (auto-
    # concat / RHS aliases LHS) doubles correctly, an allocating RHS
    # forces the fallback path, and chained concats agree.
    "string_concat_loop.capa",
    # perf/wasm-json-builder (2026-06-22): ``to_json`` on an array /
    # object is now O(n) on the Wasm backend. The serialiser collects
    # every output piece into a ``List<String>`` first (phase 1, all
    # child allocation here) then folds the pieces with ``out = out +
    # piece`` over a ``for piece in parts`` loop (phase 2, which binds
    # each element as an allocation-free (ptr, len) view), so ``out``
    # stays the last bump allocation and grows in place. Pre-builder
    # the naive ``out = out + __capa_to_json(x)`` allocated the child
    # right before the concat, defeating the v1.8.0 grow-in-place fast
    # path: every element copied the whole prefix again (quadratic) and
    # a large array trapped at the 256-page memory cap. The program
    # pins byte-identical output for a large array of objects (the
    # headline linear case) plus the empty array / empty object, an
    # array of mixed scalars (int / fraction / scientific / -0.0 / bool
    # / null / string), strings with escapes and an astral code point,
    # a nested object, and a deeply nested array.
    "json_serialize_builder.capa",
    # Range transform + indexed-query methods (2026-06-24): map /
    # filter / fold / first / last / get / find / find_index on a
    # Range. The teaching material promises "a range is just a List,
    # so everything you have learned about lists applies", but these
    # methods previously raised "type 'Range' has no method ...".
    # Both backends now desugar ``range.method(...)`` to
    # ``range.to_list().method(...)`` (the transpiler via the CapaRange
    # methods, the Wasm IR lowerer by materialising then routing
    # through the List emitters), so the result is byte-identical to
    # the materialised-list form. Covers the exact book example
    # ``(0..10).filter(x % 2 == 0)``, map / fold, an empty range
    # (5..5), inclusive (a..=b), variable bounds at both ends, the
    # indexed queries, and a filter -> map chain.
    "range_transform_methods.capa",
    # stdlib List methods slice (2026-06-26): List.reverse / enumerate
    # / zip / flat_map, each returning a FRESH list (the receiver is
    # never mutated) with a specified iteration order so both backends
    # print byte-identically. reverse copies element slots verbatim via
    # memory.copy (shape-agnostic); enumerate / zip build a per-element
    # (Int, T) / (T, U) tuple record; flat_map routes through the HOF
    # closure path and concatenates the per-element result lists in
    # order. Covers empty lists, reverse non-mutation, 0-based
    # enumerate indices, flat_map result lists of different sizes
    # (including an empty one interleaved and an empty receiver), and
    # zip truncation to the shorter length from either side, over Int
    # and String element types.
    "list_reverse_enumerate_zip_flatmap.capa",
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
    "wasi_random_clock.capa": (
        "Experimental --wasi mode demo: Clock + system_seed Random are "
        "non-deterministic so there is no byte-equality reference. "
        "Covered by the dedicated TestWasiMode property tests in "
        "tests/test_wasi_mode.py (monotonic non-decreasing, wall "
        "plausible, system_seed distinct, seeded byte-identical)."
    ),
    "wasi_env.capa": (
        "Experimental --wasi mode demo: env.get / env.args read the "
        "ambient host environment + argv, which the auto-list harness "
        "does not control (and the default backend would read the "
        "real environment), so there is no fixed byte-equality "
        "reference. Covered by the dedicated TestWasiEnvMode tests in "
        "tests/test_wasi_mode.py, which set a known env var + argv and "
        "assert controlled-key parity with the Python backend."
    ),
    "wasi_env_attenuation.capa": (
        "Experimental --wasi mode demo: guest-side Env attenuation "
        "(restrict_to_keys / allows / fail-closed get) reads the "
        "ambient host environment, which the auto-list harness does "
        "not control, so there is no fixed byte-equality reference "
        "here. Covered by the dedicated TestWasiEnvAttenuation tests "
        "in tests/test_wasi_mode.py, which set known env vars and "
        "assert three-backend byte-parity (Python oracle == capa:host "
        "host-side narrowing == WASI guest-side narrowing)."
    ),
    "wasi_fs_metadata.capa": (
        "Experimental --wasi mode demo: Fs metadata (exists / is_dir / "
        "mkdir via wasi:filesystem + the preopen ceiling). The result "
        "depends on host filesystem state (which directories the demo "
        "paths point at), which the auto-list harness does not control, "
        "so there is no fixed byte-equality reference here. Covered by "
        "the dedicated TestWasiFsMode tests in tests/test_wasi_mode.py, "
        "which build a known temp directory and assert three-backend "
        "parity (Python oracle == capa:host == WASI)."
    ),
    "wasi_fs_read.capa": (
        "Experimental --wasi mode demo: Fs.read via wasi:filesystem "
        "open-at -> read-via-stream -> wasi:io/streams blocking-read "
        "loop + the preopen ceiling. The output depends on host "
        "filesystem state (the contents of the demo's data/file.txt), "
        "which the auto-list harness does not control, so there is no "
        "fixed byte-equality reference here. Covered by the dedicated "
        "TestWasiFsRead tests in tests/test_wasi_mode.py, which build a "
        "known temp directory (small / empty / large-multichunk / UTF-8 "
        "files) and assert three-backend byte parity (Python oracle == "
        "capa:host == WASI)."
    ),
    "wasi_fs_write.capa": (
        "Experimental --wasi mode demo: Fs.write via wasi:filesystem "
        "open-at (create|truncate) -> write-via-stream -> wasi:io/streams "
        "blocking-write-and-flush loop -> blocking-flush + the preopen "
        "ceiling. The demo writes to and reads back the host filesystem "
        "(its data/note.txt), which the auto-list harness does not "
        "control, so there is no fixed byte-equality reference here. "
        "Covered by the dedicated TestWasiFsWrite tests in "
        "tests/test_wasi_mode.py, which build a known temp directory "
        "(small / empty / large-multichunk / UTF-8 / overwrite) and "
        "assert three-backend byte parity AND on-disk byte equality "
        "(Python oracle == capa:host == WASI) via write-then-read-back."
    ),
    "wasi_fs_list_dir.capa": (
        "Experimental --wasi mode demo: Fs.list_dir via wasi:filesystem "
        "open-at (directory open-flag) -> read-directory -> "
        "directory-entry-stream.read-directory-entry loop + a guest-side "
        "lexicographic sort + the preopen ceiling. The output depends on "
        "host filesystem state (the entries of the demo's data/ "
        "directory), which the auto-list harness does not control, so "
        "there is no fixed byte-equality reference here. Covered by the "
        "dedicated TestWasiFsListDir tests in tests/test_wasi_mode.py, "
        "which build a known temp directory (multi-entry mixed-case + a "
        "subdirectory / empty / UTF-8 names / a non-directory / a missing "
        "path) and assert three-backend byte parity INCLUDING the sorted "
        "order (Python oracle == capa:host == WASI)."
    ),
    "wasi_fs_attenuation.capa": (
        "Experimental --wasi mode demo: GUEST-SIDE Fs fine attenuation "
        "(Level 2) -- Fs.restrict_to builds a prefix allow-list and every "
        "privileged op fails closed on a path outside it, with LEXICAL "
        "path containment in place of the oracle's realpath. The literal "
        "paths point at an absolute directory the runner must create "
        "(/tmp/capa/data/...), which the auto-list parity harness does not "
        "control, so there is no fixed byte-equality reference here. "
        "Covered by the dedicated TestWasiFsAttenuation tests in "
        "tests/test_wasi_mode.py, which build a known temp directory and "
        "assert three-backend byte parity (Python oracle == capa:host == "
        "WASI) for restrict_to + allows + every op's fail-closed deny, "
        "chaining/intersection, isolation, the unrestricted root, and the "
        "cross-function-boundary restriction survival."
    ),
    "wasi_net_get.capa": (
        "Experimental --wasi mode demo: Net.get via wasi:http "
        "(outgoing-handler.handle + the outgoing-request / future-incoming-"
        "response / incoming-response / incoming-body chain) + wasi:io/streams "
        "blocking-read body loop + the guest-side host ceiling. The demo GETs "
        "a live HTTP server (its literal url points at 127.0.0.1:8080), which "
        "the auto-list parity harness does not run, so there is no fixed "
        "byte-equality reference here. Covered by the dedicated TestWasiNetGet "
        "tests in tests/test_wasi_mode.py, which start a controlled local "
        "127.0.0.1 server (small / empty / large-multichunk / UTF-8 bodies / "
        "404 / 500 / connection-refused) and assert three-backend byte parity "
        "(Python urllib oracle == capa:host == WASI)."
    ),
    "wasi_net_post.capa": (
        "Experimental --wasi mode demo: Net.post via wasi:http (Phase 2). "
        "Reuses the Net.get chain and adds a flow-controlled outgoing-body "
        "write of the request body before the handle. The demo POSTs to a "
        "live HTTP server (its literal url points at 127.0.0.1:8080), which "
        "the auto-list parity harness does not run, so there is no fixed "
        "byte-equality reference here. Covered by the dedicated "
        "TestWasiNetPost / TestWasiNetPostCeiling tests in "
        "tests/test_wasi_mode.py, which start a controlled local 127.0.0.1 "
        "server (small / empty / large-multichunk request bodies / "
        "large-multichunk responses / UTF-8 / 404 / 500 / connection-refused) "
        "and assert three-backend byte parity of the RESPONSE plus the exact "
        "request body the server received."
    ),
    "wasi_net_attenuation.capa": (
        "Experimental --wasi mode demo: Net FINE ATTENUATION via guest-side "
        "Level 2 (Phase 3) -- Net.restrict_to (host allow-list intersection) "
        "and Net.allows (exact-hostname equality membership), with get / post "
        "fail-closed on a host outside the allow-list, layered on top of the "
        "static ceiling. The demo GETs a live HTTP server (its literal url "
        "points at 127.0.0.1:8080), which the auto-list parity harness does "
        "not run, so there is no fixed byte-equality reference here. Covered "
        "by the dedicated TestWasiNetAttenuation tests in "
        "tests/test_wasi_mode.py, which start a controlled local 127.0.0.1 "
        "server and assert three-backend byte parity (Python oracle == "
        "capa:host == WASI) for restrict + allowed + denied (get and post), "
        "allows true / false, chaining / intersection-collapse, parent "
        "isolation, the unrestricted root, and exact-equality-not-substring."
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

    def test_lambda_inference(self):
        self._assert_parity("lambda_inference.capa")

    def test_lambda_inference_cir_matches_annotated(self):
        """A lambda whose parameter / return types are INFERRED must
        lower to byte-identical CIR (and Python source, and Wasm bytes)
        as the SAME lambda written out by hand. The inference is a
        pure front-end concern: the analyzer fills the omitted
        annotations back into the AST before lowering, so neither
        backend can tell the two forms apart."""
        annotated = (
            "fun apply(f: Fun(Int) -> Int, n: Int) -> Int\n"
            "    return f(n)\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3, 4, 5]\n"
            "    let doubled = xs.map(fun (x: Int) -> Int => x * 2)\n"
            "    let evens = xs.filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    let total = xs.fold(0, fun (acc: Int, x: Int) -> Int => acc + x)\n"
            "    let r = apply(fun (x: Int) -> Int => x * 3, 4)\n"
            "    stdio.println(\"${doubled[0]} ${evens.length()} ${total} ${r}\")\n"
        )
        inferred = (
            "fun apply(f: Fun(Int) -> Int, n: Int) -> Int\n"
            "    return f(n)\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3, 4, 5]\n"
            "    let doubled = xs.map(fun (x) => x * 2)\n"
            "    let evens = xs.filter(fun (x) => x % 2 == 0)\n"
            "    let total = xs.fold(0, fun (acc, x) => acc + x)\n"
            "    let r = apply(fun (x) => x * 3, 4)\n"
            "    stdio.println(\"${doubled[0]} ${evens.length()} ${total} ${r}\")\n"
        )

        def build(src):
            module, result = _parse_and_analyze(src)
            py = transpile(
                module, types=result.types, bindings=result.bindings,
            )
            wasm = compile_wasm(module, types=result.types)
            return py, wasm

        py_annot, wasm_annot = build(annotated)
        py_infer, wasm_infer = build(inferred)
        self.assertEqual(
            py_annot, py_infer,
            "inferred-lambda Python source differs from annotated",
        )
        self.assertEqual(
            wasm_annot, wasm_infer,
            "inferred-lambda Wasm bytes differ from annotated",
        )

    def test_self_in_impl_lambda(self):
        self._assert_parity("self_in_impl_lambda.capa")

    def test_json_demo(self):
        self._assert_parity("json_demo.capa")

    def test_json_parse_span(self):
        self._assert_parity("json_parse_span.capa")

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

    def test_set_algebra(self):
        self._assert_parity("set_algebra.capa")

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

    def test_string_case_ascii(self):
        # Parity slice: ``to_upper`` / ``to_lower`` are ASCII-only on
        # both backends. Only A-Z <-> a-z fold; accents (é), Greek,
        # Cyrillic, and a 4-byte emoji pass through untouched. The
        # Python backend routes through ``_capa_to_upper`` /
        # ``_capa_to_lower`` instead of Python's full-Unicode
        # ``str.upper()`` / ``str.lower()``, which would have folded
        # the non-ASCII letters and diverged silently from Wasm. This
        # closes the last non-numeric cross-backend divergence.
        self._assert_parity("string_case_ascii.capa")

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

    def test_option_unwrap_expect(self):
        # Slice (2026-06-26): Option<T> / Result<T, E> unwrap() +
        # expect(msg) on the value-bearing variant (Some / Ok), across
        # Int and String payloads. The success path extracts the
        # offset-8 payload exactly like unwrap_or's value arm, so the
        # two backends print byte-identical results; the None / Err
        # panic paths abort and are covered in tests/test_panic.py.
        self._assert_parity("option_unwrap_expect.capa")

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

    def test_allows_dynamic_prefix_parity(self):
        # GAP-2b (2026-06-21): dynamic-prefix attenuation parity on
        # the guest-side ``.allows()`` query for EVERY restriction-
        # bearing cap. Pre-route the inline query could not handle a
        # non-literal attenuation prefix: Fs / Db / Net / Proc crashed
        # emit (WasmEmissionError from ``_unquote_attenuation_arg``)
        # and Env diverged SILENTLY (the lexical key-list rebuild
        # returned [] for a dynamic restrict_to_keys list, so the
        # query said "no" where Python said "yes"). The query now
        # routes through the authoritative ``$<Cap>_allows`` host
        # function, so every cap is byte-identical with Python AND the
        # query answer equals the enforcement (the program includes a
        # ``..`` traversal-escape case where the old guest-side lexical
        # check could drift from the host's realpath containment).
        self._assert_parity("allows_dynamic_prefix_parity.capa")

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

    def test_allows_traversal_parity(self):
        # Audit 2026-06-17: the guest-side .allows() QUERY (not the
        # host-side enforcement, which was already safe) drifted from
        # the Python runtime on two purely-lexical shapes:
        #   - Proc: ``restrict_to("git")`` is a BARE-NAME restriction;
        #     the pre-fix Wasm collapse stripped a path cmd to its
        #     basename and admitted ``/attacker/git``. Python denies a
        #     path cmd against a bare-name restriction (identity rule);
        #     both the literal collapse and the ``$proc_allows`` helper
        #     now mirror it via the ``$str_has_slash`` guard.
        #   - Db: ``db.allows("prefix/../escaped.db")`` walks out of
        #     the prefix; the pre-fix lexical startswith admitted it.
        #     Both backends now normalise ``..`` away (lexically, at
        #     emit time for literals) before the boundary check.
        self._assert_parity("allows_traversal_parity.capa")

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

    def test_string_interp_nested(self):
        # fix/interp-nested-strings (2026-06-25): a string literal
        # inside a ``${...}`` interpolation (``"a is ${m.get("a")...}"``)
        # used to make the lexer terminate the OUTER string at the
        # nested ``"`` ("unterminated interpolation"). The lexer and
        # the parser's matching-``}`` scan now both step over nested
        # strings. The example pins the headline idiom, a ``}`` living
        # inside a nested string, recursive nesting, and every
        # preserved interpolation behaviour (plain / arithmetic /
        # chained method / ``$$`` escape / raw string / literal ``}`` /
        # empty string), all byte-identical across backends.
        self._assert_parity("string_interp_nested.capa")

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

    def test_range_transform_methods(self):
        # Range transform + indexed queries (2026-06-24): map / filter /
        # fold / first / last / get / find / find_index on a Range. These
        # were previously absent ("type 'Range' has no method 'filter'"),
        # contradicting the teaching material's "a range is just a List"
        # promise. Both backends desugar ``range.m(...)`` to
        # ``range.to_list().m(...)``, so ``range.map(f)`` is byte-
        # identical to ``range.to_list().map(f)``. Covers the exact book
        # example ``(0..10).filter(x % 2 == 0)``, map / fold, empty range
        # (5..5), inclusive (a..=b), variable bounds, indexed queries,
        # and a filter -> map chain.
        self._assert_parity("range_transform_methods.capa")

    def test_list_reverse_enumerate_zip_flatmap(self):
        # stdlib List methods (2026-06-26): reverse / enumerate / zip /
        # flat_map, each returning a fresh list (no mutation of the
        # receiver) with a specified iteration order. reverse copies
        # element slots verbatim; enumerate / zip build per-element
        # (Int, T) / (T, U) tuple records; flat_map concatenates the
        # per-element result lists in order via the HOF closure path.
        # Covers empty lists, non-mutation, 0-based indices, zip
        # truncation from either side, and Int / String / struct
        # (pointer-shaped) element types.
        self._assert_parity("list_reverse_enumerate_zip_flatmap.capa")

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

    def test_string_order_cmp(self):
        # Bug #2: String < > <= >= lower through $str_cmp on the Wasm
        # backend (byte-by-byte UTF-8 == Python code-point order),
        # previously rejected at emit. Covers a sorted_by comparator
        # and Unicode.
        self._assert_parity("string_order_cmp.capa")

    def test_match_unit_payload(self):
        # Bug #3: a named binder over a Unit payload (Ok(s) on
        # Result<Unit, _>) is treated as a wildcard rather than
        # emitting local.set for an undeclared local; the
        # ``let _ = unit_returning_fn()`` call-site bind is also fixed.
        self._assert_parity("match_unit_payload.capa")

    def test_string_concat_loop(self):
        # perf/wasm-concat-inplace: String ``+`` lowers to the
        # ``$str_concat`` helper that grows the left operand's buffer
        # in place when it is the last bump allocation. This pins
        # byte-identical output for the loop accumulator (the O(n)
        # win) AND the grow-only aliasing contract -- snapshot before
        # a grow, substring view across a grow, ``out = out + out``
        # auto-concat, an allocating RHS forcing the fallback, and
        # chained concats. Any corruption from the in-place write
        # surfaces here as a Python/Wasm divergence.
        self._assert_parity("string_concat_loop.capa")

    def test_json_serialize_builder(self):
        # perf/wasm-json-builder: ``to_json`` on an array / object is
        # now O(n) on the Wasm backend via a two-phase builder
        # (collect pieces into a List<String> in phase 1, fold them
        # with ``out = out + piece`` over an allocation-free
        # ``for piece in parts`` loop in phase 2 so ``out`` keeps
        # growing in place). This pins byte-identical output for a
        # large array of objects (the headline linear case that
        # pre-builder ran quadratically and trapped at the 256-page
        # memory cap) plus the empty array / empty object, an array
        # of mixed scalars, strings with escapes and an astral code
        # point, a nested object, and a deeply nested array. The
        # builder only reorders WHEN concatenation happens, never
        # WHAT, so the text matches the pre-builder revision and
        # json.dumps. The dedicated linearity / large-input cap
        # cases live in TestJsonSerializeBuilderLinearity below.
        self._assert_parity("json_serialize_builder.capa")

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
    "allows_inline.capa",  # Fs.allows / Env.allows / Clock.allows
    # GAP-2b (2026-06-21): dynamic-prefix ``.allows()`` host-route on
    # the Component Model path (Fs / Net / Db / Proc / Env), incl. the
    # Env silent-divergence case and the realpath/traversal query.
    "allows_dynamic_prefix_parity.capa",
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
    point count) identical. A real terminal cannot encode a lone
    surrogate (``UnicodeEncodeError`` at the stdout codec), but the
    parity harness captures stdout into an ``io.StringIO``, which
    keeps the surrogate untouched -- exactly the mode in which the
    printed-output divergence shows. See
    ``test_print_lone_surrogate_parity`` below: the Python backend
    hands ``'\ud800'`` to the writer while the pre-fix Wasm host
    (``decode("utf-8", errors="replace")``) handed three U+FFFD.
    Both backends now decode with ``surrogatepass`` so the printed
    bytes match.

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

    def test_print_lone_surrogate_parity(self):
        # Regression for the stdio decode divergence: printing a
        # String holding a lone surrogate (from a JSON \uXXXX escape)
        # must produce byte-identical output on both backends.
        #
        # The bytes stored are byte-identical already (WTF-8: ED A0 80
        # for U+D800); the divergence was purely in the Wasm host's
        # stdio bridge, which decoded the outgoing String with
        # ``errors="replace"`` and turned the three surrogate bytes
        # into three U+FFFD BEFORE the writer saw them, while the
        # Python backend handed the writer the surrogate intact
        # (``'\ud800'``). The fix aligns both on
        # ``errors="surrogatepass"``.
        #
        # This assertion FAILS against the old ``errors="replace"``
        # host (Python ``'\ud800'`` vs Wasm three ``U+FFFD``) and
        # passes after. The ``io.StringIO`` capture in the harness
        # preserves lone surrogates, so the divergence is observable
        # here where a real cp1252 / strict-utf-8 terminal would mask
        # it by collapsing both backends to replacement characters.
        #
        # Variants: high isolated (D800, DBFF), low isolated (DC00,
        # DFFF), two surrogates in one string, a surrogate mixed with
        # plain text, and a lone surrogate immediately followed by a
        # VALID astral pair (the emoji must still decode to its single
        # astral code point, unaffected by the surrogatepass change).
        for esc, label in (
            (r"\\uD800", "high D800"),
            (r"\\uDBFF", "high DBFF"),
            (r"\\uDC00", "low DC00"),
            (r"\\uDFFF", "low DFFF"),
            (r"\\uDC00\\uDFFF", "two lows"),
            (r"a\\uD800b", "mixed with text"),
            (r"\\uD800\\ud83d\\ude00", "surrogate then astral pair"),
        ):
            with self.subTest(case=label):
                src = self._string_value_probe(
                    f'"\\"{esc}\\""',
                    "${v} ${to_json(jv)}",
                )
                self._assert_src_parity(src)

    def test_print_plain_string_unaffected(self):
        # The surrogatepass change must not perturb ordinary strings:
        # an ASCII / BMP / astral mix stays byte-identical and prints
        # the same exact characters on both backends.
        src = self._string_value_probe(
            r'"\"abc \\u00e9 \\u4e2d \\ud83d\\ude00\""',
            "${v} ${to_json(jv)}",
        )
        self._assert_src_parity(
            src,
            expect='abc é 中 \U0001f600 '
            '"abc é 中 \U0001f600"\n',
        )

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
        # round-trips. Exponent forms are now included: the Wasm
        # parse_float gained scientific notation and a correctly-rounded
        # bignum conversion, so JSON numbers with exponents round-trip
        # bit-identically across backends.
        for doc, out in (
            ('"0"', "0"),
            ('"10"', "10"),
            ('"-7"', "-7"),
            ('"1.25"', "1.25"),
            ('"-0.5"', "-0.5"),
            ('"[0.0, 12.75]"', "[0, 12.75]"),
            ('"2.5e2"', "250"),
            ('"1.5e-10"', "1.5e-10"),
            ('"6.022e23"', "6.022e+23"),
            ('"1e308"', "1e+308"),
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
    """Closed gap (was a known limitation): a lambda inside an impl
    method that captures ``self`` and reads one of its fields used to
    fail loud on Wasm with "FieldAccess on receiver of type 'Unknown':
    no struct layout known" while the Python backend ran it correctly.

    The lambda body lifts to a top-level Wasm function; the lifted
    function's ``self`` capture carried no concrete type on the
    FieldAccess receiver Value (it stays ``Unknown``) and was absent
    from the synthesised function's ``locals`` (it is a capture, not a
    body-local). The lift's env layout did resolve ``self``'s concrete
    impl type, so the field-access emitter now consults it. These
    assert byte-identical Python/Wasm output; the example fixture
    ``self_in_impl_lambda.capa`` (in ``_PARITY_PROGRAMS``) covers the
    same shapes end-to-end."""

    def _assert_parity(self, src: str, expect: str) -> None:
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"Python/Wasm divergence.\n"
                f"--- python ---\n{py_out}\n--- wasm ---\n{wasm_out}"
            ),
        )
        self.assertEqual(py_out, expect)

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
        self._assert_parity(src, "n=5\n")

    def test_self_multiple_fields_in_lambda(self):
        # One lambda reading two distinct fields of self.
        src = (
            "type Box { n: Int, label: String }\n"
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let f = fun () -> String =>\n"
            '            return "${self.label}=${self.n}"\n'
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let b = Box { n: 5, label: "count" }\n'
            "    stdio.println(b.describe())\n"
        )
        self._assert_parity(src, "count=5\n")

    def test_self_and_local_captured_in_lambda(self):
        # The lambda closes over self AND an enclosing let-local.
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let bump = 10\n"
            "        let f = fun () -> String =>\n"
            '            return "n=${self.n + bump}"\n'
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 5 }\n"
            "    stdio.println(b.describe())\n"
        )
        self._assert_parity(src, "n=15\n")

    def test_self_field_in_nested_lambda(self):
        # The inner lambda reads self.n through two lift levels.
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun describe(self) -> String\n"
            "        let outer = fun () -> String =>\n"
            "            let inner = fun () -> String =>\n"
            '                return "n=${self.n}"\n'
            "            return inner()\n"
            "        return outer()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 7 }\n"
            "    stdio.println(b.describe())\n"
        )
        self._assert_parity(src, "n=7\n")

    def test_self_int_field_in_lambda(self):
        # A non-String (Int) field returned straight out of the lambda.
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun next(self) -> Int\n"
            "        let f = fun () -> Int =>\n"
            "            return self.n + 1\n"
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 41 }\n"
            '    stdio.println("${b.next()}")\n'
        )
        self._assert_parity(src, "42\n")

    def test_self_field_mutated_in_lambda(self):
        # The lambda WRITES a field of the captured ``self`` (``self.n
        # = self.n + 100``), exercising the symmetric _emit_field_store
        # capture fallback (the read tests above only cover
        # _emit_field_access). The in-place write must be visible to
        # the subsequent read, on both backends, byte-identically.
        src = (
            "type Box { n: Int }\n"
            "\n"
            "impl Box\n"
            "    fun bump(self) -> Int\n"
            "        let f = fun () -> Int =>\n"
            "            self.n = self.n + 100\n"
            "            return self.n\n"
            "        return f()\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { n: 5 }\n"
            '    stdio.println("${b.bump()}")\n'
        )
        self._assert_parity(src, "105\n")


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


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestParseFloatBitParity(unittest.TestCase):
    r"""Cross-backend BIT parity for ``parse_float`` and exponent-form
    JSON numbers (2026-06-15, closing the float-PARSE slice deferred by
    TestJsonStrictNumbersDepthAndSignParity).

    Before this change the Wasm ``$parse_float`` was a hand-rolled
    ``val*10+digit`` accumulator that (a) rejected scientific notation
    and (b) produced an f64 with a DIFFERENT precision from CPython's
    ``float()`` (a value miscompile). It is now a correctly-rounded
    decimal-string -> f64 parser: a Clinger fast path (one exact f64
    op) with a limb-bignum slow path for the hard-rounding cases, a
    transliteration of ``tools/float_ref.py::strtod`` (validated
    bit-for-bit against ``float()`` on millions of cases).

    The probe parses a string and prints the resulting Float. Two f64
    values with the same ``repr`` are bit-identical except for the
    +0.0 / -0.0 pair, which the probe disambiguates by also printing
    ``f * 2.0`` (still signed-zero) and the sign via ``f < 0.0`` is
    not reliable for zero, so signed zero is pinned separately below.
    Any 1-ULP divergence shows up as a different ``repr`` on the two
    backends.
    """

    def _probe(self, value_literal: str) -> str:
        return (
            "fun main(stdio: Stdio)\n"
            f"    match parse_float({value_literal})\n"
            '        Some(f) -> stdio.println("${f}")\n'
            '        None -> stdio.println("NONE")\n'
        )

    def _assert_parity(self, value_literal: str) -> None:
        src = self._probe(value_literal)
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(
            py_out, wasm_out,
            msg=(
                f"parse_float divergence for {value_literal}.\n"
                f"--- python ---\n{py_out}\n--- wasm ---\n{wasm_out}"
            ),
        )

    def test_representative_values_bit_identical(self):
        for v in (
            "123456789.987654321", "1.5e-10", "2.5e2", "0.1", "0.3",
            "3.14159", "-0.5", "42", ".5", "12.", "007.5", "1E3",
            "2.5E-3", "100.5", "0.0001", "6.022e23", "-7.5e-300",
            "1.18e-38", "1e308", "1e-308", "5e-324", "4.9e-324",
            "1.7976931348623157e308", "9007199254740993",
            "2.2250738585072014e-308", "2.2250738585072011e-308",
            "1234567890123456789", "99999999999999999999e-5",
        ):
            self._assert_parity(f'"{v}"')

    def test_grammar_rejections_both_none(self):
        # inf / nan / underscores / overflow -> NONE on both backends.
        for v in ("inf", "nan", "infinity", "Infinity", "NaN",
                  "1_000", "1.2.3", "1e", "1e+", "--1", "abc",
                  "1e400", "1e309"):
            self._assert_parity(f'"{v}"')

    def test_signed_zero_and_underflow(self):
        for v in ("0", "-0", "0.0", "-0.0", "1e-400", "-1e-400"):
            self._assert_parity(f'"{v}"')

    def test_whitespace_trim(self):
        # The six ASCII whitespace bytes are trimmed on both backends;
        # Unicode whitespace stays rejected (byte scanner cannot see it).
        for v in (r'"  3.5  "', r'"\t-2.5\n"'):
            self._assert_parity(v)

    def test_random_corpus_bit_identical(self):
        # A few thousand random number spellings (e-form + decimal +
        # f64-bit-roundtrip) batched into single programs per backend,
        # asserting byte-identical line-by-line output. Any 1-ULP
        # precision divergence fails here.
        import random
        import struct

        rng = random.Random(0xF10A7)

        def gen() -> str:
            k = rng.random()
            if k < 0.4:
                nd = rng.randint(1, 19)
                s = "".join(rng.choice("0123456789") for _ in range(nd))
                return s + "e" + str(rng.randint(-330, 330))
            if k < 0.7:
                a = "".join(rng.choice("0123456789")
                            for _ in range(rng.randint(1, 10)))
                b = "".join(rng.choice("0123456789")
                            for _ in range(rng.randint(0, 10)))
                return a + "." + b
            bits = rng.getrandbits(64) & 0x7FFFFFFFFFFFFFFF
            if (bits >> 52) == 0x7FF:
                bits &= ~(0x7FF << 52)
            return repr(struct.unpack("<d", struct.pack("<Q", bits))[0])

        total = 0
        for _ in range(8):
            vals = [gen() for _ in range(200)]
            vals = [v for v in vals if '"' not in v and "\\" not in v]
            lines = ["fun main(stdio: Stdio)"]
            for v in vals:
                lines.append(f'    match parse_float("{v}")')
                lines.append('        Some(f) -> stdio.println("${f}")')
                lines.append('        None -> stdio.println("NONE")')
            src = "\n".join(lines) + "\n"
            py_out = _capture_stdout(lambda: _run_python(src))
            wasm_out = _capture_stdout(lambda: _run_wasm(src))
            self.assertEqual(
                py_out, wasm_out,
                msg="parse_float random-corpus divergence",
            )
            total += len(vals)
        self.assertGreater(total, 1000)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestStringConcatInPlaceGrow(unittest.TestCase):
    """Adversarial aliasing + performance coverage for the
    ``$str_concat`` in-place-grow optimisation (perf/wasm-concat-
    inplace, 2026-06-22).

    The optimisation grows the left operand's buffer in place when it
    is the last bump allocation, so a snapshot / view of the old
    value, an auto-concat, or an allocating RHS could each in
    principle observe corruption if the grow-only contract were
    wrong. Every test below asserts byte-identical Python/Wasm output
    so any corruption surfaces as a divergence. The final test pins
    the headline win: a ~2 MB string built by ``out = out + chunk``
    in a loop -- which trapped (out-of-bounds / OOM) under the old
    O(n^2) allocate-and-copy-both emit -- now completes."""

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

    def test_snapshot_before_inplace_concat(self):
        # (i) A snapshot taken before the growing concat must keep the
        # OLD value. ``out`` is the last allocation so the next concat
        # grows it in place; ``s`` (a separate (ptr, len) bound to the
        # pre-grow length) must NOT see the appended bytes.
        src = (
            "fun build() -> String\n"
            '    var out = "abc"\n'
            "    out = out + \"d\"\n"  # make out a heap allocation (last)
            "    let s = out\n"
            "    out = out + \"EF\"\n"  # grows out in place
            '    return "s=${s} out=${out}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(build())\n"
        )
        self._assert_src_parity(src, expect="s=abcd out=abcdEF\n")

    def test_substring_view_before_concat(self):
        # (ii) A substring view of ``out`` captured before a growing
        # concat must remain correct after the concat appends bytes.
        src = (
            "fun build() -> String\n"
            '    var out = "hello"\n'
            '    out = out + " world"\n'
            "    let view = out.substring(0, 5)\n"
            '    out = out + "!!!"\n'
            '    return "view=${view} out=${out}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(build())\n"
        )
        self._assert_src_parity(
            src, expect="view=hello out=hello world!!!\n",
        )

    def test_literal_initial_first_concat_does_not_optimize(self):
        # (iii) ``out = "lit"; out = out + x``: the first concat reads
        # ``out`` from the data segment (a literal, not a heap
        # allocation), so the in-place guard fails and it falls back to
        # alloc+copy; the SECOND concat then grows the heap buffer.
        src = (
            "fun build(x: String) -> String\n"
            '    var out = "lit"\n'
            "    out = out + x\n"
            '    out = out + "Z"\n'
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println(build("MID"))\n'
        )
        self._assert_src_parity(src, expect="litMIDZ\n")

    def test_rhs_allocation_forces_fallback(self):
        # (iv) ``let mid = a + b`` makes ``a`` no longer the last
        # allocation, so ``let r = a + c`` must take the fallback path
        # and copy ``a`` fresh -- not grow ``a`` in place over ``mid``.
        src = (
            "fun build() -> String\n"
            '    let a = "AA"\n'
            '    let mid = a + "BB"\n'
            '    let r = a + "CC"\n'
            '    return "mid=${mid} r=${r} a=${a}"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(build())\n"
        )
        self._assert_src_parity(src, expect="mid=AABB r=AACC a=AA\n")

    def test_auto_concat_rhs_aliases_lhs(self):
        # (v) ``out = out + out``: the RHS is the LHS buffer itself.
        # The disjointness guard (b ends exactly at the write cursor)
        # keeps source and destination non-overlapping, so the result
        # is the correctly doubled string.
        src = (
            "fun build() -> String\n"
            '    var out = "xy"\n'
            '    out = out + "z"\n'  # make out a heap allocation (last)
            "    out = out + out\n"  # auto-concat
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(build())\n"
        )
        self._assert_src_parity(src, expect="xyzxyz\n")

    def test_chained_concats_and_interpolation(self):
        # (vi) Chained concats in one expression and an interpolation
        # (which lowers through FormatStr, a single-buffer fill) must
        # both agree with Python.
        src = (
            "fun build(n: Int) -> String\n"
            '    let chain = "1" + "2" + "3" + "4"\n'
            '    let interp = "n=${n} chain=${chain}"\n'
            '    return interp + "!"\n'
            "\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(build(7))\n"
        )
        self._assert_src_parity(src, expect="n=7 chain=1234!\n")

    def test_loop_accumulator_parity(self):
        # Loop accumulator (``out = out + chunk``) byte-identical
        # across backends at a size large enough to cross several
        # 64 KiB pages (so the in-place page-grow path is exercised).
        src = (
            "fun build(n: Int) -> String\n"
            '    var out = ""\n'
            "    var i = 0\n"
            "    while i < n\n"
            '        out = out + "0123456789"\n'
            "        i = i + 1\n"
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let s = build(10000)\n"
            '    stdio.println("len=${s.length()}")\n'
            '    stdio.println(s.substring(0, 10))\n'
            '    stdio.println(s.substring(99990, 100000))\n'
        )
        self._assert_src_parity(
            src, expect="len=100000\n0123456789\n0123456789\n",
        )

    def test_two_megabyte_string_no_trap(self):
        # Headline: a ~2 MB string built by loop concat. Under the old
        # O(n^2) emit (allocate len(a)+len(b) and copy BOTH operands
        # every iteration) the bump allocator's never-freed garbage
        # crossed the default 16 MiB memory cap and trapped well
        # before completing. With in-place grow the live footprint is
        # ~2 MB and the run finishes; we assert the produced length.
        src = (
            "fun build(n: Int) -> String\n"
            '    var out = ""\n'
            "    var i = 0\n"
            "    while i < n\n"
            '        out = out + "01234567890123456789"\n'
            "        i = i + 1\n"
            "    return out\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let s = build(100000)\n"  # 100000 * 20 = 2,000,000 bytes
            '    stdio.println("len=${s.length()}")\n'
        )
        # Wasm must complete without trapping AND match Python.
        self._assert_src_parity(src, expect="len=2000000\n")


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestJsonSerializeBuilderLinearity(unittest.TestCase):
    """Linearity + large-input coverage for the two-phase JSON
    serialiser (perf/wasm-json-builder, 2026-06-22).

    ``__cj_array_to_string`` / ``__cj_object_to_string`` used to
    accumulate with ``out = out + __capa_to_json(child)``, where the
    recursive call ALLOCATES the child string immediately before the
    concat. That left ``out`` no longer the last bump allocation, so
    the v1.8.0 grow-in-place ``$str_concat`` fast path could not fire
    and every element copied the whole accumulated prefix again --
    O(n^2) time and O(n^2) never-freed bump garbage that trapped at
    the 256-page memory cap for a large array.

    The serialiser now collects every output piece into a
    ``List<String>`` first (phase 1, where all child allocation
    happens) and folds the pieces with ``out = out + piece`` over a
    ``for piece in parts`` loop (phase 2). On the Wasm backend that
    loop binds each element as an allocation-free (ptr, len) view, so
    ``out`` stays the last allocation and each piece appends in O(1)
    amortised. These tests pin that a large runtime-built array now
    serialises with byte-identical Python/Wasm output, including a
    size that traps at the DEFAULT memory cap but completes once the
    cap is raised (so the win is the per-call linearity, not a bigger
    ceiling)."""

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

    @staticmethod
    def _run_wasm_with_cap(src: str, cap_pages: int) -> None:
        """Compile + run under ``WasmHost`` with an explicit memory
        cap (pages). Lets a large-array test prove the work completes
        when the bump heap has headroom even though the same input
        traps at the 256-page default."""
        from capa.runtime._wasm_host import WasmHost
        module, result = _parse_and_analyze(src)
        blob = compile_wasm(
            module, types=result.types, memory_cap_pages=cap_pages,
        )
        host = WasmHost()
        host.run_main(blob)

    @staticmethod
    def _array_of_objects_src(n: int) -> str:
        """A main() that builds a JSON array of ``n`` objects
        ``{"id": i, "sq": i*i}`` and prints the serialisation's length
        plus its head and tail (so a truncated / reordered result
        cannot pass)."""
        return (
            "fun main(stdio: Stdio)\n"
            "    var xs: List<JsonValue> = []\n"
            "    var i = 0\n"
            f"    while i < {n}\n"
            "        var o: Map<String, JsonValue> = new_map()\n"
            "        let fi = to_float(i)\n"
            '        o.set("id", JNum(fi))\n'
            '        o.set("sq", JNum(fi * fi))\n'
            "        xs.push(JObj(o))\n"
            "        i = i + 1\n"
            "    let s = to_json(JArr(xs))\n"
            "    let n = s.length()\n"
            '    stdio.println("len=${n}")\n'
            '    stdio.println(s.substring(0, 20))\n'
            "    stdio.println(s.substring(n - 4, n))\n"
        )

    def test_large_array_of_objects_parity_default_cap(self):
        # 4000 objects serialise (well under the default cap) with
        # byte-identical output. Pre-builder this both ran
        # quadratically and exhausted the bump heap.
        src = self._array_of_objects_src(4000)
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(py_out, wasm_out)
        # Head / tail pin the exact text; the leading "[" and the
        # closing "}]" bracket the builder's phase-2 fold.
        self.assertIn('[{"id": 0, "sq": 0}', py_out)
        self.assertTrue(py_out.rstrip().endswith("}]"))

    def test_large_array_traps_at_default_cap_completes_when_raised(self):
        # The headline cap case: a 60000-object array. The never-freed
        # bump garbage from building 60000 JsonValue records crosses
        # the 256-page (16 MiB) default cap and traps. The SAME module
        # with a raised cap completes -- proving the serialiser's
        # phase-2 fold is itself bounded (each append grows ``out`` in
        # place; the trap is the upstream record-building volume, not a
        # quadratic blow-up in the fold). Pre-builder the quadratic
        # fold trapped at a far smaller N regardless of the cap.
        src = self._array_of_objects_src(60000)
        from wasmtime import Trap
        with self.assertRaises(Trap):
            _capture_stdout(lambda: _run_wasm(src))
        # Raised to 8192 pages (512 MiB) the run completes; pin the
        # length against the Python reference for byte parity.
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(
            lambda: self._run_wasm_with_cap(src, 8192)
        )
        self.assertEqual(py_out, wasm_out)

    def test_array_quadruples_without_quadratic_blowup(self):
        # Two sizes N and 4N (both under a raised cap) must agree with
        # Python. The brief's linearity claim is timed out-of-band in
        # the slice report; here the functional guard is that a 4x
        # larger array still produces byte-identical output and does
        # not trap -- a quadratic fold would have exhausted even the
        # raised cap at 4N (an O(n^2) copy of a 4x-longer prefix per
        # element is 16x the bytes).
        for n in (8000, 32000):
            src = self._array_of_objects_src(n)
            py_out = _capture_stdout(lambda: _run_python(src))
            wasm_out = _capture_stdout(
                lambda: self._run_wasm_with_cap(src, 8192)
            )
            self.assertEqual(
                py_out, wasm_out,
                msg=f"divergence at N={n}",
            )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestJsonParseSpanLinearity(unittest.TestCase):
    """Linearity + parity + memory-safety for the O(1) value / key
    extraction in the bundled JSON parser (perf/wasm-json-span,
    2026-06-22).

    ``__cj_parse_string`` / ``__cj_finish_number`` / object keys used
    to extract values with ``s.substring(a, b)``. On the Wasm backend
    ``substring`` re-walks the input from byte 0 to map code point
    ``a`` to a byte offset, so the k-th extraction cost O(its position
    in the document) and N values summed to O(N^2) (Python's
    ``json.loads`` is linear, so a big document was a silent parity-of-
    behaviour gap and a DoS surface). The internal ``_capa_str_span``
    builtin now forms each value as an O(1) (ptr, len) view spanning
    the code points' already-materialised bytes inside the input
    buffer -- the same slice, byte-identical, no walk and no copy.

    These tests pin: byte-identical Python/Wasm output on large
    arrays (the pure span signal, no Map involved), on a document
    whose keys / values sit AFTER multibyte prefixes (so a wrong span
    would point at the wrong bytes), and on the escape / empty-string
    paths (the ``a == b`` empty-span guard and the chunked decode);
    plus a LONGEVITY check that a string value extracted as a view
    stays correct after the parser allocates a great deal more. The
    view aliases the input buffer, so its bytes must never be the
    bump heap's last allocation that ``$str_concat`` grows in place;
    the parser never concatenates onto the input, so the view is
    stable for the program's lifetime (bump heap, no free, immutable
    strings)."""

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

    @staticmethod
    def _run_wasm_with_cap(src: str, cap_pages: int) -> None:
        from capa.runtime._wasm_host import WasmHost
        module, result = _parse_and_analyze(src)
        blob = compile_wasm(
            module, types=result.types, memory_cap_pages=cap_pages,
        )
        host = WasmHost()
        host.run_main(blob)

    def test_multibyte_prefix_extraction_points_at_right_bytes(self):
        # The decisive span test: every key and value in this object
        # sits AFTER multibyte (2- / 3- / 4-byte) code points earlier
        # in the document. ``substring`` re-walked from byte 0 so it
        # was immune to the prefix; the span uses chars[a].ptr
        # directly, so a one-byte error in the offset would corrupt
        # the slice. Byte-identical Python/Wasm output proves the view
        # lands on the exact bytes the old substring copied.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "{\\"caf\\u{e9}\\": \\"r\\u{e9}sum\\u{e9}\\", '
            '\\"\\u{1f600}key\\": 42, \\"after\\": [1, 2, 3], '
            '\\"\\u{4e2d}\\u{6587}\\": \\"\\u{2728}done\\"}"\n'
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err ${m}")\n'
        )
        self._assert_src_parity(src)

    def test_number_extraction_after_multibyte_prefix(self):
        # Numbers (int / fraction / scientific / -0.0) extracted after
        # a multibyte string element. __cj_finish_number now spans the
        # number token; a wrong offset would feed parse_float garbage.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "[\\"\\u{1f680}\\u{1f6f0}\\", 12345, -7, '
            '1.25, -0.5, 6.022e23, 1e308, -0.0]"\n'
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err ${m}")\n'
        )
        self._assert_src_parity(src)

    def test_empty_string_span_guard(self):
        # ``a == b`` must yield the empty string WITHOUT reading
        # chars[b-1] (which underflows at a==b==0). Several empty
        # string values, including the leading one at code point 1.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "[\\"\\", \\"x\\", \\"\\", \\"\\u{e9}\\", \\"\\"]"\n'
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err ${m}")\n'
        )
        self._assert_src_parity(src, expect='Ok ["", "x", "", "é", ""]\n')

    def test_escape_chunks_are_spans(self):
        # The escape path folds between-escape runs; each run is now a
        # span chunk (not a substring). Tab / newline / quote /
        # backslash / \\uXXXX (BMP) / surrogate-pair (astral) all
        # round-trip byte-identically, with multibyte text between the
        # escapes so a wrong chunk offset would surface.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let doc = "\\"caf\\u{e9} \\\\u00e9 \\\\ud83d\\\\ude00 '
            'a\\\\tb\\\\nc \\u{4e2d} \\\\\\\\ end\\""\n'
            "    match parse_json(doc)\n"
            '        Ok(jv) -> stdio.println("Ok ${to_json(jv)}")\n'
            '        Err(m) -> stdio.println("Err ${m}")\n'
        )
        self._assert_src_parity(src)

    def test_view_longevity_after_more_allocations(self):
        # MEMORY SAFETY: a string value extracted as a view into the
        # input buffer must stay correct after the parser allocates a
        # great deal more. Parse a document, keep its first string
        # value, then parse a SECOND large document (thousands of
        # allocations) and build a long concatenated string (which
        # exercises $str_concat's grow-in-place), then read the kept
        # value again. If the view had aliased reused / grown memory
        # the second print would differ from the first; byte-identical
        # output on both backends proves the alias is stable.
        src = (
            "fun main(stdio: Stdio)\n"
            '    let kept = match parse_json("[\\"keepsafe\\", 1, 2]")\n'
            "        Ok(jv) -> to_json(jv)\n"
            '        Err(m) -> "err"\n'
            '    stdio.println(kept)\n'
            # Churn the bump heap: parse a big second document...
            '    var big = "["\n'
            "    var i = 0\n"
            "    while i < 3000\n"
            '        big = big + "1,"\n'
            "        i = i + 1\n"
            '    big = big + "0]"\n'
            "    match parse_json(big)\n"
            '        Ok(jv2) -> stdio.println("parsed2")\n'
            '        Err(m) -> stdio.println("err2")\n'
            # ...and grow a long string in place.
            '    var s = ""\n'
            "    var j = 0\n"
            "    while j < 2000\n"
            '        s = s + "xy"\n'
            "        j = j + 1\n"
            '    stdio.println("slen=${s.length()}")\n'
            # Re-read the kept value: must equal the first print.
            "    stdio.println(kept)\n"
        )
        self._assert_src_parity(src)

    @staticmethod
    def _array_of_strings_src(n: int) -> str:
        """A main() that parses a JSON array of ``n`` distinct string
        elements (embedded as a Capa string LITERAL so the document is
        a single interned allocation, not a quadratic runtime build)
        and prints the parsed array's length plus its first and last
        element (so a wrong span would corrupt the printed text). No
        Map, so the timing signal is the span extraction alone (object
        parsing is O(n^2) in the Map's linear-scan set, unrelated to
        this slice)."""
        body = "[" + ",".join('\\"item%d\\"' % i for i in range(n)) + "]"
        return (
            "fun main(stdio: Stdio)\n"
            f'    let doc = "{body}"\n'
            "    match parse_json(doc)\n"
            "        Ok(jv) -> match jv.as_array()\n"
            "            Some(xs) ->\n"
            "                let m = xs.length()\n"
            '                stdio.println("len=${m}")\n'
            "                match xs.first()\n"
            '                    Some(f) -> stdio.println("first=${to_json(f)}")\n'
            '                    None -> stdio.println("nofirst")\n'
            "                match xs.last()\n"
            '                    Some(l) -> stdio.println("last=${to_json(l)}")\n'
            '                    None -> stdio.println("nolast")\n'
            '            None -> stdio.println("notarray")\n'
            '        Err(m) -> stdio.println("err ${m}")\n'
        )

    def test_large_array_of_strings_parity(self):
        # 8000 string elements parse with byte-identical Python/Wasm
        # output, well under the default cap. Pre-span the k-th
        # substring re-walked O(k) bytes so this ran quadratically;
        # the span makes each extraction O(1). The first / last element
        # pin the exact decoded text.
        src = self._array_of_strings_src(8000)
        py_out = _capture_stdout(lambda: _run_python(src))
        wasm_out = _capture_stdout(lambda: _run_wasm(src))
        self.assertEqual(py_out, wasm_out)
        self.assertIn("len=8000", py_out)
        self.assertIn('first="item0"', py_out)
        self.assertIn('last="item7999"', py_out)

    def test_array_quadruples_without_quadratic_blowup(self):
        # N and 4N both agree with Python and complete under a raised
        # cap. Pre-span the 4x-longer document re-walked a 4x-longer
        # buffer on every one of 4x-more extractions -- 16x the byte
        # traffic, the quadratic signature. Byte-identical output at
        # both sizes is the functional guard for the linearity claim
        # timed out-of-band in the slice report.
        for n in (5000, 20000):
            src = self._array_of_strings_src(n)
            py_out = _capture_stdout(lambda: _run_python(src))
            wasm_out = _capture_stdout(
                lambda: self._run_wasm_with_cap(src, 8192)
            )
            self.assertEqual(
                py_out, wasm_out,
                msg=f"divergence at N={n}",
            )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestMapPayloadlessVariantValueParity(unittest.TestCase):
    """Regression net for the silent Wasm miscompile where a Map whose
    VALUE is a payloadless variant (``None``, a user sum's nullary
    variant like ``Empty``) and whose KEY is i32-shaped (String / Bool)
    reported a present key as absent.

    Root cause: the canonical key was stashed in the shared
    ``$_alloc_tmp``; the value pushed next constructs a heap record for
    the payloadless variant via ``call $alloc`` + ``local.tee
    $_alloc_tmp``, which clobbered the key pointer between the
    canonical-key push and the append-branch pair-key store. The pair's
    key was then written from the variant's heap pointer instead of the
    real key, so a subsequent ``get`` / ``contains_key`` never matched.
    Fixed by stashing the i32 key (String ptr / Bool value) in a
    dedicated ``$_alloc_tmp_key_i32`` local immune to the value's
    construction scratch. The Python backend was always correct (it is
    the oracle); these assert byte-identical output."""

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

    def test_string_key_none_value_found(self):
        # The headline repro: Map<String, Option<Int>> with a None
        # value. Pre-fix the Wasm backend printed "missing".
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Option<Int>> = new_map()\n"
            '    m.set("b", None)\n'
            '    match m.get("b")\n'
            '        Some(inner) -> stdio.println("found")\n'
            '        None -> stdio.println("missing")\n'
        )
        self._assert_src_parity(src, expect="found\n")

    def test_string_key_user_nullary_variant_value(self):
        # A user sum's payloadless variant value is the same hazard
        # (the variant ctor's alloc+tee clobbers the key ptr).
        src = (
            "type E =\n"
            "    Empty\n"
            "    Full(Int)\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, E> = new_map()\n"
            '    m.set("b", Empty)\n'
            '    match m.get("b")\n'
            '        Some(inner) -> stdio.println("found")\n'
            '        None -> stdio.println("missing")\n'
        )
        self._assert_src_parity(src, expect="found\n")

    def test_bool_key_none_value_found(self):
        # The same shared-scratch collision affects Bool keys: the Bool
        # key value also lived in $_alloc_tmp pre-fix.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Bool, Option<Int>> = new_map()\n"
            "    m.set(true, None)\n"
            "    match m.get(true)\n"
            '        Some(inner) -> stdio.println("found")\n'
            '        None -> stdio.println("missing")\n'
        )
        self._assert_src_parity(src, expect="found\n")

    def test_string_key_contains_none_value(self):
        # contains_key shares the canonical-key + compare path with get.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Option<Int>> = new_map()\n"
            '    m.set("b", None)\n'
            '    if m.contains_key("b")\n'
            '        stdio.println("has b")\n'
            "    else\n"
            '        stdio.println("no b")\n'
        )
        self._assert_src_parity(src, expect="has b\n")

    def test_string_key_payload_value_still_works(self):
        # Neighbour guard: a payload-bearing variant value (Some(7))
        # was always correct and must stay so.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Option<Int>> = new_map()\n"
            '    m.set("b", Some(7))\n'
            '    match m.get("b")\n'
            "        Some(inner) -> match inner\n"
            '            Some(x) -> stdio.println("found ${x}")\n'
            '            None -> stdio.println("found none")\n'
            '        None -> stdio.println("missing")\n'
        )
        self._assert_src_parity(src, expect="found 7\n")

    def test_string_key_miss_still_misses(self):
        # Neighbour guard: a genuinely absent key still reports None.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Option<Int>> = new_map()\n"
            '    m.set("b", None)\n'
            '    match m.get("z")\n'
            '        Some(inner) -> stdio.println("found")\n'
            '        None -> stdio.println("missing")\n'
        )
        self._assert_src_parity(src, expect="missing\n")

    def test_string_key_none_value_across_grow(self):
        # Many None-valued keys force the data array to grow; every key
        # must still be found afterwards (the append-branch pair-key
        # store is the corrupted path).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Option<Int>> = new_map()\n"
            "    for i in 0..20\n"
            '        m.set("k${i}", None)\n'
            '    match m.get("k0")\n'
            '        Some(inner) -> stdio.println("found k0")\n'
            '        None -> stdio.println("missing k0")\n'
            '    match m.get("k19")\n'
            '        Some(inner) -> stdio.println("found k19")\n'
            '        None -> stdio.println("missing k19")\n'
        )
        self._assert_src_parity(src, expect="found k0\nfound k19\n")



@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestSetTupleIterPointerComponentParity(unittest.TestCase):
    """Regression net for the silent Wasm miscompile where iterating a
    ``Set`` of tuples whose element has a pointer-shaped component (a
    String) decoded that component as a raw i64 scalar.

    Root cause: the IR lowerer's ``_lower_for`` resolved the loop
    variable's element type only for ``List<T>`` iterables; a ``Set<T>``
    fell through to ``Unknown``, so a tuple-destructured component
    (``let (n, t) = pair`` over ``Set<(Int, String)>``) bound the String
    ``t`` as ``Unknown``. The emitter then defaulted it to an i64 scalar
    load and printed the packed ``ptr | len << 32`` as a garbage integer
    (e.g. ``4294967307``) instead of the string. Fixed by stripping the
    Set's element type identically to the List path. The Python backend
    (the oracle) was always correct; these assert byte-identical
    output."""

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

    def test_set_int_string_let_destructure(self):
        # The headline repro: ``let (n, t) = pair`` over a single set
        # element. Pre-fix ``t`` printed a garbage integer.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<(Int, String)> = new_set()\n"
            '    s.add((1, "a"))\n'
            "    for pair in s\n"
            "        let (n, t) = pair\n"
            '        stdio.println("elem ${n},${t}")\n'
        )
        self._assert_src_parity(src, expect="elem 1,a\n")

    def test_set_int_string_for_tuple_pattern(self):
        # The ``for (n, t) in s`` form over several elements.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<(Int, String)> = new_set()\n"
            '    s.add((1, "a"))\n'
            '    s.add((2, "bb"))\n'
            "    for (n, t) in s\n"
            '        stdio.println("elem ${n},${t}")\n'
        )
        self._assert_src_parity(src, expect="elem 1,a\nelem 2,bb\n")

    def test_set_string_int_pointer_first(self):
        # The pointer component in slot 0 (String, Int) must decode too.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<(String, Int)> = new_set()\n"
            '    s.add(("a", 1))\n'
            "    for (t, n) in s\n"
            '        stdio.println("elem ${t},${n}")\n'
        )
        self._assert_src_parity(src, expect="elem a,1\n")

    def test_set_int_int_unaffected(self):
        # Neighbour guard: a scalar-only tuple element was always
        # correct (no pointer component to mis-decode).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<(Int, Int)> = new_set()\n"
            "    s.add((1, 2))\n"
            "    for (a, b) in s\n"
            '        stdio.println("elem ${a},${b}")\n'
        )
        self._assert_src_parity(src, expect="elem 1,2\n")

    def test_set_struct_with_string_field_unaffected(self):
        # Neighbour guard: a struct element with a String field was
        # always correct (the loop binds a single struct pointer; the
        # field read goes through the struct layout, not the tuple slot).
        src = (
            "type P { name: String, n: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let s: Set<P> = new_set()\n"
            '    s.add(P { name: "ann", n: 3 })\n'
            "    for p in s\n"
            '        stdio.println("p=${p.name},${p.n}")\n'
        )
        self._assert_src_parity(src, expect="p=ann,3\n")

    def test_set_string_scalar_iter_unaffected(self):
        # Neighbour guard: a bare Set<String> (element IS the String,
        # not a tuple component) iterated correctly before and after.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<String> = new_set()\n"
            '    s.add("x")\n'
            '    s.add("yy")\n'
            "    for t in s\n"
            '        stdio.println("t=${t}")\n'
        )
        self._assert_src_parity(src, expect="t=x\nt=yy\n")

    def test_set_tuple_dedup_and_grow(self):
        # Force a grow (>8 elements) and a dedup, then iterate; every
        # String component must still decode after the data array moves.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s: Set<(Int, String)> = new_set()\n"
            "    for i in 0..12\n"
            '        s.add((i, "v${i}"))\n'
            '    s.add((0, "v0"))\n'
            "    for (n, t) in s\n"
            '        stdio.println("${n}:${t}")\n'
        )
        expect = "".join(f"{i}:v{i}\n" for i in range(12))
        self._assert_src_parity(src, expect=expect)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestIntMinLiteralParity(unittest.TestCase):
    """Regression net for the Wasm trap on the ``i64::MIN`` literal
    (``-9223372036854775808``).

    Root cause: the parser emits a negative int literal as
    ``UnaryOp('-', IntLit(9223372036854775808))``. The Wasm backend
    has no ``i64.neg`` and synthesised ``-x`` as ``0 - x`` behind an
    overflow guard that traps when ``x == i64::MIN``. For the literal
    that guard fired on a *valid* value: ``9223372036854775808`` pushed
    as ``i64.const`` is already the i64::MIN bit pattern, so the guard
    saw MIN and trapped, even though the written literal is in range.
    The Python backend (the oracle) folds the same expression with
    bignums and prints it correctly. Fixed by constant-folding
    ``-<int literal>`` into a single negative ``lit_int`` in the
    lowerer, which emits ``i64.const -9223372036854775808`` directly
    and bypasses the runtime negation path.

    Crucially the fix preserves the overflow guard for *runtime*
    negation: negating a value computed at runtime that equals
    i64::MIN still overflows and traps in BOTH backends (Python
    ``OverflowError``, Wasm ``unreachable``), secure-by-default."""

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

    def test_int_min_literal_interpolated(self):
        # The headline repro: the i64::MIN literal must print, not trap.
        src = (
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${-9223372036854775808}")\n'
        )
        self._assert_src_parity(src, expect="-9223372036854775808\n")

    def test_int_min_literal_let_and_arithmetic(self):
        # Bound to a let and used in arithmetic (add / divide).
        src = (
            "fun main(stdio: Stdio)\n"
            "    let mn = -9223372036854775808\n"
            '    stdio.println("${mn + 0}")\n'
            '    stdio.println("${mn / 2}")\n'
        )
        self._assert_src_parity(
            src, expect="-9223372036854775808\n-4611686018427387904\n",
        )

    def test_int_min_literal_returned_from_fun(self):
        # Returned from a function and printed by the caller.
        src = (
            "fun f() -> Int\n"
            "    return -9223372036854775808\n"
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${f()}")\n'
        )
        self._assert_src_parity(src, expect="-9223372036854775808\n")

    def test_neighbour_literals(self):
        # i64::MAX, -i64::MAX, a normal negative, double negation, zero.
        src = (
            "fun main(stdio: Stdio)\n"
            '    stdio.println("${9223372036854775807}")\n'
            '    stdio.println("${-9223372036854775807}")\n'
            '    stdio.println("${-5}")\n'
            '    stdio.println("${-(-5)}")\n'
            '    stdio.println("${-0}")\n'
        )
        self._assert_src_parity(
            src,
            expect=(
                "9223372036854775807\n"
                "-9223372036854775807\n"
                "-5\n5\n0\n"
            ),
        )

    def test_runtime_negate_int_min_traps_in_both_backends(self):
        # The distinction the fix must preserve: i64::MIN reached as a
        # RUNTIME value (folded -i64::MAX minus 1) and then negated
        # overflows (+2^63 does not fit in i64) and MUST trap in both
        # backends. The literal fold must not have weakened the guard.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let almost = -9223372036854775807\n"
            "    let mn = almost - 1\n"
            "    let neg = -mn\n"
            '    stdio.println("${neg}")\n'
        )
        with self.assertRaises(OverflowError):
            _capture_stdout(lambda: _run_python(src))
        with self.assertRaises(Exception) as ctx:
            _capture_stdout(lambda: _run_wasm(src))
        self.assertNotIsInstance(ctx.exception, OverflowError)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestStructDestructureLetForParity(unittest.TestCase):
    """Struct destructuring in ``let`` and ``for`` bindings.

    ``let Point { x, y } = p`` and ``for P { a, b } in xs`` used to
    pass ``capa --check`` but raise ``TranspilerError: complex pattern
    in let/for not yet supported: StructPat`` at run time (and were
    rejected by the IR lowerer too). These pin the now-supported forms
    and keep the two backends bit-identical.
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
            self.assertEqual(py_out, expect)

    def test_book_idiom_let_struct_destructure(self):
        # The exact Chapter 7 teaching idiom from the bug report.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    let Point { x, y } = p\n"
            '    stdio.println("${x + y}")\n'
        )
        self._assert_src_parity(src, expect="7\n")

    def test_let_struct_multi_field_types(self):
        # Mixed field types (String / Int / Bool) bound positionally
        # by name; all three components must round-trip.
        src = (
            "type Named { label: String, value: Int, flag: Bool }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let n = Named { label: "hi", value: 10, flag: true }\n'
            "    let Named { label, value, flag } = n\n"
            '    stdio.println("${label} ${value} ${flag}")\n'
        )
        self._assert_src_parity(src, expect="hi 10 true\n")

    def test_let_struct_field_rename(self):
        # ``Named { value: v, label: l }`` binds the renamed locals and
        # tolerates fields in a different order than the declaration.
        src = (
            "type Named { label: String, value: Int, flag: Bool }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let n = Named { label: "hi", value: 10, flag: true }\n'
            "    let Named { value: v, label: l } = n\n"
            '    stdio.println("${l} ${v}")\n'
        )
        self._assert_src_parity(src, expect="hi 10\n")

    def test_let_struct_partial_fields(self):
        # Only one field listed: the others are simply not bound.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 9, y: 4 }\n"
            "    let Point { y } = p\n"
            '    stdio.println("${y}")\n'
        )
        self._assert_src_parity(src, expect="4\n")

    def test_let_struct_wildcard_subpattern(self):
        # ``Point { x: _, y }`` reads and binds nothing for x.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 9, y: 4 }\n"
            "    let Point { x: _, y } = p\n"
            '    stdio.println("${y}")\n'
        )
        self._assert_src_parity(src, expect="4\n")

    def test_let_nested_struct_in_struct(self):
        # A struct field is itself a struct; destructure both levels.
        src = (
            "type Point { x: Int, y: Int }\n"
            "type Wrap { p: Point, tag: String }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let w = Wrap { p: Point { x: 1, y: 2 }, tag: \"outer\" }\n"
            "    let Wrap { p: inner, tag } = w\n"
            "    let Point { x: ix, y: iy } = inner\n"
            '    stdio.println("${tag} ${ix} ${iy}")\n'
        )
        self._assert_src_parity(src, expect="outer 1 2\n")

    def test_for_struct_destructure_over_list(self):
        # ``for Point { x, y } in pts`` binds each element's fields per
        # iteration and accumulates.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let pts = [Point { x: 1, y: 1 }, Point { x: 2, y: 3 }, "
            "Point { x: 5, y: 8 }]\n"
            "    var total = 0\n"
            "    for Point { x, y } in pts\n"
            "        total += x + y\n"
            '    stdio.println("${total}")\n'
        )
        self._assert_src_parity(src, expect="20\n")

    def test_for_struct_destructure_mixed_field_types(self):
        # for-loop struct destructure with String / Int / Bool fields.
        src = (
            "type Named { label: String, value: Int, flag: Bool }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            '    let xs = [Named { label: "a", value: 1, flag: false }, '
            'Named { label: "b", value: 2, flag: true }]\n'
            "    for Named { label, value, flag } in xs\n"
            '        stdio.println("${label}=${value} ${flag}")\n'
        )
        self._assert_src_parity(src, expect="a=1 false\nb=2 true\n")

    def test_for_struct_destructure_wildcard_subpattern(self):
        # ``for Point { x, y: _ } in pts``: bind x, drop y.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let pts = [Point { x: 1, y: 2 }, Point { x: 3, y: 4 }]\n"
            "    for Point { x, y: _ } in pts\n"
            '        stdio.println("${x}")\n'
        )
        self._assert_src_parity(src, expect="1\n3\n")

    def test_tuple_destructure_still_works(self):
        # Non-regression: the tuple let/for path must be unchanged.
        src = (
            "fun main(stdio: Stdio)\n"
            "    let pair = (3, 4)\n"
            "    let (a, b) = pair\n"
            '    stdio.println("${a + b}")\n'
            "    let pairs = [(1, 2), (3, 4)]\n"
            "    for (x, y) in pairs\n"
            '        stdio.println("${x * y}")\n'
        )
        self._assert_src_parity(src, expect="7\n2\n12\n")

    def test_match_struct_pattern_still_works(self):
        # Non-regression: struct destructuring inside ``match`` (which
        # always worked) must be unchanged.
        src = (
            "type Point { x: Int, y: Int }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 3, y: 4 }\n"
            "    match p\n"
            '        Point { x, y } -> stdio.println("${x + y}")\n'
        )
        self._assert_src_parity(src, expect="7\n")


if __name__ == "__main__":
    unittest.main()
