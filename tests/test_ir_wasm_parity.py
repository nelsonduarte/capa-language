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
    "fizzbuzz.capa",
    "shape_area.capa",
    "strings.capa",
    "word_count.capa",
    "closures.capa",
    "json_demo.capa",
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
    "tuple_arity_n.capa",
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
]

# Programs deliberately excluded from parity and why; documented
# here so a future contributor doesn't accidentally widen the
# parity list without thinking about the divergence.
_EXCLUDED: dict[str, str] = {
    "clock_demo.capa": (
        "Clock.now_secs / now_monotonic are time-dependent; their "
        "values differ between back-to-back runs even on one backend."
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
        # ``Option<Int>`` (byte offset). D3 retired the legacy -1
        # sentinel; the Python emitter wraps ``.find()`` in a
        # ``Some/None_`` lambda, the Wasm emitter writes the
        # Option record directly.
        self._assert_parity("string_index_of.capa")

    def test_tuple_arity_n(self):
        # Slice 5 (2026-05): the 2-arity tuple cap was lifted; the
        # uniform 8-byte slot stride covers arity-3 / arity-4.
        # Co-shipped with the Index lowering type-recovery fix that
        # parses elem types out of the receiver's tuple shape when
        # the analyzer didn't carry a precise type for the slot.
        self._assert_parity("tuple_arity_n.capa")

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


if __name__ == "__main__":
    unittest.main()
