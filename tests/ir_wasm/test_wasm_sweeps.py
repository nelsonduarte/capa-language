"""WebAssembly backend: the two structural sweeps (the discarded-call
stack-balance sweep and the WAT call-closure guard).

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py; the sweep recipe tables, the emit-path
variants, the WAT-closure corpus, and _parse_and_analyze_ok are facet-
local and live here with the sweep.
"""

from __future__ import annotations

import re
import typing
import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa import Lexer, Parser, analyze
from capa.ir import emit_wat, compile_wat, compile_wasm


# ----------------------------------------------------------------------
# Discarded-call sweep: the structural guard for the "value-discarded
# call leaves values on the Wasm stack" bug class.
#
# A call whose value is discarded (``xs.length()`` as a bare statement)
# must leave the operand stack balanced: the emitter drops exactly as
# many slots as the callee pushed. The bug surfaced three separate times
# in three different emit paths (user calls, builtin methods, capability
# / set-algebra / convert builtins) because each emitter hand-rolled its
# own ``if dst is not None: local.set`` with no ``else``. Rather than
# keep patching sites, this sweep enumerates EVERY shape from the two
# authoritative tables (``capa.builtins.METHODS`` and
# ``capa.builtins.FREE_FUNCTIONS``), discards a call of that shape, and
# asserts the module still validates.
#
# ``test_discard_recipes_cover_every_builtin`` is what makes this a
# guard rather than a snapshot: a builtin added to either table without
# a recipe here FAILS, so a new emit path cannot silently skip the
# sweep.
# ----------------------------------------------------------------------

# (receiver_type, method) -> (capability params, setup lines, discarded
# expression). ``__JSON__`` setup means "wrap the body in a
# parse_json match arm so ``j`` is a JsonValue".
_DISCARD_RECIPES: dict[tuple[str, str], tuple[list, list, str]] = {}


def _recipe(ty, method, caps, setup, expr):
    _DISCARD_RECIPES[(ty, method)] = (caps, setup, expr)


_S_STR = ['let s = "hello"']
_S_LIST = ["var xs = [1, 2, 3]"]
_S_RANGE = ["let r = 0..5"]
_S_MAP = ["var m = new_map()", 'm.set("k", 1)']
_S_SET = ["var st = new_set()", "st.add(1)",
          "var st2 = new_set()", "st2.add(2)"]
_S_OPT = ["let o = Some(1)"]
_S_RES = ['let rs = parse_int("1").ok_or("e")']

for _m, _e in [
    ("length", "s.length()"), ("contains", 's.contains("e")'),
    ("starts_with", 's.starts_with("h")'), ("ends_with", 's.ends_with("o")'),
    ("to_upper", "s.to_upper()"), ("to_lower", "s.to_lower()"),
    ("trim", "s.trim()"), ("trim_start", "s.trim_start()"),
    ("trim_end", "s.trim_end()"), ("split", 's.split("l")'),
    ("replace", 's.replace("l", "L")'), ("is_empty", "s.is_empty()"),
    ("char_at", "s.char_at(0)"), ("substring", "s.substring(0, 2)"),
    ("index_of", 's.index_of("e")'), ("bytes", "s.bytes()"),
]:
    _recipe("String", _m, [], _S_STR, _e)

for _m, _e in [
    ("length", "xs.length()"), ("push", "xs.push(4)"),
    ("contains", "xs.contains(2)"),
    ("map", "xs.map(fun (a: Int) -> Int => a + 1)"),
    ("filter", "xs.filter(fun (a: Int) -> Bool => a > 1)"),
    ("fold", "xs.fold(0, fun (a: Int, b: Int) -> Int => a + b)"),
    ("is_empty", "xs.is_empty()"), ("first", "xs.first()"),
    ("last", "xs.last()"), ("get", "xs.get(0)"),
    ("find", "xs.find(fun (a: Int) -> Bool => a > 1)"),
    ("find_index", "xs.find_index(fun (a: Int) -> Bool => a > 1)"),
    ("sorted_by", "xs.sorted_by(fun (a: Int, b: Int) -> Int => a - b)"),
    ("reverse", "xs.reverse()"), ("enumerate", "xs.enumerate()"),
    ("zip", "xs.zip(xs)"),
    ("flat_map", "xs.flat_map(fun (a: Int) -> List<Int> => [a])"),
]:
    _recipe("List", _m, [], _S_LIST, _e)

for _m, _e in [
    ("length", "r.length()"), ("contains", "r.contains(2)"),
    ("to_list", "r.to_list()"), ("is_empty", "r.is_empty()"),
    ("map", "r.map(fun (a: Int) -> Int => a + 1)"),
    ("filter", "r.filter(fun (a: Int) -> Bool => a > 1)"),
    ("fold", "r.fold(0, fun (a: Int, b: Int) -> Int => a + b)"),
    ("first", "r.first()"), ("last", "r.last()"), ("get", "r.get(0)"),
    ("find", "r.find(fun (a: Int) -> Bool => a > 1)"),
    ("find_index", "r.find_index(fun (a: Int) -> Bool => a > 1)"),
]:
    _recipe("Range", _m, [], _S_RANGE, _e)

for _m, _e in [
    ("length", "m.length()"), ("get", 'm.get("k")'),
    ("set", 'm.set("k", 2)'), ("contains_key", 'm.contains_key("k")'),
    ("keys", "m.keys()"), ("values", "m.values()"),
    ("pairs", "m.pairs()"), ("is_empty", "m.is_empty()"),
]:
    _recipe("Map", _m, [], _S_MAP, _e)

for _m, _e in [
    ("length", "st.length()"), ("add", "st.add(2)"),
    ("remove", "st.remove(1)"), ("contains", "st.contains(1)"),
    ("to_list", "st.to_list()"), ("is_empty", "st.is_empty()"),
    ("union", "st.union(st2)"), ("intersection", "st.intersection(st2)"),
    ("difference", "st.difference(st2)"), ("is_subset", "st.is_subset(st2)"),
]:
    _recipe("Set", _m, [], _S_SET, _e)

for _m, _e in [
    ("is_some", "o.is_some()"), ("is_none", "o.is_none()"),
    ("unwrap_or", "o.unwrap_or(0)"), ("unwrap", "o.unwrap()"),
    ("expect", 'o.expect("boom")'),
    ("map", "o.map(fun (a: Int) -> Int => a + 1)"),
    ("and_then", "o.and_then(fun (a: Int) -> Option<Int> => Some(a))"),
    ("ok_or", 'o.ok_or("e")'),
    ("or_else", "o.or_else(fun () -> Option<Int> => Some(0))"),
    ("filter", "o.filter(fun (a: Int) -> Bool => a > 0)"),
]:
    _recipe("Option", _m, [], _S_OPT, _e)

for _m, _e in [
    ("is_ok", "rs.is_ok()"), ("is_err", "rs.is_err()"),
    ("unwrap_or", "rs.unwrap_or(0)"), ("unwrap", "rs.unwrap()"),
    ("expect", 'rs.expect("boom")'),
    ("map", "rs.map(fun (a: Int) -> Int => a + 1)"),
    ("and_then", "rs.and_then(fun (a: Int) -> Result<Int, String> => Ok(a))"),
    ("map_err", "rs.map_err(fun (e: String) -> String => e)"),
    ("or_else", "rs.or_else(fun (e: String) -> Result<Int, String> => Ok(0))"),
    ("ok", "rs.ok()"), ("err", "rs.err()"),
]:
    _recipe("Result", _m, [], _S_RES, _e)

for _m, _e in [
    ("print", 'stdio.print("x")'), ("println", 'stdio.println("x")'),
    ("eprintln", 'stdio.eprintln("x")'), ("read_line", "stdio.read_line()"),
]:
    _recipe("Stdio", _m, ["stdio: Stdio"], [], _e)

for _m, _e in [
    ("restrict_to", 'fs.restrict_to("a")'), ("allows", 'fs.allows("a")'),
    ("read", 'fs.read("a.txt")'), ("write", 'fs.write("a.txt", "d")'),
    ("exists", 'fs.exists("a.txt")'), ("is_dir", 'fs.is_dir("a")'),
    ("mkdir", 'fs.mkdir("a")'), ("list_dir", 'fs.list_dir("a")'),
]:
    _recipe("Fs", _m, ["fs: Fs"], [], _e)

for _m, _e in [
    ("restrict_to_keys", 'env.restrict_to_keys(["K"])'),
    ("allows", 'env.allows("K")'), ("get", 'env.get("K")'),
    ("args", "env.args()"),
]:
    _recipe("Env", _m, ["env: Env"], [], _e)

for _m, _e in [
    ("restrict_to_after", "clock.restrict_to_after(0.0)"),
    ("allows", "clock.allows()"), ("now_secs", "clock.now_secs()"),
    ("now_monotonic", "clock.now_monotonic()"),
    # ``sleep`` returns Unit: the negative that must NOT gain a drop.
    ("sleep", "clock.sleep(0.0)"),
]:
    _recipe("Clock", _m, ["clock: Clock"], [], _e)

for _m, _e in [
    ("restrict_to", 'net.restrict_to("h")'), ("allows", 'net.allows("h")'),
    ("get", 'net.get("http://h/")'), ("post", 'net.post("http://h/", "b")'),
]:
    _recipe("Net", _m, ["net: Net"], [], _e)

for _m, _e in [
    ("with_seed", "random.with_seed(1)"),
    ("int_range", "random.int_range(0, 5)"),
    ("float_unit", "random.float_unit()"),
]:
    _recipe("Random", _m, ["random: Random"], [], _e)

for _m, _e in [
    ("restrict_to", 'db.restrict_to("t")'), ("allows", 'db.allows("t")'),
    ("exec", 'db.exec("t", "SELECT 1")'),
    ("query", 'db.query("t", "SELECT 1")'),
]:
    _recipe("Db", _m, ["db: Db"], [], _e)

for _m, _e in [
    ("restrict_to", 'proc.restrict_to("p")'), ("allows", 'proc.allows("p")'),
    ("exec", 'proc.exec("p", "[]")'),
]:
    _recipe("Proc", _m, ["proc: Proc"], [], _e)

for _m, _e in [
    ("is_null", "j.is_null()"), ("as_bool", "j.as_bool()"),
    ("as_num", "j.as_num()"), ("as_number", "j.as_number()"),
    ("as_int", "j.as_int()"), ("as_string", "j.as_string()"),
    ("as_array", "j.as_array()"), ("as_object", "j.as_object()"),
]:
    _recipe("JsonValue", _m, [], ["__JSON__"], _e)

# Free-function builtins. Same shape as the method recipes minus the
# receiver.
_FREE_FN_RECIPES: dict[str, tuple[list, list, str]] = {
    "parse_int": ([], [], 'parse_int("1")'),
    "to_float": ([], [], "to_float(1)"),
    "to_int": ([], [], "to_int(1.0)"),
    "parse_json": ([], [], 'parse_json("1")'),
    "to_json": ([], ["__JSON__"], "to_json(j)"),
    "new_map": ([], [], "new_map()"),
    "new_set": ([], [], "new_set()"),
    "parse_float": ([], [], 'parse_float("1.0")'),
}

# Free-function builtins deliberately outside the sweep, with the
# reason each is exempt. Keeping them listed (rather than silently
# absent) means the coverage assertion still accounts for every entry in
# FREE_FUNCTIONS.
_FREE_FN_EXEMPT = {
    # Diverges by design: emits ``call $panic`` + ``unreachable``, so
    # there is no value to discard and no stack to balance.
    "panic",
    # Compiler-internal: the analyzer rejects a direct call ("not part
    # of the Capa language surface"), so no user program can discard
    # one. Both already drop correctly on the dst-None path; they are
    # the precedent the rest of this fix follows.
    "_capa_chr", "_capa_str_span",
    # IFC-erasure marker, not a Wasm-emitting call.
    "declassify",
    # Python-interop FFI: rejected on the Wasm backend by design.
    "py_import", "py_invoke",
}


def _method_is_exempt_from_the_sweep(ty: str) -> bool:
    """True for methods that can never reach the Wasm emitter, so a
    discarded-call recipe for them could not be built (and would not
    mean anything if it were).

    The sweep proves a DISCARDED call still balances the Wasm operand
    stack. A capability the Wasm backend rejects outright at discovery
    time has no emit path at all: any program exercising it raises
    ``WasmEmissionError`` before a single instruction is produced, so
    there is no stack to balance.

    Derived from ``PYTHON_ONLY_CAPS`` rather than spelled out, for the
    same reason the WIT guard is: the exemption and its justification
    should be one fact, not two that can drift. ``Serve`` (2026-07) is
    the first such capability that HAS methods -- ``Unsafe`` is
    method-less, which is why this guard never had to express the idea
    before. This mirrors the ``py_import`` / ``py_invoke`` exemption in
    ``_FREE_FN_EXEMPT`` directly above.
    """
    from capa.ir._capa_types import PYTHON_ONLY_CAPS
    return ty in PYTHON_ONLY_CAPS


class _EmitVariant(typing.NamedTuple):
    """One flag-selected emit path for a discarded call.

    ``_DISCARD_RECIPES`` is keyed by ``(type, method)``, which cannot
    express an emit site chosen by COMPILE FLAGS rather than by the call
    shape: ``fs.exists`` has three separate emitters (capa:host, WASI
    static-path, WASI dynamic-path under an operator preopen) behind one
    ``(Fs, exists)`` key. Each such variant is listed here with the
    compile kwargs that select it, so removing the drop from any ONE of
    them fails the sweep."""

    label: str
    compile_kw: dict
    src: str


# A discarded fs.exists / fs.is_dir in each of the three Fs metadata
# emit paths. The capa:host variant duplicates what the (Fs, exists)
# recipe covers, and is kept deliberately: it pins that all three
# variants are exercised by the SAME assertion, so the three cannot
# drift apart again.
_WASI_STATIC_SRC = (
    "fun main(fs: Fs, stdio: Stdio)\n"
    '    fs.exists("a.txt")\n'
    '    fs.is_dir("a.txt")\n'
    '    stdio.println("x")\n'
)

# The dynamic-path emitter only fires for a NON-literal path, which
# needs an operator preopen (``--preopen``, i.e. wasi_dynamic_fs=True).
# Mirrors the shape tests/wasi/test_wasi_fs.py's dynamic tests use.
_WASI_DYNAMIC_SRC = (
    "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    match args.get(0)\n"
    "        Some(p) ->\n"
    "            fs.exists(p)\n"
    "            fs.is_dir(p)\n"
    '            stdio.println("x")\n'
    '        None -> stdio.println("none")\n'
)

# The aggregate-returning capability methods under WASI. These are the
# delta-0 controls: they materialise into a `_ret_area` in linear memory
# rather than the operand stack, so a discarded call must emit NO drop.
# Sweeping them proves the WASI wrappers did not gain a spurious drop
# (which would underflow) while the pushing variants above gained a
# correct one.
_WASI_AGG_STATIC_SRC = (
    "fun main(fs: Fs, stdio: Stdio)\n"
    '    fs.read("a.txt")\n'
    '    fs.write("a.txt", "d")\n'
    '    fs.mkdir("a")\n'
    '    fs.list_dir("a")\n'
    '    stdio.println("x")\n'
)
_WASI_AGG_DYNAMIC_SRC = (
    "fun main(fs: Fs, env: Env, stdio: Stdio)\n"
    "    let args = env.args()\n"
    "    match args.get(0)\n"
    "        Some(p) ->\n"
    "            fs.read(p)\n"
    '            fs.write(p, "d")\n'
    "            fs.mkdir(p)\n"
    "            fs.list_dir(p)\n"
    '            stdio.println("x")\n'
    '        None -> stdio.println("none")\n'
)
_WASI_NET_SRC = (
    "fun main(net: Net, stdio: Stdio)\n"
    '    net.get("http://example.com/a")\n'
    '    net.post("http://example.com/a", "b")\n'
    '    stdio.println("x")\n'
)

_EMIT_PATH_VARIANTS: tuple[_EmitVariant, ...] = (
    _EmitVariant(
        "Fs.exists/is_dir (capa:host)", {}, _WASI_STATIC_SRC,
    ),
    _EmitVariant(
        "Fs.exists/is_dir (WASI static path)",
        {"wasi": True},
        _WASI_STATIC_SRC,
    ),
    _EmitVariant(
        "Fs.exists/is_dir (WASI dynamic path, operator preopen)",
        {"wasi": True, "wasi_dynamic_fs": True},
        _WASI_DYNAMIC_SRC,
    ),
    # Delta-0 controls: the WASI ret-area wrappers must stay drop-free.
    _EmitVariant(
        "Fs read/write/mkdir/list_dir (WASI static path)",
        {"wasi": True},
        _WASI_AGG_STATIC_SRC,
    ),
    _EmitVariant(
        "Fs read/write/mkdir/list_dir (WASI dynamic path)",
        {"wasi": True, "wasi_dynamic_fs": True},
        _WASI_AGG_DYNAMIC_SRC,
    ),
    _EmitVariant(
        "Net get/post (WASI wasi:http wrappers)",
        {"wasi": True},
        _WASI_NET_SRC,
    ),
)


def _build_discard_program(caps, setup, expr) -> str:
    """A program whose only interesting statement DISCARDS ``expr``."""
    if setup and setup[0] == "__JSON__":
        return (
            "fun main(stdio: Stdio)\n"
            '    match parse_json("1")\n'
            "        Ok(j) ->\n"
            f"            {expr}\n"
            '            stdio.println("x")\n'
            '        Err(e) -> stdio.println("e")\n'
        )
    params = list(caps)
    if "stdio: Stdio" not in params:
        params.append("stdio: Stdio")
    lines = [f"fun main({', '.join(params)})"]
    lines.extend(f"    {s}" for s in setup)
    lines.append(f"    {expr}")
    lines.append('    stdio.println("x")')
    return "\n".join(lines) + "\n"


class TestDiscardedCallSweepCoverage(unittest.TestCase):
    """The coverage half of the sweep: pure Python, no wasm tooling, so
    it runs on the no-wasm-extra CI job too."""

    def test_discard_recipes_cover_every_builtin(self):
        # THE GUARD: every entry in the authoritative tables must have a
        # discard recipe. A builtin added without one fails here, which
        # is the whole point -- a new emit path cannot skip the sweep.
        from capa.builtins import METHODS, FREE_FUNCTIONS
        missing_methods = [
            (ty, entry[0])
            for ty, entries in METHODS.items()
            for entry in entries
            if (ty, entry[0]) not in _DISCARD_RECIPES
            and not _method_is_exempt_from_the_sweep(ty)
        ]
        self.assertEqual(
            missing_methods, [],
            msg=(
                "capa.builtins.METHODS gained entries with no discarded-"
                "call recipe. Add one to _DISCARD_RECIPES so the sweep "
                "proves a discarded call of that shape still balances "
                "the Wasm operand stack."
            ),
        )
        # The exemption must not become a hiding place: a recipe for a
        # Wasm-rejected capability would fail to emit, so assert none
        # was written rather than silently tolerating one.
        exempt_with_recipes = [
            key for key in _DISCARD_RECIPES
            if _method_is_exempt_from_the_sweep(key[0])
        ]
        self.assertEqual(
            exempt_with_recipes, [],
            msg=(
                "a discarded-call recipe exists for a capability the "
                "Wasm backend rejects outright; it can never emit"
            ),
        )
        missing_free = [
            name for name in FREE_FUNCTIONS
            if name not in _FREE_FN_RECIPES and name not in _FREE_FN_EXEMPT
        ]
        self.assertEqual(
            missing_free, [],
            msg=(
                "capa.builtins.FREE_FUNCTIONS gained entries with no "
                "discarded-call recipe. Add one to _FREE_FN_RECIPES, or "
                "to _FREE_FN_EXEMPT with the reason it cannot be swept."
            ),
        )
        # Guard the guard: a stale recipe for a builtin that no longer
        # exists would silently weaken the sweep.
        stale = [
            key for key in _DISCARD_RECIPES
            if key[1] not in {e[0] for e in METHODS.get(key[0], [])}
        ]
        self.assertEqual(stale, [], msg="stale recipes for removed builtins")

    def test_every_discarded_builtin_emits(self):
        # Pure emitter path: every discarded shape must reach WAT
        # without a WasmEmissionError. Validation of the stack balance
        # itself needs wasmtime and lives in the gated sweep below.
        for (ty, method), (caps, setup, expr) in sorted(
            _DISCARD_RECIPES.items()
        ):
            with self.subTest(receiver=ty, method=method):
                src = _build_discard_program(caps, setup, expr)
                ir_mod, _, _ = _parse_lower(src)
                emit_wat(ir_mod)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestDiscardedCallSweepValidates(unittest.TestCase):
    """The validation half of the sweep: compile each discarded shape to
    a real module and let wasmtime's validator judge the stack balance.

    This is the test that would have caught all three rounds of the bug
    class at once. A regression shows up as "values remaining on stack
    at end of block" (a missing drop) or "type mismatch" / stack
    underflow (a spurious drop)."""

    def _assert_validates(self, src: str, label: str, **compile_kw) -> None:
        import wasmtime
        module, result = _parse_and_analyze_ok(src)
        blob = compile_wasm(module, types=result.types, **compile_kw)
        try:
            wasmtime.Module(wasmtime.Engine(), blob)
        except Exception as exc:  # noqa: BLE001 - want the raw reason
            self.fail(
                f"discarded {label} produced an INVALID module: {exc}\n"
                f"--- program ---\n{src}"
            )

    def test_every_discarded_builtin_method_validates(self):
        for (ty, method), (caps, setup, expr) in sorted(
            _DISCARD_RECIPES.items()
        ):
            with self.subTest(receiver=ty, method=method):
                self._assert_validates(
                    _build_discard_program(caps, setup, expr),
                    f"{ty}.{method}",
                )

    def test_every_discarded_free_function_validates(self):
        for name, (caps, setup, expr) in sorted(_FREE_FN_RECIPES.items()):
            with self.subTest(free_function=name):
                self._assert_validates(
                    _build_discard_program(caps, setup, expr), name,
                )

    def test_every_discarded_emit_path_variant_validates(self):
        # The (type, method) recipes above only ever exercise the DEFAULT
        # capa:host emit path, because a plain program compiled with
        # default flags is all they build. Several methods have more than
        # one emit site selected by COMPILE FLAGS rather than by the call
        # shape -- fs.exists / fs.is_dir alone have three (capa:host,
        # WASI static-path, WASI dynamic-path under an operator preopen).
        # Keying by (type, method) structurally cannot reach those, so
        # each flag-selected variant is enumerated explicitly here.
        for variant in _EMIT_PATH_VARIANTS:
            with self.subTest(variant=variant.label):
                self._assert_validates(
                    variant.src, variant.label, **variant.compile_kw,
                )


# ----------------------------------------------------------------------
# WAT call-closure guard.
#
# Every ``call $x`` in an emitted module must resolve to a function that
# the module either DEFINES (``(func $x ...)``) or IMPORTS
# (``(import ... (func $x ...))``). The conditionally-emitted runtime
# helpers ($pow10_i32, $ftoa, $bn_*, $str_cmp, ...) are gated on feature
# predicates, and a called-but-ungated helper produces a module that
# fails to assemble ("unknown func"). This guard walks a corpus that
# lights up each gated feature (and the combinations that previously
# left a callee ungated, notably parse_float WITHOUT any Float
# formatting) and asserts the call graph is closed.
# ----------------------------------------------------------------------

_WAT_CLOSURE_CORPUS: list[tuple[str, str]] = [
    # The Ticket-1 regression: parse_float pulls in $bn_mul_pow10, which
    # calls $pow10_i32; without a Float format nothing else emits it.
    ("parse_float_no_format",
     "fun main(stdio: Stdio)\n"
     '    let f = parse_float("3.5")\n'
     '    stdio.println("done")\n'),
    ("parse_float_discarded",
     "fun main(stdio: Stdio)\n"
     '    parse_float("3.5")\n'
     '    stdio.println("done")\n'),
    # Float formatting alone: the other $pow10_i32 caller (Grisu2).
    ("float_format_only",
     "fun main(stdio: Stdio)\n"
     "    let x = 3.5\n"
     '    stdio.println("${x}")\n'),
    # Both callers present: the latch must not double-define anything.
    ("parse_float_and_float_format",
     "fun main(stdio: Stdio)\n"
     '    let f = parse_float("3.5").unwrap_or(0.0)\n'
     '    stdio.println("${f}")\n'),
    ("parse_int",
     "fun main(stdio: Stdio)\n"
     '    let n = parse_int("3")\n'
     '    stdio.println("done")\n'),
    ("int_format",
     "fun main(stdio: Stdio)\n"
     "    let n = 3\n"
     '    stdio.println("${n}")\n'),
    ("string_ops",
     "fun main(stdio: Stdio)\n"
     '    let s = "hello"\n'
     "    stdio.println(s.to_upper())\n"),
    ("string_order_cmp",
     "fun main(stdio: Stdio)\n"
     '    let b = "a" < "b"\n'
     '    stdio.println("done")\n'),
    ("compound_equality",
     "fun main(stdio: Stdio)\n"
     "    let a = [1, 2]\n"
     "    let b = [1, 2]\n"
     "    let eq = a == b\n"
     '    stdio.println("done")\n'),
    ("set_algebra",
     "fun main(stdio: Stdio)\n"
     "    var s1 = new_set()\n"
     "    s1.add(1)\n"
     "    var s2 = new_set()\n"
     "    s2.add(2)\n"
     "    let u = s1.union(s2)\n"
     '    stdio.println("done")\n'),
    ("json_parse",
     "fun main(stdio: Stdio)\n"
     '    match parse_json("1")\n'
     '        Ok(j) -> stdio.println("ok")\n'
     '        Err(e) -> stdio.println("e")\n'),
]

_WAT_FUNC_DECL = re.compile(r"\(func\s+\$(\w+)")
_WAT_IMPORT_FUNC = re.compile(r"\(import\b.*\(func\s+\$(\w+)")
_WAT_CALL = re.compile(r"\bcall\s+\$(\w+)")


def _wat_call_closure(wat: str) -> set[str]:
    """Return the set of ``call $x`` targets with no defining or
    importing ``(func $x ...)`` in the module (should be empty)."""
    declared = set(_WAT_FUNC_DECL.findall(wat))
    imported = {
        m
        for line in wat.splitlines()
        if "(import" in line
        for m in _WAT_IMPORT_FUNC.findall(line)
    }
    called = set(_WAT_CALL.findall(wat))
    return called - declared - imported


class TestWatCallClosure(unittest.TestCase):
    """Feature-agnostic guard: no emitted module may ``call`` a function
    it neither defines nor imports. Structurally catches a callable-but-
    ungated runtime helper for any future feature, not just parse_float.
    """

    def test_every_call_is_defined_or_imported(self):
        for label, src in _WAT_CLOSURE_CORPUS:
            with self.subTest(program=label):
                # compile_wat runs the full pipeline (inject_into splices
                # the bundled JSON parser, monomorphise specialises
                # generics), so the WAT here is exactly what assembles.
                _, types, ast_mod = _parse_lower(src)
                wat = compile_wat(ast_mod, types=types)
                missing = _wat_call_closure(wat)
                self.assertEqual(
                    missing, set(),
                    msg=(
                        f"{label}: module calls undefined/unimported "
                        f"function(s): {sorted(missing)}"
                    ),
                )


def _parse_and_analyze_ok(src: str):
    """Lex + parse + analyze, asserting the program is well-typed.
    Returns (ast_module, analysis_result)."""
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    return module, result
