# pyright: reportCallIssue=none
#
# wasmtime-py types ``instance.exports(store)[name]`` as a union
# ``Func | Global | Memory | Table | SharedMemory``. Every call site
# in this module passes the resulting export through ``(...)``, so
# Pyright flags each non-callable variant of the union. We know the
# relevant export is a Func because the WAT we emit always declares it
# as one; silencing ``reportCallIssue`` for the whole module is the
# smallest fix that does not bury the test code in per-line type-ignore
# noise. Real "not callable" errors are still caught at runtime by
# ``python -m unittest``.
"""WebAssembly backend: trait dispatch, user capability-method dispatch,
and generic monomorphisation.

Part of the tests/ir_wasm package; see tests/ir_wasm/__init__.py for
the growth convention. The shared _parse_lower / skip gates live in
tests/ir_wasm/_helpers.py.
"""

from __future__ import annotations

import unittest

from tests.ir_wasm._helpers import _parse_lower, _has_wasm_tools, _has_wasmtime_py
from capa.ir import compile_wasm


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTraitDispatch(unittest.TestCase):
    """Phase 6J: user-defined trait + capability dispatch via
    monomorphisation (unique impl per trait). Covers both the
    trait-typed receiver (param of type Greeter) and the concrete-
    impl-typed self call inside an impl body."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_user_capability_with_unique_impl(self):
        src = (
            'pub capability Greeter\n'
            '    fun greet(self, name: String) -> Unit\n'
            'pub type StdioGreeter {\n'
            '    stdio: Stdio,\n'
            '    prefix: String,\n'
            '}\n'
            'pub fun make_greeter(stdio: Stdio, prefix: String) -> StdioGreeter\n'
            '    return StdioGreeter { stdio: stdio, prefix: prefix }\n'
            'impl Greeter for StdioGreeter\n'
            '    fun greet(self, name: String) -> Unit\n'
            '        self.stdio.println("${self.prefix}, ${name}!")\n'
            'fun say_hi(g: Greeter, name: String) -> Unit\n'
            '    g.greet(name)\n'
            'fun main(stdio: Stdio)\n'
            '    let g = make_greeter(stdio, "Hi")\n'
            '    say_hi(g, "Capa")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "Hi, Capa!\n")

    def test_nested_variant_pattern(self):
        # Two-level destructuring: Result<T, ArgError> with
        # variant patterns inside Err. Each arm combines the
        # outer + inner tag checks into a single AND-bool.
        src = (
            'pub type ArgError =\n'
            '    Missing(String)\n'
            '    Unknown(String)\n'
            'fun classify(r: Result<Int, ArgError>) -> String\n'
            '    match r\n'
            '        Ok(_)             -> return "ok"\n'
            '        Err(Missing(n))   -> return "missing ${n}"\n'
            '        Err(Unknown(a))   -> return "unknown ${a}"\n'
            'fun main(stdio: Stdio)\n'
            '    let m: Result<Int, ArgError> = Err(Missing("name"))\n'
            '    let u: Result<Int, ArgError> = Err(Unknown("flag"))\n'
            '    let o: Result<Int, ArgError> = Ok(7)\n'
            '    stdio.println(classify(m))\n'
            '    stdio.println(classify(u))\n'
            '    stdio.println(classify(o))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "missing name\nunknown flag\nok\n",
        )

    def test_self_method_call_inside_impl(self):
        # Impl method delegates to another method on self via the
        # concrete-impl-type entry in _method_table.
        src = (
            'pub capability Logger\n'
            '    fun log(self, msg: String) -> Unit\n'
            '    fun info(self, msg: String) -> Unit\n'
            'pub type StdioLogger { stdio: Stdio }\n'
            'pub fun make_logger(stdio: Stdio) -> StdioLogger\n'
            '    return StdioLogger { stdio: stdio }\n'
            'impl Logger for StdioLogger\n'
            '    fun log(self, msg: String) -> Unit\n'
            '        self.stdio.println("[LOG] ${msg}")\n'
            '    fun info(self, msg: String) -> Unit\n'
            '        self.log(msg)\n'
            'fun main(stdio: Stdio)\n'
            '    let log = make_logger(stdio)\n'
            '    log.info("boot")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "[LOG] boot\n")


class TestWasmActionableErrors(unittest.TestCase):
    """Placeholder for future actionable-error tests. The two
    cases that lived here (generic user functions, lambda over
    String) are both closed:
    - generics: monomorphised by the IR pass; see
      TestWasmGenericMonomorphisation
    - lambda over String: handled via multi-value lowering;
      see TestWasmClosureStringTypes

    Kept as a class so a future surfacing of a NEW unsupported
    construct has an obvious home for its actionable-error test.
    """


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmUserCapMethodDispatch(unittest.TestCase):
    """User-defined capability methods (``capability ReadOnlyFs``
    plus ``impl ReadOnlyFs for ...``) used to fall through to
    TyUnknown in the analyzer because ``_check_method_call``
    only routed built-in capability names to the cap-method
    table. The fix in 2026-05-26 broadens the check to any
    SymbolKind.CAPABILITY symbol and populates the cap's
    method table during the second declarations pass. These
    tests pin user-cap method calls + ``?`` propagation
    end-to-end under ``--wasm --run``."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_user_cap_method_call_typed_correctly(self):
        # Before the fix: greet's call to log.info(...) was
        # typed as TyUnknown; the lowerer dropped the dst type
        # to ``?`` and the Wasm emitter raised a generic
        # layout error. Now the call returns Unit correctly
        # and the program runs end-to-end.
        src = (
            'pub capability Logger\n'
            '    fun info(self, msg: String) -> Unit\n'
            'pub type StdioLogger { stdio: Stdio }\n'
            'pub fun make_logger(stdio: Stdio) -> StdioLogger\n'
            '    return StdioLogger { stdio: stdio }\n'
            'impl Logger for StdioLogger\n'
            '    fun info(self, msg: String) -> Unit\n'
            '        self.stdio.println("[INFO] ${msg}")\n'
            'fun greet(log: Logger, name: String)\n'
            '    log.info("hello ${name}")\n'
            'fun main(stdio: Stdio)\n'
            '    let log = make_logger(stdio)\n'
            '    greet(log, "world")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "[INFO] hello world\n",
        )

    def test_user_cap_method_returning_int(self):
        # Pins the analyzer's return-type propagation for a
        # user-cap method whose return is a single-value Int.
        # Without the fix, ``inc.bump()`` would have typed as
        # TyUnknown and the caller's ``Int`` annotation would
        # have raised a let-binding mismatch in the analyzer.
        src = (
            'pub capability Counter\n'
            '    fun bump(self) -> Int\n'
            'pub type C { n: Int }\n'
            'pub fun make_c() -> C\n'
            '    return C { n: 42 }\n'
            'impl Counter for C\n'
            '    fun bump(self) -> Int\n'
            '        return self.n + 1\n'
            'fun use_counter(inc: Counter) -> Int\n'
            '    return inc.bump()\n'
            'fun main(stdio: Stdio)\n'
            '    let c = make_c()\n'
            '    let v: Int = use_counter(c)\n'
            '    stdio.println("v=${v}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "v=43\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmTupleParamTypes(unittest.TestCase):
    """Bare tuple types in function parameter / return positions
    (``fun f(p: (String, Int)) -> (String, Int)``) lower to an
    i32 pointer-shaped value at the Wasm level. Before
    2026-05-26 the IR's ``_type_name`` helper had no
    ``TupleType`` AST case and fell through to ``repr(te)``,
    which stuffed the AST node's text into a ``ty`` string.
    Wrapped forms (``List<(String, Int)>``) short-circuited
    via the ``head in ("List", ...)`` branch in
    ``_wasm_type`` and worked by accident; bare tuple params
    surfaced the gap. Test pins the fix."""

    def _run(self, src: str) -> int:
        import wasmtime
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        engine = wasmtime.Engine()
        mod = wasmtime.Module(engine, blob)
        store = wasmtime.Store(engine)
        linker = wasmtime.Linker(engine)
        instance = linker.instantiate(store, mod)
        return instance.exports(store)["main"](store)

    def test_tuple_param_and_return(self):
        # main returns the second element of a (Int, Int) tuple
        # passed through a helper. Pins the lowerer +
        # _wasm_type contract for bare tuple types.
        src = (
            'fun second(t: (Int, Int)) -> Int\n'
            '    let (a, b) = t\n'
            '    return b\n'
            'fun main() -> Int\n'
            '    return second((10, 42))\n'
        )
        self.assertEqual(self._run(src), 42)


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGenericMonomorphisationFunType(unittest.TestCase):
    """Bonus regression added 2026-05-27: the monomorphiser's
    string-based unifier originally treated ``Fun(...) -> R``
    as an opaque atom because ``_parse_ty`` had no case for
    closure types. Consequence: a generic HOF whose param
    list included a closure (the showcase's
    ``count_by<T>(items: List<T>, key: Fun(T) -> String)``)
    failed unification at every call site and was never
    monomorphised, leaving an undefined ``$count_by`` call in
    the WAT. Test pins the now-working shape."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_generic_hof_with_closure_param(self):
        src = (
            'fun count_matching<T>(items: List<T>, pred: Fun(T) -> Bool) -> Int\n'
            '    var n = 0\n'
            '    for x in items\n'
            '        if pred(x)\n'
            '            n = n + 1\n'
            '    return n\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [1, 2, 3, 4, 5]\n'
            '    let n = count_matching(xs, fun(v: Int) -> Bool => v > 2)\n'
            '    stdio.println("n=${n}")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "n=3\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmCapCallViaFieldAccess(unittest.TestCase):
    """The IR's MethodCall.cap_used field was set only when the
    receiver was a capability parameter (``param.method(...)``).
    User-defined cap impls that reach a built-in cap via a struct
    field (``self.fs.read(...)``) left cap_used as None, so the
    Wasm backend's ``has_indirect_cap_call`` detector in
    ``_collect_locals`` missed the call. The canonical-ABI
    indirect-return area ``$_ret_area`` then went undeclared and
    wasm-tools rejected the WAT with ``unknown local: $_ret_area``.

    Fix landed 2026-05-27: the lowerer now also tags cap_used
    when the receiver's type string resolves to a built-in cap,
    regardless of how it was reached. Test pins the impl-method-
    calls-built-in-cap pattern that the capa_showcase exercised
    via its ReadOnlyFs wrapper."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_user_cap_impl_calls_builtin_cap_via_self_field(self):
        # ReadOnlyFs.read delegates to self.fs.read (built-in
        # Fs.read with canonical-ABI Result<String, IoError>
        # return area). Caller matches the Result and routes
        # Err to a default string. Exercises the full chain:
        # user-cap method dispatch + impl body's built-in-cap
        # call via field access + $_ret_area declaration.
        src = (
            'pub capability ReadOnlyFs\n'
            '    fun read(self, path: String) -> Result<String, IoError>\n'
            'pub type ReadOnlyFsImpl { fs: Fs }\n'
            'pub fun make_ro_fs(fs: Fs) -> ReadOnlyFsImpl\n'
            '    return ReadOnlyFsImpl { fs: fs }\n'
            'impl ReadOnlyFs for ReadOnlyFsImpl\n'
            '    fun read(self, path: String) -> Result<String, IoError>\n'
            '        return self.fs.read(path)\n'
            'fun describe(fs: ReadOnlyFs, path: String) -> String\n'
            '    match fs.read(path)\n'
            '        Ok(s)  -> return s\n'
            '        Err(_) -> return "<missing>"\n'
            'fun main(stdio: Stdio, fs: Fs)\n'
            '    let ro = make_ro_fs(fs)\n'
            '    stdio.println(describe(ro, "/does/not/exist"))\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src), "<missing>\n",
        )


@unittest.skipUnless(
    _has_wasm_tools() and _has_wasmtime_py(),
    "wasm-tools and/or wasmtime-py not installed",
)
class TestWasmGenericMonomorphisation(unittest.TestCase):
    """Generic free functions (``fun first<T>(items: List<T>) -> Option<T>``)
    used to crash the Wasm backend at layout time because the IR
    carried ``T`` as a string with no Wasm encoding. The
    monomorphisation pass at ``capa/ir/_monomorphise.py`` walks
    the IR after lowering, infers each call's type-parameter
    substitution from the actual arg types, and synthesises a
    specialised clone with a mangled name (e.g., ``first__Int``).
    These tests pin the new behaviour end-to-end through
    ``--wasm --run``."""

    def _run_capturing_stdout(self, src: str) -> str:
        import io
        import sys
        from capa.runtime._wasm_host import WasmHost
        _, types, ast_mod = _parse_lower(src)
        blob = compile_wasm(ast_mod, types=types)
        host = WasmHost()
        out = io.StringIO()
        saved_out = sys.stdout
        sys.stdout = out
        try:
            host.run_main(blob)
        finally:
            sys.stdout = saved_out
        return out.getvalue()

    def test_generic_first_with_int_arg(self):
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<Int> = [10, 20, 30]\n'
            '    match first(xs)\n'
            '        Some(n) -> stdio.println("got ${n}")\n'
            '        None    -> stdio.println("empty")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "got 10\n")

    def test_generic_first_with_string_arg(self):
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let xs: List<String> = ["alpha", "beta"]\n'
            '    match first(xs)\n'
            '        Some(s) -> stdio.println(s)\n'
            '        None    -> stdio.println("empty")\n'
        )
        self.assertEqual(self._run_capturing_stdout(src), "alpha\n")

    def test_same_generic_function_called_with_two_types(self):
        # Both call sites must produce their own monomorphic clone;
        # the dedupe key is the substitution, not the source name.
        src = (
            'fun first<T>(items: List<T>) -> Option<T>\n'
            '    for x in items\n'
            '        return Some(x)\n'
            '    return None\n'
            'fun main(stdio: Stdio)\n'
            '    let ns: List<Int> = [1, 2]\n'
            '    let ss: List<String> = ["x", "y"]\n'
            '    match first(ns)\n'
            '        Some(n) -> stdio.println("int=${n}")\n'
            '        None    -> stdio.println("ne")\n'
            '    match first(ss)\n'
            '        Some(s) -> stdio.println("str=${s}")\n'
            '        None    -> stdio.println("se")\n'
        )
        self.assertEqual(
            self._run_capturing_stdout(src),
            "int=1\nstr=x\n",
        )
