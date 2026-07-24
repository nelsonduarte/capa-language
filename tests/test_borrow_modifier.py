"""The ``borrow`` parameter modifier: invoke-only higher-order inlets.

``borrow`` marks a ``Fun``-typed parameter as invoke-only. A function
that only INVOKES a caller-supplied callback (never storing, returning,
aliasing, passing on, or capturing it) does not have to charge the
callback's authority to its OWN package ceiling: the closure's authority
is charged at its creation site, and the product SBOM still sees it. So
``serve_once(serve: Serve, borrow handler: Fun(Request) -> Response)``
keeps a ``max = ["Serve"]`` ceiling honest, which Option C rejected
because the bare ``Fun`` voided the ceiling.

The verification is local and syntactic and fails CLOSED: the only
accepted occurrence is ``handler(...)``; every other occurrence is an
escape and a compile error. These tests pin:

- the ceiling newly PASSES for an invoke-only ``borrow`` handler;
- every escape shape is REJECTED naming the parameter and the site;
- ``borrow`` on a non-``Fun`` parameter is refused;
- the product SBOM still shows a handler's ``Fs`` (borrow hides no
  authority; it only lets the callee's OWN ceiling stay honest);
- the strict ``provably_excluded_capabilities`` is unchanged (a borrow
  inlet still cannot claim to exclude the handler's caps);
- the signal split (strict flag False, ceiling flag True);
- the modifier round-trips through the formatter;
- both backends emit identical output with and without the modifier.
"""

from __future__ import annotations

import io
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from capa import Lexer, Parser, analyze, transpile
from capa.formatter import format_source
from capa.formatter._emit import format_source_emit
from capa.ir import compile_wasm
from capa.loader import ModuleLoader
from capa.manifest import build_composed_sbom, build_manifest


def _has_wasm() -> bool:
    if shutil.which("wasm-tools") is None:
        return False
    try:
        import wasmtime  # noqa: F401
        return True
    except ImportError:
        return False


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
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    assert result.ok, result.errors

    def _go() -> None:
        code = transpile(
            module, types=result.types, bindings=result.bindings,
        )
        ns: dict = {"__name__": "__main__"}
        exec(compile(code, "<borrow>", "exec"), ns)

    return _capture_stdout(_go)


def _run_wasm(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    assert result.ok, result.errors

    def _go() -> None:
        blob = compile_wasm(module, types=result.types)
        WasmHost().run_main(blob)

    return _capture_stdout(_go)


def _analyze(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    return analyze(module, source=src)


def _manifest(src: str):
    tokens = Lexer(src).lex()
    module = Parser(tokens, source=src).parse_module()
    result = analyze(module, source=src)
    assert result.ok, result.errors
    return build_manifest(
        module, filename="m.capa", expr_labels=result.expr_labels,
    )


def _func(manifest, source_name: str):
    for fn in manifest["functions"]:
        if fn["source_name"] == source_name:
            return fn
    raise AssertionError(
        f"no function {source_name!r} in "
        f"{[f['source_name'] for f in manifest['functions']]}"
    )


def _write(base: Path, rel: str, text: str) -> None:
    p = base / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def _compose(root_dir: Path, root_file: str):
    """Compile ``root_file`` and compose the product SBOM, exactly as
    ``--check-capabilities`` does."""
    root_dir = root_dir.resolve()
    search = [root_dir]
    for vendor in root_dir.rglob("vendor"):
        if vendor.is_dir():
            search.append(vendor)
    filename = str(root_dir / root_file)
    source = Path(filename).read_text(encoding="utf-8")
    loader = ModuleLoader(search_paths=search)
    linked = loader.load_root(source, filename)
    result = analyze(
        linked.module, source=source, filename=filename,
        sources=linked.sources, module_privates=linked.module_privates,
    )
    if not result.ok:
        raise AssertionError(f"analyzer errors: {result.errors}")
    manifest = build_manifest(
        linked.module, filename=filename, expr_labels=result.expr_labels,
    )
    return manifest, build_composed_sbom(linked.module, manifest, root_dir)


# A ``serve_once`` shape reduced to what the ceiling reacts to: it holds
# ``Serve`` and INVOKES a caller-supplied handler, nothing more.
SERVE_ONCE_SRC = (
    "type Request {\n"
    "    path: String\n"
    "}\n"
    "\n"
    "type Response {\n"
    "    code: Int\n"
    "}\n"
    "\n"
    "pub fun serve_once("
    "serve: Serve, borrow handler: Fun(Request) -> Response) -> Response\n"
    '    let ok = serve.allows("0.0.0.0", 8080)\n'
    '    let req = Request { path: "/" }\n'
    "    return handler(req)\n"
)


class TestBorrowCeilingPasses(unittest.TestCase):
    """The whole point: an invoke-only ``borrow`` handler no longer voids
    the declaring package's ceiling."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_borrow_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def _pkg(self, ceiling_block: str) -> Path:
        root = self.tmp / "srv"
        _write(root, "capa.toml", (
            '[package]\nname = "srv"\nversion = "0.1.0"\n\n' + ceiling_block
        ))
        _write(root, "server.capa", SERVE_ONCE_SRC)
        return root

    def test_serve_once_with_borrow_passes_serve_ceiling(self):
        root = self._pkg('[capabilities]\nmax = ["Serve"]\n')
        _manifest_out, composed = _compose(root, "server.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["checked"])
        self.assertTrue(ceilings["pass"], ceilings["violations"])

    def test_signal_split_strict_false_ceiling_true(self):
        # The strict flag stays False (there IS a Fun in the signature);
        # only the ceiling-scoped flag flips True.
        m = _manifest(SERVE_ONCE_SRC)
        fn = _func(m, "serve_once")
        self.assertFalse(fn["authority_provable_from_types"])
        self.assertTrue(fn["ceiling_authority_provable"])

    def test_provably_excluded_does_not_gain_fs(self):
        # The strict flag still voids the exclusion proof, so serve_once
        # makes NO exclusion claim; it certainly does not claim to exclude
        # Fs (which a passed handler could exercise).
        m = _manifest(SERVE_ONCE_SRC)
        fn = _func(m, "serve_once")
        self.assertEqual(fn["provably_excluded_capabilities"], [])
        self.assertNotIn("Fs", fn["provably_excluded_capabilities"])

    def test_param_record_carries_borrowing_flag(self):
        m = _manifest(SERVE_ONCE_SRC)
        fn = _func(m, "serve_once")
        handler = [p for p in fn["params"] if p["name"] == "handler"][0]
        self.assertTrue(handler["borrowing"])
        serve = [p for p in fn["params"] if p["name"] == "serve"][0]
        self.assertFalse(serve["borrowing"])


# A single-package product whose handler WRITES a file: the closure
# captures ``fs: Fs`` from ``main``, so the product footprint must show
# ``Fs`` even though ``serve_once`` only holds ``Serve``.
FS_HANDLER_SRC = (
    "type Request {\n"
    "    path: String\n"
    "}\n"
    "\n"
    "type Response {\n"
    "    code: Int\n"
    "}\n"
    "\n"
    "pub fun serve_once("
    "serve: Serve, borrow handler: Fun(Request) -> Response) -> Response\n"
    '    let ok = serve.allows("0.0.0.0", 8080)\n'
    '    let req = Request { path: "/" }\n'
    "    return handler(req)\n"
    "\n"
    "pub fun main(serve: Serve, fs: Fs) -> Unit\n"
    "    let handler = fun (r: Request) -> Response =>\n"
    '        let _w = fs.write("/tmp/log", "hit")\n'
    "        Response { code: 200 }\n"
    "    let _resp = serve_once(serve, handler)\n"
    "    return\n"
)


class TestBorrowDoesNotHideAuthority(unittest.TestCase):
    """``borrow`` relaxes only the callee's OWN ceiling. The handler's
    authority is charged to its creator and reaches the product SBOM."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_borrow_fs_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_product_footprint_still_shows_fs(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n'
        ))
        _write(root, "main.capa", FS_HANDLER_SRC)
        _manifest_out, composed = _compose(root, "main.capa")
        self.assertIn("Fs", composed["composed"]["capabilities"])
        self.assertIn("Serve", composed["composed"]["capabilities"])

    def test_serve_once_itself_only_holds_serve(self):
        m = _manifest(FS_HANDLER_SRC)
        fn = _func(m, "serve_once")
        self.assertEqual(fn["declared_capabilities"], ["Serve"])
        self.assertNotIn("Fs", fn["transitively_reachable_capabilities"])


class TestBorrowEscapesRejected(unittest.TestCase):
    """Every escape shape is a compile error naming the parameter."""

    def _reject(self, src: str) -> list[str]:
        r = _analyze(src)
        self.assertFalse(r.ok, "expected the escape to be rejected")
        return [e.message for e in r.errors]

    def test_returned_handler_is_rejected(self):
        src = (
            "pub fun leak(borrow h: Fun() -> Unit) -> Fun() -> Unit\n"
            "    return h\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'h'" in m and "escapes" in m for m in msgs),
            msgs,
        )

    def test_handler_in_struct_literal_is_rejected(self):
        src = (
            "type Box {\n"
            "    cb: Fun() -> Unit\n"
            "}\n"
            "\n"
            "pub fun stash(borrow h: Fun() -> Unit) -> Box\n"
            "    return Box { cb: h }\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'h'" in m for m in msgs), msgs,
        )

    def test_handler_passed_to_another_function_is_rejected(self):
        src = (
            "pub fun sink(x: Fun() -> Unit) -> Unit\n"
            "    return\n"
            "\n"
            "pub fun forward(borrow h: Fun() -> Unit) -> Unit\n"
            "    sink(h)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'h'" in m for m in msgs), msgs,
        )

    def test_handler_captured_by_returned_lambda_is_rejected(self):
        src = (
            "pub fun wrap(borrow h: Fun() -> Unit) -> Fun() -> Unit\n"
            "    return fun () -> Unit => h()\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'h'" in m for m in msgs), msgs,
        )

    def test_handler_aliased_into_a_let_is_rejected(self):
        # A bare alias is rejected rather than proven safe (fail closed).
        src = (
            "pub fun alias(borrow h: Fun() -> Unit) -> Unit\n"
            "    let g = h\n"
            "    g()\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'h'" in m for m in msgs), msgs,
        )

    def test_borrow_on_non_fun_parameter_is_rejected(self):
        src = (
            "pub fun bad(borrow x: Int) -> Unit\n"
            "    return\n"
        )
        r = _analyze(src)
        self.assertFalse(r.ok)
        self.assertTrue(
            any(
                "borrow applies only to a function-typed parameter" in e.message
                for e in r.errors
            ),
            [e.message for e in r.errors],
        )


class TestBorrowParsing(unittest.TestCase):
    """The modifier reaches the AST as ``Param.borrowing``."""

    def test_borrow_sets_the_param_flag(self):
        src = (
            "pub fun f(borrow h: Fun() -> Unit) -> Unit\n"
            "    h()\n"
            "    return\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        fn = module.items[0]
        self.assertTrue(fn.params[0].borrowing)
        self.assertFalse(fn.params[0].consuming)


class TestBorrowInvokeOnlyAccepted(unittest.TestCase):
    """The accepted shape compiles and produces the relaxed signal."""

    def test_direct_invocation_is_accepted(self):
        src = (
            "pub fun run_once(borrow h: Fun() -> Unit) -> Unit\n"
            "    h()\n"
            "    return\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_accepted_shape_relaxes_ceiling_signal(self):
        src = (
            "pub fun run_once(borrow h: Fun() -> Unit) -> Unit\n"
            "    h()\n"
            "    return\n"
        )
        m = _manifest(src)
        fn = _func(m, "run_once")
        self.assertFalse(fn["authority_provable_from_types"])
        self.assertTrue(fn["ceiling_authority_provable"])


class TestBorrowFormatterRoundTrip(unittest.TestCase):
    """The modifier prints back as ``borrow`` and re-parses identically."""

    def test_borrow_round_trips_through_the_formatter(self):
        src = (
            "pub fun serve_once("
            "serve: Serve, borrow handler: Fun(Request) -> Response)"
            " -> Response\n"
            "    return handler(req)\n"
        )
        emitted = format_source_emit(src)
        self.assertIn("borrow handler", emitted)
        # Idempotent: formatting the formatted text is a fixed point.
        self.assertEqual(emitted, format_source(emitted))

    def test_borrow_and_consume_both_print(self):
        # Consume and borrow are independent modifiers; both survive.
        src = (
            "fun f(consume a: Handle, borrow h: Fun() -> Unit) -> Unit\n"
            "    h()\n"
            "    return\n"
        )
        emitted = format_source_emit(src)
        self.assertIn("consume a", emitted)
        self.assertIn("borrow h", emitted)


@unittest.skipUnless(_has_wasm(), "wasm-tools and/or wasmtime-py not installed")
class TestBorrowIsRuntimeInert(unittest.TestCase):
    """``borrow`` is a compile-time discipline marker with no runtime
    effect: the same program with and without it compiles and runs
    identically on both backends."""

    _WITH = (
        "fun run_once(borrow handler: Fun() -> Unit) -> Unit\n"
        "    handler()\n"
        "    return\n"
        "\n"
        "fun main(stdio: Stdio)\n"
        '    let h = fun () -> Unit => stdio.println("handled")\n'
        "    run_once(h)\n"
    )
    _WITHOUT = _WITH.replace("borrow handler", "handler")

    def test_both_backends_identical_with_and_without_borrow(self):
        outputs = {
            ("with", "py"): _run_python(self._WITH),
            ("with", "wasm"): _run_wasm(self._WITH),
            ("without", "py"): _run_python(self._WITHOUT),
            ("without", "wasm"): _run_wasm(self._WITHOUT),
        }
        self.assertEqual(outputs[("with", "py")], "handled\n")
        for key, out in outputs.items():
            self.assertEqual(out, "handled\n", key)


if __name__ == "__main__":
    unittest.main()
