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


class TestBorrowForwarding(unittest.TestCase):
    """Intra-module FORWARDING: a ``borrow`` parameter may be passed as an
    argument into a same-module call whose target position is itself
    ``borrow``, without counting as an escape. This is what lets
    ``serve_connections(borrow handler)`` drive ``serve_once(borrow
    handler)`` and keep a honest ceiling.

    The relaxation is sound because ``borrow`` is self-verifying: a callee
    declaring ``borrow`` that leaked it would itself be a compile error, so
    the caller may trust the callee's signature. It stays fail-closed
    outside three traps, each pinned below:
      1. POSITION: forwarding into a bare-``Fun`` position stays rejected.
      2. RETURN LEAK: a callee that declares ``borrow`` but leaks is still
         a compile error, so the trust the annotation earns is real.
      3. STATIC RESOLVABILITY: a first-class call through a ``Fun``-typed
         local, and a dynamically dispatched method, are still rejected.
    And the scope is intra-module: a cross-package forward stays rejected.
    """

    def _analyze(self, src: str):
        return _analyze(src)

    def _reject(self, src: str) -> list[str]:
        r = _analyze(src)
        self.assertFalse(r.ok, "expected the forward to be rejected")
        return [e.message for e in r.errors]

    # -- the serve_connections shape: both borrow, forward accepted -----

    def test_forwarding_into_a_borrow_position_compiles(self):
        # ``outer(borrow cb)`` forwarding into ``inner(borrow cb)`` (both
        # borrow) is no longer an escape. It errored "escapes here" before.
        src = (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_forwarding_functions_ceiling_is_provable(self):
        # The whole point: the forwarding function's OWN ceiling signal
        # flips provable once its handler is a verified invoke-only borrow.
        src = (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
        )
        m = _manifest(src)
        fn = _func(m, "outer")
        self.assertFalse(fn["authority_provable_from_types"])
        self.assertTrue(fn["ceiling_authority_provable"])

    def test_forward_resolves_a_callee_declared_later_in_the_file(self):
        # The resolver is backed by the Phase-1 symbol table, so a forward
        # target declared AFTER the forwarder still resolves.
        src = (
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
            "\n"
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_provably_excluded_does_not_gain_the_handlers_caps(self):
        # The forwarding relaxation is CEILING-ONLY. The strict flag still
        # voids the exclusion proof (there is a Fun in the signature), so
        # ``outer`` makes NO exclusion claim it could later be sued over.
        src = (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
        )
        m = _manifest(src)
        fn = _func(m, "outer")
        self.assertEqual(fn["provably_excluded_capabilities"], [])

    # -- trap 1: POSITION-sensitive --------------------------------------

    def test_forwarding_into_a_bare_fun_position_is_rejected(self):
        # ``inner``'s parameter is NOT borrow, so it may legally retain or
        # return the callback; forwarding into it must stay an escape.
        src = (
            "pub fun inner(x: Fun() -> Unit) -> Unit\n"
            "    x()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m and "escapes" in m for m in msgs),
            msgs,
        )

    def test_second_argument_into_a_bare_position_stays_an_escape(self):
        # ``f(cb, cb)`` where position 0 is borrow and position 1 is bare:
        # the borrow occurrence is fine, the bare one still escapes.
        src = (
            "pub fun inner(borrow a: Fun() -> Unit, b: Fun() -> Unit) -> Unit\n"
            "    a()\n"
            "    b()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb, cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m for m in msgs), msgs,
        )

    # -- trap 2: RETURN LEAK earns the trust -----------------------------

    def test_callee_that_declares_borrow_but_leaks_is_still_rejected(self):
        # The trust the caller places in ``inner``'s ``borrow`` annotation
        # is earned: ``inner`` cannot itself return the callback.
        src = (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Fun() -> Unit\n"
            "    return cb\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m and "escapes" in m for m in msgs),
            msgs,
        )

    # -- trap 3: STATIC RESOLVABILITY ------------------------------------

    def test_forwarding_through_a_fun_typed_local_is_rejected(self):
        # A first-class call through a ``Fun``-typed local has no static
        # borrow signature; the local shadows any same-named function, so
        # the forward fails closed.
        src = (
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    let g = fun (f: Fun() -> Unit) -> Unit => f()\n"
            "    g(cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m for m in msgs), msgs,
        )

    def test_forwarding_into_a_method_call_is_rejected(self):
        # A dynamically dispatched method has no static borrow signature,
        # even when the method's own parameter IS declared borrow.
        src = (
            "type Holder {\n"
            "    n: Int\n"
            "}\n"
            "\n"
            "impl Holder\n"
            "    fun run(self, borrow x: Fun() -> Unit) -> Unit\n"
            "        x()\n"
            "        return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    let hold = Holder { n: 0 }\n"
            "    hold.run(cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m for m in msgs), msgs,
        )

    def test_shadowing_local_is_not_mistaken_for_the_top_level_function(self):
        # A local ``inner`` (a bare-Fun-retaining lambda) shadows the
        # same-named top-level borrow function; the forward through it must
        # stay an escape rather than trust the top-level signature.
        src = (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    let inner = fun (f: Fun() -> Unit) -> Unit => f()\n"
            "    inner(cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m for m in msgs), msgs,
        )


class TestBorrowForwardingStructShadow(unittest.TestCase):
    """A struct-pattern SHORTHAND binder (``let Box { inner } = b``, and the
    same inside a match arm) introduces a LOCAL named ``inner``. The real
    call ``inner(cb)`` binds to that local, so the borrow resolver must NOT
    trust a same-named top-level ``borrow`` signature. The shorthand binder
    is a bare ``str`` field on the pattern, not an ``IdentPat`` node, so a
    node-only shadow scan misses it; a miss would let the local (a bare Fun
    that may retain or return the callback) pass as a verified invoke-only
    forward, defeating the guarantee the relaxation composes on.
    """

    def _reject(self, src: str) -> list[str]:
        r = _analyze(src)
        self.assertFalse(r.ok, "expected the shadowed forward to be rejected")
        return [e.message for e in r.errors]

    def _ceiling_provable(self, src: str, fn_name: str) -> bool:
        # Pin the per-function ceiling signal directly. ``build_manifest``
        # recomputes the invoke-only verdict from the body in hand, so it is
        # meaningful even when the analyzer rejected the program.
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        m = build_manifest(
            module, filename="m.capa", expr_labels=result.expr_labels,
        )
        return _func(m, fn_name)["ceiling_authority_provable"]

    _BOX = (
        "type Box {\n"
        "    inner: Fun(Fun() -> Unit) -> Unit\n"
        "}\n"
        "\n"
    )
    _INNER = (
        "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
        "    cb()\n"
        "    return\n"
        "\n"
    )

    def test_let_struct_shorthand_shadow_is_rejected(self):
        src = (
            self._BOX
            + "fun make_box() -> Box\n"
            "    return Box { inner: fun (f: Fun() -> Unit) -> Unit => f() }\n"
            "\n"
            + self._INNER
            + "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    let b = make_box()\n"
            "    let Box { inner } = b\n"
            "    inner(cb)\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m and "escapes" in m for m in msgs),
            msgs,
        )
        # The per-function ceiling signal must NOT be provable either: the
        # forward is a genuine escape, not a verified invoke-only inlet.
        self.assertFalse(self._ceiling_provable(src, "outer"))

    def test_match_arm_struct_shorthand_shadow_is_rejected(self):
        src = (
            self._BOX
            + "fun make_opt() -> Option<Box>\n"
            "    return Some("
            "Box { inner: fun (f: Fun() -> Unit) -> Unit => f() })\n"
            "\n"
            + self._INNER
            + "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    match make_opt()\n"
            "        Some(Box { inner }) ->\n"
            "            inner(cb)\n"
            "        None ->\n"
            "            return\n"
            "    return\n"
        )
        msgs = self._reject(src)
        self.assertTrue(
            any("borrow parameter 'cb'" in m and "escapes" in m for m in msgs),
            msgs,
        )
        self.assertFalse(self._ceiling_provable(src, "outer"))

    def test_struct_shorthand_that_does_not_shadow_still_compiles(self):
        # An ordinary destructure whose binder does NOT collide with the
        # forwarded borrow function must keep compiling: the shadow scan is
        # precise, never a blanket ban on destructuring near a forward.
        src = (
            "type Pair {\n"
            "    left: Int\n"
            "}\n"
            "\n"
            "fun make_pair() -> Pair\n"
            "    return Pair { left: 5 }\n"
            "\n"
            + self._INNER
            + "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    let Pair { left } = make_pair()\n"
            "    let _keep = left\n"
            "    inner(cb)\n"
            "    return\n"
        )
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertTrue(self._ceiling_provable(src, "outer"))


class TestBorrowForwardingCrossModule(unittest.TestCase):
    """Scope trap: the relaxation is intra-module only. A forward whose
    callee resolves in ANOTHER package is rejected, because ``borrow``-ness
    is not carried across the module boundary (it is not in the exported
    interface). Fail closed, with the same "escapes here" message."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_borrow_xmod_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_forward_into_a_vendored_dependency_is_rejected(self):
        root = self.tmp / "prod"
        _write(root, "capa.toml", (
            '[package]\nname = "prod"\nversion = "0.1.0"\n\n'
            '[dependencies.dep]\n'
            'git = "https://github.com/example/dep"\ntag = "v1"\n'
        ))
        _write(root, "main.capa", (
            "import dep.lib\n"
            "\n"
            "pub fun outer(borrow cb: Fun() -> Unit) -> Unit\n"
            "    inner(cb)\n"
            "    return\n"
        ))
        _write(root, "vendor/dep/capa.toml",
               '[package]\nname = "dep"\nversion = "0.1.0"\n')
        _write(root, "vendor/dep/lib.capa", (
            "pub fun inner(borrow cb: Fun() -> Unit) -> Unit\n"
            "    cb()\n"
            "    return\n"
        ))
        root = root.resolve()
        search = [root]
        for vendor in root.rglob("vendor"):
            if vendor.is_dir():
                search.append(vendor)
        filename = str(root / "main.capa")
        source = Path(filename).read_text(encoding="utf-8")
        loader = ModuleLoader(search_paths=search)
        linked = loader.load_root(source, filename)
        result = analyze(
            linked.module, source=source, filename=filename,
            sources=linked.sources, module_privates=linked.module_privates,
        )
        self.assertFalse(result.ok, "cross-module forward must be rejected")
        self.assertTrue(
            any(
                "borrow parameter 'cb'" in e.message and "escapes" in e.message
                for e in result.errors
            ),
            [e.message for e in result.errors],
        )


# The real proof, reduced to the shape the ceiling reacts to: a package
# whose ``serve_connections(borrow handler)`` forwards the handler into
# ``serve_once(borrow handler)`` in the same file. Both hold only
# ``Serve``; the forward is what previously voided the ceiling.
SERVE_FORWARD_SRC = (
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
    "pub fun serve_connections("
    "serve: Serve, borrow handler: Fun(Request) -> Response, count: Int)"
    " -> Response\n"
    "    var served = 0\n"
    "    var last = Response { code: 0 }\n"
    "    while served < count\n"
    "        last = serve_once(serve, handler)\n"
    "        served = served + 1\n"
    "    return last\n"
)


class TestBorrowForwardingServerShape(unittest.TestCase):
    """The capa_server proof: ``serve_connections`` forwards ``handler``
    into ``serve_once``, both ``borrow``, and the package ceiling passes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="capa_borrow_srv_"))
        self.addCleanup(lambda: shutil.rmtree(self.tmp, ignore_errors=True))

    def test_forwarding_server_passes_the_serve_ceiling(self):
        root = self.tmp / "srv"
        _write(root, "capa.toml", (
            '[package]\nname = "srv"\nversion = "0.1.0"\n\n'
            '[capabilities]\nmax = ["Serve"]\n'
        ))
        _write(root, "server.capa", SERVE_FORWARD_SRC)
        _manifest_out, composed = _compose(root, "server.capa")
        ceilings = composed["capability_ceilings"]
        self.assertTrue(ceilings["checked"])
        self.assertTrue(ceilings["pass"], ceilings["violations"])

    def test_both_functions_ceiling_signal_is_provable(self):
        m = _manifest(SERVE_FORWARD_SRC)
        once = _func(m, "serve_once")
        conns = _func(m, "serve_connections")
        self.assertTrue(once["ceiling_authority_provable"])
        self.assertTrue(conns["ceiling_authority_provable"])
        # The strict flag stays False for both (there IS a Fun in the sig).
        self.assertFalse(once["authority_provable_from_types"])
        self.assertFalse(conns["authority_provable_from_types"])


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
