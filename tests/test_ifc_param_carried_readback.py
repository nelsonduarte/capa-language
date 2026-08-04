"""Cross-function param-carried container/field read-back (closed false
negative).

A ``@secret`` value arriving as a FUNCTION PARAMETER of a caller ``leak``
is passed to a user callee that mutates a FRESH LOCAL ``leak`` created (an
empty ``List`` / ``Map`` / ``Set`` / struct), inserting the secret into
it. ``leak`` then reads the value back out of the local and sends it to a
public sink. Because the secret is only a plain parameter of ``leak`` (not
an intra-procedural secret there), the intra-procedural pass cannot see
it: only ``leak``'s cross-function SUMMARY can, by reflecting the callee's
tainted write on the read-back of the local.

Before the fix ``capa/analyzer/_ifc_summary.py`` recorded the callee's
mutation against ``leak``'s own parameters (the mutation-TARGET channel)
but never raised the caller-local's read-back CONTENT, so ``leak``'s
summary did not mark the parameter sink-reaching and the leak crossed to
``main`` unflagged. The fix adds a distinct, ADDITIVE content channel:
the callee's translated write raises the local's content label, joined
into ``_taint_of`` on a read-back, applied REGARDLESS of whether the
local is itself a writable mutation target of ``leak``. That independence
is load-bearing: on the ``1ee06ae`` base the mutation-target precision fix
narrows the target set to EMPTY for exactly these shapes (a fresh local,
or one seeded from a built-in-immutable-typed parameter the precision fix
drops), so a content write gated on a non-empty target set would close
nothing.

The distinction from ``tests/test_ifc_container_effect.py`` (and the
``TestRealLeaksStayCaught`` corpus in
``tests/test_ifc_immutable_target_drop.py``): those place the secret at
the frame that OWNS the local, so the intra-procedural pass catches them.
These place the secret as a PARAMETER of an intermediate function, so only
the summary-side content channel this fix introduces can catch them.
"""

import shutil
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str) -> str:
    """Opt ``main`` -- which holds the CALL that raises the cross-function
    diagnostic -- into ``@strict_ifc``, the tier where the same flow is a
    hard error."""
    return src.replace("fun main(", "@strict_ifc()\nfun main(", 1)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


# ---- program builders --------------------------------------------------
#
# ``main`` passes a module-level ``@secret`` const into ``leak``'s plain
# ``secret`` parameter, so the whole program is self-contained and runnable
# on both backends without environment plumbing while still exercising the
# param-carried shape.

_PUSH_IT = (
    "fun push_it(xs: List<String>, v: String)\n"
    "    xs.push(v)\n"
)

LIST = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    + _PUSH_IT +
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    push_it(xs, secret)\n"
    "    match xs.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

MAP = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    "fun stash(m: Map<String, String>, v: String)\n"
    "    m.set(\"k\", v)\n"
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var m: Map<String, String> = new_map()\n"
    "    stash(m, secret)\n"
    "    match m.get(\"k\")\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

SET = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    "fun stash(xs: Set<String>, v: String)\n"
    "    xs.add(v)\n"
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var xs: Set<String> = new_set()\n"
    "    stash(xs, secret)\n"
    "    for x in xs.to_list()\n"
    "        stdio.println(x)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

STRUCT = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    "type Box { field: String }\n"
    "fun stash(b: Box, v: String)\n"
    "    b.field = v\n"
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    stash(b, secret)\n"
    "    stdio.println(b.field)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

TWO_HOP = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    "fun innermost(xs: List<String>, v: String)\n"
    "    xs.push(v)\n"
    "fun middle(xs: List<String>, v: String)\n"
    "    innermost(xs, v)\n"
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    middle(xs, secret)\n"
    "    match xs.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

# The sink is the trailing (implicit-return) expression of ``leak``, so
# ``_analyze_body`` walks it twice (once in the block, once as the block
# tail); the content join must be idempotent for the diagnostic count to
# stay 1.
TAIL = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    + _PUSH_IT +
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    push_it(xs, secret)\n"
    "    match xs.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n"
)

# Seeded: a PUBLIC value is pushed inline FIRST, so the local's taint set
# already carries a built-in-immutable (String) parameter's index that the
# precision fix drops from the mutation-target set (making it empty). The
# secret is then pushed cross-function. The content channel must still fire.
SEEDED = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    + _PUSH_IT +
    "fun leak(tag: String, secret: String, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    xs.push(tag)\n"
    "    push_it(xs, secret)\n"
    "    match xs.get(1)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    leak(\"publictag\", TOKEN, stdio)\n"
)


_MUST_CATCH = {
    "list": LIST,
    "map": MAP,
    "set": SET,
    "struct_field_store": STRUCT,
    "two_hop": TWO_HOP,
    "tail_position": TAIL,
    "seeded_local_string": SEEDED,
}


class TestParamCarriedReadbackFlagged(unittest.TestCase):
    """Every param-carried read-back shape is newly caught: a warning by
    default, a hard error under ``@strict_ifc`` -- the same two-tier
    discipline the inline and other cross-function checks follow."""

    def test_default_tier_is_a_single_warning(self):
        for name, src in _MUST_CATCH.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                w = _flow_warnings(r)
                self.assertEqual(len(w), 1, [x.message for x in r.warnings])
                self.assertIn("passed to 'leak'", w[0].message)
                self.assertEqual(len(_flow_errors(r)), 0)

    def test_strict_tier_is_a_single_hard_error(self):
        for name, src in _MUST_CATCH.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src))
                self.assertFalse(r.ok, "strict tier must be a hard error")
                e = _flow_errors(r)
                self.assertEqual(len(e), 1, [x.message for x in r.errors])
                self.assertIn("passed to 'leak'", e[0].message)


class TestSeededImmutableTypeCorpus(unittest.TestCase):
    """The seed that makes the mutation-target set empty is a
    built-in-immutable parameter the precision fix drops. Confirm the
    content channel stays INDEPENDENT of the (empty) target set for every
    such type, not only ``String``: ``Int`` / ``Float`` / ``Bool`` /
    ``Char`` (a fresh local seeded by pushing the typed parameter) and a
    built-in ``Serve`` CAPABILITY (a fresh local seeded from a value the
    capability produced). A content write gated on the target set would
    close none of these."""

    @staticmethod
    def _scalar(elem: str, secret_val: str, tag_val: str) -> str:
        return (
            f"const TOKEN: @secret {elem} = {secret_val}\n"
            f"fun push_it(xs: List<{elem}>, v: {elem})\n"
            "    xs.push(v)\n"
            f"fun leak(tag: {elem}, secret: {elem}, stdio: Stdio)\n"
            f"    var xs: List<{elem}> = []\n"
            "    xs.push(tag)\n"
            "    push_it(xs, secret)\n"
            "    match xs.get(1)\n"
            "        Some(x) -> stdio.println(\"${x}\")\n"
            "        None -> stdio.println(\"empty\")\n"
            "fun main(stdio: Stdio)\n"
            f"    leak({tag_val}, TOKEN, stdio)\n"
        )

    _SCALARS = {
        "Int": ("42", "7"),
        "Float": ("3.5", "1.0"),
        "Bool": ("true", "false"),
        "Char": ("'z'", "'a'"),
    }

    # A fresh ``List<Int>`` seeded from bytes the built-in ``Serve``
    # capability produced (``serve.recv`` -> ``chunk`` -> its length), so
    # the local's taint set carries the ``Serve`` (and no other) parameter
    # index, which the precision fix drops. The callee then pushes the
    # secret.
    _CAP = (
        "const TOKEN: @secret Int = 42\n"
        "fun push_it(xs: List<Int>, v: Int)\n"
        "    xs.push(v)\n"
        "fun leak(serve: Serve, secret: Int, stdio: Stdio)\n"
        "    var xs: List<Int> = []\n"
        "    let conn = 0\n"
        "    let chunk = match serve.recv(conn, 10)\n"
        "        Ok(c)  -> c\n"
        "        Err(_) -> []\n"
        "    xs.push(chunk.length())\n"
        "    push_it(xs, secret)\n"
        "    match xs.get(1)\n"
        "        Some(x) -> stdio.println(\"${x}\")\n"
        "        None -> stdio.println(\"empty\")\n"
        "fun main(serve: Serve, stdio: Stdio)\n"
        "    leak(serve, TOKEN, stdio)\n"
    )

    def test_scalar_immutable_seed_still_closes(self):
        for elem, (secret_val, tag_val) in self._SCALARS.items():
            with self.subTest(ty=elem):
                src = self._scalar(elem, secret_val, tag_val)
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 1,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src))
                self.assertFalse(rs.ok)
                self.assertEqual(len(_flow_errors(rs)), 1,
                                 [e.message for e in rs.errors])

    def test_builtin_capability_seed_still_closes(self):
        r = _analyze(self._CAP)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(self._CAP))
        self.assertFalse(rs.ok)
        self.assertEqual(len(_flow_errors(rs)), 1,
                         [e.message for e in rs.errors])


class TestNoRegression(unittest.TestCase):
    """Shapes already caught on the base must STAY caught (the fix only
    ADDS a channel; it must not perturb these)."""

    # The callee RETURNS the tainted container; the caller binds the
    # result. Caught by the return-effect summary, not the content channel.
    _RETURN_EFFECT = (
        "const TOKEN: @secret String = \"s3cr3t\"\n"
        "fun wrap(v: String) -> List<String>\n"
        "    var xs: List<String> = []\n"
        "    xs.push(v)\n"
        "    return xs\n"
        "fun leak(secret: String, stdio: Stdio)\n"
        "    let xs = wrap(secret)\n"
        "    match xs.get(0)\n"
        "        Some(x) -> stdio.println(x)\n"
        "        None -> stdio.println(\"empty\")\n"
        "fun main(stdio: Stdio)\n"
        "    leak(TOKEN, stdio)\n"
    )

    # The secret enters at the frame that OWNS the local (``main`` reads it
    # from ``env`` and pushes it through the callee), the sibling shape
    # already caught by the main walk.
    _OWNER_FRAME = (
        "fun stash(xs: List<String>, v: String)\n"
        "    xs.push(v)\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: List<String> = []\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> stash(xs, k)\n"
        "        None -> stash(xs, \"none\")\n"
        "    match xs.get(0)\n"
        "        Some(v) -> stdio.println(v)\n"
        "        None -> stdio.println(\"empty\")\n"
    )

    # The inline analog: no callee, the push is written directly in the
    # frame that owns the local.
    _INLINE = (
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: List<String> = []\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> xs.push(k)\n"
        "        None -> xs.push(\"none\")\n"
        "    match xs.get(0)\n"
        "        Some(v) -> stdio.println(v)\n"
        "        None -> stdio.println(\"empty\")\n"
    )

    def test_return_effect_variant_stays_caught(self):
        r = _analyze(self._RETURN_EFFECT)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(self._RETURN_EFFECT))
        self.assertFalse(rs.ok)
        self.assertEqual(len(_flow_errors(rs)), 1,
                         [e.message for e in rs.errors])

    def test_owner_frame_shape_stays_caught(self):
        r = _analyze(self._OWNER_FRAME)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_inline_analog_stays_caught(self):
        r = _analyze(self._INLINE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])


class TestNoFalsePositive(unittest.TestCase):
    """Precision: the additive content channel must not fire where no
    secret is actually read back."""

    def test_sibling_local_never_touched_is_clean(self):
        # The callee mutates ``secret_bag``; ``leak`` reads a DIFFERENT,
        # untouched ``public_bag``.
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            + _PUSH_IT +
            "fun leak(secret: String, stdio: Stdio)\n"
            "    var secret_bag: List<String> = []\n"
            "    var public_bag: List<String> = []\n"
            "    public_bag.push(\"plain\")\n"
            "    push_it(secret_bag, secret)\n"
            "    match public_bag.get(0)\n"
            "        Some(x) -> stdio.println(x)\n"
            "        None -> stdio.println(\"empty\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak(TOKEN, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_local_written_but_never_read_back_is_clean(self):
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            + _PUSH_IT +
            "fun leak(secret: String, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    push_it(xs, secret)\n"
            "    stdio.println(\"done\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak(TOKEN, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_declassified_push_is_clean(self):
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            + _PUSH_IT +
            "fun leak(secret: String, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    push_it(xs, declassify(secret, reason: \"audited\"))\n"
            "    match xs.get(0)\n"
            "        Some(x) -> stdio.println(x)\n"
            "        None -> stdio.println(\"empty\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak(TOKEN, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_tail_reads_before_it_pushes_is_clean(self):
        # The read-back sink executes BEFORE the callee push in program
        # order, so the content is not yet populated when the sink is
        # walked: no flow.
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            + _PUSH_IT +
            "fun leak(secret: String, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    xs.push(\"plain\")\n"
            "    match xs.get(0)\n"
            "        Some(x) -> stdio.println(x)\n"
            "        None -> stdio.println(\"empty\")\n"
            "    push_it(xs, secret)\n"
            "fun main(stdio: Stdio)\n"
            "    leak(TOKEN, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_whole_secret_struct_that_escapes_is_clean(self):
        # A fresh local the callee mutates with the secret ESCAPES ``leak``
        # (it is returned) rather than being read into a sink there; no
        # public sink is reached inside ``leak``, so its summary marks no
        # sink-reaching parameter.
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            "type Box { field: String }\n"
            "fun stash(b: Box, v: String)\n"
            "    b.field = v\n"
            "fun leak(secret: String) -> Box\n"
            "    var b: Box = Box { field: \"public\" }\n"
            "    stash(b, secret)\n"
            "    return b\n"
            "fun main(stdio: Stdio)\n"
            "    let b = leak(TOKEN)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_plain_public_data_is_clean(self):
        r = _analyze(
            _PUSH_IT +
            "fun leak(plain: String, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    push_it(xs, plain)\n"
            "    match xs.get(0)\n"
            "        Some(x) -> stdio.println(x)\n"
            "        None -> stdio.println(\"empty\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak(\"public\", stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])


# ---- both-backends run (the missed diagnostic is a real leak) ----------
#
# The warn tier does not block compilation, so each program still runs and
# prints the secret; assert both backends print it identically. This is
# what makes the fixed false negative a real leak rather than a paper one.

_RUNNABLE = {
    "list": (LIST, "s3cr3t\n"),
    "map": (MAP, "s3cr3t\n"),
    "set": (SET, "s3cr3t\n"),
    "struct_field_store": (STRUCT, "s3cr3t\n"),
    "two_hop": (TWO_HOP, "s3cr3t\n"),
    "tail_position": (TAIL, "s3cr3t\n"),
    "seeded_local_string": (SEEDED, "s3cr3t\n"),
}


class TestBothBackendsRunTheLeak(unittest.TestCase):
    def _capture(self, thunk) -> str:
        import io
        import sys
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            thunk()
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def _run_py(self, src: str) -> str:
        module = _parse(src)
        result = analyze(module, source=src)
        code = transpile(
            module, types=result.types, bindings=result.bindings,
        )
        ns: dict = {"__name__": "__main__"}
        return self._capture(
            lambda: exec(compile(code, "<param-carried>", "exec"), ns),
        )

    def _run_wasm(self, src: str) -> str:
        from capa.runtime._wasm_host import WasmHost
        module = _parse(src)
        result = analyze(module, source=src)
        blob = compile_wasm(module, types=result.types)
        return self._capture(lambda: WasmHost().run_main(blob))

    def test_python_backend_prints_the_secret(self):
        for name, (src, expected) in _RUNNABLE.items():
            with self.subTest(shape=name):
                self.assertEqual(self._run_py(src), expected)

    def test_both_backends_print_the_same(self):
        if shutil.which("wasm-tools") is None:
            self.skipTest("wasm-tools not installed")
        try:
            import wasmtime  # noqa: F401
        except ImportError:
            self.skipTest("wasmtime-py not installed")
        for name, (src, expected) in _RUNNABLE.items():
            with self.subTest(shape=name):
                py_out = self._run_py(src)
                wasm_out = self._run_wasm(src)
                self.assertEqual(py_out, wasm_out)
                self.assertEqual(py_out, expected)


if __name__ == "__main__":
    unittest.main()
