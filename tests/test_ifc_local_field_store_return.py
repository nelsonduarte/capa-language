"""Cross-function local field-store RETURN laundering (closed false
negative + caller-side field precision).

A ``@secret`` introduced INSIDE a callee -- a declared-``@secret`` field
read, or an opaque call that returns one -- that is field-STORED into a
LOCAL struct which is then RETURNED and sunk by the caller was
``--check``-clean at both tiers and leaked on both backends (the
``L2_field`` residual). The direct field store recorded only a
cross-function mutation EFFECT (which needs a parameter-rooted target, so a
fresh local recorded nothing) and never raised the local's read-back /
return CONTENT.

The closure:

* a direct field store ``obj.f = v`` now content-writes the root at the
  STORED field's path, so a same-body read-back of that path (or a whole
  read) observes it while a disjoint public sibling stays clean
  (``I_barelocal``);
* a struct-literal RHS is leaf-seeded per leaf path (Part 2), so a clean
  leaf of a stored sub-struct stays clean;
* the return-read records the returned LOCAL's content per path (Part 3),
  so the caller observes the returned struct's field-keyed taint. A
  ``return o.sub`` / call / literal / unwrap / param falls back to the
  whole-value carrier ``()`` (recording a source-relative path there would
  misplace the taint -- the ``G_subreturn`` trap);
* a container mutation on a field chain rooted at a LOCAL
  (``box.items.push(secret)``) records content at the container's field
  path.

The return channel is whole-value, so a sink of ANY field of a returned
struct that received an inside-callee secret flags (an accepted
over-approximation for the LEAK shapes ``C_nested`` / ``E_opaque``); the
per-field precision is delivered intra-body (``I_barelocal``).
"""

import shutil
import unittest

from capa import Lexer, Parser, analyze, transpile
from capa.ir import compile_wasm


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str, fn: str) -> str:
    """Opt the caller ``fn`` (holding the cross-function call) into
    ``@strict_ifc`` -- the tier where the flow is a hard error."""
    return src.replace("fun " + fn + "(", "@strict_ifc()\nfun " + fn + "(", 1)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


def _capture(thunk) -> str:
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


def _run_py(src: str) -> str:
    module = _parse(src)
    result = analyze(module, source=src)
    code = transpile(module, types=result.types, bindings=result.bindings)
    ns: dict = {"__name__": "__main__"}
    return _capture(lambda: exec(compile(code, "<lfsr>", "exec"), ns))


def _run_wasm(src: str) -> str:
    from capa.runtime._wasm_host import WasmHost
    module = _parse(src)
    result = analyze(module, source=src)
    blob = compile_wasm(module, types=result.types)
    return _capture(lambda: WasmHost().run_main(blob))


def _wasm_unavailable():
    if shutil.which("wasm-tools") is None:
        return "wasm-tools not installed"
    try:
        import wasmtime  # noqa: F401
    except ImportError:
        return "wasmtime-py not installed"
    return None


_EMP = "type Emp { iban: @secret String }\n"
_BOX = "type Box { field: String }\n"
TOK = "const TOKEN: @secret String = \"s3cr3t\"\n"


# ---- the LEAK shapes: FLAGGED after Commit 3, run and print the secret ----

# L2_field: callee reads a declared-@secret field, stores it into a fresh
# local struct, returns the local; the caller sinks the stored field.
L2_FIELD = (_EMP + _BOX +
    "fun leak(e: Emp) -> Box\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    b.field = e.iban\n"
    "    return b\n"
    "fun main(stdio: Stdio)\n"
    "    let emp = Emp { iban: \"s3cr3t\" }\n"
    "    let b = leak(emp)\n"
    "    stdio.println(b.field)\n")

# C_nested: a struct built from a returned struct, then a nested field sunk.
C_NESTED = (_EMP + _BOX + "type Wrapper { sub: Box }\n"
    "fun mk(e: Emp) -> Box\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    b.field = e.iban\n"
    "    return b\n"
    "fun caller(e: Emp, stdio: Stdio)\n"
    "    let inner = mk(e)\n"
    "    let outer = Wrapper { sub: inner }\n"
    "    stdio.println(outer.sub.field)\n"
    "fun main(stdio: Stdio)\n"
    "    let emp = Emp { iban: \"s3cr3t\" }\n"
    "    caller(emp, stdio)\n")

# E_opaque: the stored field value comes from an OPAQUE call that returns a
# declared-@secret field.
E_OPAQUE = (_EMP + _BOX +
    "fun getsecret(e: Emp) -> String\n"
    "    return e.iban\n"
    "fun leak(e: Emp) -> Box\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    b.field = getsecret(e)\n"
    "    return b\n"
    "fun main(stdio: Stdio)\n"
    "    let emp = Emp { iban: \"s3cr3t\" }\n"
    "    let b = leak(emp)\n"
    "    stdio.println(b.field)\n")

_LEAKS = {"L2_field": (L2_FIELD, "main"),
          "C_nested": (C_NESTED, "caller"),
          "E_opaque": (E_OPAQUE, "main")}


class TestLocalFieldStoreReturnLeak(unittest.TestCase):
    """L2_field, C_nested and E_opaque are FLAGGED at both tiers on both
    backends (the closed false negative)."""

    def test_flagged_default_tier(self):
        for name, (src, _caller) in _LEAKS.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_hard_error_under_strict(self):
        for name, (src, caller) in _LEAKS.items():
            with self.subTest(shape=name):
                rs = _analyze(_strict(src, caller))
                self.assertFalse(rs.ok)
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, (src, _caller) in _LEAKS.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- I_barelocal: intra-body field-store precision (FP-class-2 pair). A
# store into one field of a local taints only that field; a disjoint sibling
# stays clean. The secret is a PLAIN parameter so only the summary sees it. --

_TWO = "type TwoField { a: String, b: String }\n"

I_BARELOCAL_TAINTED = (TOK + _TWO +
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var box: TwoField = TwoField { a: \"public\", b: \"public\" }\n"
    "    box.a = secret\n"
    "    stdio.println(box.a)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n")

I_BARELOCAL_CLEAN = (TOK + _TWO +
    "fun leak(secret: String, stdio: Stdio)\n"
    "    var box: TwoField = TwoField { a: \"public\", b: \"public\" }\n"
    "    box.a = secret\n"
    "    stdio.println(box.b)\n"
    "fun main(stdio: Stdio)\n"
    "    leak(TOKEN, stdio)\n")


class TestBareLocalFieldPrecision(unittest.TestCase):
    """Storing a secret into ``box.a`` taints reading ``box.a`` (FLAGGED) but
    not the disjoint sibling ``box.b`` (CLEAN)."""

    def test_stored_field_read_flagged(self):
        r = _analyze(I_BARELOCAL_TAINTED)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(I_BARELOCAL_TAINTED, "main"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])

    def test_sibling_field_read_clean(self):
        r = _analyze(I_BARELOCAL_CLEAN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(I_BARELOCAL_CLEAN, "main"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_both_backends_run(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(I_BARELOCAL_TAINTED), "s3cr3t\n")
        self.assertEqual(_run_py(I_BARELOCAL_CLEAN), "public\n")
        if skip is None:
            self.assertEqual(_run_wasm(I_BARELOCAL_TAINTED), "s3cr3t\n")
            self.assertEqual(_run_wasm(I_BARELOCAL_CLEAN), "public\n")


# ---- anti-FN: shapes that were caught before Commit 3 must STAY flagged. --

# G_subreturn: ``return h.sub`` returns a sub-struct holding a @secret field;
# recording the source-relative path would drop the caller's taint. Falls
# back to the whole-value carrier, so it stays flagged.
G_SUBRETURN = (_EMP + "type Holder { sub: Emp }\n"
    "fun leak(h: Holder) -> Emp\n"
    "    return h.sub\n"
    "fun main(stdio: Stdio)\n"
    "    let h = Holder { sub: Emp { iban: \"s3cr3t\" } }\n"
    "    let e = leak(h)\n"
    "    stdio.println(e.iban)\n")

# H_alias: ``let a = e; return a`` returns a whole-value alias of a
# secret-bearing parameter; stays flagged.
H_ALIAS = (_EMP +
    "fun leak(e: Emp) -> Emp\n"
    "    let a = e\n"
    "    return a\n"
    "fun main(stdio: Stdio)\n"
    "    let emp = Emp { iban: \"s3cr3t\" }\n"
    "    let out = leak(emp)\n"
    "    stdio.println(out.iban)\n")

_ANTI_FN = {"G_subreturn": G_SUBRETURN, "H_alias": H_ALIAS}


class TestReturnReadStaysSound(unittest.TestCase):
    """The per-path return-read must not introduce a false negative: a
    sub-struct return and a whole-value alias return stay flagged."""

    def test_stays_flagged(self):
        for name, src in _ANTI_FN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _ANTI_FN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- no-FP dual: a returned struct that received an inside-callee secret
# but is NEVER SUNK stays clean (mirrors
# test_whole_secret_struct_that_escapes_is_clean, direct-store variant). --

ESCAPES_CLEAN = (_EMP + _BOX +
    "fun leak(e: Emp) -> Box\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    b.field = e.iban\n"
    "    return b\n"
    "fun main(stdio: Stdio)\n"
    "    let emp = Emp { iban: \"s3cr3t\" }\n"
    "    let b = leak(emp)\n"
    "    stdio.println(\"done\")\n")


class TestReturnedButNotSunkIsClean(unittest.TestCase):
    """A local that received an inside-callee secret and is returned but
    NEVER sunk raises no diagnostic."""

    def test_clean(self):
        r = _analyze(ESCAPES_CLEAN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(ESCAPES_CLEAN, "main"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_runs_clean_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(ESCAPES_CLEAN), "done\n")
        if skip is None:
            self.assertEqual(_run_wasm(ESCAPES_CLEAN), "done\n")


if __name__ == "__main__":
    unittest.main()
