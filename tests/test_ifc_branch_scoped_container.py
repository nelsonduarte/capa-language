"""Branch-scoped container-mutation taint (a coupled soundness fix).

Two defects both stemmed from the container-mutation taint being flat /
monotone across branches while the read reflected it everywhere:

* C1 (false POSITIVE): a secret pushed DIRECTLY into a fresh local
  (``xs.push(secret)``) in one branch of an ``if`` / ``elif`` / ``else`` or
  ``match``, then read in a MUTUALLY-EXCLUSIVE sibling branch, was flagged
  (a warning, a hard error under ``@strict_ifc``) on leak-free code.
* S1-match (false NEGATIVE / real leak): a secret pushed into a fresh local
  inside a ``match`` arm and read (or stored into a parameter) AFTER the
  match leaked at runtime but was NOT flagged, while the identical ``if``
  shape was.

The fix keeps two separate branch-scoped channels, each isolated per branch
and deferred-unioned back, mirroring the 1.26.0 cross-function content
channel:

* INTRA (``capa/analyzer/_ifc.py``): a per-binding container-mutation taint
  map, joined into a binding's label only on a READ; the shared
  ``Symbol.label`` / field labels / alias groups / escape tracking stay
  flat.
* SUMMARY (``capa/analyzer/_ifc_summary.py``): the inline container-mutator
  read-back is routed into the existing branch-scoped content channel
  instead of the flat ``env`` (whose alias / mutation-target role is left
  untouched).

Both close C1 (sibling isolation) while keeping S1 flagged (deferred union
carries the push to a read after the construct). Out of scope, still
disclosed residuals: the ASSIGNMENT sibling-branch false positive (A1), and
the general list-aliasing false negatives (``var alias = xs``, embed-then
-mutate).
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
    """Opt the function ``fn`` into ``@strict_ifc`` -- the function holding
    the sink for an intra-procedural leak, or the caller for a
    cross-function one."""
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
    return _capture(lambda: exec(compile(code, "<branch-ct>", "exec"), ns))


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


TOK = "const TOKEN: @secret String = \"s3cr3t\"\n"
PUSH = "fun push_it(xs: List<String>, v: String)\n    xs.push(v)\n"
RD = ("fun read_print(xs: List<String>, stdio: Stdio)\n"
      "    match xs.get(0)\n"
      "        Some(x) -> stdio.println(x)\n"
      "        None -> stdio.println(\"empty\")\n")


# ---- C1: direct push in one branch, read in a mutually-exclusive sibling
# (leak-free; ``main`` runs the READ branch, printing the public "empty") --

C1_SUMMARY_IF = (TOK + RD +
    "fun leak(secret: String, flag: Bool, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        xs.push(secret)\n"
    "    else\n        read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, false, stdio)\n")

C1_SUMMARY_WHILE = (TOK + RD +
    "fun leak(secret: String, flag: Bool, n: Int, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        var i: Int = 0\n        while i < n\n"
    "            xs.push(secret)\n            i = i + 1\n"
    "    else\n        read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, false, 1, stdio)\n")

C1_SUMMARY_MATCH = (TOK + RD +
    "fun leak(secret: String, flag: Bool, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n"
    "        false -> read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, false, stdio)\n")

C1_INTRA_IF = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        xs.push(secret)\n"
    "    else\n        match xs.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, false)\n")

C1_INTRA_MATCH = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n"
    "        false ->\n            match xs.get(0)\n"
    "                Some(x) -> stdio.println(x)\n"
    "                None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, false)\n")

# {name: (src, strict_fn)} -- all print "empty" at runtime.
_C1_CLEAN = {
    "summary_if": (C1_SUMMARY_IF, "main"),
    "summary_while": (C1_SUMMARY_WHILE, "main"),
    "summary_match": (C1_SUMMARY_MATCH, "main"),
    "intra_if": (C1_INTRA_IF, "leak"),
    "intra_match": (C1_INTRA_MATCH, "leak"),
}


# ---- S1-match: push in a match arm, read / store-into-param AFTER the
# match (a real leak; prints the secret) ----

S1_MATCH_READ = (TOK + RD +
    "fun leak(secret: String, flag: Bool, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n        false -> ()\n"
    "    read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, true, stdio)\n")

S1_MATCH_STORE = (TOK +
    "type Box { field: String }\n"
    "fun stash(b: Box, secret: String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n        false -> ()\n"
    "    match xs.get(0)\n        Some(x) -> b.field = x\n        None -> ()\n"
    "fun main(stdio: Stdio)\n"
    "    var b: Box = Box { field: \"public\" }\n"
    "    stash(b, TOKEN, true)\n"
    "    stdio.println(b.field)\n")

_S1_MATCH_LEAK = {
    "read_after_match": (S1_MATCH_READ, "main"),
    "store_into_param_after_match": (S1_MATCH_STORE, "main"),
}


# ---- must-stay-flagged (the fix must not weaken these) ----

S1_IF_SUMMARY = (TOK + RD +
    "fun leak(secret: String, flag: Bool, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        xs.push(secret)\n"
    "    read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, true, stdio)\n")

S1_INTRA_IF = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        xs.push(secret)\n"
    "    match xs.get(0)\n        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

S1_INTRA_MATCH = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n        false -> ()\n"
    "    match xs.get(0)\n        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

S1_INTRA_WHILE = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n    var i: Int = 0\n"
    "    while i < 1\n        xs.push(secret)\n        i = i + 1\n"
    "    match xs.get(0)\n        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

REAL_LEAK_BOTH_ARMS = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var xs: List<String> = []\n"
    "    match flag\n        true -> xs.push(secret)\n"
    "        false -> xs.push(secret)\n"
    "    match xs.get(0)\n        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

XFN_EFFECT = (TOK + PUSH + RD +
    "fun leak(secret: String, flag: Bool, stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    if flag\n        push_it(xs, secret)\n"
    "    read_print(xs, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(TOKEN, true, stdio)\n")

_MUST_STAY_FLAGGED = {
    "s1_if_summary": (S1_IF_SUMMARY, "main"),
    "s1_intra_if": (S1_INTRA_IF, "leak"),
    "s1_intra_match": (S1_INTRA_MATCH, "leak"),
    "s1_intra_while": (S1_INTRA_WHILE, "leak"),
    "real_leak_both_arms": (REAL_LEAK_BOTH_ARMS, "leak"),
    "xfn_effect": (XFN_EFFECT, "main"),
}

# Embed alias mutated inside a branch, then read after: analyzer-only (the
# entry point is ``caller``, not a runnable ``main``).
EMBED_AFTER_BRANCH = (
    "type Inner { sv: String }\ntype Outer { inner: Inner }\n"
    "fun put(box: Inner, v: String)\n    box.sv = v\n"
    "fun caller(stdio: Stdio, token: @secret String, b: Inner, flag: Bool)\n"
    "    let o = Outer { inner: b }\n"
    "    if flag\n        put(b, token)\n"
    "    stdio.println(o.inner.sv)\n")


class TestC1FalsePositiveClosed(unittest.TestCase):
    """C1: a direct push in one branch read in a mutually-exclusive sibling
    is leak-free and must NOT be flagged, for if / while / match, on the
    intra-procedural and the cross-function tiers, both backends."""

    def test_default_tier_is_clean(self):
        for name, (src, _fn) in _C1_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])

    def test_strict_tier_is_clean(self):
        for name, (src, fn) in _C1_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, fn))
                self.assertEqual(len(_flow_errors(r)), 0,
                                 [e.message for e in r.errors])

    def test_both_backends_are_leak_free(self):
        skip = _wasm_unavailable()
        for name, (src, _fn) in _C1_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "empty\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "empty\n")


class TestS1MatchLeakClosed(unittest.TestCase):
    """S1-match: a push in a match arm read (or stored into a param) after
    the match is a real leak and must now be flagged -- a warning by
    default, a hard error under @strict_ifc -- both backends."""

    def test_default_tier_flags(self):
        for name, (src, _fn) in _S1_MATCH_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_strict_tier_errors(self):
        for name, (src, fn) in _S1_MATCH_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, fn))
                self.assertFalse(r.ok)
                self.assertGreaterEqual(len(_flow_errors(r)), 1,
                                        [e.message for e in r.errors])

    def test_both_backends_print_the_secret(self):
        skip = _wasm_unavailable()
        for name, (src, _fn) in _S1_MATCH_LEAK.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


class TestMustStayFlagged(unittest.TestCase):
    """The fix must not weaken any real leak: S1 for if / match / while, the
    both-arms real-leak baseline, the cross-function-effect case, and the
    embed-mutated-in-a-branch case all stay flagged."""

    def test_default_tier_flags(self):
        for name, (src, _fn) in _MUST_STAY_FLAGGED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_strict_tier_errors(self):
        for name, (src, fn) in _MUST_STAY_FLAGGED.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, fn))
                self.assertFalse(r.ok)
                self.assertGreaterEqual(len(_flow_errors(r)), 1,
                                        [e.message for e in r.errors])

    def test_both_backends_print_the_secret(self):
        skip = _wasm_unavailable()
        for name, (src, _fn) in _MUST_STAY_FLAGGED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")

    def test_embed_mutated_in_branch_stays_flagged(self):
        r = _analyze(EMBED_AFTER_BRANCH)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(EMBED_AFTER_BRANCH, "caller"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])


if __name__ == "__main__":
    unittest.main()
