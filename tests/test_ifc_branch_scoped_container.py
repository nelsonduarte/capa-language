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

FIELD-CHAIN RECEIVER (the same channel, keyed on a field path): a mutator
called on a field chain rather than a plain identifier
(``bag.items.push(secret)``, ``bag.m.set(k, secret)``, ``bag.tags.add(
secret)``, nested ``o.inner.items.push``) was silently dropped and leaked.
It is now recorded on the ``(root-binding, field-path)`` the container lives
at and joined on a read of that path (or a container of it), so the leak
closes -- a warning by default, a hard error under ``@strict_ifc`` -- while
a public sibling field (``bag.other``), a mutually-exclusive branch's read,
and a loop-carried push stay exactly as precise as the plain-identifier
channel. Set.add / Map.set and depth > 1 are handled uniformly.

Disclosed residuals (still open after this fix): all are the same taint-keyed
-on-the-syntactic-root false negative, all members of the already-disclosed
list-aliasing class (``var alias = xs``, embed-then-mutate), and all would
need a points-to analysis (which Capa does not have) to close. Only the
field-chain mutate-then-read on the container's DECLARED root is closed here;
these reach the same container through a root the taint is not keyed on, so
they leak at runtime and stay UNFLAGGED:

* rename out of the struct: ``var lst = bag.items; lst.push(secret)`` taints
  the fresh local, not the field, so the ``bag.items`` read-back is not caught
  -- the plain ``var alias = xs`` rename lifted to a field (see
  ``TestFieldChainRenameResidualDisclosed``);
* whole-struct alias: ``var b2 = bag; b2.items.push(secret)`` then
  ``read bag.items`` mutates the same container through a DIFFERENT root
  symbol, which the root-keyed taint misses;
* cross-function whole-struct and embed-whole-struct: passing the whole
  ``bag`` to a callee that reads the field, and embedding a push-mutated sub
  -struct into an outer struct then reading through it, both reach the
  container through a root the taint is not keyed on.

Do not read the rename residual as the ONLY open case; these three are the
same class and remain open together.
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


# ---- loop-family REAL leaks (must stay flagged) ----
#
# Inside a while / for body the container-mutation taint is intentionally
# NOT branch-isolated (the two-pass loop walk makes a push anywhere in the
# body visible to every read in the body), a sound MAY over-approximation.
# These shapes genuinely leak across iterations, so they must stay flagged
# on BOTH backends -- the review's blindspot was that only a read-AFTER-loop
# case existed.

# Loop-carried read-before-write: the read at the top of the body is fed by
# the PREVIOUS iteration's push (iteration 2 reads iteration 1's secret).
LOOP_CARRIED_WHILE = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n    var i: Int = 0\n"
    "    while i < 2\n"
    "        match xs.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "        xs.push(secret)\n        i = i + 1\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

LOOP_CARRIED_FOR = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, items: List<String>)\n"
    "    var xs: List<String> = []\n"
    "    for it in items\n"
    "        match xs.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "        xs.push(secret)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, [\"a\", \"b\"])\n")

# Loop-VARYING sibling: the branch selector varies across iterations, so the
# push (one iteration) and the sibling read (a later iteration) DO both run.
VARYING_SIBLING_WHILE = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n    var i: Int = 0\n"
    "    while i < 2\n"
    "        if i == 0\n            xs.push(secret)\n"
    "        else\n            match xs.get(0)\n"
    "                Some(x) -> stdio.println(x)\n"
    "                None -> stdio.println(\"empty\")\n"
    "        i = i + 1\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

VARYING_SIBLING_FOR = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String, items: List<String>)\n"
    "    var xs: List<String> = []\n    var first: Bool = true\n"
    "    for it in items\n"
    "        if first\n            xs.push(secret)\n            first = false\n"
    "        else\n            match xs.get(0)\n"
    "                Some(x) -> stdio.println(x)\n"
    "                None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, [\"a\", \"b\"])\n")

# {name: (src, strict_fn, expected_output)} -- every one prints the secret.
_LOOP_LEAK = {
    "loop_carried_while": (LOOP_CARRIED_WHILE, "leak", "empty\ns3cr3t\n"),
    "loop_carried_for": (LOOP_CARRIED_FOR, "leak", "empty\ns3cr3t\n"),
    "varying_sibling_while": (VARYING_SIBLING_WHILE, "leak", "s3cr3t\n"),
    "varying_sibling_for": (VARYING_SIBLING_FOR, "leak", "s3cr3t\n"),
}


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


class TestLoopFamilyLeaksStayFlagged(unittest.TestCase):
    """Inside a loop the container-mutation taint is NOT branch-isolated (a
    sound over-approximation). A loop-carried read-before-write and a
    loop-varying sibling read are REAL leaks across iterations and must stay
    flagged -- a warning by default, a hard error under @strict_ifc -- both
    backends printing the secret. (The prior tests only had a read-AFTER
    -loop case.)"""

    def test_default_tier_flags(self):
        for name, (src, _fn, _out) in _LOOP_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_strict_tier_errors(self):
        for name, (src, fn, _out) in _LOOP_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, fn))
                self.assertFalse(r.ok)
                self.assertGreaterEqual(len(_flow_errors(r)), 1,
                                        [e.message for e in r.errors])

    def test_both_backends_leak_the_secret(self):
        skip = _wasm_unavailable()
        for name, (src, _fn, out) in _LOOP_LEAK.items():
            with self.subTest(shape=name):
                py_out = _run_py(src)
                self.assertEqual(py_out, out)
                self.assertIn("s3cr3t", py_out)
                if skip is None:
                    self.assertEqual(_run_wasm(src), out)


# ---- field-chain receiver: a mutator on ``bag.items`` (a field chain),
# not a plain identifier. The taint is keyed on the (root-binding,
# field-path) the container lives at, so the leak closes while a public
# sibling field / a mutually-exclusive branch stays clean. Set.add and
# Map.set behave identically, and a nested path is keyed in full. ----

FC_LEAK_LIST = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

FC_LEAK_SET = (TOK +
    "type Bag { tags: Set<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { tags: new_set() }\n"
    "    bag.tags.add(secret)\n"
    "    for t in bag.tags\n"
    "        stdio.println(t)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

FC_LEAK_MAP = (TOK +
    "type Bag { m: Map<String, String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { m: new_map() }\n"
    "    bag.m.set(\"k\", secret)\n"
    "    match bag.m.get(\"k\")\n"
    "        Some(v) -> stdio.println(v)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# depth > 1: keyed on the full path ("inner", "items").
FC_LEAK_NESTED = (TOK +
    "type Inner { items: List<String>, note: String }\n"
    "type Outer { inner: Inner }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var o: Outer = Outer { inner: Inner { items: [], note: \"public\" } }\n"
    "    o.inner.items.push(secret)\n"
    "    match o.inner.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# push in a branch, read AFTER: the deferred union carries the taint past
# the construct (the S1 shape for a field chain).
FC_LEAK_AFTER_BRANCH = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    if flag\n        bag.items.push(secret)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

# push in a loop, read after: the loop body is NOT branch-isolated (a sound
# over-approximation), so a loop-carried field-chain push stays flagged.
FC_LEAK_LOOP = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n    var i: Int = 0\n"
    "    while i < 1\n        bag.items.push(secret)\n        i = i + 1\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_FC_LEAK = {
    "list_push": FC_LEAK_LIST,
    "set_add": FC_LEAK_SET,
    "map_set": FC_LEAK_MAP,
    "nested_depth2": FC_LEAK_NESTED,
    "push_in_branch_read_after": FC_LEAK_AFTER_BRANCH,
    "push_in_loop_read_after": FC_LEAK_LOOP,
}


# The public-sibling read and the mutually-exclusive-branch read stay clean:
# the taint is keyed on the mutated path, never the whole binding, so it
# neither escapes the root nor pollutes a sibling / sibling branch. Each
# prints its PUBLIC value at runtime.

FC_CLEAN_SIBLING = (TOK +
    "type Bag { items: List<String>, other: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], other: \"public\" }\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(bag.other)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

FC_CLEAN_MAP_SIBLING = (TOK +
    "type Bag { m: Map<String, String>, other: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { m: new_map(), other: \"public\" }\n"
    "    bag.m.set(\"k\", secret)\n"
    "    stdio.println(bag.other)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

FC_CLEAN_NESTED_SIBLING = (TOK +
    "type Inner { items: List<String>, note: String }\n"
    "type Outer { inner: Inner }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var o: Outer = Outer { inner: Inner { items: [], note: \"public\" } }\n"
    "    o.inner.items.push(secret)\n"
    "    stdio.println(o.inner.note)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# push in the then-branch, read in the mutually-exclusive else. ``main``
# runs the READ branch (flag = false), printing the public "empty".
FC_CLEAN_BRANCH = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    if flag\n        bag.items.push(secret)\n"
    "    else\n        match bag.items.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, false)\n")

# The SAME program with the branches flipped (read first, push in the else):
# the verdict must not depend on branch order. ``main`` runs the READ branch
# (flag = true), again printing "empty".
FC_CLEAN_BRANCH_FLIPPED = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String, flag: Bool)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    if flag\n        match bag.items.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "    else\n        bag.items.push(secret)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

# {name: (src, expected_output)}
_FC_CLEAN = {
    "sibling_list": (FC_CLEAN_SIBLING, "public\n"),
    "sibling_map": (FC_CLEAN_MAP_SIBLING, "public\n"),
    "sibling_nested": (FC_CLEAN_NESTED_SIBLING, "public\n"),
    "branch_read_in_sibling": (FC_CLEAN_BRANCH, "empty\n"),
    "branch_read_in_sibling_flipped": (FC_CLEAN_BRANCH_FLIPPED, "empty\n"),
}


# DISCLOSED residual (out of scope, must stay UNFLAGGED): the container is
# renamed out of the struct into a fresh local before the mutation, then
# read back through the field. The push taints ``lst``, not ``bag.items``,
# so the read-back is not caught -- the same points-to residual as the plain
# ``var alias = xs`` list rename. It leaks at runtime; kept as an honest,
# documented false negative, NOT silently closed.
FC_RESIDUAL_RENAME = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    var lst = bag.items\n"
    "    lst.push(secret)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


# DISCLOSED SAFE over-report (must stay FLAGGED): reassigning the container's
# ROOT binding to a fresh, leak-free value AFTER a field-chain push, then
# reading the field. The container-mutation taint is monotonic -- once the
# (root, field-path) is tainted it stays tainted -- so the read is still
# flagged even though the reassigned ``bag`` holds nothing secret (it prints
# the public "empty" at runtime). This is the deliberately-chosen SOUND
# direction, exactly mirroring the plain-identifier channel below: clearing
# the taint on reassignment is NOT done, because a reassignment to ANOTHER
# tainted value would then become a real false NEGATIVE.
FC_REASSIGN_ROOT = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    bag = Bag { items: [] }\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# The pre-existing plain-identifier channel the field chain mirrors: push into
# a fresh local, reassign the local to ``[]``, then read it. Also stays
# flagged (same monotonic taint), also prints the public "empty".
PLAIN_REASSIGN_ROOT = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n"
    "    xs.push(secret)\n"
    "    xs = []\n"
    "    match xs.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# {name: src} -- both stay flagged, both print the public "empty".
_REASSIGN_OVER_REPORT = {
    "field_chain_reassign_root": FC_REASSIGN_ROOT,
    "plain_identifier_reassign_root": PLAIN_REASSIGN_ROOT,
}


class TestFieldChainReceiverLeakClosed(unittest.TestCase):
    """A mutator on a field-chain receiver (``bag.items.push(secret)``,
    ``bag.m.set(k, secret)``, ``bag.tags.add(secret)``, nested
    ``o.inner.items.push``) taints the (root, field-path) it lives at, so a
    read of that path is caught -- a warning by default, a hard error under
    @strict_ifc -- both backends printing the secret. Also covers the
    deferred-union read-after-branch and the loop over-approximation."""

    def test_default_tier_flags(self):
        for name, src in _FC_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_strict_tier_errors(self):
        for name, src in _FC_LEAK.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, "leak"))
                self.assertFalse(r.ok)
                self.assertGreaterEqual(len(_flow_errors(r)), 1,
                                        [e.message for e in r.errors])

    def test_both_backends_print_the_secret(self):
        skip = _wasm_unavailable()
        for name, src in _FC_LEAK.items():
            with self.subTest(shape=name):
                self.assertIn("s3cr3t", _run_py(src))
                if skip is None:
                    self.assertIn("s3cr3t", _run_wasm(src))


class TestFieldChainReceiverStaysClean(unittest.TestCase):
    """Keyed on the mutated path, the taint never escapes the root binding:
    a public sibling field (``bag.other``, ``o.inner.note``) and a
    mutually-exclusive branch's read stay clean -- no warning by default, no
    error under @strict_ifc -- and the verdict is independent of branch
    order. Both backends print the public value."""

    def test_default_tier_is_clean(self):
        for name, (src, _out) in _FC_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])

    def test_strict_tier_is_clean(self):
        for name, (src, _out) in _FC_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(r)), 0,
                                 [e.message for e in r.errors])

    def test_both_backends_are_leak_free(self):
        skip = _wasm_unavailable()
        for name, (src, out) in _FC_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)
                if skip is None:
                    self.assertEqual(_run_wasm(src), out)


class TestFieldChainRenameResidualDisclosed(unittest.TestCase):
    """DISCLOSED residual (out of scope): renaming the container out of the
    struct before mutating it (``var lst = bag.items; lst.push(secret)``)
    taints the fresh local, not ``bag.items``, so the read-back through the
    field is NOT caught -- the same points-to residual as ``var alias = xs``.
    An honest, documented false negative that leaks at runtime. If a future
    points-to slice closes it, this test flips (and the disclosure above
    comes down)."""

    def test_rename_is_unflagged(self):
        r = _analyze(FC_RESIDUAL_RENAME)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_rename_leaks_at_runtime(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(FC_RESIDUAL_RENAME), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(FC_RESIDUAL_RENAME), "s3cr3t\n")


class TestReassignRootSafeOverReport(unittest.TestCase):
    """DISCLOSED SAFE over-report (locked in as deliberate behaviour):
    reassigning the container's ROOT binding to a leak-free value AFTER a push,
    then reading, stays FLAGGED because the container-mutation taint is
    monotonic (once tainted, stays tainted). The field-chain channel
    (``bag.items.push(secret); bag = Bag { items: [] }; read bag.items``)
    mirrors the pre-existing plain-identifier one (``xs.push(secret); xs = [];
    read xs``). Clearing the taint on reassignment is deliberately NOT done:
    reassigning to ANOTHER tainted value would turn it into a real false
    negative, so the sound (over-report) direction is chosen. Nothing secret
    reaches the sink -- both shapes print the public "empty" -- so this is a
    safe precision loss, not a real leak. Do NOT "fix" the analyzer to clear
    the taint; this test documents and locks in the safe behaviour."""

    def test_default_tier_flags(self):
        for name, src in _REASSIGN_OVER_REPORT.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])

    def test_strict_tier_errors(self):
        for name, src in _REASSIGN_OVER_REPORT.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, "leak"))
                self.assertFalse(r.ok)
                self.assertGreaterEqual(len(_flow_errors(r)), 1,
                                        [e.message for e in r.errors])

    def test_over_report_is_safe_no_secret_reaches_the_sink(self):
        skip = _wasm_unavailable()
        for name, src in _REASSIGN_OVER_REPORT.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "empty\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "empty\n")


if __name__ == "__main__":
    unittest.main()
