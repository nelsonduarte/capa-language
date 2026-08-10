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

CLOSED: WHOLE-STRUCT read of the SAME root. After ``bag.items.push(secret)``
the taint is keyed on ``(bag, ("items",))``. A read of the WHOLE ``bag`` --
string interpolation via a to_string method (``"${bag}"``), a method whose
body reads the field (``bag.reveal()``), or passing the whole ``bag`` to a
callee that reads ``bag.items`` (``show(bag)``) -- now joins EVERY field taint
of the root (the length-0 access-path query ``x.f^0 = x``), so it is caught at
both tiers on both backends. The public-sibling false positives commits
b895ca6 / 4c69a02 removed stay removed, because the whole-read prefix scan is
applied only to a WHOLE read, while a FIELD read (``bag.other``) still scans
only its own path and an escaped field read falls back to the receiver's BASE
label (no container channel), so a clean sibling stays clean. See
``TestWholeStructSameRootReadClosed``.

Disclosed residuals (still open, three DISTINCT mechanisms, not one class;
each leaks at runtime and stays UNFLAGGED at both tiers on both backends):

(1) RECEIVER not rooted at a binding. A mutator called on a call- or
    index-rooted receiver (``get_items(bag).push(secret)``,
    ``arr[0].items.push(secret)``) has no ``(root, field-path)`` key at all,
    so the push itself is untracked and the later read of the same container
    is not caught (see ``TestCallIndexRootedReceiverResidualDisclosed``).

(2) DIFFERENT-root points-to. The container is reached through a root the
    taint is not keyed on, which only a points-to analysis (which Capa does
    not have) could close:
    * rename out of the struct: ``var lst = bag.items; lst.push(secret)``
      taints the fresh local, not the field, so the ``bag.items`` read-back
      is missed -- the plain ``var alias = xs`` rename lifted to a field (see
      ``TestFieldChainRenameResidualDisclosed``);
    * whole-struct alias where the mutation is written INLINE through the
      alias: ``var b2 = bag; b2.items.push(secret)`` then ``read bag.items``
      mutates the same container through a DIFFERENT root symbol (a
      CROSS-FUNCTION push through a struct alias IS caught, via the alias
      group);
    * a whole-struct value copy ``var b2 = bag`` made AFTER the push then a
      sibling read through the copy (a SAFE over-report -- flags but leaks
      nothing; see ``TestWholeCopySiblingOverReportDisclosed``);
    * embed-then-mutate: pushing into a sub-struct's container through its
      own root after embedding it in an outer struct, then reading through
      the outer.

(3) LAMBDA-FLOW sensitivity, two faces:
    * SINK side -- CLOSED (Stage A): a bare @secret passed to a
      LOCALLY-RESOLVABLE lambda that sinks it,
      ``let g = fun(s) => sink_str(s, stdio); g(secret)``, or to an IIFE
      ``(fun(s) => sink_str(s, stdio))(secret)``, is now flagged (a warning
      by default, a hard error under strict), the same tier as the direct
      named call. Every lambda literal carries its own sink-reaching summary
      and the call site applies it to the actual arguments (see
      ``TestSecretIntoLocalLambdaSinkClosed``). Lambdas that ESCAPE local
      resolution -- a reassigned ``var``, an alias, a call-result binding, or
      a lambda invoked inside a higher-order callee -- stay disclosed
      residuals (see ``TestEscapingLambdaSinkResidualDisclosed``);
    * CAPTURE side -- the RESULT-SINK case is CLOSED (Stage B) for a
      locally-resolved lambda (let-bound / IIFE): a container captured by a
      closure defined BEFORE a push and read through the closure AFTER, where
      the CALLER SINKS THE CLOSURE'S RESULT -- ``let f = fun() => bag.reveal();
      bag.items.push(secret); stdio.println(f())`` -- is now flagged (a warning
      by default, a hard error under strict). At the invocation of a
      locally-resolved lambda each captured free binding's CURRENT LIVE label is
      re-read (the branch-scoped container-taint map, and for a REFERENCE-typed
      capture the live ``sym.label``), not the label cached at the lambda's
      DEFINITION (see ``TestClosureCaptureBeforePushClosed``). A closure defined
      AFTER the push was already caught. Branch-sound by construction (the live
      map is branch-scoped). What STAYS disclosed on the capture side:
      - a sink INTERNAL to the closure body (a side effect, not the result --
        ``let f = fun() => stdio.println(bag.reveal()); ...; f()``), which needs
        a future field-store / access-path channel slice, not this label
        re-read (see ``TestCaptureInternalSinkResidualDisclosed``);
      - a closure that ESCAPES local resolution -- invoked inside a higher-order
        callee (``apply(f)``) or otherwise unresolvable (see
        ``TestHofInvokedClosureResidualDisclosed``);
      - SAFE over-reports (sound, never leak): the whole-value re-read flags a
        closure reading only a CLEAN sibling of a pushed container, and REFTYPE
        flags a captured STRUCT whole-reassigned to a secret (it cannot tell a
        whole reassign from an in-place field store); a VALUE-typed capture
        reassigned to a secret is captured by value and is correctly CLEAN (see
        ``TestCaptureLiveRereadPrecision`` and ``TestCaptureRereadReftype``).

Do not read any single bullet as the ONLY open case.
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


# DISCLOSED residual (mechanism 1, out of scope): the mutator's RECEIVER is
# rooted at a call or an index, not a binding. ``_container_mutation_key``
# only tracks a plain identifier or an Ident-rooted field chain, so a call-
# or index-rooted receiver has no (root, field-path) key at all -- the push
# is untracked and the later read of the same container is not caught. Both
# forms leak at runtime, UNFLAGGED at both tiers on both backends. Lists are
# reference values, so the push through the returned / indexed alias mutates
# the very container the field read then observes.
RECV_CALL_ROOTED = (TOK +
    "type Bag { items: List<String> }\n"
    "fun get_items(bag: Bag) -> List<String>\n"
    "    return bag.items\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    get_items(bag).push(secret)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

RECV_INDEX_ROOTED = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var arr: List<Bag> = [Bag { items: [] }]\n"
    "    arr[0].items.push(secret)\n"
    "    match arr[0].items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_RECV_ROOT_RESIDUAL = {
    "call_rooted": RECV_CALL_ROOTED,
    "index_rooted": RECV_INDEX_ROOTED,
}


# CLOSED: reading or passing the WHOLE struct of the SAME root after a
# field-chain push. The taint is keyed on (bag, ("items",)); a WHOLE read now
# joins every field taint of the root (the length-0 access-path query), so all
# three shapes -- interpolating the whole struct through a to_string method, a
# method whose body reads the field (``bag.reveal()``), and passing the whole
# ``bag`` to a callee that reads ``bag.items`` -- are FLAGGED (warning default,
# hard error @strict_ifc) and leak s3cr3t at runtime on both backends.
WS_INTERP = (TOK +
    "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun to_string(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(\"${bag}\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

WS_METHOD = (TOK +
    "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(bag.reveal())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

WS_CALLEE = (TOK +
    "type Bag { items: List<String> }\n"
    "fun show(bag: Bag, stdio: Stdio)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    show(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_WHOLE_STRUCT_CLOSED = {
    "interpolate_whole_struct": WS_INTERP,
    "method_reads_field": WS_METHOD,
    "pass_whole_struct_to_callee": WS_CALLEE,
}


# CLOSED (the coordinator's CRITICAL): the CROSS-FUNCTION analog. A CALLEE
# pushes the secret into ``bag.items`` (a field-keyed container effect on the
# caller's ``(bag, ("items",))`` channel), and the caller reads back the WHOLE
# struct. Before the whole-read prefix scan this slipped, because dropping the
# whole-value carrier for the container effect removed the only thing that
# caught a whole / getter read-back cross-function. All four shapes now FLAG
# (warning default, hard error @strict_ifc) and leak on both backends.
MX_GETTER = (TOK +
    "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    bag.items.push(secret)\n"
    "fun main(stdio: Stdio)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    fill(bag, TOKEN)\n"
    "    stdio.println(bag.reveal())\n")

MX_INTERP = (TOK +
    "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun to_string(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    bag.items.push(secret)\n"
    "fun main(stdio: Stdio)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    fill(bag, TOKEN)\n"
    "    stdio.println(\"${bag}\")\n")

MX_CALLEE = (TOK +
    "type Bag { items: List<String> }\n"
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    bag.items.push(secret)\n"
    "fun show(bag: Bag, stdio: Stdio)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    fill(bag, TOKEN)\n"
    "    show(bag, stdio)\n")

# {name: src} -- const-sourced, so each prints the secret at runtime.
_CROSSFN_WHOLE_READ_CLOSED = {
    "crossfn_getter": MX_GETTER,
    "crossfn_interpolate": MX_INTERP,
    "crossfn_pass_whole": MX_CALLEE,
}

# The Env-sourced getter variant: the secret enters through ``env.get`` inside
# the caller, is pushed by the callee, and read back whole through a getter.
# Analysis MUST flag it (the source is @public-in / @secret content); at
# runtime ``env`` is unset so it prints the public fallback, which is why this
# one is asserted on the analysis verdict, not a secret print.
MX_GETTER_ENV = (
    "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    bag.items.push(secret)\n"
    "fun main(env: Env, stdio: Stdio)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    match env.get(\"API_KEY\")\n"
    "        Some(k) -> fill(bag, k)\n"
    "        None -> fill(bag, \"none\")\n"
    "    stdio.println(bag.reveal())\n")


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

# Field-GRANULAR reassignment: clear only the field (``bag.items = []``) after
# the push, then read that same field. Same monotonic over-report -- once the
# (root, field-path) is tainted it stays tainted, so the read is still flagged
# though the reassigned field now holds nothing secret (it prints the public
# "empty"). Clearing the taint on a field reassignment is likewise deliberately
# NOT done: reassigning the field to ANOTHER tainted value would then become a
# real false negative.
FC_REASSIGN_FIELD = (TOK +
    "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    bag.items = []\n"
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

# {name: src} -- all stay flagged, all print the public "empty".
_REASSIGN_OVER_REPORT = {
    "field_chain_reassign_root": FC_REASSIGN_ROOT,
    "field_chain_reassign_field": FC_REASSIGN_FIELD,
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


class TestCallIndexRootedReceiverResidualDisclosed(unittest.TestCase):
    """DISCLOSED residual (mechanism 1, out of scope): a mutator whose
    RECEIVER is rooted at a call or an index (``get_items(bag).push(secret)``,
    ``arr[0].items.push(secret)``), not a binding, has no (root, field-path)
    key, so the push is untracked and the later read of the same container is
    NOT caught -- UNFLAGGED at both tiers, a runtime leak on both backends.
    Honest, documented false negatives, not silently closed. If a future
    points-to slice reaches call- / index-rooted receivers, these flip (and
    the disclosure above comes down)."""

    def test_unflagged_at_both_tiers(self):
        for name, src in _RECV_ROOT_RESIDUAL.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_leaks_at_runtime(self):
        skip = _wasm_unavailable()
        for name, src in _RECV_ROOT_RESIDUAL.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


class TestWholeStructSameRootReadClosed(unittest.TestCase):
    """CLOSED (was a disclosed residual): reading or passing the WHOLE struct
    of the SAME root after a field-chain push. The taint is keyed on
    (bag, ("items",)); a WHOLE read now joins EVERY field taint of the root
    (the length-0 access-path query ``x.f^0 = x``), so all three shapes --
    interpolating the whole struct through a to_string method, a method whose
    body reads the field (``bag.reveal()``), and passing the whole ``bag`` to a
    callee that reads ``bag.items`` -- are FLAGGED (warning by default, a hard
    error under @strict_ifc), both backends printing the secret. The
    public-sibling precision is preserved because a FIELD read scans only its
    own path and an escaped field read falls back to the receiver's BASE label
    (no container channel), so ``bag.other`` stays clean (see
    ``TestFieldChainReceiverStaysClean``)."""

    def test_flagged_at_both_tiers(self):
        for name, src in _WHOLE_STRUCT_CLOSED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leaks_at_runtime(self):
        skip = _wasm_unavailable()
        for name, src in _WHOLE_STRUCT_CLOSED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


class TestCrossFnContainerWholeReadClosed(unittest.TestCase):
    """CLOSED (the coordinator's CRITICAL regression): a CALLEE pushes a secret
    into ``bag.items`` and the caller reads it back through the WHOLE struct --
    a getter (``bag.reveal()``), string interpolation (``"${bag}"``), or by
    passing the whole ``bag`` to a sink-reaching callee (``show(bag)``). Moving
    the cross-function container-mutation effect onto the field-keyed
    ``(root, path)`` channel dropped the whole-value carrier that used to catch
    this, so it briefly slipped; the whole-read prefix scan closes it precisely.
    All four shapes FLAG (warning default, hard error @strict_ifc); the three
    const-sourced ones leak the secret on both backends. Locked in so it can
    never silently re-regress."""

    def test_const_sourced_flag_at_both_tiers(self):
        for name, src in _CROSSFN_WHOLE_READ_CLOSED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "main"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_const_sourced_leak_on_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _CROSSFN_WHOLE_READ_CLOSED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")

    def test_env_sourced_getter_flags(self):
        r = _analyze(MX_GETTER_ENV)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(MX_GETTER_ENV, "main"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])


# The escaped-sibling clean cases: a CALLEE pushes the secret into one field
# and the caller reads a DIFFERENT (public) field of the SAME struct AFTER the
# struct escaped through the call. The whole-read prefix scan must NOT re-taint
# the sibling: a FIELD read scans only its own path, and an escaped field read
# falls back to the receiver's BASE label (no container channel). Each prints
# its public value on both backends.
XFN_SIBLING_CLEAN = (TOK +
    "type Bag { items: List<String>, other: List<String> }\n"
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    bag.items.push(secret)\n"
    "fun main(stdio: Stdio)\n"
    "    var bag: Bag = Bag { items: [], other: [] }\n"
    "    bag.other.push(\"public\")\n"
    "    fill(bag, TOKEN)\n"
    "    match bag.other.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n")

# Nested: push ``bag.inner.items`` cross-function (through ``bag.inner``), read
# the nested sibling ``bag.inner.other``. The composed path
# ``(bag, ("inner","items"))`` must not taint ``(bag, ("inner","other"))``.
XFN_SIBLING_CLEAN_NESTED = (TOK +
    "type Inner { items: List<String>, other: List<String> }\n"
    "type Bag { inner: Inner }\n"
    "fun fill(inner: Inner, secret: @secret String)\n"
    "    inner.items.push(secret)\n"
    "fun main(stdio: Stdio)\n"
    "    var bag: Bag = Bag { inner: Inner { items: [], other: [] } }\n"
    "    bag.inner.other.push(\"public\")\n"
    "    fill(bag.inner, TOKEN)\n"
    "    match bag.inner.other.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n")

_XFN_SIBLING_CLEAN = {
    "escaped_sibling": XFN_SIBLING_CLEAN,
    "escaped_sibling_nested": XFN_SIBLING_CLEAN_NESTED,
}


class TestCrossFnEscapedSiblingStaysClean(unittest.TestCase):
    """No new FP: after a callee pushes a secret into one field and the struct
    ESCAPES through the call, reading a DIFFERENT public field of the same root
    stays CLEAN (no warning by default, no error under @strict_ifc), including
    a nested sibling. The whole-read prefix scan is confined to WHOLE reads; a
    field read scans only its own path and an escaped field read uses the
    receiver's BASE label, so ``bag.other`` / ``bag.inner.other`` do not
    inherit the sibling's container taint. Both backends print the public
    value."""

    def test_default_tier_is_clean(self):
        for name, src in _XFN_SIBLING_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])

    def test_strict_tier_is_clean(self):
        for name, src in _XFN_SIBLING_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(_strict(src, "main"))
                self.assertEqual(len(_flow_errors(r)), 0,
                                 [e.message for e in r.errors])

    def test_both_backends_print_public(self):
        skip = _wasm_unavailable()
        for name, src in _XFN_SIBLING_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "public\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "public\n")


class TestReassignRootSafeOverReport(unittest.TestCase):
    """DISCLOSED SAFE over-report (locked in as deliberate behaviour):
    reassigning to a leak-free value AFTER a push, then reading, stays FLAGGED
    because the container-mutation taint is monotonic (once tainted, stays
    tainted). Three shapes are covered: reassigning the container's ROOT
    binding (``bag.items.push(secret); bag = Bag { items: [] }; read
    bag.items``), reassigning only the FIELD (``bag.items.push(secret);
    bag.items = []; read bag.items``), and the pre-existing plain-identifier
    one (``xs.push(secret); xs = []; read xs``). Clearing the taint on ANY of
    these reassignments is deliberately NOT done: reassigning to ANOTHER
    tainted value would turn it into a real false negative, so the sound
    (over-report) direction is chosen. Nothing secret reaches the sink -- all
    three shapes print the public "empty" -- so this is a safe precision loss,
    not a real leak. Do NOT "fix" the analyzer to clear the taint; this test
    documents and locks in the safe behaviour."""

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


# ---- Stage 2: read-side field-qualified cross-function SINK summary. When a
# whole struct with a container-tainted field is passed to a callee, the call
# site intersects the argument's tainted access paths against the callee's SUNK
# access paths, so passing a struct tainted at ``secret_items`` to a callee
# that sinks only the sibling ``note`` is CLEAN (no leak). The mirror leak
# (the callee sinks the TAINTED field, or the whole struct) stays FLAGGED. ----

_BAG2 = "type Bag { secret_items: List<String>, note: String }\n"

# CLEAN: pass whole, callee sinks only the clean sibling ``note``.
SF_CLEAN = (TOK + _BAG2 +
    "fun show_note(bag: Bag, stdio: Stdio)\n"
    "    stdio.println(bag.note)\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_items: [], note: \"public\" }\n"
    "    bag.secret_items.push(secret)\n"
    "    show_note(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# CLEAN through a hop: ``relay`` passes the whole struct to ``show_note``; the
# composed sunk path stays ``("note",)``, disjoint from the tainted
# ``("secret_items",)``.
SF_CLEAN_MULTIHOP = (TOK + _BAG2 +
    "fun show_note(bag: Bag, stdio: Stdio)\n"
    "    stdio.println(bag.note)\n"
    "fun relay(bag: Bag, stdio: Stdio)\n"
    "    show_note(bag, stdio)\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_items: [], note: \"public\" }\n"
    "    bag.secret_items.push(secret)\n"
    "    relay(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_SF_CLEAN = {"pass_whole_clean_sibling": SF_CLEAN,
             "multihop_clean_sibling": SF_CLEAN_MULTIHOP}

# FLAGGED: pass whole, callee sinks the TAINTED field (the mirror leak; the
# whole-value carrier the field channel replaced must NOT drop this).
SF_TAINTED = (TOK + _BAG2 +
    "fun show_items(bag: Bag, stdio: Stdio)\n"
    "    match bag.secret_items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_items: [], note: \"public\" }\n"
    "    bag.secret_items.push(secret)\n"
    "    show_items(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# FLAGGED through a hop.
SF_TAINTED_MULTIHOP = (TOK + _BAG2 +
    "fun show_items(bag: Bag, stdio: Stdio)\n"
    "    match bag.secret_items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun relay(bag: Bag, stdio: Stdio)\n"
    "    show_items(bag, stdio)\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_items: [], note: \"public\" }\n"
    "    bag.secret_items.push(secret)\n"
    "    relay(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# FLAGGED: the callee sinks the WHOLE receiver (a method that reads its own
# container). The conservative sentinel () sunk path is prefix-compatible with
# every tainted path, so it always flags.
SF_DUMP_WHOLE = (TOK + "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun dump(self, stdio: Stdio)\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    bag.items.push(secret)\n"
    "    bag.dump(stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_SF_TAINTED = {"pass_whole_tainted_field": SF_TAINTED,
               "multihop_tainted_field": SF_TAINTED_MULTIHOP,
               "callee_sinks_whole_receiver": SF_DUMP_WHOLE}


class TestCrossFnSinkFieldQualified(unittest.TestCase):
    """Stage 2: the read-side field-qualified sink summary. Passing a whole
    struct tainted only at one container field to a callee that sinks a CLEAN
    SIBLING field is not a leak and must be CLEAN (this was a sound over-report
    the field-keyed container channel introduced when it dropped the whole
    -value carrier). The MIRROR leak -- the callee sinks the tainted field, or
    the whole struct -- stays FLAGGED at both tiers, on both backends. The
    precision composes through a hop (``relay``)."""

    def test_clean_sibling_is_clean(self):
        for name, src in _SF_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_clean_sibling_prints_public_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _SF_CLEAN.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "public\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "public\n")

    def test_tainted_or_whole_stays_flagged(self):
        for name, src in _SF_TAINTED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_tainted_or_whole_leaks_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _SF_TAINTED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- Commit 1: cross-function FIELD-STORE field-keying. A callee that stores
# into a struct field (``bag.secret_field = secret``) records a FIELD-KEYED
# ``(param, field-path)`` effect exactly like a container mutation, routed by
# the caller onto the same ``(root, field-path)`` branch-scoped container
# channel. So a caller reading a CLEAN SIBLING field after the call is no
# longer flagged as an ERROR under strict (was the R3 whole-struct-read
# over-report), while the leak-catching cases are preserved: a read of the
# STORED path, a WHOLE / getter read, and a pass-whole to a callee sinking the
# stored path all stay flagged. An ALIASED field-store root (the callee stores
# through ``var inner = bag``) is not parameter-relative, so it keeps the
# WHOLE-VALUE carrier -- the cross-function whole-value leak never regresses. --

_BAG_SF = "type Bag { secret_field: String, note: String }\n"
_FILL = ("fun fill(bag: Bag, secret: @secret String)\n"
         "    bag.secret_field = secret\n")

# CLEAN SIBLING: the callee stores ``secret_field``, the caller reads the
# public ``note`` -- no strict ERROR (prints "public").
XFS_SIBLING = (TOK + _BAG_SF + _FILL +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_field: \"x\", note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(bag.note)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# STORED-FIELD read: reading the very field the callee stored -- a real leak,
# stays flagged (prints "s3cr3t").
XFS_SAME_FIELD = (TOK + _BAG_SF + _FILL +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_field: \"x\", note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(bag.secret_field)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# PASS-WHOLE to a callee that sinks the STORED path -- the read-side sink
# summary is prefix-compatible, so it stays flagged (prints "s3cr3t").
XFS_PASS_WHOLE = (TOK + _BAG_SF + _FILL +
    "fun show(bag: Bag, stdio: Stdio)\n"
    "    stdio.println(bag.secret_field)\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_field: \"x\", note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    show(bag, stdio)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# WHOLE / getter read (``reveal`` reads ``self.secret_field``): the length-0
# prefix scan over ``(root, *)`` observes the stored path, stays flagged.
XFS_WHOLE_GETTER = (TOK + _BAG_SF +
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        return self.secret_field\n" + _FILL +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_field: \"x\", note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(bag.reveal())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# ALIASED field-store root: the callee stores through ``var inner = bag`` (a
# reference alias), which is not parameter-relative, so the effect keeps the
# WHOLE-VALUE carrier. The caller's read-back stays flagged (prints "s3cr3t").
XFS_ALIAS = (TOK + _BAG_SF +
    "fun fill(bag: Bag, secret: @secret String)\n"
    "    var inner: Bag = bag\n"
    "    inner.secret_field = secret\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { secret_field: \"x\", note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(bag.secret_field)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_XFS_FLAGGED = {
    "stored_field_read": XFS_SAME_FIELD,
    "pass_whole_to_stored_sink": XFS_PASS_WHOLE,
    "whole_getter_read": XFS_WHOLE_GETTER,
    "aliased_store_root": XFS_ALIAS,
}


class TestCrossFnFieldStoreFieldKeyed(unittest.TestCase):
    """Commit 1: a cross-function field store is field-keyed on the
    ``(root, field-path)`` container channel, so a clean sibling read after
    the call no longer raises a strict ERROR, while every leak-catching shape
    stays flagged (the stored-field read, the pass-whole to a sink of the
    stored path, the whole / getter read, and the aliased-root whole-value
    fallback)."""

    def test_clean_sibling_closes_strict_error(self):
        # The R3 strict-tier ERROR is closed: reading the public sibling
        # ``note`` after a callee stores ``secret_field`` is not an error.
        # (The residual default-tier warning is closed by Commit 2; here we
        # pin only the strict-error closure this commit is responsible for.)
        rs = _analyze(_strict(XFS_SIBLING, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_clean_sibling_prints_public_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(XFS_SIBLING), "public\n")
        if skip is None:
            self.assertEqual(_run_wasm(XFS_SIBLING), "public\n")

    def test_leak_shapes_stay_flagged(self):
        for name, src in _XFS_FLAGGED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leak_shapes_leak_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _XFS_FLAGGED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- Commit 2: field-key the summary CONTENT channel. The channel a callee's
# mutation effect writes into a caller-local is now keyed by ``(root,
# field-path)`` and read FIELD-PRECISELY, so sinking a genuinely CLEAN SIBLING
# of a cross-function-mutated struct produces NO warning (closing the R3
# residual coarse warning that survived at the caller after Commit 1), while a
# sink of the mutated path still warns. Covers both the FIELD-STORE effect
# (Commit 1) and the CONTAINER-mutation effect (1.29.0). ----

_BAG_ITEMS = "type Bag { items: List<String>, note: String }\n"
_FILL_PUSH = ("fun fill(bag: Bag, secret: @secret String)\n"
              "    bag.items.push(secret)\n")

# CLEAN: callee pushes ``items``, caller sinks the public sibling ``note``.
XCC_SIBLING = (TOK + _BAG_ITEMS + _FILL_PUSH +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(bag.note)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# CLEAN: callee mutates, caller sinks a CONSTANT (nothing from ``bag``).
XCC_PROBE = (TOK + _BAG_ITEMS + _FILL_PUSH +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    stdio.println(\"constant only\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# FLAGGED: callee pushes ``items``, caller reads the mutated container path and
# sinks it -- the content channel must still carry the taint on the read path.
XCC_TAINTED_PATH = (TOK + _BAG_ITEMS + _FILL_PUSH +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], note: \"public\" }\n"
    "    fill(bag, secret)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_XCC_CLEAN = {"container_push_sibling": XCC_SIBLING,
              "constant_after_mutation": XCC_PROBE,
              "field_store_sibling": XFS_SIBLING}


class TestCrossFnContentFieldPrecise(unittest.TestCase):
    """Commit 2: the summary content channel is field-keyed on ``(root,
    field-path)`` and read field-precisely. Sinking a genuinely CLEAN SIBLING
    of a cross-function-mutated struct now produces NO warning at ANY tier
    (R3's residual coarse warning is closed, for both the field-store and the
    container-mutation effect), while a sink of the mutated path still warns
    (soundness: the precision gain never drops a leak)."""

    def test_clean_sibling_no_warning_at_any_tier(self):
        for name, src in _XCC_CLEAN.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_clean_sibling_prints_public_both_backends(self):
        skip = _wasm_unavailable()
        for name, src, out in (("container_push_sibling", XCC_SIBLING, "public\n"),
                               ("constant_after_mutation", XCC_PROBE,
                                "constant only\n"),
                               ("field_store_sibling", XFS_SIBLING, "public\n")):
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), out)
                if skip is None:
                    self.assertEqual(_run_wasm(src), out)

    def test_mutated_path_sink_still_warns(self):
        r = _analyze(XCC_TAINTED_PATH)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(XCC_TAINTED_PATH, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])

    def test_mutated_path_sink_leaks_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(XCC_TAINTED_PATH), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(XCC_TAINTED_PATH), "s3cr3t\n")


# ---- CLOSED (Stage B, capture-side lambda-flow): a container captured by a
# CLOSURE defined BEFORE the push, read through the closure AFTER, and invoked
# LOCALLY. At the invocation the closure's captured free bindings are re-read
# LIVE (the branch-scoped container-taint map + ``sym.label``), so the later
# push is now visible through the earlier-captured binding -- a warning by
# default, a hard error under strict. A closure defined AFTER the push was
# already caught. Each still leaks at runtime (a warning does not block). ----

CC_GETTER = (TOK + "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    let f = fun() -> String => bag.reveal()\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

CC_PLAINLIST = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n"
    "    let f = fun() -> String =>\n"
    "        match xs.get(0)\n"
    "            Some(v) -> v\n"
    "            None -> \"empty\"\n"
    "    xs.push(secret)\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_CLOSURE_CAPTURE_CLOSED = {
    "getter_via_closure": CC_GETTER,
    "plain_list_via_closure": CC_PLAINLIST,
}

# ---- DISCLOSED residual (out of scope, Stage B): the captured closure ESCAPES
# to a higher-order callee, so its invocation is not locally resolvable to this
# lambda and the live re-read does not apply. Stays UNFLAGGED, still leaks. ----
CC_HOF = (TOK + "type Bag { items: List<String> }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "fun apply(g: Fun() -> String) -> String\n"
    "    return g()\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    let f = fun() -> String => bag.reveal()\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(apply(f))\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# ---- capture-side live-re-read PRECISION shapes (branch-soundness, no-push
# clean, and the disclosed whole-value sibling over-report). Shared Bag with a
# clean ``note`` sibling and a getter for it. ----
_BAG_NOTE = (TOK + "type Bag { items: List<String>, note: String }\n"
    "impl Bag\n"
    "    fun reveal(self) -> String\n"
    "        match self.items.get(0)\n"
    "            Some(x) -> return x\n"
    "            None -> return \"empty\"\n"
    "    fun getnote(self) -> String\n"
    "        return self.note\n")

# Push in the ``then`` branch, invoke in the mutually-exclusive ``else``: the
# live container-taint map is branch-scoped, so the push is not in the map at
# the invocation point -> NOT flagged. ``main`` runs the else (prints "empty").
CC_BRANCH_EXCLUSIVE = (_BAG_NOTE +
    "fun leak(stdio: Stdio, secret: @secret String, cond: Bool)\n"
    "    var bag: Bag = Bag { items: [], note: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => bag.reveal()\n"
    "    if cond\n        bag.items.push(secret)\n"
    "    else\n        stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, false)\n")

# Push then invoke in the SAME path -> flagged (prints the secret).
CC_BRANCH_SAME = (_BAG_NOTE +
    "fun leak(stdio: Stdio, secret: @secret String, cond: Bool)\n"
    "    var bag: Bag = Bag { items: [], note: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => bag.reveal()\n"
    "    if cond\n        bag.items.push(secret)\n        stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN, true)\n")

# No push at all: the captured binding is genuinely clean -> clean.
CC_NO_PUSH = (_BAG_NOTE +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], note: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => bag.reveal()\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# The disclosed SAFE over-report: the closure reads only the CLEAN ``note``,
# but its other field ``items`` was pushed. The live re-read is whole-value on
# the captured root ``bag``, so it FLAGS though nothing leaks (prints "pub").
CC_SIBLING_OVERREPORT = (_BAG_NOTE +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], note: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => bag.getnote()\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# A second disclosed SAFE over-report: the live re-read reads the RAW container
# taint and is DECLASSIFY-BLIND (unlike the result-label path), so a closure
# that ``declassify``s its captured value IN-BODY, captured BEFORE the push, is
# still FLAGGED though the disclosure was sanctioned. Sound (over-report, never
# leaks). Declassify at the CALL SITE (``declassify(f(), reason: ...)``) is the
# clean workaround.
CC_INBODY_DECLASSIFY = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n"
    "    let f: Fun() -> String = fun() -> String =>\n"
    "        match xs.get(0)\n"
    "            Some(v) -> declassify(v, reason: \"intended\")\n"
    "            None -> \"empty\"\n"
    "    xs.push(secret)\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

CC_CALLSITE_DECLASSIFY = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var xs: List<String> = []\n"
    "    let f: Fun() -> String = fun() -> String =>\n"
    "        match xs.get(0)\n"
    "            Some(v) -> v\n"
    "            None -> \"empty\"\n"
    "    xs.push(secret)\n"
    "    stdio.println(declassify(f(), reason: \"intended\"))\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


class TestClosureCaptureBeforePushClosed(unittest.TestCase):
    """CLOSED (Stage B, capture-side RESULT-SINK face): a container captured by
    a closure defined BEFORE the push and read through the closure AFTER, where
    the CALLER SINKS THE CLOSURE'S RESULT and the closure is invoked LOCALLY, is
    now flagged (a warning by default, a hard error under strict). At the
    invocation of a locally-resolved lambda each captured free binding's CURRENT
    LIVE label is re-read -- the branch-scoped container-taint map, and for a
    REFERENCE-typed capture the live ``sym.label`` -- NOT the label cached at
    the lambda's definition (before the push). The value still leaks at runtime
    on both backends (a warning does not block).

    Stage B closes the RESULT-sink case only: a sink INTERNAL to the closure
    body (a side effect) stays a disclosed residual
    (``TestCaptureInternalSinkResidualDisclosed``), as does the HOF-invoked
    shape (``TestHofInvokedClosureResidualDisclosed``). The SINK-SIDE face was
    closed in Stage A (``TestSecretIntoLocalLambdaSinkClosed``)."""

    def test_flagged_at_both_tiers(self):
        for name, src in _CLOSURE_CAPTURE_CLOSED.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_leaks_at_runtime_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _CLOSURE_CAPTURE_CLOSED.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


class TestCaptureLiveRereadPrecision(unittest.TestCase):
    """Precision of the Stage B live capture re-read: branch-soundness, a
    genuinely-clean capture, and the disclosed whole-value sibling
    over-report.

    * BRANCH-SOUND: the re-read consults the LIVE, branch-scoped
      container-taint map, so a push in a mutually-exclusive branch is not
      observed at the other branch's invocation point (clean, prints the
      public value); a push then invoke on the SAME path flags.
    * NO OVER-EAGER FLAG: a closure over a container never pushed stays clean.
    * DISCLOSED SAFE over-reports (sound, never under-report; a field-precise /
      declassify-aware re-read to remove them is a later precision follow-up):
      - WHOLE-VALUE on the captured ROOT: a closure reading only a CLEAN
        sibling of a container whose OTHER field was pushed FLAGS though it
        leaks nothing (prints the public value), at parity with the existing
        ``ALIAS_COPY_AFTER`` over-report;
      - DECLASSIFY-BLIND: the re-read reads the RAW container taint, so a
        closure that ``declassify``s its captured value IN-BODY (defined before
        the push) still FLAGS though the disclosure was sanctioned. Declassify
        at the CALL SITE (``declassify(f(), reason: ...)``) is the clean
        workaround."""

    def test_branch_exclusive_is_clean(self):
        r = _analyze(CC_BRANCH_EXCLUSIVE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_BRANCH_EXCLUSIVE, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_branch_same_path_is_flagged(self):
        r = _analyze(CC_BRANCH_SAME)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_BRANCH_SAME, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])

    def test_no_push_is_clean(self):
        r = _analyze(CC_NO_PUSH)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_sibling_over_report_flags_but_leaks_nothing(self):
        # SOUND over-report: flags (whole-value re-read on the captured root),
        # but prints the PUBLIC value on both backends (nothing leaks).
        r = _analyze(CC_SIBLING_OVERREPORT)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_SIBLING_OVERREPORT), "pub\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_SIBLING_OVERREPORT), "pub\n")

    def test_branch_and_same_path_run_values(self):
        # Runtime witnesses: the exclusive case prints public "empty"; the
        # same-path case leaks the secret (a warning does not block).
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_BRANCH_EXCLUSIVE), "empty\n")
        self.assertEqual(_run_py(CC_BRANCH_SAME), "s3cr3t\n")
        self.assertEqual(_run_py(CC_NO_PUSH), "empty\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_BRANCH_EXCLUSIVE), "empty\n")
            self.assertEqual(_run_wasm(CC_BRANCH_SAME), "s3cr3t\n")
            self.assertEqual(_run_wasm(CC_NO_PUSH), "empty\n")

    def test_inbody_declassify_over_reports_callsite_declassify_clean(self):
        # DISCLOSED SAFE over-report: the live re-read reads the RAW container
        # taint and is DECLASSIFY-BLIND, so a closure that declassifies its
        # captured value IN-BODY (defined before the push) still FLAGS at both
        # tiers though the disclosure was sanctioned. Sound (over-report, never
        # a missed leak).
        r = _analyze(CC_INBODY_DECLASSIFY)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_INBODY_DECLASSIFY, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])
        # WORKAROUND: declassify at the CALL SITE (declassify(f(), ...)) is the
        # clean escape hatch -- no flag at either tier.
        rw = _analyze(CC_CALLSITE_DECLASSIFY)
        self.assertTrue(rw.ok, [e.message for e in rw.errors])
        self.assertEqual(len(_flow_warnings(rw)), 0,
                         [w.message for w in rw.warnings])
        rws = _analyze(_strict(CC_CALLSITE_DECLASSIFY, "leak"))
        self.assertEqual(len(_flow_errors(rws)), 0,
                         [e.message for e in rws.errors])


class TestHofInvokedClosureResidualDisclosed(unittest.TestCase):
    """DISCLOSED residual (out of scope, Stage B): the captured closure ESCAPES
    to a higher-order callee (``apply(f)`` where ``apply(g)`` calls ``g()``),
    so its invocation is not locally resolvable to this lambda and the live
    capture re-read (which fires only at a locally-resolved invocation) does
    not apply. Stays UNFLAGGED at both tiers though it leaks the secret on both
    backends. Closing it needs higher-order resolution of the invoked closure.
    Leaks on main too; disclosed for honesty."""

    def test_unflagged_at_both_tiers(self):
        r = _analyze(CC_HOF)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_HOF, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_leaks_at_runtime_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_HOF), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_HOF), "s3cr3t\n")


# ---- REFTYPE (Finding 2): the capture re-read joins the whole-value
# ``sym.label`` only for a REFERENCE-typed capture. Three shapes pin the sound
# boundary. ----

# VALUE-typed (String) capture reassigned to a secret AFTER the closure is
# defined: captured BY VALUE, so nothing leaks (prints "pub") -- must NOT flag.
CC_SCALAR_REASSIGN = (TOK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var x: String = \"pub\"\n"
    "    let f: Fun() -> String = fun() -> String => x\n"
    "    x = secret\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# REFERENCE-typed (struct) capture FIELD-STORED in place then result-sunk: a
# REAL leak (prints "s3cr3t"), must STAY flagged -- this is why sym.label is
# kept for reference types (dropping it entirely would clear this leak).
CC_STRUCT_FIELDSTORE_RESULT = (TOK +
    "type Box { data: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var box: Box = Box { data: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => box.data\n"
    "    box.data = secret\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

# REFERENCE-typed (struct) capture WHOLE-REASSIGNED to a secret: captured by
# value here, so nothing leaks (prints "pub"), yet REFTYPE FLAGS it -- a
# disclosed SAFE over-rejection (a reference type raises sym.label on a whole
# reassign identically to an in-place field store, which REFTYPE cannot tell
# apart). Precedent: the reassigned-var sink recovery also fails closed.
CC_STRUCT_WHOLE_REASSIGN = (TOK +
    "type Box { data: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var box: Box = Box { data: \"pub\" }\n"
    "    let f: Fun() -> String = fun() -> String => box.data\n"
    "    box = Box { data: secret }\n"
    "    stdio.println(f())\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


class TestCaptureRereadReftype(unittest.TestCase):
    """REFTYPE (Finding 2): the whole-value ``sym.label`` re-read at a capture
    invocation fires only for a REFERENCE-typed capture. A VALUE-typed (built-in
    immutable primitive) capture is captured by value, so a later reassignment
    is not observed and must not flag; a reference-typed capture keeps the
    re-read, so a real in-place field-store-then-result-sink leak stays caught.

    The reference-typed re-read cannot tell a WHOLE reassign (by-value, no leak)
    from an in-place field store (a real leak): both raise the whole-value
    label. So a captured struct whole-reassigned to a secret is a disclosed SAFE
    over-rejection (flags but leaks nothing), precedented by the reassigned-var
    sink recovery failing closed under strict."""

    def test_value_typed_capture_reassign_is_clean(self):
        # l_a_scalar_reassign: fixed FP. Clean at both tiers, prints "pub".
        r = _analyze(CC_SCALAR_REASSIGN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_SCALAR_REASSIGN, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_SCALAR_REASSIGN), "pub\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_SCALAR_REASSIGN), "pub\n")

    def test_reference_typed_fieldstore_result_stays_flagged(self):
        # s_struct_fieldstore_result: a REAL leak, must stay flagged (proves
        # dropping sym.label entirely would be unsound). Prints "s3cr3t".
        r = _analyze(CC_STRUCT_FIELDSTORE_RESULT)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_STRUCT_FIELDSTORE_RESULT, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_STRUCT_FIELDSTORE_RESULT), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_STRUCT_FIELDSTORE_RESULT), "s3cr3t\n")

    def test_struct_whole_reassign_over_reports_but_leaks_nothing(self):
        # s_struct_reassign: disclosed SAFE over-rejection. Flags (REFTYPE keeps
        # sym.label for a reference type), but prints the PUBLIC value "pub".
        r = _analyze(CC_STRUCT_WHOLE_REASSIGN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(CC_STRUCT_WHOLE_REASSIGN, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(CC_STRUCT_WHOLE_REASSIGN), "pub\n")
        if skip is None:
            self.assertEqual(_run_wasm(CC_STRUCT_WHOLE_REASSIGN), "pub\n")


# ---- DISCLOSED residual (out of scope, Stage B): a sink INTERNAL to the
# closure body (a side effect, not the result the caller sinks). Stage B's
# capture re-read carries a captured value's later taint into the closure's
# RESULT label, so only a caller that sinks that RESULT is caught. A container
# pushed / a field stored after definition and then SUNK INSIDE the body leaks
# unflagged. Closable by a future field-store / access-path channel slice, not
# this label re-read. Each leaks "s3cr3t" on both backends. ----
CC_INTERNAL_SINK_PUSH = (TOK + "type Bag { items: List<String> }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    let f: Fun() -> Unit = fun() -> Unit =>\n"
    "        match bag.items.get(0)\n"
    "            Some(x) -> stdio.println(x)\n"
    "            None -> stdio.println(\"empty\")\n"
    "    bag.items.push(secret)\n"
    "    f()\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

CC_INTERNAL_SINK_CALLEE = (TOK + "type Bag { items: List<String> }\n"
    "fun show(bag: Bag, stdio: Stdio)\n"
    "    match bag.items.get(0)\n"
    "        Some(x) -> stdio.println(x)\n"
    "        None -> stdio.println(\"empty\")\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [] }\n"
    "    let f: Fun() -> Unit = fun() -> Unit => show(bag, stdio)\n"
    "    bag.items.push(secret)\n"
    "    f()\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

CC_INTERNAL_SINK_FIELDSTORE = (TOK + "type Bag { data: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { data: \"pub\" }\n"
    "    let f: Fun() -> Unit = fun() -> Unit => stdio.println(bag.data)\n"
    "    bag.data = secret\n"
    "    f()\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

_CAPTURE_INTERNAL_SINK_RESIDUAL = {
    "push_sunk_inside_body": CC_INTERNAL_SINK_PUSH,
    "sink_via_named_callee": CC_INTERNAL_SINK_CALLEE,
    "fieldstore_printed_inside_body": CC_INTERNAL_SINK_FIELDSTORE,
}


class TestCaptureInternalSinkResidualDisclosed(unittest.TestCase):
    """DISCLOSED residual (out of scope, Stage B): a captured value mutated
    after the closure is defined and SUNK INSIDE the closure body (a side
    effect, not the closure's result). Stage B's capture re-read carries the
    later taint into the closure's RESULT label only, so a caller that sinks the
    RESULT is caught but an INTERNAL sink is not. Stays UNFLAGGED at both tiers
    though it leaks "s3cr3t" on both backends -- via a direct push read inside
    the body, via a named callee inside the body, and via an in-place field
    store printed inside the body. Closable by a future field-store /
    access-path channel slice, not this label re-read. Leaks on main too."""

    def test_unflagged_at_both_tiers(self):
        for name, src in _CAPTURE_INTERNAL_SINK_RESIDUAL.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_leaks_at_runtime_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _CAPTURE_INTERNAL_SINK_RESIDUAL.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- CLOSED (Stage A, sink-side lambda-flow): a bare @secret passed to a
# LOCALLY-RESOLVABLE lambda (or an IIFE) whose body sinks its parameter is now
# flagged -- a warning by default, a hard error under @strict_ifc -- mirroring
# the direct named call. Every lambda literal carries its own sink-reaching
# summary (keyed by ``("lambda", id)``) and the call site applies it to the
# actual arguments exactly as the named-call check does. The value still leaks
# at runtime on both backends (a warning does not block execution). ----
_SINK = ("fun sink_str(s: String, stdio: Stdio)\n"
         "    stdio.println(s)\n")


def _leak(body: str) -> str:
    """A ``leak(stdio, secret)`` body plus the shared const / sink / ``main``
    caller, so the shapes below differ only in the lambda indirection."""
    return (TOK + _SINK +
            "fun leak(stdio: Stdio, secret: @secret String)\n" + body +
            "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


# let g = fun(s) => sink_str(s, stdio); g(secret) -- locally resolvable.
HO_LAMBDA_SINK = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => sink_str(s, stdio)\n"
    "    g(secret)\n")

# (fun(s) => sink_str(s, stdio))(secret) -- immediately-invoked lambda literal.
HO_IIFE_SINK = _leak(
    "    (fun(s: String) -> Unit => sink_str(s, stdio))(secret)\n")

# The control: the SAME sink reached by a DIRECT named call is flagged too, so
# the closed cases are specifically the lambda indirection, not the sink.
HO_NAMED_CONTROL = _leak("    sink_str(secret, stdio)\n")

# ---- no false positive: a lambda that does NOT sink its parameter, a PUBLIC
# argument to a sinking lambda, and an in-body ``declassify`` are all clean. ----
HO_LAMBDA_NOSINK = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => stdio.println(\"hi\")\n"
    "    g(secret)\n")

HO_LAMBDA_PUBARG = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => sink_str(s, stdio)\n"
    "    g(\"public\")\n")

HO_LAMBDA_DECLASSIFY = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => sink_str(declassify(s, reason: \"ok\"), stdio)\n"
    "    g(secret)\n")

# ---- wrong-target soundness: two locals, ``g`` (safe) and ``h`` (sinks its
# param). ``g(secret)`` stays CLEAN and ``h(secret)`` FLAGS -- per-target
# exact, no summary bleed between sibling lambdas. ----
HO_TWO_LAMBDA_SAFE = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => stdio.println(\"safe\")\n"
    "    let h: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => sink_str(s, stdio)\n"
    "    g(secret)\n")

HO_TWO_LAMBDA_SINK = _leak(
    "    let g: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => stdio.println(\"safe\")\n"
    "    let h: Fun(String) -> Unit = "
    "fun(s: String) -> Unit => sink_str(s, stdio)\n"
    "    h(secret)\n")

# ---- DISCLOSED residuals (still out of scope, Stage A): lambdas that ESCAPE
# local resolution -- a reassigned ``var`` (poisoned to None), an alias
# ``let g2 = g``, a call-result binding ``let g = mk()``, and a lambda passed to
# a higher-order function and invoked there. The caller cannot resolve any of
# these to one certain lambda literal, so on the conservative-miss rule they
# stay UNFLAGGED though they leak at runtime. Closing them needs higher-order
# CFA / points-to Capa lacks. ----
_MK = ("fun mk(stdio: Stdio) -> Fun(String) -> Unit\n"
       "    return fun(s: String) -> Unit => sink_str(s, stdio)\n")
_APPLY = ("fun apply(g: Fun(String) -> Unit, x: @secret String)\n"
          "    g(x)\n")

_LAMBDA_SINK_ESCAPING = {
    "reassigned_var": _leak(
        "    var g: Fun(String) -> Unit = "
        "fun(s: String) -> Unit => sink_str(s, stdio)\n"
        "    g = fun(s: String) -> Unit => sink_str(s, stdio)\n"
        "    g(secret)\n"),
    "alias_let": _leak(
        "    let g: Fun(String) -> Unit = "
        "fun(s: String) -> Unit => sink_str(s, stdio)\n"
        "    let g2: Fun(String) -> Unit = g\n"
        "    g2(secret)\n"),
    "call_result_binding": (TOK + _SINK + _MK +
        "fun leak(stdio: Stdio, secret: @secret String)\n"
        "    let g: Fun(String) -> Unit = mk(stdio)\n"
        "    g(secret)\n"
        "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n"),
    "passed_to_hof": (TOK + _SINK + _APPLY +
        "fun leak(stdio: Stdio, secret: @secret String)\n"
        "    apply(fun(s: String) -> Unit => sink_str(s, stdio), secret)\n"
        "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n"),
}


class TestSecretIntoLocalLambdaSinkClosed(unittest.TestCase):
    """CLOSED (Stage A, the sink-side face of the lambda-flow item): a bare
    @secret passed to a LOCALLY-RESOLVABLE lambda -- ``let g = fun(s) =>
    sink_str(s, stdio); g(secret)`` -- or to an IIFE ``(fun(s) =>
    sink_str(s, stdio))(secret)`` whose body sinks its parameter is now flagged
    (a warning by default, a hard error under @strict_ifc), the same tier as
    the direct named call. Every lambda literal is registered as a synthetic
    callable and summarised on the same sink-reaching fixpoint as a named
    function; the call site applies that summary to the actual arguments. The
    value still leaks at runtime on both backends (a warning does not block).

    ESCAPING lambdas the caller cannot resolve to one certain literal stay
    DISCLOSED residuals below; the CAPTURE-SIDE face (a container captured by a
    closure defined before a push, read after) is CLOSED for a locally-invoked
    closure in Stage B (``TestClosureCaptureBeforePushClosed``), with the
    HOF-invoked shape still disclosed
    (``TestHofInvokedClosureResidualDisclosed``)."""

    def test_lambda_indirection_is_flagged(self):
        for name, src in (("let-bound", HO_LAMBDA_SINK), ("iife", HO_IIFE_SINK)):
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                        [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                        [e.message for e in rs.errors])

    def test_flagged_shapes_leak_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in (("let-bound", HO_LAMBDA_SINK), ("iife", HO_IIFE_SINK)):
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")

    def test_named_call_control_is_flagged(self):
        # The gap closed is the lambda indirection: the SAME sink via a direct
        # named call must stay caught (a warning by default, a hard error
        # under strict).
        r = _analyze(HO_NAMED_CONTROL)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        rs = _analyze(_strict(HO_NAMED_CONTROL, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rs)), 1,
                                [e.message for e in rs.errors])

    def test_no_false_positive_shapes_are_clean(self):
        # A lambda that does not sink its param, a public argument, and an
        # in-body declassify must NOT flag at either tier.
        for name, src in (("nosink", HO_LAMBDA_NOSINK),
                          ("public_arg", HO_LAMBDA_PUBARG),
                          ("declassify", HO_LAMBDA_DECLASSIFY)):
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_wrong_target_is_per_lambda_exact(self):
        # ``g`` (safe) and ``h`` (sinks) coexist: calling the safe one stays
        # clean, the sinking one flags -- no summary bleed between siblings.
        rg = _analyze(HO_TWO_LAMBDA_SAFE)
        self.assertTrue(rg.ok, [e.message for e in rg.errors])
        self.assertEqual(len(_flow_warnings(rg)), 0,
                         [w.message for w in rg.warnings])
        rgs = _analyze(_strict(HO_TWO_LAMBDA_SAFE, "leak"))
        self.assertEqual(len(_flow_errors(rgs)), 0,
                         [e.message for e in rgs.errors])
        rh = _analyze(HO_TWO_LAMBDA_SINK)
        self.assertTrue(rh.ok, [e.message for e in rh.errors])
        self.assertGreaterEqual(len(_flow_warnings(rh)), 1,
                                [w.message for w in rh.warnings])
        rhs = _analyze(_strict(HO_TWO_LAMBDA_SINK, "leak"))
        self.assertGreaterEqual(len(_flow_errors(rhs)), 1,
                                [e.message for e in rhs.errors])


class TestEscapingLambdaSinkResidualDisclosed(unittest.TestCase):
    """DISCLOSED residuals (out of scope, Stage A): a lambda the caller cannot
    resolve to one certain literal -- a reassigned ``var`` (poisoned to None),
    an alias ``let g2 = g``, a call-result binding ``let g = mk()``, or a
    lambda passed to a higher-order function and invoked there -- stays
    UNFLAGGED at both tiers though it leaks the secret at runtime on both
    backends. The conservative-miss rule never applies a summary to a target it
    did not resolve; closing these needs higher-order CFA / points-to Capa
    lacks. If such a slice lands, these flip."""

    def test_unflagged_at_both_tiers(self):
        for name, src in _LAMBDA_SINK_ESCAPING.items():
            with self.subTest(shape=name):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])
                rs = _analyze(_strict(src, "leak"))
                self.assertEqual(len(_flow_errors(rs)), 0,
                                 [e.message for e in rs.errors])

    def test_leaks_at_runtime_both_backends(self):
        skip = _wasm_unavailable()
        for name, src in _LAMBDA_SINK_ESCAPING.items():
            with self.subTest(shape=name):
                self.assertEqual(_run_py(src), "s3cr3t\n")
                if skip is None:
                    self.assertEqual(_run_wasm(src), "s3cr3t\n")


# ---- DISCLOSED residual (out of scope, Stage A): a sink reached ONLY through a
# nested LOCAL-lambda invocation inside the body. The summary walk resolves a
# body's calls to NAMED (fun / method) callees only, never to a LOCAL-lambda
# binding (the same limitation named callables have), so ``g``'s body calling
# a sibling local lambda ``inner(s)`` does not surface ``inner``'s sink. So
# "sinks its parameter" means directly or via a NAMED callee; this stays
# unflagged though it leaks on both backends (as on main). ----
HO_NESTED_LOCAL_LAMBDA = (TOK + _SINK +
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    let inner: Fun(String) -> Unit = "
    "fun(t: String) -> Unit => sink_str(t, stdio)\n"
    "    let g: Fun(String) -> Unit = fun(s: String) -> Unit => inner(s)\n"
    "    g(secret)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


class TestNestedLocalLambdaSinkOpaqueResidualDisclosed(unittest.TestCase):
    """DISCLOSED residual (out of scope, Stage A): a bare @secret passed to a
    local lambda whose body reaches a sink ONLY through a NESTED LOCAL-lambda
    invocation -- ``let inner = fun(t) => sink_str(t, stdio); let g = fun(s) =>
    inner(s); g(secret)`` -- stays UNFLAGGED at both tiers though it leaks on
    both backends. The summary walk resolves a body's calls to NAMED
    (fun / method) callees only, never to a LOCAL-lambda binding, so ``inner``'s
    sink is opaque to ``g``'s summary. This is the same limitation named
    callables have; "sinks its parameter" (Stage A) means directly or via a
    NAMED callee. Leaks on main too (not a regression), disclosed for honesty."""

    def test_unflagged_at_both_tiers(self):
        r = _analyze(HO_NESTED_LOCAL_LAMBDA)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        rs = _analyze(_strict(HO_NESTED_LOCAL_LAMBDA, "leak"))
        self.assertEqual(len(_flow_errors(rs)), 0,
                         [e.message for e in rs.errors])

    def test_leaks_at_runtime_both_backends(self):
        skip = _wasm_unavailable()
        self.assertEqual(_run_py(HO_NESTED_LOCAL_LAMBDA), "s3cr3t\n")
        if skip is None:
            self.assertEqual(_run_wasm(HO_NESTED_LOCAL_LAMBDA), "s3cr3t\n")


# ---- DISCLOSED SAFE over-report (out of scope): a WHOLE-struct value copy
# ``var b2 = bag`` created AFTER a container push, then reading a CLEAN sibling
# through the copy. The copy reads ``bag`` whole (which now observes the
# container taint), collapsing to a whole-value @secret on ``b2``; ``b2`` has no
# per-field map, so the sibling read falls back to it and is FLAGGED though
# nothing leaks (it prints the public value). This same whole-value collapse
# correctly catches a read of the TAINTED field through the copy, so clearing
# it needs alias-group-aware per-field tracking (a points-to-adjacent change),
# the same family as the different-root alias residual. A copy made BEFORE the
# push keeps field precision and is CLEAN. ----
ALIAS_COPY_AFTER = (TOK +
    "type Bag { items: List<String>, other: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], other: \"public\" }\n"
    "    bag.items.push(secret)\n"
    "    var b2: Bag = bag\n"
    "    stdio.println(b2.other)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")

ALIAS_COPY_BEFORE = (TOK +
    "type Bag { items: List<String>, other: String }\n"
    "fun leak(stdio: Stdio, secret: @secret String)\n"
    "    var bag: Bag = Bag { items: [], other: \"public\" }\n"
    "    var b2: Bag = bag\n"
    "    bag.items.push(secret)\n"
    "    stdio.println(b2.other)\n"
    "fun main(stdio: Stdio)\n    leak(stdio, TOKEN)\n")


class TestWholeCopySiblingOverReportDisclosed(unittest.TestCase):
    """DISCLOSED SAFE over-report: a whole-struct value copy ``var b2 = bag``
    made AFTER a container push, then reading a clean sibling through the copy,
    is FLAGGED though nothing leaks (prints the public value). The copy reads
    ``bag`` whole and collapses to a whole-value @secret on ``b2`` (which has no
    per-field map), so the sibling falls back to it. This is the sound
    direction: the same collapse catches a read of the TAINTED field through
    the copy, so clearing the sibling needs alias-group-aware per-field
    tracking (a points-to-adjacent change, the different-root alias family). A
    copy made BEFORE the push keeps field precision and is CLEAN."""

    def test_copy_after_push_over_reports_but_is_safe(self):
        r = _analyze(ALIAS_COPY_AFTER)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertGreaterEqual(len(_flow_warnings(r)), 1,
                                [w.message for w in r.warnings])
        self.assertEqual(_run_py(ALIAS_COPY_AFTER), "public\n")
        skip = _wasm_unavailable()
        if skip is None:
            self.assertEqual(_run_wasm(ALIAS_COPY_AFTER), "public\n")

    def test_copy_before_push_is_clean(self):
        r = _analyze(ALIAS_COPY_BEFORE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])
        self.assertEqual(_run_py(ALIAS_COPY_BEFORE), "public\n")
        skip = _wasm_unavailable()
        if skip is None:
            self.assertEqual(_run_wasm(ALIAS_COPY_BEFORE), "public\n")


if __name__ == "__main__":
    unittest.main()
