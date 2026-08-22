"""Cross-function CONTAINER-MUTATION effect (closed false negative).

A secret pushed into a mutable container by a CALLED FUNCTION used to
escape the information-flow check entirely, while the identical push
written INLINE was caught. ``capa/analyzer/_ifc_summary.py`` recorded a
cross-function effect for a field store (``obj.f = v``) and propagated
it at call sites, but the container mutators of ``_CONTAINER_MUTATORS``
were reflected only into the summary walk's LOCAL environment, so no
effect was recorded and nothing crossed the boundary. A struct field
written by a callee was caught; a container mutated by a callee was
not.

The mutators now record the SAME effect the field store does, so they
share its fixpoint (depth: a callee that calls a callee that pushes)
and its call-site propagation (a container reached through a parameter
that was itself passed along), and both tiers behave as the inline case
does: a warning by default, a hard error under ``@strict_ifc``.

``_MUTATOR_PROGRAMS`` below is keyed by the ``_CONTAINER_MUTATORS``
registry entries, and ``test_every_registered_mutator_is_covered``
asserts the two key sets are equal -- a mutator added to the registry
without a leak program here fails the suite.
"""

import unittest

from capa import Lexer, Parser
from capa.analyzer._ifc_tables import _CONTAINER_MUTATORS


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    from capa import analyze
    return analyze(_parse(src), source=src)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _flow_errors(r):
    return [e for e in r.errors if "information-flow" in e.message]


def _sink_errors(r):
    """The DATA-FLOW errors only. Under ``@strict_ifc`` a ``match`` on a
    secret also raises implicit-flow (secret control flow) errors; those
    are a separate, pre-existing check and fire identically whether the
    push is inline or in a callee, so the data-flow tier is asserted on
    its own message."""
    return [
        e for e in r.errors
        if "a @secret value reaches" in e.message
    ]


# One leak program per ``_CONTAINER_MUTATORS`` entry: a helper mutates
# the container passed to it with a secret-derived value, and the caller
# then reads an element out and prints it. Every one of these exited the
# analyzer clean before the fix.
_MUTATOR_PROGRAMS: dict = {
    ("List", "push"): (
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
    ),
    ("Set", "add"): (
        "fun stash(xs: Set<String>, v: String)\n"
        "    xs.add(v)\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: Set<String> = new_set()\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> stash(xs, k)\n"
        "        None -> stash(xs, \"none\")\n"
        "    for v in xs.to_list()\n"
        "        stdio.println(v)\n"
    ),
    ("Map", "set"): (
        "fun stash(m: Map<String, String>, v: String)\n"
        "    m.set(\"k\", v)\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var m: Map<String, String> = new_map()\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> stash(m, k)\n"
        "        None -> stash(m, \"none\")\n"
        "    match m.get(\"k\")\n"
        "        Some(v) -> stdio.println(v)\n"
        "        None -> stdio.println(\"empty\")\n"
    ),
}


class TestEveryMutatorIsCovered(unittest.TestCase):
    """The registry is the source of truth: a mutator added to
    ``_CONTAINER_MUTATORS`` without a leak program here fails, so a
    future mutator cannot be introduced uncovered."""

    def test_every_registered_mutator_is_covered(self):
        self.assertEqual(
            set(_MUTATOR_PROGRAMS), set(_CONTAINER_MUTATORS),
            "add a callee-mutation leak program for every "
            "_CONTAINER_MUTATORS entry",
        )

    def test_every_registered_mutator_leak_is_flagged(self):
        for key, src in _MUTATOR_PROGRAMS.items():
            with self.subTest(mutator=key):
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(
                    len(_flow_warnings(r)), 1,
                    [w.message for w in r.warnings],
                )


class TestContainerMutationEffectShapes(unittest.TestCase):
    """The shapes the effect must cross: one hop, two hops, a
    passed-along parameter, a method receiver, a container held in a
    struct field."""

    def test_callee_push_of_secret_is_flagged(self):
        r = _analyze(_MUTATOR_PROGRAMS[("List", "push")])
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _flow_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("Stdio.println", w[0].message)

    def test_two_hop_callee_push_is_flagged(self):
        # ``outer`` does not push; ``inner`` does. The effect is
        # computed to the same fixpoint as the field-write effect, so
        # depth costs nothing.
        r = _analyze(
            "fun inner(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun outer(xs: List<String>, v: String)\n"
            "    inner(xs, v)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> outer(xs, k)\n"
            "        None -> outer(xs, \"none\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_three_hop_callee_push_is_flagged(self):
        r = _analyze(
            "fun innermost(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun inner(xs: List<String>, v: String)\n"
            "    innermost(xs, v)\n"
            "fun outer(xs: List<String>, v: String)\n"
            "    inner(xs, v)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> outer(xs, k)\n"
            "        None -> outer(xs, \"none\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_passed_along_parameter_is_flagged(self):
        # The container the leaf mutates is reached through a parameter
        # that was itself passed along, under a DIFFERENT name at each
        # hop, and the secret argument travels in a different parameter
        # position than at the leaf.
        r = _analyze(
            "fun leaf(v: String, xs: List<String>)\n"
            "    xs.push(v)\n"
            "fun middle(ys: List<String>, tok: String)\n"
            "    leaf(tok, ys)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var bag: List<String> = []\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> middle(bag, k)\n"
            "        None -> middle(bag, \"none\")\n"
            "    match bag.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_method_parameter_push_is_flagged(self):
        r = _analyze(
            "type Sink { name: String }\n"
            "impl Sink\n"
            "    fun stash(self, xs: List<String>, v: String)\n"
            "        xs.push(v)\n"
            "fun main(env: Env, stdio: Stdio, s: Sink)\n"
            "    var xs: List<String> = []\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> s.stash(xs, k)\n"
            "        None -> s.stash(xs, \"none\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_container_in_struct_field_push_is_flagged(self):
        # ``self.items.push(v)``: the mutated container is reached
        # through a FIELD of the receiver, so the effect is recorded
        # against the root parameter (``self``) whole-value.
        r = _analyze(
            "type Bag { items: List<String> }\n"
            "impl Bag\n"
            "    fun stash(self, v: String)\n"
            "        self.items.push(v)\n"
            "fun main(env: Env, stdio: Stdio, b: Bag)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> b.stash(k)\n"
            "        None -> b.stash(\"none\")\n"
            "    match b.items.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_declared_secret_param_source_is_flagged(self):
        # The source need not be Env: an explicitly @secret argument
        # bound to the value parameter fires the same effect.
        r = _analyze(
            "fun stash(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var xs: List<String> = []\n"
            "    stash(xs, token)\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_secret_const_source_is_flagged(self):
        # An internal secret source inside the callee (a module-level
        # @secret const) taints the caller's container unconditionally.
        r = _analyze(
            "const TOKEN: @secret String = \"s3cr3t\"\n"
            "fun stash(xs: List<String>)\n"
            "    xs.push(TOKEN)\n"
            "fun main(stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    stash(xs)\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])


class TestInlineBaselineUnmoved(unittest.TestCase):
    """The inline case behaved correctly before the change and must
    behave identically after it, at both tiers."""

    INLINE = (
        "fun main(env: Env, stdio: Stdio)\n"
        "    var xs: List<String> = []\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> xs.push(k)\n"
        "        None -> xs.push(\"none\")\n"
        "    match xs.get(0)\n"
        "        Some(v) -> stdio.println(v)\n"
        "        None -> stdio.println(\"empty\")\n"
    )

    def test_inline_push_still_warns_once(self):
        r = _analyze(self.INLINE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_inline_push_strict_is_error(self):
        r = _analyze("@strict_ifc()\n" + self.INLINE)
        self.assertFalse(r.ok)
        self.assertEqual(len(_sink_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_inline_public_push_is_clean(self):
        r = _analyze(
            "fun main(stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    xs.push(\"plain\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])


class TestStrictTier(unittest.TestCase):
    """Warn by default, hard error under ``@strict_ifc`` -- the same
    two-tier discipline the inline case and the field-write effect
    already follow. The strict flag is the one on the function that
    holds the leaking READ."""

    LEAK = (
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

    def test_default_tier_is_a_warning(self):
        r = _analyze(self.LEAK)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])
        self.assertEqual(len(_flow_errors(r)), 0)

    def test_strict_tier_is_a_hard_error(self):
        r = _analyze(self._strict(self.LEAK))
        self.assertFalse(r.ok)
        self.assertEqual(len(_sink_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_strict_tier_matches_the_inline_baseline_exactly(self):
        # Not just "an error fires": the callee shape must produce the
        # SAME strict diagnostics as the inline shape, so the tier
        # behaviour is genuinely matched rather than approximated.
        inline = _analyze(
            self._strict(TestInlineBaselineUnmoved.INLINE),
        )
        callee = _analyze(self._strict(self.LEAK))
        self.assertEqual(
            sorted(e.message for e in inline.errors),
            sorted(e.message for e in callee.errors),
        )
        self.assertEqual(
            sorted(w.message for w in inline.warnings),
            sorted(w.message for w in callee.warnings),
        )

    def test_default_tier_matches_the_inline_baseline_exactly(self):
        inline = _analyze(TestInlineBaselineUnmoved.INLINE)
        callee = _analyze(self.LEAK)
        self.assertEqual(
            sorted(w.message for w in inline.warnings),
            sorted(w.message for w in callee.warnings),
        )
        self.assertEqual(inline.errors, [])
        self.assertEqual(callee.errors, [])

    @staticmethod
    def _strict(src: str) -> str:
        return src.replace(
            "fun main(env: Env, stdio: Stdio)",
            "@strict_ifc()\nfun main(env: Env, stdio: Stdio)",
        )


class TestNoFalsePositives(unittest.TestCase):
    """Precision: a callee that touches a container holding no secret
    must stay clean."""

    def test_callee_pushes_public_value(self):
        r = _analyze(
            "fun stash(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun main(stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    stash(xs, \"plain\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_callee_pushes_a_literal_ignoring_the_secret_param(self):
        # The secret reaches the callee but does NOT flow into the
        # container, so no effect fires.
        r = _analyze(
            "fun stash(xs: List<String>, v: String)\n"
            "    let _ = v\n"
            "    xs.push(\"literal\")\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var xs: List<String> = []\n"
            "    stash(xs, token)\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_callee_only_reads_the_container(self):
        r = _analyze(
            "fun size(xs: List<String>) -> Int\n"
            "    return xs.length()\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var xs: List<String> = []\n"
            "    xs.push(\"plain\")\n"
            "    let _ = token\n"
            "    stdio.println(\"{size(xs)}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_declassified_push_is_clean(self):
        # declassify breaks the chain across the boundary exactly as it
        # does inline.
        r = _analyze(
            "fun stash(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var xs: List<String> = []\n"
            "    stash(xs, declassify(token, reason: \"audited\"))\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_untouched_sibling_container_stays_public(self):
        # Only the container the callee actually mutates is tainted.
        r = _analyze(
            "fun stash(xs: List<String>, v: String)\n"
            "    xs.push(v)\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var secret_bag: List<String> = []\n"
            "    var public_bag: List<String> = []\n"
            "    public_bag.push(\"plain\")\n"
            "    stash(secret_bag, token)\n"
            "    match public_bag.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])


class TestUserMethodNameCollision(unittest.TestCase):
    """The cross-function container-mutation effect matches the mutator
    by METHOD NAME. It must be gated by the receiver TYPE so a
    USER-defined method that merely shares a mutator's name
    (``push`` / ``add`` / ``set``) does NOT taint its receiver across a
    call boundary. The intra-procedural check is already type-aware
    (``_CONTAINER_MUTATORS.get((cap_name, method))``); the summary path
    must not be laxer. A user type's genuine mutation is still carried
    by that method's own summary, so gating out the by-name shortcut
    does not reopen the hole.

    ``fp_min``: a ``Box`` with a discarding ``push``, a ``bump`` that
    calls ``c.push(v)``, and a ``main`` that reads an unrelated,
    never-written field afterwards. Parent 6321246: 0 warnings. The
    by-name summary regression made this 1 spurious @secret warning, and
    a HARD COMPILE ERROR under ``@strict_ifc``."""

    _FP_MIN = (
        "type Box { a: String }\n"
        "impl Box\n"
        "    fun push(self, v: String)\n"
        "        let _ = v\n"
        "fun bump(c: Box, v: String)\n"
        "    c.push(v)\n"
        "fun main(stdio: Stdio, token: @secret String)\n"
        "    var c: Box = Box { a: \"public\" }\n"
        "    bump(c, token)\n"
        "    stdio.println(c.a)\n"
    )

    _FP_TRANSITIVE = (
        "type Box { a: String }\n"
        "impl Box\n"
        "    fun push(self, v: String)\n"
        "        let _ = v\n"
        "fun leaf(c: Box, v: String)\n"
        "    c.push(v)\n"
        "fun middle(b: Box, v: String)\n"
        "    leaf(b, v)\n"
        "fun main(stdio: Stdio, token: @secret String)\n"
        "    var c: Box = Box { a: \"public\" }\n"
        "    middle(c, token)\n"
        "    stdio.println(c.a)\n"
    )

    def test_user_push_collision_no_warning(self):
        r = _analyze(self._FP_MIN)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_user_push_collision_no_strict_error(self):
        strict = self._FP_MIN.replace(
            "fun main(stdio: Stdio, token: @secret String)",
            "@strict_ifc()\nfun main(stdio: Stdio, token: @secret String)",
        )
        r = _analyze(strict)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_errors(r)), 0,
                         [e.message for e in r.errors])

    def test_user_push_collision_transitive_no_warning(self):
        r = _analyze(self._FP_TRANSITIVE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_user_add_and_set_collisions_no_warning(self):
        # The gate must cover every mutator name, not only ``push``.
        for meth in ("add", "set"):
            with self.subTest(method=meth):
                src = (
                    "type Box { a: String }\n"
                    "impl Box\n"
                    f"    fun {meth}(self, v: String)\n"
                    "        let _ = v\n"
                    f"fun bump(c: Box, v: String)\n"
                    f"    c.{meth}(v)\n"
                    "fun main(stdio: Stdio, token: @secret String)\n"
                    "    var c: Box = Box { a: \"public\" }\n"
                    "    bump(c, token)\n"
                    "    stdio.println(c.a)\n"
                )
                r = _analyze(src)
                self.assertTrue(r.ok, [e.message for e in r.errors])
                self.assertEqual(len(_flow_warnings(r)), 0,
                                 [w.message for w in r.warnings])

    def test_builtin_container_still_warns_after_gate(self):
        # The gate must NOT reopen the closed hole: a genuine built-in
        # List mutated by a callee is still flagged.
        r = _analyze(_MUTATOR_PROGRAMS[("List", "push")])
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_user_type_that_really_stores_still_caught(self):
        # A user "container" whose ``push`` genuinely stores the value
        # into a @secret-reachable field is caught through that method's
        # OWN summary (the field-write effect), so gating out the
        # by-name shortcut does not lose a real leak. Here ``push``
        # stores ``v`` into ``self.a`` and ``main`` reads it back.
        r = _analyze(
            "type Box { a: String }\n"
            "impl Box\n"
            "    fun push(self, v: String)\n"
            "        self.a = v\n"
            "fun bump(c: Box, v: String)\n"
            "    c.push(v)\n"
            "fun main(stdio: Stdio, token: @secret String)\n"
            "    var c: Box = Box { a: \"public\" }\n"
            "    bump(c, token)\n"
            "    stdio.println(c.a)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])


# The leaking program, run end to end. The check is a WARNING, so the
# program still compiles and runs; both backends must print the same
# thing, which is what makes the missed diagnostic a real leak rather
# than a paper one.
_RUNNABLE_LEAK = (
    "const TOKEN: @secret String = \"s3cr3t\"\n"
    "fun stash(xs: List<String>, v: String)\n"
    "    xs.push(v)\n"
    "fun main(stdio: Stdio)\n"
    "    var xs: List<String> = []\n"
    "    stash(xs, TOKEN)\n"
    "    match xs.get(0)\n"
    "        Some(v) -> stdio.println(v)\n"
    "        None -> stdio.println(\"empty\")\n"
)


class TestBothBackendsRunTheLeak(unittest.TestCase):
    """The warn tier does not block compilation, so the leaking program
    runs; assert both backends print the secret identically."""

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

    def test_analyzer_warns_but_program_is_compilable(self):
        r = _analyze(_RUNNABLE_LEAK)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_python_backend_prints_the_secret(self):
        from capa import analyze, transpile
        module = _parse(_RUNNABLE_LEAK)
        result = analyze(module, source=_RUNNABLE_LEAK)
        code = transpile(
            module, types=result.types, bindings=result.bindings,
        )
        ns: dict = {"__name__": "__main__"}
        out = self._capture(
            lambda: exec(compile(code, "<ifc-container>", "exec"), ns),
        )
        self.assertEqual(out, "s3cr3t\n")

    def test_both_backends_print_the_same(self):
        import shutil
        if shutil.which("wasm-tools") is None:
            self.skipTest("wasm-tools not installed")
        try:
            import wasmtime  # noqa: F401
        except ImportError:
            self.skipTest("wasmtime-py not installed")
        from capa import analyze, transpile
        from capa.ir import compile_wasm
        from capa.runtime._wasm_host import WasmHost

        module = _parse(_RUNNABLE_LEAK)
        result = analyze(module, source=_RUNNABLE_LEAK)
        code = transpile(
            module, types=result.types, bindings=result.bindings,
        )
        ns: dict = {"__name__": "__main__"}
        py_out = self._capture(
            lambda: exec(compile(code, "<ifc-container>", "exec"), ns),
        )

        wasm_module = _parse(_RUNNABLE_LEAK)
        wasm_result = analyze(wasm_module, source=_RUNNABLE_LEAK)
        blob = compile_wasm(wasm_module, types=wasm_result.types)
        host = WasmHost()
        wasm_out = self._capture(lambda: host.run_main(blob))

        self.assertEqual(py_out, wasm_out)
        self.assertEqual(py_out, "s3cr3t\n")


if __name__ == "__main__":
    unittest.main()
