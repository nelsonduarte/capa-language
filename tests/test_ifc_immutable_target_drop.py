"""Cross-function mutation-effect precision: drop only a PROVABLY
built-in-immutable parameter from the mutation-TARGET set.

``capa/analyzer/_ifc_summary.py`` used a value's data-flow TAINT set as
its alias / mutation-TARGET set at two sites (``_record_mutation_effect``
and ``_propagate_callee_effects``). A fresh local whose ELEMENTS were
derived from a parameter carries that parameter's taint, so mutating the
fresh local was mis-recorded as mutating the parameter. When such an
immutable-typed parameter merely carried a secret's taint, the callee's
mutation effect propagated back into the caller and raised a
FALSE-POSITIVE ``@secret``-reaches-sink diagnostic (a warning by default,
a hard error under ``@strict_ifc``). In the ``capa_server.serve_once``
inbound-server function this flagged ``serve`` (a ``Serve`` capability)
and ``conn`` (an ``Int``).

The fix drops a parameter from the mutation-effect target set ONLY when
its type PROVABLY has no writable interior: a BUILT-IN capability, a
built-in primitive (``Int`` / ``Float`` / ``Bool`` / ``Char`` /
``Unit``) or built-in ``String``. Resolution is by the type's SYMBOL
ORIGIN (the built-in source position), never by name or symbol kind
alone, so the two soundness traps the design review proved stay closed:

* a USER-defined capability (its methods are a real mutable data
  channel) is kept, even though it also lands as ``SymbolKind.CAPABILITY``
  -- the drop distinguishes a BUILT-IN capability from a user one; and
* a user type that merely SHADOWS a built-in name (``type Int { .. }`` is
  a mutable struct) is kept -- the drop confirms the name resolves to the
  actual BUILT-IN symbol, not a redeclaration.

``TestBuiltinImmutableTargetDropped`` pins the precision the fix buys (a
built-in-immutable parameter is no longer a mutation target, and the
reduced ``serve_once`` shape stops warning). ``TestRealLeaksStayCaught``
is the adversarial corpus: seven genuine write-back channels that MUST
stay caught. Every one of them warns by default and errors under
``@strict_ifc`` on the pre-fix compiler too; if any stops being caught
after the fix, the drop criterion is too broad. Together they bracket
the change: the precision tests fail if the drop is too NARROW (the
false positive survives), the corpus tests fail if it is too BROAD (a
real leak is dropped).
"""

import unittest

from capa import Lexer, Parser, analyze
from capa.analyzer import Analyzer
from capa.analyzer._ifc_summary import compute_ifc_summaries, _SummaryBuilder


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    return analyze(_parse(src), source=src)


def _strict(src: str) -> str:
    """Opt the ``main`` (which holds the leaking READ) into ``@strict_ifc``,
    the tier where the same flow is a hard error."""
    return src.replace("fun main(", "@strict_ifc()\nfun main(", 1)


def _flow_warnings(r):
    return [w for w in r.warnings if "information-flow" in w.message]


def _sink_errors(r):
    """The cross-boundary DATA-FLOW errors only. Under ``@strict_ifc`` a
    ``match`` on a secret also raises implicit-flow (secret control flow)
    errors; those are a separate, pre-existing check, so the data-flow
    tier is asserted on its own message."""
    return [e for e in r.errors if "a @secret value reaches" in e.message]


def _field_effect_targets(src: str, callable_key) -> set:
    """The mutation-effect TARGET parameter indices recorded for
    ``callable_key`` in ``src``'s summary, computed exactly as the
    analyzer computes them (populated global scope, same fixpoint). The
    effect map is keyed by ``(target_param_idx, field_path)`` (Stage 1
    field-path granularity), so the target parameter index is the first
    component of each key."""
    module = _parse(src)
    an = Analyzer()
    an.analyze(module)
    _sinks, feffects, _reffects, _scaps, _spaths = compute_ifc_summaries(
        module, an.global_scope,
    )
    return {key[0] for key in feffects.get(callable_key, {})}


def _immutable_params(src: str, callable_key) -> set:
    """The parameter indices ``src``'s summary builder classifies as
    provably built-in immutable (dropped from every mutation-target set)
    for ``callable_key``."""
    module = _parse(src)
    an = Analyzer()
    an.analyze(module)
    builder = _SummaryBuilder(module, an.global_scope)
    return set(builder.immutable_params.get(callable_key, frozenset()))


class TestBuiltinImmutableTargetDropped(unittest.TestCase):
    """The precision the fix buys: a parameter whose type is a built-in
    immutable is dropped from the mutation-effect target set, so a fresh
    local that merely carries its taint no longer mis-records a mutation
    of it. These FAIL on the pre-fix compiler (the false positive was
    live), so they pin that the fix is present and not too narrow."""

    # A callee that pushes a value derived from `handle` (an Int) into a
    # fresh local, and separately a real `xs: List` mutation. Only the
    # List parameter is a genuine mutation target.
    _MIXED = (
        "fun relay(handle: Int, xs: List<String>, v: String)\n"
        "    var buf: List<String> = []\n"
        "    buf.push(\"${handle}\")\n"
        "    buf.push(v)\n"
        "    xs.push(v)\n"
    )

    def test_immutable_param_is_not_a_mutation_target(self):
        targets = _field_effect_targets(self._MIXED, ("fun", "relay"))
        # `handle` is parameter 0 (Int, dropped); `xs` is parameter 1
        # (List, a real writable interior, kept). `v` (parameter 2,
        # String) is never a receiver, so it never appears as a target.
        self.assertNotIn(0, targets, "Int param wrongly kept as a target")
        self.assertIn(1, targets, "List param wrongly dropped as a target")

    def test_every_primitive_and_string_kind_is_dropped(self):
        # One callee per built-in primitive / String type: a fresh local
        # carries the parameter's taint (via interpolation for the scalars,
        # directly for String) and is mutated, so pre-fix the parameter was
        # recorded as a mutation target. Post-fix none is.
        cases = {
            "Int": "\"${p}\"",
            "Float": "\"${p}\"",
            "Bool": "\"${p}\"",
            "Char": "p",
            "String": "p",
        }
        for ty, pushed in cases.items():
            with self.subTest(ty=ty):
                src = (
                    f"fun relay(p: {ty})\n"
                    "    var buf: List<String> = []\n"
                    f"    buf.push({pushed})\n"
                )
                targets = _field_effect_targets(src, ("fun", "relay"))
                self.assertEqual(
                    targets, set(),
                    f"{ty} parameter wrongly kept as a mutation target",
                )

    # A fresh buffer whose elements the callee derives from a built-in
    # `Serve` capability (via `recv`) and the `conn` Int handle: exactly
    # the `read_request` shape. Pre-fix, pushing into the buffer recorded
    # a spurious mutation effect on both the capability and the Int.
    _CAP_RECV = (
        "fun relay(serve: Serve, conn: Int)\n"
        "    var buf: List<Int> = []\n"
        "    let chunk = match serve.recv(conn, 10)\n"
        "        Ok(c)  -> c\n"
        "        Err(_) -> []\n"
        "    buf.push(chunk.length())\n"
    )

    def test_builtin_capability_and_int_handle_dropped(self):
        targets = _field_effect_targets(self._CAP_RECV, ("fun", "relay"))
        self.assertEqual(
            targets, set(),
            "built-in Serve / Int handle wrongly kept as a mutation target",
        )

    def test_unit_typed_param_is_immutable(self):
        # `()` (the built-in Unit node) is sourced from the AST shape, not
        # a name a user could shadow, and is trivially immutable; a List
        # parameter alongside it is not.
        src = "fun relay(p: (), xs: List<String>)\n    let _ = p\n"
        imm = _immutable_params(src, ("fun", "relay"))
        self.assertEqual(imm, {0}, "Unit param must be classified immutable")

    # The reduced serve_once shape: an I/O handle (Int) whose value the
    # callee derives request-like bytes from, a fresh buffer, and a caller
    # that reads the handle back after the call. Pre-fix the callee's
    # spurious effect on the Int handle tainted the caller's handle and
    # warned; post-fix it is clean.
    _DEMO_SHAPE = (
        "fun relay(handle: Int, v: String)\n"
        "    var buf: List<String> = []\n"
        "    buf.push(\"${handle}\")\n"
        "    buf.push(v)\n"
        "fun main(env: Env, stdio: Stdio)\n"
        "    var handle: Int = 7\n"
        "    match env.get(\"API_KEY\")\n"
        "        Some(k) -> relay(handle, k)\n"
        "        None -> relay(handle, \"none\")\n"
        "    stdio.println(\"${handle}\")\n"
    )

    def test_demo_shape_no_false_warning(self):
        r = _analyze(self._DEMO_SHAPE)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_flow_warnings(r)), 0, [w.message for w in r.warnings],
        )

    def test_demo_shape_strict_is_clean(self):
        # The strict tier is where the false positive was a HARD ERROR and
        # blocked the inbound-server class. Only the implicit-flow errors
        # from the secret `match` may remain; the data-flow sink error must
        # be gone.
        r = _analyze(_strict(self._DEMO_SHAPE))
        self.assertEqual(
            len(_sink_errors(r)), 0, [e.message for e in r.errors],
        )


class TestRealLeaksStayCaught(unittest.TestCase):
    """The adversarial corpus (task facets 2a-2g): seven genuine
    write-back channels that MUST stay caught. Each warns by default and
    errors under ``@strict_ifc`` -- the same two-tier discipline the
    inline case follows -- on the pre-fix compiler too. If any stops
    warning after the fix, the drop criterion is too broad."""

    def _assert_caught(self, src: str):
        r = _analyze(src)
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_flow_warnings(r)), 1, [w.message for w in r.warnings],
        )
        rs = _analyze(_strict(src))
        self.assertFalse(rs.ok, "strict tier must be a hard error")
        self.assertEqual(
            len(_sink_errors(rs)), 1, [e.message for e in rs.errors],
        )

    def test_2a_user_capability_writeback_channel(self):
        # A user-defined `capability Store` implemented by a mutable
        # struct. Its `put` is a real mutable data channel, so the
        # `s: Store` parameter must be KEPT as a mutation target even
        # though a user capability also lands as SymbolKind.CAPABILITY.
        self._assert_caught(
            "capability Store\n"
            "    fun put(self, v: String)\n"
            "    fun get(self) -> String\n"
            "type Backing { slot: String }\n"
            "impl Store for Backing\n"
            "    fun put(self, v: String)\n"
            "        self.slot = v\n"
            "    fun get(self) -> String\n"
            "        return self.slot\n"
            "fun make_store() -> Backing\n"
            "    return Backing { slot: \"public\" }\n"
            "fun stash(s: Store, v: String)\n"
            "    s.put(v)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var s: Backing = make_store()\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> stash(s, k)\n"
            "        None -> stash(s, \"none\")\n"
            "    stdio.println(s.get())\n"
        )

    def test_2b_user_type_shadowing_a_builtin_name(self):
        # `type Int { .. }` shadows the built-in Int with a MUTABLE struct.
        # The `b: Int` parameter must be KEPT: the drop resolves the name
        # to the user symbol (real source position), not the built-in.
        self._assert_caught(
            "type Int { data: String }\n"
            "fun stash(b: Int, v: String)\n"
            "    b.data = v\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var b: Int = Int { data: \"public\" }\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> stash(b, k)\n"
            "        None -> stash(b, \"none\")\n"
            "    stdio.println(b.data)\n"
        )

    def test_2c_direct_container_mutation(self):
        # `xs.push(secret)` where `xs: List` is a parameter.
        self._assert_caught(
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

    def test_2d_alias_through_let(self):
        # `let ys = xs; ys.push(secret)`: the alias carries the List
        # parameter's taint, and the effect is recorded against the root
        # parameter, so aliasing must not launder the write-back.
        self._assert_caught(
            "fun stash(xs: List<String>, v: String)\n"
            "    let ys = xs\n"
            "    ys.push(v)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var xs: List<String> = []\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> stash(xs, k)\n"
            "        None -> stash(xs, \"none\")\n"
            "    match xs.get(0)\n"
            "        Some(v) -> stdio.println(v)\n"
            "        None -> stdio.println(\"empty\")\n"
        )

    def test_2e_struct_field_store(self):
        # `b.field = secret` where `b` is a struct parameter.
        self._assert_caught(
            "type Box { field: String }\n"
            "fun stash(b: Box, v: String)\n"
            "    b.field = v\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var b: Box = Box { field: \"public\" }\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> stash(b, k)\n"
            "        None -> stash(b, \"none\")\n"
            "    stdio.println(b.field)\n"
        )

    def test_2f_transitive_struct_field_store(self):
        # A callee passes a struct parameter to a FURTHER callee which
        # mutates it: the effect must cross both hops.
        self._assert_caught(
            "type Box { field: String }\n"
            "fun inner(b: Box, v: String)\n"
            "    b.field = v\n"
            "fun outer(b: Box, v: String)\n"
            "    inner(b, v)\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    var b: Box = Box { field: \"public\" }\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> outer(b, k)\n"
            "        None -> outer(b, \"none\")\n"
            "    stdio.println(b.field)\n"
        )

    def test_2f_transitive_list_push(self):
        # The same transitive shape for a built-in List container.
        self._assert_caught(
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

    def test_2g_option_of_struct_mutated_in_match(self):
        # An `Option` carrying a mutable struct, mutated INSIDE a `match`
        # in the callee, then re-extracted after the call. `Option<Box>`
        # has a writable interior (its payload struct), so it is kept.
        self._assert_caught(
            "type Box { field: String }\n"
            "fun stash(ob: Option<Box>, v: String)\n"
            "    match ob\n"
            "        Some(b) -> b.field = v\n"
            "        None -> ()\n"
            "fun main(env: Env, stdio: Stdio)\n"
            "    let boxed = Box { field: \"public\" }\n"
            "    var ob: Option<Box> = Some(boxed)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> stash(ob, k)\n"
            "        None -> stash(ob, \"none\")\n"
            "    match ob\n"
            "        Some(b) -> stdio.println(b.field)\n"
            "        None -> stdio.println(\"empty\")\n"
        )


class TestUserCapabilityKeptInSummary(unittest.TestCase):
    """Trap 1 pinned at the summary level: a USER-defined capability
    parameter stays a mutation target (never dropped by symbol kind),
    while a BUILT-IN capability parameter is dropped."""

    def test_user_capability_param_is_kept(self):
        src = (
            "capability Store\n"
            "    fun put(self, v: String)\n"
            "type Backing { slot: String }\n"
            "impl Store for Backing\n"
            "    fun put(self, v: String)\n"
            "        self.slot = v\n"
            "fun stash(s: Store, v: String)\n"
            "    s.put(v)\n"
        )
        targets = _field_effect_targets(src, ("fun", "stash"))
        self.assertIn(0, targets, "user capability param wrongly dropped")

    def test_builtin_capability_param_is_dropped(self):
        # A built-in capability whose `recv` result flows into a fresh
        # local that is then mutated must NOT be a mutation target.
        src = (
            "fun relay(serve: Serve, conn: Int)\n"
            "    var buf: List<Int> = []\n"
            "    let chunk = match serve.recv(conn, 10)\n"
            "        Ok(c)  -> c\n"
            "        Err(_) -> []\n"
            "    buf.push(chunk.length())\n"
        )
        targets = _field_effect_targets(src, ("fun", "relay"))
        self.assertEqual(targets, set(), "built-in cap param wrongly kept")


class TestUserShadowKeptInSummary(unittest.TestCase):
    """Trap 2 pinned at the summary level: a user type that shadows a
    built-in primitive NAME is a mutable struct and stays a mutation
    target, while the genuine built-in primitive is dropped."""

    def test_user_int_shadow_param_is_kept(self):
        src = (
            "type Int { data: String }\n"
            "fun stash(b: Int, v: String)\n"
            "    b.data = v\n"
        )
        targets = _field_effect_targets(src, ("fun", "stash"))
        self.assertIn(0, targets, "user Int-shadow param wrongly dropped")

    def test_builtin_int_param_is_dropped(self):
        src = (
            "fun relay(n: Int)\n"
            "    var buf: List<String> = []\n"
            "    buf.push(\"${n}\")\n"
        )
        targets = _field_effect_targets(src, ("fun", "relay"))
        self.assertEqual(targets, set(), "built-in Int param wrongly kept")


if __name__ == "__main__":
    unittest.main()
