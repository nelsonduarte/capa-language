"""Tests for the Capa semantic analyzer.

Covers name resolution (defined symbols, undefined, redefinitions)
and type checking (literals, operators, assignments, calls,
struct literals, returns, conditions). Also includes smoke tests of
the canonical examples.
"""

import unittest

from capa import Lexer, Parser, analyze

from tests.analyzer._helpers import check, errors_of


# =============================================================
# Valid programs
# =============================================================



# =============================================================
# Name resolution
# =============================================================



# =============================================================
# Type checking
# =============================================================



# =============================================================
# Variants and match
# =============================================================



# =============================================================
# Trait and impl
# =============================================================



# =============================================================
# Capability discipline
# =============================================================

class TestCapabilityDiscipline(unittest.TestCase):
    """Capabilities represent permissions for effects. The discipline
    enforces that they only appear in function parameters, ensuring that
    the flow is visible in all signatures."""

    def test_cap_in_struct_field_rejected(self):
        msgs = errors_of("type S { c: Stdio, nome: String }\n")
        self.assertTrue(
            any("capability 'Stdio' cannot appear in struct field" in m for m in msgs)
        )

    def test_cap_in_variant_payload_rejected(self):
        msgs = errors_of(
            "type R =\n"
            "    Sem\n"
            "    Com(Stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in payload of variant" in m for m in msgs)
        )

    def test_cap_as_return_type_rejected(self):
        msgs = errors_of(
            "fun f() -> Stdio\n"
            "    return Stdio { }\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in return type" in m for m in msgs)
        )

    def test_cap_in_const_rejected(self):
        msgs = errors_of("const G: Fs = Fs { }\n")
        self.assertTrue(
            any("capability 'Fs' cannot appear in constant" in m for m in msgs)
        )

    def test_cap_in_let_rejected(self):
        msgs = errors_of(
            "fun f(stdio: Stdio)\n"
            "    let copia = stdio\n"
        )
        self.assertTrue(
            any("capability 'Stdio' cannot appear in a 'let' binding" in m for m in msgs)
        )

    def test_cap_in_var_rejected(self):
        msgs = errors_of(
            "fun f(fs: Fs)\n"
            "    var s: Fs = fs\n"
        )
        self.assertTrue(
            any("capability 'Fs' cannot appear in a 'var' binding" in m for m in msgs)
        )

    def test_cap_in_generic_arg_rejected(self):
        msgs = errors_of(
            "fun f() -> List<Stdio>\n"
            "    return []\n"
        )
        # The rule is detected via return type containing capability.
        self.assertTrue(
            any("capability 'Stdio'" in m for m in msgs)
        )

    def test_cap_in_tuple_rejected(self):
        msgs = errors_of(
            "fun f() -> (Stdio, Int)\n"
            "    return (Stdio { }, 0)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m for m in msgs)
        )

    def test_cap_as_param_ok(self):
        # The positive case: capability as parameter is the correct use.
        r = check(
            "fun saudar(stdio: Stdio)\n"
            "    stdio.println(\"olá\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_cap_passed_to_other_fn_ok(self):
        # Passing a capability to another function is acceptable (normal use).
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"em helper\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
            "    stdio.println(\"de volta em main\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_call_on_cap_ok(self):
        # Method calls on a capability don't consume it.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\")\n"
            "    stdio.println(\"b\")\n"
            "    stdio.println(\"c\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Non-aliasing in calls (v2 of the discipline) -------

    def test_aliased_arguments_rejected(self):
        msgs = errors_of(
            "fun pair(a: Stdio, b: Stdio)\n"
            "    a.println(\"a\")\n"
            "    b.println(\"b\")\n"
            "fun main(stdio: Stdio)\n"
            "    pair(stdio, stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 2 but was already used as argument 1"
                in m
                for m in msgs
            )
        )

    def test_aliased_receiver_and_arg_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.helper(stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 1 but was already used as receiver"
                in m
                for m in msgs
            )
        )

    def test_three_slots_with_repeat_rejected(self):
        msgs = errors_of(
            "fun trio(a: Stdio, b: Fs, c: Stdio)\n"
            "    a.println(\"a\")\n"
            "    c.println(\"c\")\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    trio(stdio, fs, stdio)\n"
        )
        self.assertTrue(
            any(
                "appears as argument 3 but was already used as argument 1"
                in m
                for m in msgs
            )
        )

    def test_distinct_caps_in_same_call_ok(self):
        r = check(
            "fun pair(s: Stdio, f: Fs)\n"
            "    s.println(\"hello\")\n"
            "    let _exists = f.exists(\"x\")\n"
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    pair(stdio, fs)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_sequential_calls_with_same_cap_ok(self):
        # Each call is its own "borrow"; sequential ones are OK.
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
            "    helper(stdio)\n"
            "    helper(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Mandatory usage of capability params -------

    def test_unused_cap_param_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    stdio.println(\"sem usar fs\")\n"
        )
        self.assertTrue(
            any("capability parameter 'fs' is declared but never used" in m for m in msgs)
        )

    def test_underscore_silences_unused_cap(self):
        r = check(
            "fun main(stdio: Stdio, _fs: Fs)\n"
            "    stdio.println(\"underscore silencia\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_used_via_pass_through_ok(self):
        r = check(
            "fun helper(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    helper(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Capability-container discipline: a capability may flow only as a
# bare, top-level function parameter, and can never be hidden inside a
# list / set / map / tuple (at any nesting depth). This closes the
# read-out / smuggle family: a container built with a capability
# element cannot be produced, stored, passed, or used, whatever the
# surrounding syntax.
# =============================================================

class TestCapabilityContainerDiscipline(unittest.TestCase):
    """A capability packed inside a container is rejected wherever it
    is produced, stored, passed, or used. A BARE capability (a direct
    parameter or a bare argument) stays accepted."""

    CONTAINER_MSG = "packed inside a list, set, map, or tuple"

    def _rejected(self, source: str) -> None:
        msgs = errors_of(source)
        self.assertTrue(
            any(self.CONTAINER_MSG in m for m in msgs),
            f"expected a capability-container rejection, got: {msgs}",
        )

    # ---- (C) entry gates: nested-capability parameters ----

    def test_list_of_cap_param_rejected(self):
        self._rejected(
            "fun sink(xs: List<Stdio>)\n"
            "    xs[0].println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    sink([stdio])\n"
        )

    def test_set_of_cap_param_rejected(self):
        self._rejected(
            "fun sink(_xs: Set<Stdio>)\n"
            "    return\n"
            "fun main(stdio: Stdio)\n"
            "    let s = new_set()\n"
            "    s.add(stdio)\n"
            "    sink(s)\n"
        )

    def test_map_of_cap_param_rejected(self):
        self._rejected(
            "fun sink(_m: Map<String, Stdio>)\n"
            "    return\n"
            "fun main(stdio: Stdio)\n"
            "    let m = new_map()\n"
            "    m.set(\"k\", stdio)\n"
            "    sink(m)\n"
        )

    def test_tuple_of_cap_param_rejected(self):
        self._rejected(
            "fun sink(_t: (Stdio, Int))\n"
            "    return\n"
            "fun main(stdio: Stdio)\n"
            "    sink((stdio, 1))\n"
        )

    def test_struct_holding_cap_container_field_rejected(self):
        # A cap-bearing struct (implements a user capability) may hold a
        # bare cap field, but not a CONTAINER of caps.
        self._rejected(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type Box {\n"
            "    caps: List<Stdio>\n"
            "}\n"
            "impl Logger for Box\n"
            "    fun log(self, msg: String)\n"
            "        return\n"
        )

    # ---- (C) entry gate: mutator insertion ----

    def test_push_cap_into_list_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(stdio)\n"
        )

    def test_add_cap_into_set_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var s = new_set()\n"
            "    s.add(stdio)\n"
        )

    def test_set_cap_into_map_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", stdio)\n"
        )

    # ---- (B) deferred recheck: inferred-empty-then-populated ----

    def test_inferred_empty_then_populated_read_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(stdio)\n"
            "    xs[0].println(\"x\")\n"
        )

    def test_deferred_read_before_populate_rejected(self):
        # The read is at a still-open element type, so only the
        # end-of-function deferred recheck sees the capability.
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    let probe = xs[0]\n"
            "    xs.push(stdio)\n"
            "    probe.println(\"late\")\n"
        )

    def test_generic_helper_escape_rejected(self):
        # The element type is opaque inside the helper and only surfaces
        # as the caller's List<Stdio> once inference completes.
        self._rejected(
            "fun stash<T>(xs: List<T>, v: T)\n"
            "    xs.push(v)\n"
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    stash(xs, stdio)\n"
            "    xs[0].println(\"via generic stash\")\n"
        )

    # ---- (A) use-gate: read-out / use shapes ----

    def test_index_bare_literal_receiver_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    [stdio][0].println(\"pwned via literal index\")\n"
        )

    def test_nested_literal_index_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    [[stdio]][0][0].println(\"via nested literal index\")\n"
        )

    def test_for_over_list_literal_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    for c in [stdio]\n"
            "        c.println(\"pwned via for over literal\")\n"
        )

    def test_for_over_set_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var s = new_set()\n"
            "    s.add(stdio)\n"
            "    for c in s\n"
            "        c.println(\"via set for\")\n"
        )

    def test_for_over_map_values_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var m = new_map()\n"
            "    m.set(\"a\", stdio)\n"
            "    for c in m.values()\n"
            "        c.println(\"via map values\")\n"
        )

    def test_map_higher_order_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    let _ = [stdio].map(fun (c: Stdio) -> Int => leak(c))\n"
            "fun leak(c: Stdio) -> Int\n"
            "    c.println(\"pwned via map closure\")\n"
            "    return 0\n"
        )

    def test_fold_higher_order_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    let _ = [stdio].fold(0, fun (a: Int, c: Stdio) -> Int => leak(c))\n"
            "fun leak(c: Stdio) -> Int\n"
            "    c.println(\"pwned via fold closure\")\n"
            "    return 0\n"
        )

    def test_flat_map_higher_order_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    let _ = [stdio].flat_map(fun (c: Stdio) -> List<Int> => leak(c))\n"
            "fun leak(c: Stdio) -> List<Int>\n"
            "    c.println(\"pwned via flat_map closure\")\n"
            "    return []\n"
        )

    def test_match_binds_cap_out_of_container_rejected(self):
        # A pattern binding a capability element out of a container
        # scrutinee is rejected: the scrutinee is a capability container.
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", stdio)\n"
            "    match m.get(\"k\")\n"
            "        Some(c) -> c.println(\"via match\")\n"
            "        None -> return\n"
        )

    def test_tuple_destructure_of_cap_rejected(self):
        self._rejected(
            "fun main(stdio: Stdio)\n"
            "    let (a, b) = (stdio, 1)\n"
            "    a.println(\"via tuple destructure\")\n"
        )

    def test_cap_container_return_rejected(self):
        self._rejected(
            "fun make(stdio: Stdio) -> List<Stdio>\n"
            "    return [stdio]\n"
        )

    # ---- allowances: the bare channel stays accepted ----

    def test_bare_cap_param_ok(self):
        r = check(
            "fun sink(s: Stdio)\n"
            "    s.println(\"ok\")\n"
            "fun main(stdio: Stdio)\n"
            "    sink(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_bare_cap_argument_ok(self):
        r = check(
            "fun helper(fs: Fs)\n"
            "    let _e = fs.exists(\"/x\")\n"
            "fun main(fs: Fs)\n"
            "    helper(fs)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_cap_struct_field_ok(self):
        # A cap-bearing struct may still hold a BARE built-in cap field.
        r = check(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type Box {\n"
            "    inner: Stdio\n"
            "}\n"
            "impl Logger for Box\n"
            "    fun log(self, msg: String)\n"
            "        self.inner.println(msg)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_cap_factory_return_ok(self):
        # A factory may return a BARE user-defined capability.
        r = check(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "type Box {\n"
            "    inner: Stdio\n"
            "}\n"
            "impl Logger for Box\n"
            "    fun log(self, msg: String)\n"
            "        self.inner.println(msg)\n"
            "fun make(stdio: Stdio) -> Logger\n"
            "    return Box { inner: stdio }\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_plain_container_of_values_ok(self):
        # A container of ordinary values is unaffected.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    var xs = []\n"
            "    xs.push(1)\n"
            "    for n in xs\n"
            "        stdio.println(\"n\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Capability forge: rejecting `Fs()`-style local construction.
# Surfaced 2026-05-24 by the empirical-study fuzz harness: the
# legacy --python backend transpiled `let fs = Fs()` to a literal
# `Fs()` instantiation that obtained unrestricted filesystem
# authority because the runtime `Fs` class defaults to an
# unrestricted instance. The analyzer must reject the call form
# so the static discipline holds across both backends.
# =============================================================

class TestCapabilityForgeRejected(unittest.TestCase):
    """A built-in capability name used as a callee is a forge
    attempt: it would let any function obtain authority it never
    declared. The analyzer rejects every such call."""

    def test_fs_forge_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let fs = Fs()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Fs' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_stdio_forge_rejected(self):
        msgs = errors_of(
            "fun no_caps()\n"
            "    let s = Stdio()\n"
            "    s.println(\"smuggled\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Stdio' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_net_forge_rejected(self):
        msgs = errors_of(
            "fun phone_home(stdio: Stdio)\n"
            "    let n = Net()\n"
            "    stdio.println(\"got net\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Net' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_env_forge_in_helper_rejected(self):
        # Forge inside a helper called from main: must still be
        # rejected. Verifies the check does not depend on the
        # enclosing function being `main`.
        msgs = errors_of(
            "fun leak()\n"
            "    let e = Env()\n"
            "    let _key = e.get(\"ANTHROPIC_API_KEY\")\n"
            "fun main(stdio: Stdio)\n"
            "    leak()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Env' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_all_builtin_caps_rejected(self):
        # Every built-in cap name must be rejected as callee.
        for cap in (
            "Stdio", "Fs", "Net", "Env", "Proc", "Clock", "Random",
            "Db", "Unsafe",
        ):
            with self.subTest(cap=cap):
                msgs = errors_of(
                    f"fun forge()\n"
                    f"    let c = {cap}()\n"
                )
                self.assertTrue(
                    any(
                        f"capability {cap!r} cannot be constructed at a "
                        f"call site" in m for m in msgs
                    ),
                    f"{cap}: {msgs}",
                )

    def test_cap_as_param_still_ok(self):
        # The legitimate use stays legitimate.
        r = check(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    match fs.read(\"x\")\n"
            "        Ok(_) -> stdio.println(\"ok\")\n"
            "        Err(_) -> stdio.println(\"err\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_defined_cap_call_also_rejected(self):
        # User-defined capabilities are abstract: they must be
        # constructed via a struct implementor + factory, not by
        # calling the cap name as if it were a constructor.
        msgs = errors_of(
            "capability Logger\n"
            "    fun log(self, msg: String)\n"
            "fun no_caps()\n"
            "    let l = Logger()\n"
            "    l.log(\"x\")\n"
        )
        self.assertTrue(
            any(
                "capability 'Logger' cannot be constructed at a call site"
                in m for m in msgs
            ),
            msgs,
        )

    def test_user_defined_cap_aliasing_rejected(self):
        # Pre-2026-05-24, the non-aliasing rule only fired on
        # built-in caps (CAPABILITY_NAMES). User-defined caps
        # slipped through, violating the single-flow property
        # the paper claims. Surfaced by the slice-6 fuzz panel
        # (cat_llm_dispatch_escape / llm_aliased_dispatch).
        msgs = errors_of(
            "capability Llm\n"
            "    fun chat(self, p: String) -> String\n"
            "fun dispatch(a: Llm, b: Llm) -> String\n"
            "    let _ = a.chat(\"x\")\n"
            "    return b.chat(\"y\")\n"
            "fun main(stdio: Stdio, llm: Llm)\n"
            "    let _ = dispatch(llm, llm)\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(
            any(
                "appears as argument 2 but was already used as argument 1"
                in m for m in msgs
            ),
            msgs,
        )


# =============================================================
# Generics inference
# =============================================================























# =============================================================
# Method dispatch
# =============================================================



# =============================================================
# Match exhaustiveness
# =============================================================

class TestMatchExhaustiveness(unittest.TestCase):
    """Match on sum types must cover all variants (or have a catch-all
    arm with wildcard or ident without guard)."""

    def test_complete_match_ok(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        Verde -> "g"\n'
            '        Azul -> "a"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_missing_variant_rejected(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        Verde -> "g"\n'
        )
        self.assertTrue(
            any("missing variants Azul" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_wildcard_makes_exhaustive(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_ident_pattern_makes_exhaustive(self):
        # Bind without guard is catch-all like _.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            '        Vermelho -> "v"\n'
            '        outro -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_guarded_arm_does_not_cover(self):
        # Arms with guards may fail, they don't count toward coverage.
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor, b: Bool) -> String\n"
            "    return match c\n"
            '        Vermelho if b -> "v"\n'
            '        Verde -> "g"\n'
        )
        self.assertTrue(
            any("missing variants Vermelho" in m for m in msgs),
            f"got: {msgs}",
        )

    def test_non_sum_types_not_checked(self):
        # Match over Int doesn't require exhaustiveness, user can use
        # _ explicitly, but the checker doesn't require it.
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            '        0 -> "zero"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    # ------- Bool exhaustiveness -------

    def test_bool_match_missing_false_rejected(self):
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
        )
        self.assertTrue(
            any("non-exhaustive match on Bool: missing false" in m for m in msgs)
        )

    def test_bool_match_missing_true_rejected(self):
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        false -> "nao"\n'
        )
        self.assertTrue(
            any("non-exhaustive match on Bool: missing true" in m for m in msgs)
        )

    def test_bool_match_complete_ok(self):
        r = check(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
            '        false -> "nao"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_bool_match_wildcard_ok(self):
        r = check(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true -> "sim"\n'
            '        _ -> "outro"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_bool_match_guards_dont_count(self):
        # Arms with guards don't count toward coverage.
        msgs = errors_of(
            "fun f(b: Bool) -> String\n"
            "    return match b\n"
            '        true if b -> "sim"\n'
            '        false if b -> "nao"\n'
        )
        self.assertTrue(
            any("missing true, false" in m for m in msgs)
        )

    # ------- Value-position open-domain exhaustiveness (BUG #2) -------
    #
    # A ``match`` used for its value (``return match ...``,
    # ``let x = match ...``) over an open scalar domain (Int / String /
    # Float / Char) must have a catch-all: a miss has no defined result
    # (Python backend raises UnboundLocalError, Wasm returns a zero
    # value). A bare statement-position ``match`` discards its value, so
    # a miss is a legal no-op and stays lenient.

    def test_value_match_on_int_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(i: Int) -> String\n"
            "    return match i\n"
            '        1 -> "one"\n'
            '        2 -> "two"\n'
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_on_string_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(s: String) -> Int\n"
            "    return match s\n"
            '        "a" -> 1\n'
            '        "b" -> 2\n'
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on String" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_in_let_without_catchall_rejected(self):
        msgs = errors_of(
            "fun t(i: Int) -> Int\n"
            "    let r = match i\n"
            "        1 -> 10\n"
            "        2 -> 20\n"
            "    return r\n"
        )
        self.assertTrue(
            any(
                "non-exhaustive match expression on Int" in m
                for m in msgs
            ),
            f"got: {msgs}",
        )

    def test_value_match_on_int_with_wildcard_ok(self):
        # Control: a wildcard catch-all keeps the value match valid.
        r = check(
            "fun t(i: Int) -> String\n"
            "    return match i\n"
            '        1 -> "one"\n'
            '        2 -> "two"\n'
            '        _ -> "other"\n'
        )
        self.assertTrue(r.ok, r.errors)

    def test_value_match_on_int_with_ident_catchall_ok(self):
        # Control: a bare ident binder is also a catch-all.
        r = check(
            "fun t(i: Int) -> Int\n"
            "    return match i\n"
            "        1 -> 10\n"
            "        other -> other\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_statement_match_on_int_without_catchall_ok(self):
        # Control: a bare statement-position match discards its value,
        # so an open-domain scrutinee needs no catch-all.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let i = 3\n"
            "    match i\n"
            '        1 -> stdio.println("one")\n'
            '        2 -> stdio.println("two")\n'
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Closures (lambdas)
# =============================================================



# =============================================================
# Trait and impl verification
# =============================================================



# =============================================================
# Standard library: List<T> builtin methods
# =============================================================

class TestListBuiltinMethods(unittest.TestCase):
    """List<T> has builtin methods: length, push, contains, map, filter,
    fold. Types are checked with substitution of T by the receiver's
    arg."""

    def test_length(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = [1, 2, 3].length()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_contains_with_correct_type(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let has = xs.contains(2)\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_contains_with_wrong_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let has = xs.contains(\"oops\")\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_map_changes_element_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let s = xs.map(fun (x: Int) -> String => \"x\")\n"
            "    stdio.println(\"${s.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        # s should have type List<String>
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "List<String>")

    def test_filter_predicate_must_return_bool(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let r = xs.filter(fun (x: Int) -> Int => x)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects fun(Int) -> Bool" in m for m in msgs)
        )

    def test_fold_with_different_acc_type(self):
        # fold may accumulate into a type different from the element.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let s = xs.fold(\"\", fun (acc: String, x: Int) -> String => acc)\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")


# =============================================================
# Multi-line method chaining (implicit line continuation by '.')
# =============================================================



# =============================================================
# Standard library: String builtin methods
# =============================================================

class TestStringBuiltinMethods(unittest.TestCase):
    """String has builtin methods: length, trim, to_upper, to_lower,
    contains, starts_with, ends_with, split, replace."""

    def test_length(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let n = s.length()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_upper_returns_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let u = s.to_upper()\n"
            "    stdio.println(u)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_u = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_u.value)]), "String")

    def test_split_returns_list_of_strings(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"a,b,c\"\n"
            "    let sep = \",\"\n"
            "    let parts = s.split(sep)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_parts = module.items[0].body.stmts[2]
        self.assertEqual(
            ty_str(result.types[id(let_parts.value)]),
            "List<String>",
        )

    def test_contains_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let bad = s.contains(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_chaining_string_methods(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let sep = \" \"\n"
            "    let r = \"  hello  \".trim().to_upper().split(sep)\n"
            "    stdio.println(\"${r.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_char_at_returns_option_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let c = s.char_at(1)\n"
            # ``c`` is Option<String>, which has no to_string, so it
            # cannot be interpolated directly; match it to prove the
            # binding typed as an Option carrying a String payload.
            "    let shown = match c\n"
            "        Some(ch) -> ch\n"
            "        None -> \"?\"\n"
            "    stdio.println(\"${shown}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        r = analyze(module, source=src)
        self.assertTrue(r.ok, r.errors)
        # find the binding for `c`
        c_ty = None
        for scope in (r.scopes if hasattr(r, "scopes") else []):
            for sym in scope.symbols.values():
                if sym.name == "c":
                    c_ty = sym.ty
        # If we cannot inspect the binding, fall back to a type-checked
        # success assertion: the program above only compiles if char_at
        # returns Option<String>.
        self.assertTrue(r.ok)

    def test_char_at_rejects_non_int_arg(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let c = s.char_at(\"oops\")\n"
        )
        self.assertFalse(r.ok)
        msgs = [e.format() for e in r.errors]
        self.assertTrue(
            any("Int" in m for m in msgs),
            msgs,
        )

    def test_substring_returns_string(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello world\"\n"
            "    let sub = s.substring(0, 5)\n"
            "    stdio.println(sub)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_substring_rejects_non_int_args(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let sub = s.substring(\"a\", 5)\n"
        )
        self.assertFalse(r.ok)

    def test_index_of_returns_option_int(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello world\"\n"
            "    let idx = match s.index_of(\"world\")\n"
            "        None -> 0 - 1\n"
            "        Some(i) -> i\n"
            "    stdio.println(\"${idx}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_index_of_rejects_non_string_arg(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    let idx = s.index_of(42)\n"
        )
        self.assertFalse(r.ok)


# =============================================================
# Interpolated strings (InterpolatedString)
# =============================================================

class TestInterpolatedString(unittest.TestCase):
    """Strings with ``${expr}`` are parsed as InterpolatedString
    with each interpolation as a real Capa expression, not raw text.
    This enables type-check, type-aware dispatch, etc."""

    def test_simple_interpolation(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let x = 42\n"
            "    stdio.println(\"value = ${x}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_method_call_in_interpolation(self):
        # Before this version, ${s.length()} would go to raw Python and fail.
        # Now it's parsed as an expression and dispatch works.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    stdio.println(\"len = ${s.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_undefined_in_interpolation_rejected(self):
        # Errors inside interpolation are reported.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"value = ${nao_existe}\")\n"
        )
        self.assertTrue(
            any("undefined name 'nao_existe'" in m for m in msgs)
        )

    def test_undefined_in_interpolation_has_correct_position(self):
        # Regression: prior to the interp_positions plumbing, a typo
        # inside ``${...}`` was reported at the string's opening
        # quote position (line 1, col 1) instead of at the actual
        # identifier inside the interpolation. Now the sub-lexer is
        # started at the source Pos of the interpolation content, so
        # the error position lands on the typo itself and the
        # rendered snippet shows the correct line with the correct
        # caret column.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let name = \"World\"\n"
            "    stdio.println(\"Hello, ${nme}!\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        # The error should report `nme` (not an empty name) and point
        # at line 3 where the typo lives, with the column landing on
        # the `n` of `nme`.
        msg = r.errors[0].message
        self.assertIn("undefined name 'nme'", msg)
        # Levenshtein hint should still find `name` as the suggestion.
        self.assertIn("did you mean 'name'", msg)
        # Position: line 3, and the caret lands on the `n` of `nme`
        # which is column 29 in the source above.
        self.assertEqual(r.errors[0].pos.line, 3)
        self.assertEqual(r.errors[0].pos.col, 29)

    def test_interpolation_position_with_escapes_before_it(self):
        # Escapes in the literal text (``\n``, ``\"``, ``\\``) consume
        # two source characters but only one byte in the resolved
        # value. The lexer-side position tracking records the
        # *source* position of each ``${...}``, so escapes earlier in
        # the literal do not throw off the column the error reports.
        source = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"a\\nb\\\"c ${missing}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'missing'", r.errors[0].message)
        # Line 2 (the println line); column lands on the `m` of
        # `missing`. The exact column comes from the source offset of
        # `${`'s opener plus 2 (for the ``${``).
        self.assertEqual(r.errors[0].pos.line, 2)
        # The string literal begins at col 19. `\n` is 2 source
        # chars, `\"` is 2 source chars, `${` is 2 source chars. So
        # ``missing`` starts at col 19 + 1 (quote) + 1 (a) + 2 (\n) +
        # 1 (b) + 2 (\") + 1 (c) + 1 (space) + 2 (${) = 30.
        self.assertEqual(r.errors[0].pos.col, 30)

    def test_two_interpolations_each_keep_their_own_position(self):
        # Two ``${...}`` in the same string. The second is the one
        # with the typo. The lexer records both positions in order,
        # and the parser pairs each interpolation with the right one,
        # so the second-interpolation diagnostic still points at the
        # second interpolation's position rather than at the first.
        source = (
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    stdio.println(\"${x} and ${y}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'y'", r.errors[0].message)
        self.assertEqual(r.errors[0].pos.line, 3)
        # ``y`` is at col 31 in the source:
        # 4 spaces + "stdio.println(" (14) + `"${x} and ${` (12) = 30,
        # then `y` is col 31.
        self.assertEqual(r.errors[0].pos.col, 31)

    def test_trailing_tokens_in_interpolation_rejected(self):
        # ``${x y}`` used to drop the ``y`` silently (the sub-parser
        # parsed ``x`` and never checked it had reached EOF), so a
        # forgotten operator compiled clean. It is now a clean parse
        # error (raised by parse_module, before analysis).
        from capa import ParserError

        for body in ("${x y}", "${a b}", "${a;}"):
            with self.subTest(body=body):
                with self.assertRaises(ParserError) as ctx:
                    check(
                        "fun main(stdio: Stdio)\n"
                        "    let x = 1\n"
                        "    let a = 2\n"
                        f"    stdio.println(\"{body}\")\n"
                    )
                self.assertIn("interpolation", ctx.exception.message)

    def test_single_expression_interpolation_still_ok(self):
        # The EOF check must not reject a legitimate single expression,
        # including multi-token ones and calls with comma arguments.
        for body in ("${x}", "${x + y}", "${f(x, y)}"):
            with self.subTest(body=body):
                r = check(
                    "fun f(p: Int, q: Int) -> Int\n"
                    "    return p\n"
                    "fun main(stdio: Stdio)\n"
                    "    let x = 1\n"
                    "    let y = 2\n"
                    f"    stdio.println(\"{body}\")\n"
                )
                self.assertTrue(r.ok, r.errors)

    def test_leading_whitespace_in_interpolation_accepted(self):
        # A leading space or tab inside ``${...}`` used to be lexed as
        # an INDENT (or trip the "tabs at start of line" rule) and
        # rejected, even though docs use ``${n * 2}``. Leading
        # horizontal whitespace is now stripped, so ``${ x }`` works;
        # interior spaces were already fine.
        for body in ("${ x }", "${ n * 2 }", "${\tx}", "${ n * 2}"):
            with self.subTest(body=body):
                r = check(
                    "fun main(stdio: Stdio)\n"
                    "    let x = 1\n"
                    "    let n = 2\n"
                    f"    stdio.println(\"{body}\")\n"
                )
                self.assertTrue(r.ok, r.errors)

    def test_leading_whitespace_keeps_correct_diagnostic_position(self):
        # Stripping leading whitespace must bias the reported position
        # so a typo inside ``${  missing}`` still points at the typo,
        # not at the (stripped) spaces.
        source = (
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${  zzz}\")\n"
        )
        r = check(source)
        self.assertFalse(r.ok)
        self.assertIn("undefined name 'zzz'", r.errors[0].message)
        self.assertEqual(r.errors[0].pos.line, 2)


class TestInterpolationFormattability(unittest.TestCase):
    """A ``${value}`` part must render on BOTH backends. The analyzer
    rejects a value whose type has no way to be formatted (no built-in
    rendering and no user ``to_string``), instead of the Python backend
    accepting it via dataclass repr while Wasm rejects it. Closes the
    cross-backend FormatStr divergence."""

    def test_primitives_are_formattable(self):
        for ty, val in (
            ("Int", "1"), ("Float", "1.5"), ("Bool", "true"),
            ("String", "\"hi\""), ("Char", "'a'"),
        ):
            r = check(
                "fun main(stdio: Stdio)\n"
                f"    let x: {ty} = {val}\n"
                "    stdio.println(\"${x}\")\n"
            )
            self.assertTrue(r.ok, f"{ty}: {r.errors}")

    def test_option_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o = Some(1)\n"
            "    stdio.println(\"${o}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)
        self.assertTrue(any("to_string" in m for m in msgs), msgs)
        self.assertTrue(any("Option" in m for m in msgs), msgs)

    def test_result_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(1)\n"
            "    stdio.println(\"${r}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_list_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    stdio.println(\"${xs}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_tuple_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let t = (1, \"a\")\n"
            "    stdio.println(\"${t}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_sum_without_to_string_rejected(self):
        msgs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Red\n"
            "    stdio.println(\"${c}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)
        self.assertTrue(any("Color" in m for m in msgs), msgs)

    def test_struct_without_to_string_rejected(self):
        msgs = errors_of(
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(any("cannot interpolate" in m for m in msgs), msgs)

    def test_struct_with_to_string_accepted(self):
        r = check(
            "type Point { x: Int, y: Int }\n"
            "impl Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"P(${self.x},${self.y})\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_sum_with_to_string_accepted(self):
        r = check(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "impl Color\n"
            "    fun to_string(self) -> String\n"
            "        return match self\n"
            "            Red -> \"red\"\n"
            "            Green -> \"green\"\n"
            "            Blue -> \"blue\"\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Red\n"
            "    stdio.println(\"${c}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_to_string_via_trait_impl_accepted(self):
        r = check(
            "trait Show\n"
            "    fun to_string(self) -> String\n"
            "type Point { x: Int, y: Int }\n"
            "impl Show for Point\n"
            "    fun to_string(self) -> String\n"
            "        return \"P(${self.x},${self.y})\"\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    stdio.println(\"${p}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_error_position_points_at_part(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let o = Some(1)\n"
            "    stdio.println(\"x = ${o}\")\n"
        )
        self.assertFalse(r.ok)
        interp = [e for e in r.errors if "cannot interpolate" in e.message]
        self.assertEqual(len(interp), 1)
        # Points at ``o`` inside the ``${...}``, not the string's quote.
        self.assertEqual(interp[0].pos.line, 3)


# =============================================================
# Standard library: Map<K, V> and Set<T>
# =============================================================

class TestMapBuiltinMethods(unittest.TestCase):
    """Map<K, V> has methods: length, get, set, contains_key, keys, values."""

    def test_basic_map_usage(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
            "    let v = m.get(\"a\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_get_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let v = m.get(\"a\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_v = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_v.value)]), "Option<Int>")

    def test_set_wrong_value_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", \"oops\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_get_wrong_key_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let _v = m.get(42)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_keys_returns_list_of_keys(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    let ks = m.keys()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_ks = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_ks.value)]), "List<String>")


class TestSetBuiltinMethods(unittest.TestCase):
    """Set<T> has methods: length, add, remove, contains, to_list,
    plus the algebra union / intersection / difference / is_subset."""

    def test_basic_set_usage(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(1)\n"
            "    s.add(2)\n"
            "    let has = s.contains(1)\n"
            "    stdio.println(\"${has}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_add_wrong_type_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s: Set<Int> = new_set()\n"
            "    s.add(\"oops\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_algebra_returns_set_and_bool(self):
        # union / intersection / difference yield a Set<Int> (so
        # chaining a Set method on the result type-checks); is_subset
        # yields a Bool.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let a: Set<Int> = new_set()\n"
            "    let b: Set<Int> = new_set()\n"
            "    let u = a.union(b)\n"
            "    let n = u.length()\n"
            "    let i = a.intersection(b)\n"
            "    let d = a.difference(b)\n"
            "    let sub = a.is_subset(b)\n"
            "    let chained = a.union(b).intersection(a)\n"
            "    stdio.println(\"${n} ${sub}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_union_wrong_element_type_rejected(self):
        # The argument must be a Set<T> with the SAME element type.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let a: Set<Int> = new_set()\n"
            "    let b: Set<String> = new_set()\n"
            "    let u = a.union(b)\n"
        )
        self.assertTrue(msgs, "expected a type error for mismatched element types")


# =============================================================
# Pattern matching with scrutinee type params
# =============================================================

class TestPatternTypeParams(unittest.TestCase):
    """Pattern matching against variants of generic types substitutes
    the owner's type params with the scrutinee's type args."""

    def test_some_payload_is_concrete_type(self):
        # match m: Option<Int> with Some(n), n should be Int, not T.
        from capa import Lexer, Parser, analyze
        src = (
            "fun main(stdio: Stdio)\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    match m.get(\"a\")\n"
            "        Some(n) -> stdio.println(\"${n + 1}\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        # No errors: n + 1 is only valid if n: Int.
        self.assertTrue(result.ok, result.errors)


# =============================================================
# Tuple patterns
# =============================================================

class TestTuplePatterns(unittest.TestCase):
    """Tuple patterns: ``(p1, p2, ...)`` destructures tuples in let,
    var, for, match. Each element can be an arbitrary pattern."""

    def test_let_tuple_destructure(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun par() -> (Int, String)\n"
            "    return (1, \"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    let (a, b) = par()\n"
            "    stdio.println(\"${a} ${b}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)

    def test_match_tuple_pattern(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let p = (1, \"um\")\n"
            "    match p\n"
            "        (1, s) -> stdio.println(s)\n"
            "        (n, _) -> stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_nested_pattern_in_tuple(self):
        # (Some(n), label), variant + literal in a tuple.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let opt: (Option<Int>, String) = (Some(42), \"x\")\n"
            "    match opt\n"
            "        (Some(n), label) -> stdio.println(\"${label}=${n}\")\n"
            "        (None, label) -> stdio.println(\"${label}=?\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_tuple_arity_mismatch_rejected(self):
        msgs = errors_of(
            "fun par() -> (Int, String)\n"
            "    return (1, \"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    let (a, b, c) = par()\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("3 elements, but type is" in m for m in msgs)
        )

    def test_string_literal_in_match(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let cmd = \"help\"\n"
            "    let r = match cmd\n"
            "        \"help\" -> \"show help\"\n"
            "        \"quit\" -> \"exit\"\n"
            "        _ -> \"unknown\"\n"
            "    stdio.println(r)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Struct-pattern bindings in let / for
# =============================================================

class TestStructPatternBinding(unittest.TestCase):
    """``let`` / ``for`` accept a one-level struct-destructuring
    pattern, but a struct sub-pattern nested inside a field is
    rejected at analysis time: neither backend can lower it (the
    transpiler raised "nested struct-pattern in let/for not
    supported" and the IR lowerer raised UnsupportedInIR), so
    ``--check`` and ``--run`` must agree by rejecting it up front.
    ``match`` arms keep their nesting support (a different code
    path) and are exercised by TestTuplePatterns / the parity
    suite, not here."""

    _NESTED_MSG = "nested struct-pattern in a 'let' / 'for' binding"

    def test_one_level_let_struct_destructure_ok(self):
        r = check(
            "type Point { x: Int, y: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Point { x: 1, y: 2 }\n"
            "    let Point { x, y } = p\n"
            "    let Point { x: a } = p\n"
            "    let Point { x: _, y: yy } = p\n"
            "    stdio.println(\"${x} ${y} ${a} ${yy}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_one_level_for_struct_destructure_ok(self):
        r = check(
            "type Pair { a: Int, b: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [Pair { a: 1, b: 2 }]\n"
            "    for Pair { a, b } in xs\n"
            "        stdio.println(\"${a} ${b}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_nested_struct_pattern_in_let_rejected(self):
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let o = Outer { inner: Inner { a: 7 } }\n"
            "    let Outer { inner: Inner { a } } = o\n"
            "    stdio.println(\"${a}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_nested_struct_pattern_in_for_rejected(self):
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let xs = [Outer { inner: Inner { a: 7 } }]\n"
            "    for Outer { inner: Inner { a } } in xs\n"
            "        stdio.println(\"${a}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_nested_struct_pattern_in_tuple_let_rejected(self):
        # A struct sub-pattern hidden inside a tuple element of a
        # let binding is the same unlowerable shape.
        msgs = errors_of(
            "type Inner { a: Int }\n"
            "fun main(stdio: Stdio)\n"
            "    let t = (Inner { a: 1 }, 2)\n"
            "    let (Inner { a }, b) = t\n"
            "    stdio.println(\"${a} ${b}\")\n"
        )
        self.assertTrue(
            any(self._NESTED_MSG in m for m in msgs), msgs
        )

    def test_match_nested_struct_pattern_still_ok(self):
        # The match path supports the nesting the let/for guard
        # rejects; confirm it was not caught in the crossfire.
        r = check(
            "type Inner { a: Int }\n"
            "type Outer { inner: Inner }\n"
            "fun main(stdio: Stdio)\n"
            "    let o = Outer { inner: Inner { a: 7 } }\n"
            "    match o\n"
            "        Outer { inner: Inner { a } } -> "
            "stdio.println(\"${a}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Or-patterns
# =============================================================

class TestOrPatterns(unittest.TestCase):
    """Or-patterns: ``A | B | C -> ...`` matches if any of the
    alternatives matches. No bindings in v0."""

    def test_or_with_variants(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Azul -> \"extremo\"\n"
            "        Verde -> \"meio\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_with_strings(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let cmd = \"help\"\n"
            "    let r = match cmd\n"
            "        \"h\" | \"help\" | \"?\" -> \"ajuda\"\n"
            "        _ -> \"outro\"\n"
            "    stdio.println(r)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_with_ints(self):
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        0 | 1 -> \"binary\"\n"
            "        2 | 3 | 5 | 7 -> \"small prime\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_pattern_with_consistent_bindings_accepted(self):
        # Bindings in or-patterns are now allowed if each alternative
        # binds the same set of names with compatible types.
        r = check(
            "type Op =\n"
            "    Add(Int)\n"
            "    Sub(Int)\n"
            "fun valor(o: Op) -> Int\n"
            "    return match o\n"
            "        Add(n) | Sub(n) -> n\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_or_pattern_with_inconsistent_names_rejected(self):
        # Each alternative must bind the same names.
        msgs = errors_of(
            "type Op =\n"
            "    Add(Int)\n"
            "    NoOp\n"
            "fun valor(o: Op) -> Int\n"
            "    return match o\n"
            "        Add(n) | NoOp -> 0\n"
        )
        self.assertTrue(
            any("binds different names" in m for m in msgs)
        )

    def test_or_pattern_with_incompatible_types_rejected(self):
        # Same name with incompatible types in different alternatives.
        msgs = errors_of(
            "type M =\n"
            "    AsInt(Int)\n"
            "    AsStr(String)\n"
            "fun foo(m: M) -> Int\n"
            "    return match m\n"
            "        AsInt(x) | AsStr(x) -> 0\n"
        )
        self.assertTrue(
            any("Int" in m and "String" in m for m in msgs)
        )

    def test_or_pattern_exhaustive(self):
        # OrPat counts each alternative toward the variant count.
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Verde -> \"a\"\n"
        )
        # Azul is missing.
        self.assertTrue(
            any("missing variants Azul" in m for m in msgs)
        )

    def test_or_pattern_exhaustive_complete(self):
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun nome(c: Cor) -> String\n"
            "    return match c\n"
            "        Vermelho | Verde -> \"qualquer\"\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Stdio: read_line and typed methods
# =============================================================

class TestStdioMethods(unittest.TestCase):
    """Stdio now has typed methods: print, println, eprintln,
    read_line. The checker catches wrong types that previously passed
    as TyUnknown."""

    def test_println_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(123)\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_read_line_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_read_line_no_args(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let r = stdio.read_line(\"oops\")\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expected 0 arguments, got 1" in m for m in msgs)
        )


class TestParseFunctions(unittest.TestCase):
    """parse_int and parse_float convert String to Option<Int|Float>."""

    def test_parse_int_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Option<Int>")

    def test_parse_int_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )


class TestRangeExpressions(unittest.TestCase):
    """Range expressions: `a..b` (exclusive) and `a..=b` (inclusive).
    Endpoints must be Int; the result has type Range<Int> (a lazy
    iterable distinct from List<Int>; ``to_list()`` materialises
    when the full List method surface is needed)."""

    def test_exclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_inclusive_range_is_range_int(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = 1..=5\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_xs = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_xs.value)]), "Range<Int>"
        )

    def test_range_with_arithmetic_endpoints(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let n = 5\n"
            "    let xs = (n - 1)..(n * 2)\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_with_float_left_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 1.0..10\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "left side" in m for m in msgs),
            msgs,
        )

    def test_range_with_string_right_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let xs = 0..\"ten\"\n"
            "    stdio.println(\"${xs.length()}\")\n"
        )
        self.assertTrue(
            any("requires Int endpoints" in m and "right side" in m for m in msgs),
            msgs,
        )

    def test_range_to_list_chains_with_list_methods(self):
        # Range's API surface is intentionally minimal (length,
        # contains, is_empty, to_list). Users that want the full
        # List API call `.to_list()` first; the materialisation
        # is then explicit in the source rather than hidden.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).to_list().filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_range_filter_directly_typechecks(self):
        # The teaching material's exact example: a Range carries the
        # List transform methods, so direct `.filter` on a range
        # type-checks and yields `List<Int>` (the same type as
        # `(0..10).to_list().filter(...)`). Both backends desugar
        # through `.to_list()`.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let evens = (0..10).filter(fun (x: Int) -> Bool => x % 2 == 0)\n"
            "    stdio.println(\"${evens.length()}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_evens = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_evens.value)]), "List<Int>")

    def test_range_transform_methods_typecheck(self):
        # map / fold / first / get carry the same signatures as their
        # List homonyms: map -> List<U>, fold -> the accumulator, the
        # indexed queries -> Option<T>.
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let squares = (0..5).map(fun (x: Int) -> Int => x * x)\n"
            "    let total = (1..=5).fold(0, fun (a: Int, x: Int) -> Int => a + x)\n"
            "    let head = (0..5).first()\n"
            "    let at = (0..5).get(2)\n"
            "    stdio.println(\"${squares.length()} ${total}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        stmts = module.items[0].body.stmts
        self.assertEqual(ty_str(result.types[id(stmts[0].value)]), "List<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[1].value)]), "Int")
        self.assertEqual(ty_str(result.types[id(stmts[2].value)]), "Option<Int>")
        self.assertEqual(ty_str(result.types[id(stmts[3].value)]), "Option<Int>")


class TestNumericConversions(unittest.TestCase):
    """to_float(Int) -> Float and to_int(Float) -> Int are the explicit
    bridges between numeric types (Capa has no implicit coercion)."""

    def test_to_float_typechecks(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let x: Int = 5\n"
            "    let y = to_float(x)\n"
            "    stdio.println(\"${y}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_y = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_y.value)]), "Float")

    def test_to_float_unblocks_int_to_float_division(self):
        # The motivating use case: Float / Int is a type error, but
        # Float / to_float(Int) is well-typed.
        r = check(
            "fun avg(sum: Float, count: Int) -> Float\n"
            "    return sum / to_float(count)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_int_typechecks(self):
        r = check(
            "fun f() -> Int\n"
            "    return to_int(3.7)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_to_float_rejects_non_int(self):
        msgs = errors_of(
            "fun f() -> Float\n"
            "    return to_float(3.14)\n"
        )
        self.assertTrue(
            any("expects Int, got Float" in m for m in msgs),
            msgs,
        )

    def test_to_int_rejects_non_float(self):
        msgs = errors_of(
            "fun f() -> Int\n"
            "    return to_int(42)\n"
        )
        self.assertTrue(
            any("expects Float, got Int" in m for m in msgs),
            msgs,
        )


# =============================================================
# Typed capabilities: Fs, Env, Clock, Random
# =============================================================

class TestCapabilityMethods(unittest.TestCase):
    """Fs, Env, Clock, Random have typed methods, they used to always
    return TyUnknown, now they have precise types."""

    def test_fs_ler_returns_result_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_fs_existe_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let b = fs.exists(\"/tmp/x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")

    def test_fs_ler_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs)
        )

    def test_env_get_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, env: Env)\n"
            "    let v = env.get(\"HOME\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_v = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_v.value)]),
            "Option<String>",
        )

    def test_clock_sleep_with_int_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, clock: Clock)\n"
            "    clock.sleep(1)\n"
        )
        self.assertTrue(
            any("expects Float, got Int" in m for m in msgs)
        )

    def test_random_int_range_with_float_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio, random: Random)\n"
            "    let n = random.int_range(1.0, 10)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects Int, got Float" in m for m in msgs)
        )


class TestNetAttenuation(unittest.TestCase):
    """Net capability, attenuation by `restrict_to`. The fresh narrowed
    capability is bindable in `let`/`var` (the structural rule against
    bare-capability lets is relaxed for method-call RHS), but a bare
    alias still is not."""

    def test_restrict_to_typechecks(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let api = net.restrict_to(\"api.example.com\")\n"
            "    stdio.println(\"${api.allows(\\\"api.example.com\\\")}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_api = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_api.value)]), "Net")

    def test_allows_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let b = net.allows(\"x\")\n"
            "    stdio.println(\"${b}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")

    def test_get_returns_result_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(net: Net, stdio: Stdio)\n"
            "    let r = net.get(\"https://x\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, IoError>",
        )

    def test_let_alias_of_bare_capability_still_rejected(self):
        # The relaxation only applies to method-call RHS. Plain identifier
        # aliases of capabilities remain forbidden, that is the case the
        # structural rule was originally there to catch.
        msgs = errors_of(
            "fun main(net: Net, stdio: Stdio)\n"
            "    let dup = net\n"
            "    stdio.println(\"${dup.allows(\\\"x\\\")}\")\n"
        )
        self.assertTrue(
            any("cannot appear in a 'let' binding" in m for m in msgs),
            msgs,
        )

    def test_restrict_to_with_non_string_rejected(self):
        msgs = errors_of(
            "fun main(net: Net, stdio: Stdio)\n"
            "    let api = net.restrict_to(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("expects String, got Int" in m for m in msgs),
            msgs,
        )

    def test_attenuation_example_clean(self):
        with open("examples/net_attenuation.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)


class TestUserDefinedCapabilities(unittest.TestCase):
    """`capability X { ... }` declarations and the relaxations they
    enable: built-in caps as struct fields when the struct implements a
    user-defined cap; user-defined caps as function return types;
    `let`-binding factory-call results; nominal subtyping via `impl`."""

    _SETUP = (
        "capability SendEmail\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "\n"
        "type SmtpMailer {\n"
        "    server: String,\n"
        "    net: Net\n"
        "}\n"
        "\n"
        "impl SendEmail for SmtpMailer\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "        return Ok(())\n"
        "\n"
        "fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer\n"
        "    return SmtpMailer { server: server, net: net.restrict_to(server) }\n"
    )

    def test_capability_decl_parses_and_typechecks(self):
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_cap_field_allowed_when_impl_user_cap(self):
        # SmtpMailer has `net: Net`, normally forbidden, allowed here
        # because SmtpMailer implements a user-defined capability.
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_struct_with_cap_field_rejected_when_no_user_cap_impl(self):
        # Plain struct (no `impl SendEmail for ...`), built-in cap as
        # field still rejected.
        msgs = errors_of(
            "type Service { net: Net, label: String }\n"
            "fun main()\n    return\n"
        )
        self.assertTrue(
            any("cannot appear in struct field 'net'" in m for m in msgs),
            msgs,
        )

    def test_factory_returning_user_cap_typechecks(self):
        # `fun make_smtp_mailer(...) -> SmtpMailer` is allowed even
        # though SmtpMailer is a user-defined capability.
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)

    def test_factory_returning_builtin_cap_rejected(self):
        # The relaxation is for *user-defined* caps. Built-in caps
        # still cannot be returned.
        msgs = errors_of(
            "fun forge() -> Net\n"
            "    return Net { }\n"
        )
        self.assertTrue(
            any("'Net' cannot appear in return type" in m for m in msgs),
            msgs,
        )

    def test_let_binding_of_factory_call_allowed(self):
        # `let mailer = make_smtp_mailer(net, ...)` is allowed because
        # the RHS is a Call producing a fresh user-defined cap.
        r = check(
            self._SETUP
            + "fun main(net: Net)\n"
            + "    let mailer = make_smtp_mailer(net, \"smtp.example.com\")\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_let_alias_of_bare_user_cap_rejected(self):
        # `let dup = mailer` (plain Ident RHS, alias) is still rejected.
        msgs = errors_of(
            self._SETUP
            + "fun use_mailer(mailer: SmtpMailer)\n"
            + "    let dup = mailer\n"
            + "    let _ = dup.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(
            any("cannot appear in a 'let' binding" in m for m in msgs),
            msgs,
        )

    def test_struct_can_be_passed_where_user_cap_expected(self):
        # Nominal subtyping: SmtpMailer is accepted where SendEmail
        # is expected, because SmtpMailer implements SendEmail.
        r = check(
            self._SETUP
            + "fun send_hello(mailer: SendEmail)\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
            + "fun main(net: Net)\n"
            + "    let m = make_smtp_mailer(net, \"smtp.example.com\")\n"
            + "    send_hello(m)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_unrelated_struct_not_accepted_where_user_cap_expected(self):
        # If Foo does NOT implement SendEmail, passing it to a
        # SendEmail parameter is a type error.
        msgs = errors_of(
            self._SETUP
            + "type Foo { x: Int }\n"
            + "fun send_hello(mailer: SendEmail)\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
            + "fun main()\n"
            + "    send_hello(Foo { x: 1 })\n"
        )
        self.assertTrue(
            any("expects SendEmail, got Foo" in m for m in msgs),
            msgs,
        )

    def test_user_capabilities_example_clean(self):
        with open("examples/user_capabilities.capa", encoding="utf-8") as f:
            r = check(f.read())
        self.assertTrue(r.ok, r.errors)

    # ---- Audit 2026-06-17 H1: field access through an abstract
    # capability / trait receiver is rejected. The runtime value is
    # the concrete implementor, so reaching its private field would
    # exercise a built-in cap the signature never declares. ----

    def test_field_access_through_abstract_cap_rejected(self):
        # ``mailer: SendEmail`` is the abstract cap as a parameter
        # type. ``mailer.net`` would reach the implementor's private
        # Net; this must be a field-access type error.
        msgs = errors_of(
            self._SETUP
            + "fun leak(mailer: SendEmail, stdio: Stdio)\n"
            + "    stdio.println(\"${mailer.net}\")\n"
        )
        self.assertTrue(
            any(
                "field 'net'" in m and "capability type 'SendEmail'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_nonexistent_field_through_abstract_cap_rejected(self):
        # Even a totally fake field name is rejected through an
        # abstract cap receiver (pre-fix it silently typed Unknown).
        msgs = errors_of(
            self._SETUP
            + "fun leak(mailer: SendEmail, stdio: Stdio)\n"
            + "    stdio.println(\"${mailer.totally_fake}\")\n"
        )
        self.assertTrue(
            any("capability type 'SendEmail'" in m for m in msgs),
            msgs,
        )

    def test_field_access_through_trait_receiver_rejected(self):
        # The same rule applies to a plain (non-capability) trait
        # used as a parameter type: the holder sees only the trait's
        # surface, not the implementor's fields.
        msgs = errors_of(
            "trait Greeter\n"
            "    fun greet(self) -> String\n"
            "type Person { name: String }\n"
            "impl Greeter for Person\n"
            "    fun greet(self) -> String\n"
            "        return self.name\n"
            "fun peek(g: Greeter) -> String\n"
            "    return g.name\n"
        )
        self.assertTrue(
            any(
                "field 'name'" in m and "trait type 'Greeter'" in m
                for m in msgs
            ),
            msgs,
        )

    def test_field_access_through_concrete_struct_still_allowed(self):
        # The legitimate reachable-via-struct model: a parameter of
        # the CONCRETE struct type that implements a cap can still
        # read its fields (e.g. a factory's own helper). Only the
        # abstract-cap type is barred.
        r = check(
            self._SETUP
            + "fun host_of(m: SmtpMailer) -> String\n"
            + "    return m.server\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_self_field_access_in_impl_still_allowed(self):
        # ``self`` inside the impl is the concrete struct, so
        # ``self.net`` / ``self.server`` keep compiling.
        r = check(
            "capability SendEmail\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "type SmtpMailer { server: String, net: Net }\n"
            "impl SendEmail for SmtpMailer\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "        let _ = self.server\n"
            "        return Ok(())\n"
        )
        self.assertTrue(r.ok, r.errors)

    # ---- Audit 2026-06-17 C5(a): Unsafe is rejected as a struct
    # field even when the struct implements a user-cap. The
    # cap-bearing relaxation covers only the attenuable built-in
    # caps, never the FFI escape hatch. ----

    def test_unsafe_field_rejected_in_cap_bearing_struct(self):
        msgs = errors_of(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { u: Unsafe }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any(
                "'Unsafe' cannot appear in struct field 'u'" in m
                and "capability-bearing struct" in m
                for m in msgs
            ),
            msgs,
        )

    def test_unsafe_nested_in_field_rejected_in_cap_bearing_struct(self):
        # Unsafe reached through a generic argument of a field type
        # is rejected too (the relaxation is not a blanket pass).
        msgs = errors_of(
            "capability Client\n"
            "    fun do_it(self) -> Int\n"
            "type RealClient { us: List<Unsafe> }\n"
            "impl Client for RealClient\n"
            "    fun do_it(self) -> Int\n"
            "        return 0\n"
        )
        self.assertTrue(
            any("'Unsafe' cannot appear in struct field 'us'" in m for m in msgs),
            msgs,
        )

    def test_attenuable_cap_field_still_allowed_in_cap_bearing_struct(self):
        # The relaxation still admits the attenuable built-in caps
        # (here Net) - only Unsafe is carved out.
        r = check(self._SETUP + "fun main()\n    return\n")
        self.assertTrue(r.ok, r.errors)


class TestStructCapConsume(unittest.TestCase):
    """Audit B-F2: a cap-bearing STRUCT is a consumable capability source
    on the argument-consume path, so ``dispose(m); m.send(..)`` (m a
    struct cap) is use-after-consume, exactly as a directly-typed cap is.
    A struct cap stays droppable and is not linear-by-containment: a
    multi-use with no consume still compiles."""

    _SETUP = (
        "capability SendEmail\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "type SmtpMailer {\n"
        "    server: String,\n"
        "    net: Net\n"
        "}\n"
        "impl SendEmail for SmtpMailer\n"
        "    fun send(self, to: String, subject: String, body: String) -> Result<Unit, IoError>\n"
        "        return Ok(())\n"
        "fun dispose(consume m: SmtpMailer)\n"
        "    return\n"
    )

    def test_struct_cap_use_after_consume_ident_rejected(self):
        # Consume a struct cap by bare Ident, then use it: rejected.
        msgs = errors_of(
            self._SETUP
            + "fun run(m: SmtpMailer)\n"
            + "    dispose(m)\n"
            + "    let _ = m.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(
            any(
                "'m' was consumed earlier and cannot be used again" in msg
                for msg in msgs
            ),
            msgs,
        )

    def test_struct_cap_use_after_consume_field_rejected(self):
        # FieldAccess variant: consume ``box.mailer`` then use it. The
        # wrapping Box implements a user cap so the struct field is legal.
        msgs = errors_of(
            self._SETUP
            + "capability Mailbox\n"
            + "    fun noop(self)\n"
            + "type Box {\n"
            + "    mailer: SmtpMailer\n"
            + "}\n"
            + "impl Mailbox for Box\n"
            + "    fun noop(self)\n"
            + "        return\n"
            + "fun run(box: Box)\n"
            + "    dispose(box.mailer)\n"
            + "    let _ = box.mailer.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(
            any(
                "'box.mailer' was consumed earlier and cannot be used again"
                in msg
                for msg in msgs
            ),
            msgs,
        )

    def test_struct_cap_multi_use_no_consume_compiles(self):
        # No consume anywhere: a struct cap may be used repeatedly.
        r = check(
            self._SETUP
            + "fun run(m: SmtpMailer)\n"
            + "    let _ = m.send(\"a@b\", \"s\", \"b\")\n"
            + "    let _ = m.send(\"c@d\", \"s\", \"b\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_struct_cap_let_bound_from_factory_then_used_compiles(self):
        # let-bound from a factory then used: still droppable, compiles.
        r = check(
            self._SETUP
            + "fun make_smtp_mailer(net: Net, server: String) -> SmtpMailer\n"
            + "    return SmtpMailer { server: server, net: net.restrict_to(server) }\n"
            + "fun run(net: Net)\n"
            + "    let mailer = make_smtp_mailer(net, \"smtp.example.com\")\n"
            + "    let _ = mailer.send(\"a@b\", \"s\", \"b\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# JSON: built-in JsonValue type and parse_json/to_json
# =============================================================

class TestJson(unittest.TestCase):
    """JsonValue is a built-in sum type with 6 variants. parse_json and
    to_json are built-in functions."""

    def test_parse_json_returns_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_json(\"{}\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<JsonValue, String>",
        )

    def test_match_all_json_variants(self):
        r = check(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
            "        JNum(n) -> \"num\"\n"
            "        JStr(s) -> \"str\"\n"
            "        JArr(xs) -> \"arr\"\n"
            "        JObj(m) -> \"obj\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_non_exhaustive_json_match_rejected(self):
        msgs = errors_of(
            "fun describe(j: JsonValue) -> String\n"
            "    return match j\n"
            "        JNull -> \"null\"\n"
            "        JBool(b) -> \"bool\"\n"
        )
        self.assertTrue(
            any("missing variants" in m and "JArr" in m and "JObj" in m
                for m in msgs)
        )

    def test_jstr_payload_is_string(self):
        # In match against JStr(s), s should be String.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"hello\")\n"
            "    match v\n"
            "        JStr(s) -> stdio.println(s.to_upper())\n"
            "        _ -> stdio.println(\"\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_jstr_with_int_rejected(self):
        # JStr expects String in the payload.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(42)\n"
            "    stdio.println(\"x\")\n"
        )
        self.assertTrue(
            any("String" in m for m in msgs)
        )

    def test_to_json_returns_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let s = to_json(JNull)\n"
            "    stdio.println(s)\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[0]
        self.assertEqual(ty_str(result.types[id(let_s.value)]), "String")


class TestJsonHelpers(unittest.TestCase):
    """Methods as_string, as_num, etc. on JsonValue avoid boilerplate."""

    def test_as_string_returns_option_string(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JStr(\"x\")\n"
            "    let s = v.as_string()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_is_null_returns_bool(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let v = JNull\n"
            "    let b = v.is_null()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_b = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_b.value)]), "Bool")


class TestOptionResultMethods(unittest.TestCase):
    """Option and Result have is_some/is_none/is_ok/is_err/unwrap_or."""

    def test_option_is_some(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(42)\n"
            "    if o.is_some()\n"
            "        stdio.println(\"some\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_option_unwrap_or(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(0)\n"
            "    stdio.println(\"${n}\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_n = module.items[0].body.stmts[1]
        self.assertEqual(ty_str(result.types[id(let_n.value)]), "Int")

    def test_option_unwrap_or_wrong_type_rejected(self):
        # unwrap_or<T>(default: T), default must have the same T as Option<T>.
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let n = o.unwrap_or(\"oops\")\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(
            any("expects Int, got String" in m for m in msgs)
        )

    def test_result_is_ok(self):
        r = check(
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\")\n"
            "    if r.is_ok()\n"
            "        stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestFunctionalCombinators(unittest.TestCase):
    """map, and_then, ok_or, map_err on Option/Result."""

    def test_option_map_changes_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let n = parse_int(\"42\")\n"
            "    let s = n.map(fun (x: Int) -> String => \"n\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_s = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_s.value)]),
            "Option<String>",
        )

    def test_option_ok_or_to_result(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r = parse_int(\"42\").ok_or(\"bad\")\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<Int, String>",
        )

    def test_result_map_err_changes_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").map_err(fun (e: IoError) -> Int => 1)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_option_filter_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Bool => x > 5)\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_f = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_f.value)]),
            "Option<Int>",
        )

    def test_option_filter_rejects_non_bool_predicate(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = Some(7)\n"
            "    let f = o.filter(fun (x: Int) -> Int => x + 1)\n"
        )
        self.assertTrue(any("Bool" in m for m in msgs), msgs)

    def test_option_or_else_returns_option_t(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let o: Option<Int> = None\n"
            "    let r = o.or_else(fun () -> Option<Int> => Some(42))\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Option<Int>",
        )

    def test_result_or_else_can_change_error_type(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio, fs: Fs)\n"
            "    let r = fs.read(\"/tmp/x\").or_else(\n"
            "        fun (e: IoError) -> Result<String, Int> => Err(1)\n"
            "    )\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_r = module.items[0].body.stmts[0]
        self.assertEqual(
            ty_str(result.types[id(let_r.value)]),
            "Result<String, Int>",
        )

    def test_result_ok_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Ok(7)\n"
            "    let o = r.ok()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<Int>",
        )

    def test_result_err_to_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let r: Result<Int, String> = Err(\"boom\")\n"
            "    let o = r.err()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_o = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_o.value)]),
            "Option<String>",
        )


class TestCollectionHelpers(unittest.TestCase):
    """is_empty/first/last/get on List, is_empty on String/Map/Set."""

    def test_list_first_returns_option(self):
        from capa import Lexer, Parser, analyze, ty_str
        src = (
            "fun main(stdio: Stdio)\n"
            "    let xs = [1, 2, 3]\n"
            "    let f = xs.first()\n"
            "    stdio.println(\"x\")\n"
        )
        tokens = Lexer(src).lex()
        module = Parser(tokens, source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        let_f = module.items[0].body.stmts[1]
        self.assertEqual(
            ty_str(result.types[id(let_f.value)]),
            "Option<Int>",
        )

    def test_list_get_returns_option(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs = [\"a\", \"b\", \"c\"]\n"
            "    match xs.get(0)\n"
            "        Some(s) -> stdio.println(s)\n"
            "        None -> stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_string_is_empty(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    if s.is_empty()\n"
            "        stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_empty_list_with_annotation(self):
        # `let xs: List<Int> = []` should compile.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let xs: List<Int> = []\n"
            "    if xs.is_empty()\n"
            "        stdio.println(\"vazio\")\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# if-expression: ``if cond then e1 else e2``
# =============================================================



# =============================================================
# Full linearity: consume keyword + flow analysis
# =============================================================

class TestConsume(unittest.TestCase):
    """The `consume` qualifier on a parameter indicates that the call
    transfers ownership of the passed capability. After a consuming
    call, the name cannot be used again.

    In branches (if/else, match), fork/merge is done: snapshot of
    consumed before each branch, conservative union after.
    """

    def test_consume_then_use_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier and cannot be used again" in m for m in msgs)
        )

    def test_consume_then_pass_again_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    adoptar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_does_not_consume(self):
        # Function without `consume` borrows, caller keeps the cap.
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_then_consume_ok(self):
        # Borrows followed by a final consume: typical pattern.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"y\")\n"
            "fun main(stdio: Stdio)\n"
            "    emprestar(stdio)\n"
            "    emprestar(stdio)\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_one_branch_makes_unusable_after(self):
        # If any branch of the if consumes, after the if the cap is considered
        # consumed (conservative rule).
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_both_branches_consume_no_use_after_ok(self):
        # Both branches consume, no use afterward, OK.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_both_branches_consume_use_after_rejected(self):
        # Both branches consume, but using afterward is an error.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, cond: Bool)\n"
            "    if cond\n"
            "        adoptar(stdio)\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_match_arm(self):
        msgs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, c: Cor)\n"
            "    match c\n"
            "        Vermelho ->\n"
            "            adoptar(stdio)\n"
            "        Verde ->\n"
            "            stdio.println(\"verde\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_methods_apply(self):
        # `consume` also works on methods.
        msgs = errors_of(
            "type Recurso { id: Int }\n"
            "impl Recurso\n"
            "    fun fechar(self, consume stdio: Stdio)\n"
            "        stdio.println(\"adeus\")\n"
            "fun main(stdio: Stdio)\n"
            "    let r = Recurso { id: 1 }\n"
            "    r.fechar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    # ------- Linearity in loops -------

    def test_consume_in_while_rejected(self):
        # Consuming inside while is an error: on the 2nd iteration it's already consumed.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    while true\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_consume_in_for_rejected(self):
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"x\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        adoptar(stdio)\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs)
        )

    def test_borrow_in_loop_consume_after_ok(self):
        # Typical pattern: borrow several times in the loop, final consume outside.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio)\n"
            "    var i = 0\n"
            "    while i < 3\n"
            "        emprestar(stdio)\n"
            "        i += 1\n"
            "    adoptar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_only_in_loop_ok(self):
        r = check(
            "fun emprestar(stdio: Stdio)\n"
            "    stdio.println(\"step\")\n"
            "fun main(stdio: Stdio, xs: List<Int>)\n"
            "    for x in xs\n"
            "        emprestar(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_if_branch_ok(self):
        # If a branch consumes a cap and then diverges (return),
        # the cap is not really consumed past the if: the divergent
        # path never reaches the merge point, so the post-if code
        # can still see the cap as live. Previously the merge was
        # naively conservative and treated the divergent path's
        # consumption as if it flowed forward; this test pins the
        # NLL-style precision fix.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_else_branch_ok(self):
        # Symmetric to the if-then case: the else diverges, the
        # then is a no-op, and the post-if code still has the cap.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        stdio.println(\"keep\")\n"
            "    else\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_divergent_match_arm_ok(self):
        # Same principle applied to match: the Yes arm consumes and
        # returns; the No arm does not consume. The post-match code
        # can only be reached via the No arm, where the cap is
        # still live.
        r = check(
            "type Choice =\n"
            "    Yes\n"
            "    No\n"
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, ch: Choice)\n"
            "    match ch\n"
            "        Yes ->\n"
            "            adoptar(stdio)\n"
            "            return\n"
            "        No -> stdio.println(\"no\")\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_in_non_divergent_if_branch_still_rejected(self):
        # Soundness check: the precision fix only excludes branches
        # that diverge. A branch that consumes and then falls
        # through must still propagate the consumption to the
        # merge, otherwise we admit a real use-after-consume.
        msgs = errors_of(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "    stdio.println(\"after\")\n"
        )
        self.assertTrue(
            any("was consumed earlier" in m for m in msgs), msgs
        )

    def test_consume_in_all_divergent_branches_ok(self):
        # All if branches diverge; the code after is unreachable.
        # The analyzer should not block on a phantom consumption in
        # the unreachable continuation.
        r = check(
            "fun adoptar(consume stdio: Stdio)\n"
            "    stdio.println(\"end\")\n"
            "fun main(stdio: Stdio, b: Bool)\n"
            "    if b\n"
            "        adoptar(stdio)\n"
            "        return\n"
            "    else\n"
            "        return\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Smoke tests of the canonical examples
# =============================================================



# =============================================================
# Named arguments
# =============================================================



# =============================================================
# "Did you mean?" suggestions
# =============================================================

class TestDidYouMeanHints(unittest.TestCase):
    """The analyzer attaches ``; did you mean 'X'?`` to error
    messages where the user almost certainly mistyped a name in
    scope. Coverage: undefined name, undefined type, no method
    on type, no field on struct, unknown variant in pattern.
    Sub-3-char needles are deliberately not hinted (too many
    plausible candidates)."""

    def test_undefined_name_suggests_in_scope_name(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let result = 1\n"
            "    stdio.println(\"${reslt}\")\n"
        )
        self.assertTrue(
            any("did you mean 'result'?" in e for e in errs), errs,
        )

    def test_undefined_type_suggests_known_type(self):
        errs = errors_of(
            "fun greet(s: Strng) -> Strng\n"
            "    return s\n"
        )
        self.assertTrue(
            any("did you mean 'String'?" in e for e in errs), errs,
        )

    def test_no_method_on_string_suggests_builtin(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let n = \"hi\".lenght()\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(
            any("did you mean 'length'?" in e for e in errs), errs,
        )

    def test_no_field_on_struct_suggests_field(self):
        errs = errors_of(
            "type Person {\n"
            "    full_name: String,\n"
            "    age: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Person { full_name: \"a\", age: 1 }\n"
            "    stdio.println(p.full_naem)\n"
        )
        self.assertTrue(
            any("did you mean 'full_name'?" in e for e in errs),
            errs,
        )

    def test_struct_literal_field_typo_suggests_known(self):
        errs = errors_of(
            "type Person {\n"
            "    full_name: String,\n"
            "    age: Int\n"
            "}\n"
            "fun main(stdio: Stdio)\n"
            "    let p = Person { full_naem: \"a\", age: 1 }\n"
            "    stdio.println(p.full_name)\n"
        )
        self.assertTrue(
            any("did you mean 'full_name'?" in e for e in errs),
            errs,
        )

    def test_unknown_variant_suggests_scrutinee_variant(self):
        errs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun name(c: Color) -> String\n"
            "    return match c\n"
            "        Red -> \"r\"\n"
            "        Gren -> \"g\"\n"
            "        Blue -> \"b\"\n"
        )
        self.assertTrue(
            any("did you mean 'Green'?" in e for e in errs), errs,
        )

    def test_short_needle_does_not_hint(self):
        # 'xx' is two characters; below the hinting threshold,
        # so the message should NOT suggest anything.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = xx\n"
            "    stdio.println(\"${x}\")\n"
        )
        # 'xx' must still be reported as undefined, just without
        # a 'did you mean' suffix.
        self.assertTrue(any("undefined name 'xx'" in e for e in errs), errs)
        self.assertFalse(
            any("did you mean" in e for e in errs), errs,
        )

    def test_exact_match_does_not_hint(self):
        # No hint should appear when the only candidate is itself
        # (distance 0 is filtered).
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let length = 5\n"
            "    stdio.println(\"${lenght}\")\n"
        )
        # 'length' is distance 1 from 'lenght'; a suggestion is
        # expected, but should NOT be the needle itself.
        for e in errs:
            self.assertNotIn("did you mean 'lenght'?", e)


class TestQuestionMarkOnNonResultOption(unittest.TestCase):
    """``?`` is a Result / Option unwrap operator. Applied to any
    other type it would explode at runtime with
    ``? applied to a value that is not Result or Option`` (the
    helper in ``capa.runtime`` raises a ``RuntimeError``). The
    analyser now surfaces this at type-check time so the error
    points at the source location with the actual type the user
    wrote, instead of waiting for the runtime crash."""

    def test_question_on_int_is_rejected(self):
        errs = errors_of(
            "fun bad(x: Int) -> Int\n"
            "    return x?\n"
        )
        self.assertTrue(
            any("`?` is only valid on Result<T, E> or Option<T>" in e
                and "Int" in e
                for e in errs),
            errs,
        )

    def test_question_on_string_is_rejected(self):
        errs = errors_of(
            "fun bad(s: String) -> String\n"
            "    return s?\n"
        )
        self.assertTrue(
            any("`?` is only valid on Result<T, E> or Option<T>" in e
                and "String" in e
                for e in errs),
            errs,
        )

    def test_question_on_result_still_accepted(self):
        # The fix must not regress the legitimate uses of ``?`` on
        # Result. ``parse_int`` returns ``Result<Int, String>``.
        r = check(
            "fun add_one(s: String) -> Result<Int, String>\n"
            "    let n = parse_int(s)?\n"
            "    return Ok(n + 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_question_on_option_still_accepted(self):
        # Same check for Option<T>: the regression from before this
        # iteration applied here too.
        r = check(
            "fun first_plus_one(xs: List<Int>) -> Option<Int>\n"
            "    let x = xs.first()?\n"
            "    return Some(x + 1)\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestQuestionMarkEnclosingReturn(unittest.TestCase):
    """``?`` propagates Err / None_ to the enclosing function. If
    that function does not return Result or Option, the propagation
    has nowhere safe to go: at runtime the slow ``_capa_try`` path
    raises ``_CapaTryEarlyReturn`` and the ``@_capa_wrap`` decorator
    catches it but then returns an Err / None_ from a function
    declared to return something else (a silent type violation).
    In the lambda case the exception used to escape past the lambda's
    caller entirely. The analyser now rejects every such use at
    type-check time so the diagnostic points at the ``?`` rather than
    at the wrong-shape value bubbling up later."""

    def test_question_in_int_returning_function_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun bad() -> Int\n"
            "    let x = produce()?\n"
            "    return x\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e and "Int" in e
                for e in errs),
            errs,
        )

    def test_question_in_unit_returning_function_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun bad()\n"
            "    produce()?\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e and ("Unit" in e or "()" in e)
                for e in errs),
            errs,
        )

    def test_question_in_expr_lambda_with_non_result_return_is_rejected(self):
        # The bug that motivated this rule: a lambda whose declared
        # return type is Int but whose body uses ``?``. The lambda
        # was emitted as a Python lambda with no decorator, and the
        # raised _CapaTryEarlyReturn escaped past the lambda's caller.
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Int\n"
            "    return fun () -> Int => produce()?\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )

    def test_question_in_block_lambda_with_non_result_return_is_rejected(self):
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Int\n"
            "    let f = fun () -> Int =>\n"
            "        let x = produce()?\n"
            "        return x\n"
            "    return f\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )

    def test_question_in_block_lambda_with_result_return_is_accepted(self):
        # The legitimate shape: a lambda that returns Result and uses
        # ``?`` inside its block body. The lambda gets ``@_capa_wrap``
        # in the transpiler so the propagation is caught at the
        # lambda's own boundary.
        r = check(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun build() -> Fun() -> Result<Int, Bad>\n"
            "    let f = fun () -> Result<Int, Bad> =>\n"
            "        let x = produce()?\n"
            "        return Ok(x + 1)\n"
            "    return f\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_question_in_lambda_does_not_inherit_outer_return(self):
        # Even when the outer function returns Result, the lambda's
        # own declared return type is what governs whether ``?`` is
        # allowed inside the lambda body. A Result-returning outer
        # function with a non-Result lambda inside must still reject
        # ``?`` in the lambda.
        errs = errors_of(
            "type Bad =\n"
            "    Oops(String)\n"
            "fun produce() -> Result<Int, Bad>\n"
            "    return Ok(1)\n"
            "fun outer() -> Result<Int, Bad>\n"
            "    let f = fun () -> Int => produce()?\n"
            "    return Ok(f())\n"
        )
        self.assertTrue(
            any("can only be used in a function or lambda that returns "
                "Result or Option" in e
                for e in errs),
            errs,
        )


class TestCallNonCallable(unittest.TestCase):
    """A call expression ``x(args)`` whose callee resolves to a
    non-function, non-variant binding (an Int local, a String
    constant, a struct value, etc.) used to be silently accepted
    by the v1 checker and would explode at runtime as
    ``TypeError: 'int' object is not callable``. The analyser
    now surfaces it at compile time with the actual type of the
    receiver. Function-typed locals (lambdas assigned to a
    binding) keep working."""

    def test_call_int_local_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 5\n"
            "    let y = x(2)\n"
            "    stdio.println(\"${y}\")\n"
        )
        self.assertTrue(
            any("'x' is not callable" in e and "Int" in e for e in errs),
            errs,
        )

    def test_call_string_constant_is_rejected(self):
        errs = errors_of(
            "const NAME: String = \"capa\"\n"
            "fun main(stdio: Stdio)\n"
            "    let x = NAME(1)\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("'NAME' is not callable" in e and "String" in e for e in errs),
            errs,
        )

    def test_call_lambda_local_is_accepted(self):
        # The function-typed-local exception: a lambda bound to a
        # local is callable. The checker leaves arity / arg-type
        # validation to the existing non-Ident-callee path (which
        # currently passes through to TyUnknown for these shapes);
        # the important thing is that this does not regress.
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let f = fun (x: Int) -> Int => x * 2\n"
            "    let y = f(3)\n"
            "    stdio.println(\"${y}\")\n"
        )
        self.assertTrue(r.ok, r.errors)




class TestMatchLiteralPatternType(unittest.TestCase):
    """A literal pattern only matches values of the same type as the
    literal. ``match int_x { "hello" -> ... }`` is dead code at best
    and a typo at worst; the analyser rejects it with both types
    named. TyUnknown / TyVar scrutinees stay permissive so generic
    code is not affected."""

    def test_string_pattern_against_int_scrutinee_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x: Int = 1\n"
            "    match x\n"
            "        \"hello\" -> stdio.println(\"str\")\n"
            "        _ -> stdio.println(\"else\")\n"
        )
        self.assertTrue(
            any("literal of type String" in e
                and "scrutinee of type Int" in e
                for e in errs),
            errs,
        )

    def test_int_pattern_against_string_scrutinee_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let s: String = \"hi\"\n"
            "    match s\n"
            "        42 -> stdio.println(\"int\")\n"
            "        _ -> stdio.println(\"else\")\n"
        )
        self.assertTrue(
            any("literal of type Int" in e
                and "scrutinee of type String" in e
                for e in errs),
            errs,
        )

    def test_matching_int_literal_with_int_still_accepted(self):
        # Regression guard: the legitimate case still type-checks.
        r = check(
            "fun classify(n: Int) -> String\n"
            "    return match n\n"
            "        0 -> \"zero\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_matching_string_literal_with_string_still_accepted(self):
        r = check(
            "fun name(s: String) -> Int\n"
            "    return match s\n"
            "        \"capa\" -> 1\n"
            "        _ -> 0\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestDuplicateMatchArms(unittest.TestCase):
    """A guardless match arm whose pattern is a payload-less variant
    or a literal already covered by an earlier arm is unreachable.
    The check fires both across arms (a second ``Vermelho ->``
    after an earlier ``Vermelho ->``) and within a single arm's
    or-pattern (``Vermelho | Vermelho ->``).

    Guarded arms (``x if cond ->``) do not register coverage
    because the guard may fail."""

    def test_duplicate_variant_arm_rejected(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        Vermelho -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(
            any("variant 'Vermelho'" in e and "already covered" in e
                for e in errs),
            errs,
        )

    def test_duplicate_int_literal_arm_rejected(self):
        errs = errors_of(
            "fun f(n: Int) -> String\n"
            "    return match n\n"
            "        1 -> \"one\"\n"
            "        1 -> \"duplicate\"\n"
            "        _ -> \"other\"\n"
        )
        self.assertTrue(
            any("literal value already covered" in e for e in errs),
            errs,
        )

    def test_duplicate_string_literal_arm_rejected(self):
        errs = errors_of(
            "fun f(s: String) -> Int\n"
            "    return match s\n"
            "        \"capa\" -> 1\n"
            "        \"capa\" -> 2\n"
            "        _ -> 0\n"
        )
        self.assertTrue(
            any("literal value already covered" in e for e in errs),
            errs,
        )

    def test_duplicate_within_or_pattern_rejected(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho | Vermelho -> 1\n"
            "        Verde -> 2\n"
        )
        self.assertTrue(
            any("variant 'Vermelho'" in e and "already covered" in e
                for e in errs),
            errs,
        )

    def test_guarded_duplicate_is_allowed(self):
        # A guarded arm does not absorb the value; a later arm
        # naming the same variant is reachable when the guard
        # fails. Compiler should accept.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor, n: Int) -> Int\n"
            "    return match c\n"
            "        Vermelho if n > 0 -> 1\n"
            "        Vermelho -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_distinct_variants_still_accepted(self):
        # The legitimate shape: each variant once.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        Verde -> 2\n"
            "        Azul -> 3\n"
        )
        self.assertTrue(r.ok, r.errors)




class TestStaticCallOnUserTypeRejected(unittest.TestCase):
    """``TypeName.method()`` on a user-defined type is not a supported
    call surface: Capa has no static-method call syntax. The bare-Ident
    receiver names a TYPE_STRUCT / TYPE_SUM symbol (a type, not a value),
    so it must be rejected at ``--check`` time rather than typing the
    receiver to ``TyUnknown`` and crashing with an ``AttributeError`` at
    runtime. The reject fires on the symbol KIND, so it precedes method
    name lookup: even a genuinely absent method is rejected here."""

    MSG = "Capa has no static-method call syntax"

    def test_static_call_on_struct_type_is_rejected(self):
        errs = errors_of(
            "type Bomb { n: Int }\n"
            "type Factory { seed: Int }\n"
            "impl Factory\n"
            "    fun create() -> Bomb\n"
            "        return Bomb { n: 0 }\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Factory.create()\n"
            "    stdio.println(\"${b.n}\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_static_call_absent_method_rejected_before_lookup(self):
        # The method does not exist. The kind-based reject fires before
        # name lookup, closing the crash-at-runtime facet: this used to
        # pass ``--check`` and then raise ``AttributeError`` at runtime.
        errs = errors_of(
            "type Factory { seed: Int }\n"
            "impl Factory\n"
            "    fun create() -> Factory\n"
            "        return Factory { seed: 0 }\n"
            "fun main(stdio: Stdio)\n"
            "    let f = Factory.nonexistent()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_static_call_on_sum_type_is_rejected(self):
        errs = errors_of(
            "type Color =\n"
            "    Red\n"
            "    Blue\n"
            "fun main(stdio: Stdio)\n"
            "    let c = Color.foo()\n"
            "    stdio.println(\"done\")\n"
        )
        self.assertTrue(any(self.MSG in e for e in errs), errs)

    def test_capability_attenuator_still_accepted(self):
        # Regression: ``Net.restrict_to`` is a CAPABILITY receiver, not
        # a TYPE_STRUCT / TYPE_SUM, so the kind-based reject must not
        # fire. The gate is load-bearing.
        r = check(
            "fun main(net: Net)\n"
            "    let n = Net.restrict_to(\"example.com\")\n"
            "    let _ = net.allows(\"example.com\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestUnreachableMatchArm(unittest.TestCase):
    """An arm written after a guardless catch-all (``_`` or a bare
    binding ident) is unreachable by construction: the catch-all
    has already matched. The analyser flags this so it cannot be
    silently introduced by reordering arms or by gluing two
    fragments together."""

    def test_arm_after_wildcard_is_unreachable(self):
        errs = errors_of(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        _ -> 2\n"
            "        Verde -> 3\n"
        )
        self.assertTrue(
            any("unreachable match arm" in e for e in errs),
            errs,
        )

    def test_arm_after_bare_binding_is_unreachable(self):
        # A bare identifier in a pattern is a fresh binding that
        # matches anything, same as ``_``. ``x -> ...`` therefore
        # makes the following arm unreachable.
        errs = errors_of(
            "fun f(n: Int) -> Int\n"
            "    return match n\n"
            "        x -> x + 1\n"
            "        0 -> 0\n"
        )
        self.assertTrue(
            any("unreachable match arm" in e for e in errs),
            errs,
        )

    def test_catchall_with_guard_does_not_close_match(self):
        # ``x if x > 0`` is a guarded catch-all; it does not
        # absorb every value, so a later arm is reachable.
        r = check(
            "fun f(n: Int) -> String\n"
            "    return match n\n"
            "        x if x > 0 -> \"pos\"\n"
            "        _ -> \"non-pos\"\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_trailing_catchall_is_fine(self):
        # The expected idiomatic shape: catch-all at the end.
        r = check(
            "type Cor =\n"
            "    Vermelho\n"
            "    Verde\n"
            "    Azul\n"
            "fun f(c: Cor) -> Int\n"
            "    return match c\n"
            "        Vermelho -> 1\n"
            "        _ -> 0\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestSelfOutsideImpl(unittest.TestCase):
    """``self`` outside an impl method body has no meaningful
    referent. Before, the generic ``undefined name`` Levenshtein
    pass suggested unrelated identifiers in scope (``'Set'``,
    ``'Stdio'``, etc.). The targeted message names what is
    actually wrong: ``self`` is impl-bound."""

    def test_self_in_free_function_is_targeted(self):
        errs = errors_of(
            "fun f() -> Int\n"
            "    return self.x\n"
        )
        self.assertTrue(
            any("'self' is only valid inside an `impl` method" in e
                for e in errs),
            errs,
        )
        # The generic Levenshtein hint must NOT also fire on
        # this one; otherwise users get noisy double-hinting.
        for e in errs:
            self.assertNotIn("did you mean", e)

    def test_self_inside_impl_method_with_field_still_works(self):
        # Regression guard: the existing self.field hint path
        # still fires when self IS valid (in an impl method) but
        # the user forgot the dot.
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get(self) -> Int\n"
            "        return v\n"
        )
        self.assertTrue(
            any("did you mean `self.v`?" in e for e in errs),
            errs,
        )


class TestSelfFieldHint(unittest.TestCase):
    """Inside an ``impl`` method, a bare identifier that matches a
    field of ``self``'s struct type is almost certainly a
    forgotten ``self.``. The analyser surfaces a targeted hint
    so the fix is obvious from the diagnostic."""

    def test_bare_field_in_impl_method_suggests_self_dot(self):
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get(self) -> Int\n"
            "        return v\n"
        )
        self.assertTrue(
            any("did you mean `self.v`?" in e for e in errs),
            errs,
        )

    def test_bare_non_field_falls_back_to_generic_hint(self):
        # ``vfx`` is not a field of Counter; the targeted hint
        # should not appear (no ``self.vfx`` suggestion).
        errs = errors_of(
            "type Counter { v: Int }\n"
            "impl Counter\n"
            "    fun get(self) -> Int\n"
            "        return vfx\n"
        )
        for e in errs:
            self.assertNotIn("did you mean `self.", e)

    def test_self_hint_only_inside_impl_methods(self):
        # A free function does not have a ``self`` type; the hint
        # must not fire even if a global struct happens to have a
        # field of that name.
        errs = errors_of(
            "type Counter { v: Int }\n"
            "fun get_outside() -> Int\n"
            "    return v\n"
        )
        for e in errs:
            self.assertNotIn("did you mean `self.", e)




class TestDuplicateBindingDiagnostic(unittest.TestCase):
    """``let x = ...; let x = ...`` (or any second binding of the
    same name in the same scope) is rejected. The diagnostic
    includes the source position of the previous binding and a
    hint about the ``var`` + bare-assignment idiom for the common
    case of "I meant to update the value, not redeclare it"."""

    def test_duplicate_let_names_previous_location(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    let x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        # The previous binding is on line 2, col 9 (``    let x``).
        self.assertTrue(
            any("duplicate binding 'x'" in e
                and "line 2, col 9" in e
                for e in errs),
            errs,
        )

    def test_duplicate_let_suggests_var(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let x = 1\n"
            "    let x = 2\n"
            "    stdio.println(\"${x}\")\n"
        )
        self.assertTrue(
            any("`var x` for a mutable binding" in e for e in errs),
            errs,
        )


class TestCapabilityFieldDiscipline(unittest.TestCase):
    """Capabilities held in cap-bearing struct fields must follow
    the same flow discipline as bare capability parameters. Two
    holes surfaced by the 2026-05-25 audit:

    A. ``mailer.net = other_net`` was accepted: capability fields
       could be re-bound after construction, laundering the cap.
    B. ``f(box.cap, box.cap)`` was accepted: the aliasing check
       only canonicalised bare ``Ident`` expressions, so two
       references via the same FieldAccess path looked distinct.
    """

    _SETUP = (
        "capability Mailer\n"
        "    fun send(self, to: String) -> Result<Unit, IoError>\n"
        "\n"
        "type SmtpMailer { server: String, net: Net }\n"
        "\n"
        "impl Mailer for SmtpMailer\n"
        "    fun send(self, to: String) -> Result<Unit, IoError>\n"
        "        return Ok(())\n"
        "\n"
    )

    def test_field_assign_builtin_capability_rejected(self):
        # Hole A: mailer.net = other_net used to pass silently.
        msgs = errors_of(
            self._SETUP
            + "fun forge(mailer: SmtpMailer, other_net: Net)\n"
            + "    mailer.net = other_net\n"
        )
        self.assertTrue(
            any("capability 'Net'" in m and "cannot be re-bound" in m for m in msgs),
            msgs,
        )

    def test_field_assign_user_capability_rejected(self):
        # Same as above but the field holds a user-defined cap rather
        # than a built-in one. Same hole.
        msgs = errors_of(
            "capability Logger\n"
            "    fun log(self, msg: String) -> Result<Unit, IoError>\n"
            "\n"
            "capability Driver\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "\n"
            "type Service { name: String, log: Logger }\n"
            "\n"
            "impl Driver for Service\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "fun forge(svc: Service, other_log: Logger)\n"
            "    svc.log = other_log\n"
        )
        self.assertTrue(
            any("capability 'Logger'" in m and "cannot be re-bound" in m for m in msgs),
            msgs,
        )

    def test_field_assign_non_capability_still_allowed(self):
        # Sanity: assigning to a non-capability field of a cap-bearing
        # struct is fine.
        r = check(
            self._SETUP
            + "fun rename(mailer: SmtpMailer, new_name: String)\n"
            + "    mailer.server = new_name\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_aliasing_through_same_field_path_rejected(self):
        # Hole B: take_two(mailer.net, mailer.net) used to pass.
        msgs = errors_of(
            self._SETUP
            + "fun take_two(a: Net, b: Net) -> Result<Unit, IoError>\n"
            + "    let _ = a.get(\"https://x\")\n"
            + "    let _ = b.get(\"https://y\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun use_mailer(mailer: SmtpMailer)\n"
            + "    let _ = take_two(mailer.net, mailer.net)\n"
        )
        self.assertTrue(
            any("'mailer.net'" in m and "cannot be aliased" in m for m in msgs),
            msgs,
        )

    def test_aliasing_through_different_owners_allowed(self):
        # Sanity: take_two(m1.net, m2.net) where m1 and m2 are
        # different parameters is fine, because the paths differ.
        r = check(
            self._SETUP
            + "fun take_two(a: Net, b: Net) -> Result<Unit, IoError>\n"
            + "    let _ = a.get(\"https://x\")\n"
            + "    let _ = b.get(\"https://y\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun use_mailers(m1: SmtpMailer, m2: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    return take_two(m1.net, m2.net)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_use_after_consume_through_field_access_rejected(self):
        # Hole D (audit 2026-05-25 H1): consume_one(box.cap) followed
        # by box.cap.use() used to pass because _mark_consumed_args
        # gated on isinstance(arg, Ident) and skipped FieldAccess
        # sources entirely.
        msgs = errors_of(
            self._SETUP
            + "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            + "    let _ = n.get(\"https://x\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun bug(mailer: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    let _ = consume_net(mailer.net)\n"
            + "    let _ = mailer.net.get(\"https://y\")\n"
            + "    return Ok(())\n"
        )
        self.assertTrue(
            any(
                "'mailer.net'" in m and "was consumed earlier" in m
                for m in msgs
            ),
            msgs,
        )

    def test_use_after_consume_through_field_access_chained(self):
        # Deeper FieldAccess chain: outer.inner.net. _path_of walks
        # the whole chain so the canonical path matches at both
        # consume and use sites.
        msgs = errors_of(
            "capability Mailer\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "\n"
            "capability Driver\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "\n"
            "type Inner { net: Net }\n"
            "type Outer { inner: Inner }\n"
            "\n"
            "impl Mailer for Inner\n"
            "    fun send(self, to: String) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "impl Driver for Outer\n"
            "    fun drive(self) -> Result<Unit, IoError>\n"
            "        return Ok(())\n"
            "\n"
            "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            "    let _ = n.get(\"https://x\")\n"
            "    return Ok(())\n"
            "\n"
            "fun bug(outer: Outer) -> Result<Unit, IoError>\n"
            "    let _ = consume_net(outer.inner.net)\n"
            "    let _ = outer.inner.net.get(\"https://y\")\n"
            "    return Ok(())\n"
        )
        self.assertTrue(
            any(
                "'outer.inner.net'" in m and "was consumed earlier" in m
                for m in msgs
            ),
            msgs,
        )

    def test_consume_through_field_access_single_use_allowed(self):
        # Sanity: consuming a FieldAccess path exactly once is the
        # legitimate flow; the new check must not fire here.
        r = check(
            self._SETUP
            + "fun consume_net(consume n: Net) -> Result<Unit, IoError>\n"
            + "    let _ = n.get(\"https://x\")\n"
            + "    return Ok(())\n"
            + "\n"
            + "fun ok(mailer: SmtpMailer) -> Result<Unit, IoError>\n"
            + "    return consume_net(mailer.net)\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestCapLeakViaGenericInstantiation(unittest.TestCase):
    """Hole C from the 2026-05-25 audit: the structural check
    ``_check_no_capability`` fires on a generic function's
    declaration body (where ``T`` is an opaque type variable),
    but the call site that substitutes ``T = Stdio`` was not
    re-validated. ``id(stdio)`` and ``wrap(stdio)`` used to pass
    silently even though no parameter in either function's
    signature names a capability.

    The fix runs ``_contains_any_capability`` on every substituted
    parameter and on the substituted return type post-unification;
    a cap that appears post-substitution but not pre-substitution
    was smuggled in through a TyVar."""

    def test_identity_function_with_builtin_cap_rejected(self):
        # `id(stdio)` substitutes T = Stdio, smuggling the cap
        # through a function whose signature does not declare it.
        msgs = errors_of(
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let _s = id(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_wrap_with_builtin_cap_rejected(self):
        # `wrap(stdio)` smuggles Stdio into Box<T>; the function's
        # signature does not declare it as a capability parameter.
        msgs = errors_of(
            "type Box<T> { value: T }\n"
            "\n"
            "fun wrap<T>(x: T) -> Box<T>\n"
            "    return Box { value: x }\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let _b = wrap(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_struct_literal_with_builtin_cap_rejected(self):
        # Hole D (2026-06): a struct LITERAL that puts a cap into a
        # generic field smuggles it behind T, so a function taking
        # ``Box<Stdio>`` exercises Stdio with an empty manifest. The
        # struct-construction path must reject it like the call path.
        msgs = errors_of(
            "type Box<T> { value: T }\n"
            "fun exercise(b: Box<Stdio>)\n"
            "    b.value.println(\"x\")\n"
            "fun main(stdio: Stdio)\n"
            "    exercise(Box { value: stdio })\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_variant_constructor_with_builtin_cap_rejected(self):
        # Hole D (2026-06): the same smuggle through a generic variant
        # payload (``Wrap(stdio)``) must be rejected too.
        msgs = errors_of(
            "type H<T> =\n"
            "    Wrap(T)\n"
            "    Empty\n"
            "fun main(stdio: Stdio)\n"
            "    let _h = Wrap(stdio)\n"
        )
        self.assertTrue(
            any("capability 'Stdio'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_with_user_capability_rejected(self):
        # The leak shape generalises: a user-defined capability
        # (``Mailer`` here) smuggled through a TyVar is the same
        # hole.
        msgs = errors_of(
            "capability Mailer\n"
            "    fun send(self, to: String) -> Bool\n"
            "\n"
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun forge(m: Mailer)\n"
            "    let _m2 = id(m)\n"
        )
        self.assertTrue(
            any("capability 'Mailer'" in m and "generic" in m for m in msgs),
            msgs,
        )

    def test_generic_with_non_capability_still_allowed(self):
        # Sanity: non-cap T (Int) flows through generics without
        # complaint, otherwise we'd have broken every legitimate
        # generic call.
        r = check(
            "fun id<T>(x: T) -> T\n"
            "    return x\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    let n = id(42)\n"
            "    stdio.println(\"${n}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_explicit_cap_param_still_allowed(self):
        # Sanity: a non-generic function with a cap parameter is
        # the legitimate flow; the new check must not fire here.
        r = check(
            "fun use_stdio(s: Stdio)\n"
            "    s.println(\"ok\")\n"
            "\n"
            "fun main(stdio: Stdio)\n"
            "    use_stdio(stdio)\n"
        )
        self.assertTrue(r.ok, r.errors)


# =============================================================
# Reserved sum-type variant names (Ok / Err / Some / None)
# =============================================================

class TestReservedVariantNames(unittest.TestCase):
    """A user-declared variant named Ok / Err / Some / None used to
    silently overwrite the built-in Result / Option constructor in
    the global scope, breaking every subsequent use of the built-in.
    The analyzer now rejects such declarations at declaration time
    with a clear, rename-oriented diagnostic."""

    def test_user_variant_named_ok_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Ok\n"
            "    Bad\n"
            "fun probe() -> Result<Int, String>\n"
            "    return Ok(1)\n"
        )
        reserved = [
            m for m in msgs
            if "'Ok'" in m and "reserved" in m and "Result::Ok" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        # The built-in Result::Ok must still resolve at the call
        # site (the user variant was rejected, not registered), so
        # we should NOT see a "takes no payload" error from Ok(1).
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_err_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Err\n"
            "    Good\n"
            "fun probe() -> Result<Int, String>\n"
            "    return Err(\"bad\")\n"
        )
        reserved = [
            m for m in msgs
            if "'Err'" in m and "reserved" in m and "Result::Err" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_some_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    Some\n"
            "    Other\n"
            "fun probe() -> Option<Int>\n"
            "    return Some(1)\n"
        )
        reserved = [
            m for m in msgs
            if "'Some'" in m and "reserved" in m and "Option::Some" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)
        self.assertFalse(
            any("takes no payload" in m for m in msgs), msgs,
        )

    def test_user_variant_named_none_rejected(self):
        msgs = errors_of(
            "pub type S =\n"
            "    None\n"
            "    Other\n"
            "fun probe() -> Option<Int>\n"
            "    return None\n"
        )
        reserved = [
            m for m in msgs
            if "'None'" in m and "reserved" in m and "Option::None" in m
        ]
        self.assertEqual(len(reserved), 1, msgs)

    def test_non_reserved_variant_name_still_works(self):
        # Positive control: the canonical rename suggested by the
        # diagnostic must analyse cleanly.
        r = check(
            "pub type S =\n"
            "    Compliant\n"
            "    Bad\n"
            "fun probe() -> S\n"
            "    return Compliant\n"
        )
        self.assertTrue(r.ok, r.errors)




class TestBuiltinIoErrorReadOnly(unittest.TestCase):
    """The builtin ``IoError``'s fields are readable but not
    writable: the Python runtime backs the value with a frozen
    dataclass (a write raises FrozenInstanceError at runtime) while
    the Wasm backend would silently store through the record
    pointer, a silent backend divergence. The analyzer rejects the
    write at compile time. A USER-declared ``type IoError`` shadows
    the builtin and keeps ordinary mutable-struct semantics."""

    def test_write_to_builtin_ioerror_field_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"x\")\n"
            "    e.message = \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_augmented_write_to_builtin_ioerror_field_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"x\")\n"
            "    e.message += \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_write_via_err_pattern_binder_rejected(self):
        msgs = errors_of(
            "fun fail() -> Result<Int, IoError>\n"
            "    return Err(IoError(\"boom\"))\n"
            "fun main(stdio: Stdio)\n"
            "    match fail()\n"
            "        Ok(n) -> stdio.println(\"ok ${n}\")\n"
            "        Err(e) ->\n"
            "            e.cause = \"later\"\n"
            "            stdio.println(\"err\")\n"
        )
        self.assertTrue(
            any("built-in 'IoError'" in m and "read-only" in m
                for m in msgs),
            msgs,
        )

    def test_read_of_builtin_ioerror_fields_still_allowed(self):
        r = check(
            "fun main(stdio: Stdio)\n"
            "    let e = IoError(\"boom\", \"root\")\n"
            "    stdio.println(\"${e.message}: ${e.cause}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_user_declared_ioerror_struct_stays_mutable(self):
        r = check(
            "type IoError { message: String, cause: String }\n"
            "fun main(stdio: Stdio)\n"
            "    var e = IoError { message: \"x\", cause: \"\" }\n"
            "    e.message = \"y\"\n"
            "    stdio.println(\"${e.message}\")\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestMapKeyTypeRestrictions(unittest.TestCase):
    """Audit M4 (2026-05): the Wasm backend supports String / Int /
    Bool plus pointer-shape (struct / sum / tuple) Map keys. The
    analyzer rejects unsupported key types at the type-expression
    resolution site (declaration time) so the user sees the error
    at ``let m: Map<Float, ...>`` rather than at first method call.
    See ``_reject_unsupported_map_key`` in
    ``capa/analyzer/_declarations.py``."""

    def test_map_string_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<String, Int> = new_map()\n"
            "    m.set(\"a\", 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_int_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<Int, Int> = new_map()\n"
            "    m.set(1, 2)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_bool_key_accepted(self):
        r = check(
            "fun main()\n"
            "    let m: Map<Bool, Int> = new_map()\n"
            "    m.set(true, 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_float_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Float, Int> = new_map()\n"
        )
        self.assertTrue(
            any("Float" in m and "Map keys" in m and "NaN" in m for m in msgs),
            msgs,
        )

    def test_map_list_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<List<Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_map_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Map<Int, Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_set_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Set<Int>, Int> = new_map()\n"
        )
        self.assertTrue(
            any("nested-collection" in m for m in msgs), msgs,
        )

    def test_map_struct_key_accepted(self):
        # Struct keys are accepted: the per-key dispatch reuses the
        # slice-3 ``$eq_<TypeName>`` helper, and H2 freezes Point so
        # ``p.x = 5`` is rejected wherever Point appears as a Map key.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun main()\n"
            "    let m: Map<Point, Int> = new_map()\n"
            "    m.set(Point{x: 1, y: 2}, 42)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_sum_key_accepted(self):
        # User sum keys are accepted alongside Option / Result. The
        # per-key dispatch reuses ``$eq_<SumName>``.
        r = check(
            "type Color =\n"
            "    Red\n"
            "    Green\n"
            "    Blue\n"
            "fun main()\n"
            "    let m: Map<Color, Int> = new_map()\n"
            "    m.set(Red, 1)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_tuple_key_accepted(self):
        # Tuple keys are accepted; tuples are immutable from Capa
        # source so no extension to H2 is needed.
        r = check(
            "fun main()\n"
            "    let m: Map<(Int, Int), Int> = new_map()\n"
            "    m.set((1, 2), 3)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_map_function_key_rejected(self):
        msgs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let m: Map<Fun(Int) -> Int, Int> = new_map()\n"
        )
        self.assertTrue(
            any("function types" in m for m in msgs), msgs,
        )

    def test_map_float_key_in_function_param_rejected(self):
        # The check fires regardless of where the Map<K, V> type
        # expression lives; function parameter type counts too.
        msgs = errors_of(
            "fun take(m: Map<Float, Int>)\n"
            "    return\n"
        )
        self.assertTrue(
            any("Float" in m and "NaN" in m for m in msgs), msgs,
        )

    def test_map_struct_key_in_return_type_accepted(self):
        # Struct keys are accepted wherever a Map<K, V> type
        # expression appears, including in function return types.
        r = check(
            "type Point {\n"
            "    x: Int,\n"
            "    y: Int\n"
            "}\n"
            "fun make() -> Map<Point, Int>\n"
            "    return new_map()\n"
        )
        self.assertTrue(r.ok, r.errors)


class TestLinearTypes(unittest.TestCase):
    """Roadmap S1: ``linear type`` must-consume discipline. A linear
    value must be consumed (passed to a ``consume`` param / ``consume
    self`` method, or returned) before it leaves scope."""

    _BASE = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        # Drop the unused-cap-param noise so tests assert on the
        # linear messages only.
        return [
            e for e in errors_of(self._BASE + body)
            if "never used" not in e
        ]

    def test_consumed_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_dropped_errors(self):
        errs = self._errs(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    _s.println(\"leak\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_returned_transfers_obligation(self):
        self.assertEqual(
            self._errs(
                "fun make() -> Handle\n"
                "    let h = open()\n"
                "    return h\n"
                "fun main(_s: Stdio)\n"
                "    close(make())\n"
            ),
            [],
        )

    def test_consume_self_method_discharges(self):
        errs = [
            e for e in errors_of(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            )
            if "never used" not in e
        ]
        self.assertEqual(errs, [])

    def test_both_branches_consume_ok(self):
        self.assertEqual(
            self._errs(
                "fun main(c: Bool)\n"
                "    let h = open()\n"
                "    if c\n"
                "        close(h)\n"
                "    else\n"
                "        close(h)\n"
            ),
            [],
        )

    def test_consume_one_branch_only_errors(self):
        errs = self._errs(
            "fun main(c: Bool, _s: Stdio)\n"
            "    let h = open()\n"
            "    if c\n"
            "        close(h)\n"
            "    _s.println(\"x\")\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_consume_param_terminal_not_re_obligated(self):
        # ``close(consume h)`` is the terminal owner; its own body
        # need not re-consume h. (Regression: an early version seeded
        # consume-params into the live set and flagged close itself.)
        self.assertEqual(self._errs(""), [])

    def test_non_linear_struct_unaffected(self):
        self.assertEqual(
            [
                e for e in errors_of(
                    "type Plain { x: Int }\n"
                    "fun mk() -> Plain\n"
                    "    return Plain { x: 1 }\n"
                    "fun main(_s: Stdio)\n"
                    "    let p = mk()\n"
                )
                if "never used" not in e
            ],
            [],
        )


class TestLinearUseAfterConsume(unittest.TestCase):
    """Soundness: a linear / typestate value consumed *exactly once*
    cannot be used again. Passing it to a ``consume`` parameter, a
    ``consume self`` method, transitioning it with ``become``, or
    returning it consumes it; any later read / pass is a compile error.

    Before this fix a discharge merely cleared the must-consume
    obligation (``_live_linear``) without poisoning the name against
    later use, so a double-consume (settle the same authorization
    twice) type-checked and ran."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_double_consume_linear_param_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_read_field_after_consume_linear_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(h)\n"
            "    let bad = h.id\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_use_after_consume_self_method_rejected(self):
        errs = self._errs(
            "linear type Handle { id: Int }\n"
            "impl Handle\n"
            "    fun shut(consume self) -> Unit\n"
            "        return ()\n"
            "fun open() -> Handle\n"
            "    return Handle { id: 1 }\n"
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    h.shut()\n"
            "    h.shut()\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_double_consume_typestate_after_become_rejected(self):
        # ``become(c, Approved)`` consumes c; a second become of c is
        # a use-after-consume of the old-state value.
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    let b = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(b)\n"
        )
        self.assertTrue(
            any(
                "linear value 'c' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    def test_settle_typestate_twice_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let a = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(a)\n"
        )
        self.assertTrue(
            any(
                "linear value 'a' was consumed earlier" in e for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_single_consume_linear_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_consume_self_once_ok(self):
        self.assertEqual(
            self._errs(
                "linear type Handle { id: Int }\n"
                "impl Handle\n"
                "    fun shut(consume self) -> Unit\n"
                "        return ()\n"
                "fun open() -> Handle\n"
                "    return Handle { id: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    h.shut()\n"
            ),
            [],
        )

    def test_typestate_chain_distinct_names_ok(self):
        # The idiomatic chain: each step binds a fresh name and consumes
        # the previous. Must stay legal after the poison fix.
        self.assertEqual(
            self._errs(
                self._TS
                + "fun main(_s: Stdio)\n"
                "    let c = mk()\n"
                "    let a = become(c, Approved)\n"
                "    settle(a)\n"
            ),
            [],
        )

    def test_return_transfers_obligation_ok(self):
        self.assertEqual(
            self._errs(
                self._TS
                + "fun promote() -> Claim[Approved]\n"
                "    let c = mk()\n"
                "    return become(c, Approved)\n"
                "fun main(_s: Stdio)\n"
                "    settle(promote())\n"
            ),
            [],
        )


class TestLinearConsumeParamReuse(unittest.TestCase):
    """LIN-1: a ``consume`` linear / typestate PARAMETER is OWNED by the
    receiving body, so consuming it a second time -- or using it after a
    consume -- is a use-after-consume, exactly as for a let-bound value.

    Before the fix the consume parameter was seeded into NO tracker (not
    ``_live_linear`` and not ``_borrowed_linear``), so the first discharge
    never poisoned it and every re-use slipped ``--check`` (rc0) and ran a
    real double-free / double-spend. This is the consume analog of the
    borrowed B-F1 hole: the let-bound TWIN of each case below is already
    caught (see ``TestLinearUseAfterConsume``), which is what pins the gap
    to the parameter seeding.

    The whole class shares one root and closes on one seam -- seed the
    consume parameter into the ``_live_linear`` owned tracker (drop-exempt)
    -- so each member is rejected with the single use-after-consume
    message. The negatives pin the class boundary: dropping a consume
    parameter WITHOUT re-consuming stays legal (the terminal-owner
    semantics used by ``discard`` / ``adopt`` and the typestate
    examples)."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun release(consume h: Handle)\n"
        "    return\n"
        "fun forward(consume h: Handle)\n"
        "    release(h)\n"
    )
    _FILE = (
        "linear type File { fd: Int }\n"
        "impl File\n"
        "    fun close(consume self)\n"
        "        return\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun settle(consume c: Claim[Approved])\n"
        "    return\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _assert_reuse_rejected(self, src: str, name: str) -> None:
        errs = self._errs(src)
        self.assertTrue(
            any(
                f"linear value {name!r} was consumed earlier and cannot "
                f"be used again" in e
                for e in errs
            ),
            errs,
        )

    # ---- the six-member class (each rc0 before the fix) ----------

    def test_member1_double_consume_arg_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun choose(consume h: Handle)\n"
            "    release(h)\n"
            "    release(h)\n",
            "h",
        )

    def test_member2_use_after_consume_field_read_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun bad(consume h: Handle) -> Int\n"
            "    release(h)\n"
            "    return h.id\n",
            "h",
        )

    def test_member3_double_free_sink_twice_rejected(self):
        self._assert_reuse_rejected(
            "linear type File { fd: Int }\n"
            "fun sink(consume f: File)\n"
            "    return\n"
            "fun bad(consume f: File)\n"
            "    sink(f)\n"
            "    sink(f)\n",
            "f",
        )

    def test_member4_forward_then_reuse_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "fun bad(consume h: Handle)\n"
            "    forward(h)\n"
            "    release(h)\n",
            "h",
        )

    def test_member5_pack_after_consume_rejected(self):
        self._assert_reuse_rejected(
            self._LIN
            + "type Box { h: Handle }\n"
            "fun bad(consume h: Handle) -> Box\n"
            "    release(h)\n"
            "    return Box { h: h }\n",
            "h",
        )

    def test_member6_typestate_double_become_rejected(self):
        self._assert_reuse_rejected(
            self._TS
            + "fun bad(consume c: Claim[Draft])\n"
            "    let a = become(c, Approved)\n"
            "    let b = become(c, Approved)\n"
            "    settle(a)\n"
            "    settle(b)\n",
            "c",
        )

    def test_member1_double_consume_self_method_rejected(self):
        # The consume-self shape of the double-consume: ``f.close()`` twice.
        self._assert_reuse_rejected(
            self._FILE
            + "fun bad(consume f: File)\n"
            "    f.close()\n"
            "    f.close()\n",
            "f",
        )

    # ---- the class boundary: drop stays legal (negatives) --------

    def test_neg7_terminal_consumer_drop_is_legal(self):
        # A consume parameter received and never re-consumed is the
        # documented terminal owner (``discard`` / ``adopt``): still rc0.
        # This is the case the drop-exemption exists to preserve.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun discard(consume h: Handle)\n"
                "    return\n"
            ),
            [],
        )

    def test_neg8_typestate_examples_stay_accepted(self):
        # The canonical typestate examples end each protocol with a
        # terminal ``discard(consume ...)``; the drop-exemption keeps them
        # rc0. A regression here would reject a shipped example.
        import pathlib
        root = pathlib.Path(__file__).resolve().parents[1]
        for rel in (
            "examples/wasm/typestate_door.capa",
            "examples/wasm/typestate_methods.capa",
            "examples/wasm/typestate_socket.capa",
        ):
            src = (root / rel).read_text(encoding="utf-8")
            errs = self._errs(src)
            self.assertEqual(errs, [], f"{rel}: {errs}")

    def test_neg9_valid_single_consume_arg_is_legal(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun closeit(consume h: Handle)\n"
                "    release(h)\n"
            ),
            [],
        )

    def test_neg9_valid_single_consume_self_is_legal(self):
        self.assertEqual(
            self._errs(
                self._FILE
                + "fun closeit(consume f: File)\n"
                "    f.close()\n"
            ),
            [],
        )

    def test_neg9_valid_single_become_and_forward_is_legal(self):
        # Transition a consume typestate parameter once and hand the result
        # to a consumer: a valid single consume, not a re-use.
        self.assertEqual(
            self._errs(
                self._TS
                + "fun approve(consume c: Claim[Draft])\n"
                "    settle(become(c, Approved))\n"
            ),
            [],
        )

    def test_neg10_borrowed_linear_param_consume_still_rejected(self):
        # B-F1 unchanged: a NON-consume linear parameter is BORROWED, so
        # consuming it stays a compile error (the caller retains ownership).
        errs = self._errs(
            self._LIN
            + "fun peek(h: Handle)\n"
            "    release(h)\n"
        )
        self.assertTrue(
            any(
                "borrowed linear/typestate value 'h'" in e for e in errs
            ),
            errs,
        )

    def test_neg10_alias_consume_param_then_consume_alias_is_legal(self):
        # Aliasing the consume parameter MOVES the obligation onto the
        # alias; consuming the alias once is valid (the source is poisoned,
        # not re-consumed). Confirms the let-owned move path is unchanged.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun ok(consume h: Handle)\n"
                "    let h2 = h\n"
                "    release(h2)\n"
            ),
            [],
        )


class TestLinearConsumeParamDoubleFreeRuntime(unittest.TestCase):
    """LIN-1 member 3 (double-free) end to end. ``--check`` now REJECTS a
    consume-parameter double-consume, so a rejected program never reaches
    a backend. To prove that rejection is load-bearing -- that the base
    really would double-free -- we BYPASS the analyzer verdict and drive
    the codegen directly: the value is consumed twice (a double-spend,
    ``PAID 100`` printed twice) IDENTICALLY on all three backends (legacy
    / --ir / --wasm). The types and bindings are fully resolved even when
    the flow check rejects, so the codegen runs; the fix stops the program
    at ``--check`` before it can ever execute this double-spend."""

    # ``settle`` spends the payment; consuming ``p`` twice double-spends.
    _DOUBLE_SPEND = (
        "linear type Payment { amount: Int }\n"
        "impl Payment\n"
        "    fun settle(consume self, stdio: Stdio)\n"
        '        stdio.println("PAID ${self.amount}")\n'
        "fun process(consume p: Payment, stdio: Stdio)\n"
        "    p.settle(stdio)\n"
        "    p.settle(stdio)\n"
        "fun main(stdio: Stdio)\n"
        "    process(Payment { amount: 100 }, stdio)\n"
    )

    @staticmethod
    def _has_wasm() -> bool:
        import shutil
        if shutil.which("wasm-tools") is None:
            return False
        try:
            import wasmtime  # noqa: F401
            return True
        except ImportError:
            return False

    def _run_unchecked(self, backend: str) -> str:
        """Compile + run ``_DOUBLE_SPEND`` on ``backend`` with the analyzer
        verdict IGNORED, capturing stdout."""
        import io
        import sys
        module = Parser(
            Lexer(self._DOUBLE_SPEND).lex(), source=self._DOUBLE_SPEND,
        ).parse_module()
        result = analyze(module, source=self._DOUBLE_SPEND)  # rejects; ignored
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            if backend == "legacy":
                from capa import transpile
                code = transpile(
                    module, types=result.types, bindings=result.bindings,
                )
                exec(compile(code, "<lin1>", "exec"), {"__name__": "__main__"})
            elif backend == "ir":
                from capa.ir import compile_program
                code = compile_program(
                    module, types=result.types, bindings=result.bindings,
                )
                exec(compile(code, "<lin1>", "exec"), {"__name__": "__main__"})
            elif backend == "wasm":
                from capa.ir import compile_wasm
                from capa.runtime._wasm_host import WasmHost
                blob = compile_wasm(module, types=result.types)
                WasmHost().run_main(blob)
        finally:
            sys.stdout = saved
        return buf.getvalue()

    def test_check_rejects_the_double_spend(self):
        errs = [
            e for e in errors_of(self._DOUBLE_SPEND) if "never used" not in e
        ]
        self.assertTrue(
            any(
                "linear value 'p' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_base_double_spends_on_legacy_and_ir_when_unchecked(self):
        # Analysis bypassed: both Python backends consume ``p`` twice.
        self.assertEqual(self._run_unchecked("legacy"), "PAID 100\nPAID 100\n")
        self.assertEqual(self._run_unchecked("ir"), "PAID 100\nPAID 100\n")

    def test_base_double_spends_on_wasm_when_unchecked(self):
        if not self._has_wasm():
            self.skipTest("wasm-tools and/or wasmtime-py not installed")
        self.assertEqual(self._run_unchecked("wasm"), "PAID 100\nPAID 100\n")


class TestLinearAnonymousDrop(unittest.TestCase):
    """Soundness: a linear / typestate value cannot be dropped into an
    anonymous slot -- a wildcard binding ``let _ = open()`` or a bare
    expression statement ``open()`` / ``become(c, S)`` -- any more than
    it can be dropped under a named binding.

    Before this fix the must-consume obligation was keyed only by the
    bound name, so an anonymous drop registered no obligation and the
    value silently vanished unconsumed."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_wildcard_let_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let _ = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_expr_stmt_drops_linear_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_bare_become_stmt_drops_typestate_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_drops_typestate_become_rejected(self):
        errs = self._errs(
            self._TS
            + "fun main(_s: Stdio)\n"
            "    let c = mk()\n"
            "    let _ = become(c, Approved)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs),
            errs,
        )

    def test_wildcard_let_moves_linear_reported_once(self):
        # ``let _ = h`` moves the live binding into the void; it must be
        # reported once at the drop site and not again at function exit.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let _ = h\n"
        )
        drops = [e for e in errs if "dropped without being consumed" in e]
        self.assertEqual(len(drops), 1, errs)

    # ---- positives that must keep compiling ----------------------

    def test_bare_consume_call_stmt_ok(self):
        # ``close(h)`` as a bare statement returns Unit (not linear), so
        # it is a legal consume, not a drop.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_wildcard_let_nonlinear_ok(self):
        self.assertEqual(
            self._errs(
                "type Plain { x: Int }\n"
                "fun mk() -> Plain\n"
                "    return Plain { x: 1 }\n"
                "fun main(_s: Stdio)\n"
                "    let _ = mk()\n"
            ),
            [],
        )


class TestLinearVarAndReassign(unittest.TestCase):
    """Soundness: a ``var`` binding of a linear / typestate value carries
    the same must-consume obligation a ``let`` does -- ``var`` only makes
    the slot re-assignable, it does not waive use-once. Re-assigning a name
    that still holds a live linear value DROPS that value (a leak), while
    re-assigning a name whose value was already consumed re-arms a fresh
    obligation.

    Before this fix ``_check_var`` never registered the obligation and
    ``_check_assign`` never touched the live set, so a linear value bound
    with ``var`` (or re-assigned) escaped both the leak and the
    double-consume checks."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_var_linear_leak_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    var h = open()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_var_double_consume_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier and cannot "
                "be used again" in e
                for e in errs
            ),
            errs,
        )

    def test_reassign_drops_live_linear_rejected(self):
        # ``h = open()`` while h still holds an unconsumed value overwrites
        # (and so drops) the old value -- a leak.
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    var h = open()\n"
            "    h = open()\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' is dropped without being consumed; "
                "re-assigning to it overwrites the old value" in e
                for e in errs
            ),
            errs,
        )

    # ---- positives that must keep compiling ----------------------

    def test_var_single_consume_ok(self):
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_reassign_after_consume_ok(self):
        # The old value was consumed before the re-assignment, so the
        # name re-arms a fresh obligation that the final close discharges.
        self.assertEqual(
            self._errs(
                self._LIN
                + "fun main(_s: Stdio)\n"
                "    var h = open()\n"
                "    close(h)\n"
                "    h = open()\n"
                "    close(h)\n"
            ),
            [],
        )


class TestLinearMatchPartialConsume(unittest.TestCase):
    """Soundness: a linear / typestate value live at the entry of a
    ``match`` must be consumed on EVERY non-diverging arm or on NONE.
    Consuming it in some arms but not others leaks it on the paths that
    did not consume -- the obligation survives the merge (the union of
    each reachable arm's survivors), so the leak surfaces, and a later
    consume after the match is a use-after-consume on the arms that
    already consumed it.

    Before this fix ``_check_match_expr`` merged ``_consumed`` like
    ``_check_if`` but never snapshotted / merged ``_live_linear``, so
    consuming in a single arm removed the obligation permanently and the
    leak on the other arms went unreported."""

    _M = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun pick() -> Option<Int>\n"
        "    return Some(1)\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_match_partial_consume_rejected(self):
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> ()\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_match_consume_all_arms_ok(self):
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> close(h)\n"
                "        None -> close(h)\n"
            ),
            [],
        )

    def test_match_consume_none_then_after_ok(self):
        # Consumed in no arm, then consumed once after the match.
        self.assertEqual(
            self._errs(
                self._M
                + "fun main(_s: Stdio)\n"
                "    let h = open()\n"
                "    match pick()\n"
                "        Some(n) -> ()\n"
                "        None -> ()\n"
                "    close(h)\n"
            ),
            [],
        )

    def test_match_consume_all_arms_then_after_rejected(self):
        # Consumed in every arm, then used again after the match: a
        # use-after-consume on whichever arm ran.
        errs = self._errs(
            self._M
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    match pick()\n"
            "        Some(n) -> close(h)\n"
            "        None -> close(h)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(
                "linear value 'h' was consumed earlier" in e for e in errs
            ),
            errs,
        )


class TestLinearContainerLaundering(unittest.TestCase):
    """Soundness (already structurally closed): a linear / typestate value
    cannot be laundered into a non-linear container (tuple / list / struct
    field) to make its must-consume obligation disappear.

    The obligation on the inner value is discharged ONLY by a direct
    consume position -- a ``consume`` argument, a ``become`` operand, or a
    bare-identifier ``return``. Embedding the value in a container never
    discharges it, so the obligation stays live and is reported at scope
    exit no matter what happens to the container (dropped, returned,
    consumed). The language therefore admits no linear container, and no
    laundering escape exists. These tests lock that in."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def test_launder_into_tuple_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let t = (h, 1)\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_list_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let xs = [h]\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_struct_field_rejected(self):
        errs = self._errs(
            "type Box { h: Handle }\n"
            + self._LIN
            + "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let b = Box { h: h }\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )

    def test_launder_into_returned_tuple_rejected(self):
        # A tuple carrying a linear value is now barred by the container-of-
        # linear invariant: the `-> (Handle, Int)` return type is rejected at
        # the declaration entry-gate and the `(h, 1)` expression at the use-
        # gate, both with the container message.
        errs = self._errs(
            self._LIN
            + "fun stash() -> (Handle, Int)\n"
            "    let h = open()\n"
            "    return (h, 1)\n"
            "fun main(_s: Stdio)\n"
            "    let t = stash()\n"
        )
        self.assertTrue(
            any("linear/typestate value cannot" in e for e in errs), errs,
        )


class TestBorrowedLinearNoEscape(unittest.TestCase):
    """Audit B-F1: a non-``consume`` (borrowed) linear / typestate
    parameter is owned by the CALLER, so the callee may read it and
    forward it to other borrow positions, but must not consume it,
    return it, alias-then-consume it, ``become`` it, call a ``consume
    self`` method on it, or pack it into an aggregate. Each of those
    transfers or duplicates ownership the caller still holds, so it would
    double-consume / double-free. Before this fix a borrowed param was
    untracked and every one of these slipped past with no diagnostic.

    The over-reject guard is as load-bearing as the rejects: a borrowed
    param must still be readable and forwardable, a ``consume`` param
    stays a terminal owner, and a factory / passthrough still compiles."""

    _LIN = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "fun peek(h: Handle) -> Int\n"
        "    return h.id\n"
    )
    _LINS = (
        "linear type Handle { id: Int }\n"
        "impl Handle\n"
        "    fun close(consume self) -> Unit\n"
        "        return ()\n"
        "    fun id_of(self) -> Int\n"
        "        return self.id\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Approved\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun settle(consume c: Claim[Approved]) -> Unit\n"
        "    return ()\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    _BORROWED_MSG = "borrowed linear/typestate value"

    # ---- must REJECT ----

    def test_return_borrowed_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle) -> Handle\n"
            "    return h\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_consume_borrowed_in_callee_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    close(h)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_alias_then_consume_borrowed_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    let b = h\n"
            "    close(b)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_become_borrowed_typestate_rejected(self):
        errs = self._errs(
            self._TS
            + "fun bad(c: Claim[Draft]) -> Claim[Approved]\n"
            "    return become(c, Approved)\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_consume_self_on_borrowed_receiver_rejected(self):
        errs = self._errs(
            self._LINS
            + "fun bad(h: Handle)\n"
            "    h.close()\n"
        )
        self.assertTrue(
            any(self._BORROWED_MSG in e for e in errs), errs,
        )

    def test_pack_borrowed_into_struct_rejected(self):
        errs = self._errs(
            "type Box { h: Handle }\n"
            + self._LIN
            + "fun bad(h: Handle)\n"
            "    let b = Box { h: h }\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    def test_pack_borrowed_into_list_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle)\n"
            "    let xs = [h]\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    def test_pack_borrowed_into_tuple_rejected(self):
        errs = self._errs(
            self._LIN
            + "fun bad(h: Handle) -> (Handle, Int)\n"
            "    return (h, 1)\n"
        )
        self.assertTrue(
            any("into an aggregate" in e for e in errs), errs,
        )

    # ---- must COMPILE (over-reject guard) ----

    def test_borrow_and_read_compiles(self):
        r = check(
            self._LIN
            + "fun get_id(h: Handle) -> Int\n"
            "    return h.id\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_borrow_and_forward_compiles(self):
        r = check(
            self._LIN
            + "fun use2(h: Handle) -> Int\n"
            "    return peek(h)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_alias_then_forward_no_consume_compiles(self):
        r = check(
            self._LIN
            + "fun use3(h: Handle) -> Int\n"
            "    let b = h\n"
            "    return peek(b)\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_non_consume_self_reads_field_compiles(self):
        r = check(
            self._LINS
            + "fun run(h: Handle) -> Int\n"
            "    return h.id_of()\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_factory_produced_value_returns_compiles(self):
        r = check(
            self._LIN
            + "fun make() -> Handle\n"
            "    let h = open()\n"
            "    return h\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_param_passthrough_compiles(self):
        r = check(
            self._LIN
            + "fun passthrough(consume h: Handle) -> Handle\n"
            "    return h\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_consume_self_become_wrapper_compiles(self):
        r = check(
            "typestate Claim\n    Draft\n    Approved\n"
            "impl Claim[Draft]\n"
            "    fun approve(consume self) -> Claim[Approved]\n"
            "        return become(self, Approved)\n"
            "fun mk() -> Claim[Draft]\n"
            "    return Claim[Draft] {}\n"
        )
        self.assertTrue(r.ok, r.errors)






# =============================================================
# For-loop iterable validation (GAP 1)
#
# Capa's iterables are exactly List, Set, Range, and String. A
# Map (and any other non-iterable type) has no sound lowering on
# either backend: the Python backend would silently iterate a
# Map's keys or crash on the destructuring form, while the Wasm
# backend errors. The analyzer rejects them so both backends
# agree at compile time.
# =============================================================



# =============================================================
# Asymmetric Char / String compatibility.
#
# A Capa Char is, by definition, exactly one code point, so it is
# ALWAYS a valid String (one direction). A general String is NOT a
# Char: only a provably one-code-point string LITERAL is accepted
# where a Char is expected. A multi-char literal or a non-literal
# String value flowing into a Char slot is unsound and rejected.
# =============================================================



# =============================================================
# Index-element assignment rejection (GAP 2)
#
# ``xs[i] = v`` and the augmented ``xs[i] += 1`` have no sound
# lowering on either backend (the Python backend emits an
# assignment to a function call, a SyntaxError; the Wasm backend
# raises a CIR-lowering error). The analyzer rejects a bare Index
# assignment target. Assigning to a struct field reached THROUGH
# an index (``xs[0].field = v``) keeps working: its target is a
# FieldAccess whose receiver is the Index.
# =============================================================



# =============================================================
# Dead-Unsafe warning (migrate tooling slice 2)
# =============================================================

class TestDeadUnsafeWarning(unittest.TestCase):
    """The analyzer warns (non-fatally) on an Unsafe parameter whose
    token provably never reaches py_import/py_invoke; the verdicts
    come from capa.migrate.find_dead_unsafe."""

    def test_dead_silenced_unsafe_param_warns(self):
        r = check("fun f(_u: Unsafe) -> Int\n    return 1\n")
        self.assertTrue(r.ok, r.errors)   # a warning never breaks ok
        self.assertEqual(len(r.warnings), 1)
        w = r.warnings[0]
        self.assertIn("'_u: Unsafe'", w.message)
        self.assertIn("never exercised", w.message)
        # Positioned on the parameter name itself.
        self.assertEqual((w.pos.line, w.pos.col), (1, 7))

    def test_transitive_dead_unsafe_names_the_callee(self):
        r = check(
            "fun bottom(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun top(u: Unsafe) -> Int\n"
            "    return bottom(u)\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 2)
        top_warning = next(w for w in r.warnings if "'top'" in w.message)
        self.assertIn("bottom", top_warning.message)
        self.assertIn("forwarded", top_warning.message)

    def test_exercised_unsafe_does_not_warn(self):
        r = check(
            "fun f(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(r.warnings, [])

    def test_shadowed_callee_does_not_warn(self):
        # third let-binds the dead function's name to a reference to
        # the bridging function and calls through it: the token DOES
        # reach py_import, so neither third nor main may be advised to
        # drop Unsafe. Only dead's own silenced parameter warns.
        r = check(
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe)\n"
            "    let dead = bridge\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u)\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("'dead'", r.warnings[0].message)

    def test_struct_shorthand_shadowed_callee_does_not_warn(self):
        # Same shadowing attack through destructuring shorthand:
        # ``Holder { dead }`` binds the field name with no IdentPat
        # node, rebinding the dead function's name to a bridging
        # function smuggled in a struct field. The token DOES reach
        # py_import, so neither third nor main may be advised to drop
        # Unsafe. Only dead's own silenced parameter warns.
        r = check(
            "type Holder { dead: Fun(Unsafe) -> () }\n"
            "\n"
            "fun bridge(u: Unsafe)\n"
            "    let os_mod = py_import(u, \"os\")\n"
            "\n"
            "fun dead(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun third(u: Unsafe, h: Holder)\n"
            "    let Holder { dead } = h\n"
            "    dead(u)\n"
            "\n"
            "fun main(u: Unsafe)\n"
            "    third(u, Holder { dead: bridge })\n"
        )
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("'dead'", r.warnings[0].message)

    def test_lint_failure_warns_instead_of_crashing_or_hiding(self):
        # A regression inside the detection must not crash the compile,
        # but it must not pass silently either: it surfaces as an
        # internal-failure warning.
        from unittest import mock
        with mock.patch(
            "capa.migrate.find_dead_unsafe",
            side_effect=ValueError("boom"),
        ):
            r = check("fun f(_u: Unsafe) -> Int\n    return 1\n")
        self.assertTrue(r.ok, r.errors)
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("internal", r.warnings[0].message)
        self.assertIn("ValueError", r.warnings[0].message)

    def test_lint_skipped_when_module_has_errors(self):
        # Advice over a module that does not compile is misleading:
        # an error anywhere suppresses the lint phase entirely, so the
        # dead-Unsafe nudge never accompanies errors.
        r = check(
            "fun f(_u: Unsafe) -> Int\n"
            "    return 1\n"
            "\n"
            "fun g() -> Int\n"
            "    return missing_name\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(r.warnings, [])


class TestInternalBuiltinRejection(unittest.TestCase):
    """Underscore-prefixed builtin functions (``_capa_chr``) are
    compiler-internal plumbing for the bundled JSON parser
    (``capa/ir/_builtin_json.capa``), not language surface. They
    became reachable from user code when ``_capa_chr`` landed in
    ``FREE_FUNCTIONS`` (2026-06-10); the analyzer now rejects user
    calls and bare references with a clear message. The bundled
    source itself is analyzed with ``internal=True`` and keeps
    access (pinned here by loading its IR)."""

    def test_user_call_to_capa_chr_is_rejected(self):
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    stdio.println(_capa_chr(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_bare_reference_to_capa_chr_is_rejected(self):
        # Aliasing would smuggle the builtin past the call check.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    let f = _capa_chr\n"
            "    stdio.println(f(65))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_call_to_capa_str_span_is_rejected(self):
        # _capa_str_span (perf/wasm-json-span) is the same kind of
        # internal-only plumbing as _capa_chr: the bundled parser uses
        # it for O(1) value extraction, user code must not reach it.
        errs = errors_of(
            "fun main(stdio: Stdio)\n"
            "    var cs: List<String> = []\n"
            '    cs.push("a")\n'
            "    stdio.println(_capa_str_span(cs, 0, 1))\n"
        )
        self.assertTrue(
            any("internal compiler builtin" in e for e in errs),
            errs,
        )

    def test_user_underscore_function_still_callable(self):
        # A user-defined function that happens to start with ``_``
        # has a real source position (never BUILTIN_POS) and stays
        # callable.
        r = check(
            "fun _helper() -> Int\n"
            "    return 7\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.println(\"${_helper()}\")\n"
        )
        self.assertTrue(r.ok, r.errors)

    def test_bundled_json_parser_keeps_internal_access(self):
        # The bundled parser calls _capa_chr to decode \uXXXX; its
        # loader analyzes with internal=True. Re-analyze the shipped
        # source both ways: internal=True must be clean, and the
        # user-mode analysis of the same source must trip the
        # rejection (proving the gate actually guards _capa_chr).
        from capa.ir._builtin_json import _BUNDLED_SOURCE_PATH
        source = _BUNDLED_SOURCE_PATH.read_text(encoding="utf-8")
        tokens = Lexer(source).lex()
        module = Parser(tokens, source=source).parse_module()
        internal = analyze(module, source=source, internal=True)
        self.assertEqual([e.message for e in internal.errors], [])
        # Fresh parse for the user-mode run so the two analyses
        # cannot share AST-keyed state.
        module2 = Parser(
            Lexer(source).lex(), source=source,
        ).parse_module()
        as_user = analyze(module2, source=source)
        self.assertTrue(
            any(
                "internal compiler builtin" in e.message
                for e in as_user.errors
            ),
            [e.message for e in as_user.errors],
        )






class TestLinearMovePaths(unittest.TestCase):
    """Struct field move-paths for the linear/typestate discipline.

    Consuming, moving, or projecting a linear/typestate STRUCT FIELD is
    now tracked per path, closing the latent runtime double-free where
    ``close(s.conn)`` on a value carrying a live linear field was a silent
    no-op. The three shapes:

    - HOLE-1: per-field partial-move accounting -- moving one linear field
      leaves the others outstanding; the whole value cannot be consumed
      once a field was moved (partial-move double-free).
    - HOLE-2: aliasing a value whose type transitively owns a linear field
      (even a non-linear carrier) MOVES the base.
    - WARNING-3: overwriting a live linear field drops it (a leak).
    - WARNING-4/5: a borrowed value's field cannot be consumed or laundered
      out through a projection.

    Both facets (``linear type`` and ``typestate``) are exercised.
    Analyzer-only, reject-only; the accepted shapes are run byte-identically
    on all three backends by ``test_ir_wasm_parity``."""

    # A linear struct P carrying two linear fields a, b and a scalar tag.
    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "linear type P { a: Conn, b: Conn, tag: Int }\n"
        "fun mkp() -> P\n"
        "    return P { a: open(), b: open(), tag: 0 }\n"
        "fun sinkp(consume p: P) -> Unit\n"
        "    return ()\n"
    )
    # A NON-linear struct S carrying a linear field conn plus a scalar tag.
    _NL = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
        "fun sink(consume s: S) -> Unit\n"
        "    return ()\n"
    )
    # Typestate facet: a Claim carrying a linear/typestate field inside a
    # non-linear Record carrier.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Record { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Record\n"
        "    return Record { claim: become(mk(), Settled), tag: 0 }\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    # ---- HOLE-1 partial-move accounting ----

    def test_consume_both_linear_fields_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    close(p.b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_one_field_leaks_naming_other(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n"
        )
        self.assertTrue(
            any("'p.b'" in e and "dropped without being consumed" in e
                for e in errs),
            errs,
        )

    def test_project_field_then_use_rest_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    let c = p.a\n    close(c)\n    close(p.b)\n"
            "    let n = p.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_double_consume_through_path_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    close(p.a)\n    close(p.b)\n"
        )
        self.assertTrue(
            any("'p.a'" in e and "consumed earlier" in e for e in errs),
            errs,
        )

    def test_consume_field_then_whole_rejected(self):
        errs = self._errs(
            self._LIN + "fun main(_s: Stdio)\n    let p = mkp()\n"
            "    close(p.a)\n    sinkp(p)\n"
        )
        self.assertTrue(
            any("its field 'p.a' was already consumed" in e for e in errs),
            errs,
        )

    # ---- HOLE-2 alias-move ----

    def test_alias_move_double_free_rejected(self):
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let t = s\n    close(s.conn)\n    close(t.conn)\n"
        )
        self.assertTrue(
            any("'s'" in e and "consumed earlier" in e for e in errs), errs,
        )

    def test_field_move_out_of_non_linear_carrier_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let c = s.conn\n    close(c)\n    let n = s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_typestate_carrier_field_move_out_ok(self):
        r = check(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let n = rec.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_typestate_carrier_alias_move_double_free_rejected(self):
        errs = self._errs(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let dup = rec\n    archive(rec.claim)\n    archive(dup.claim)\n"
        )
        self.assertTrue(
            any("'rec'" in e and "consumed earlier" in e for e in errs), errs,
        )

    # ---- WARNING-3 field-store drop ----

    def test_field_store_over_live_field_rejected(self):
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    s.conn = open()\n    let c = s.conn\n    close(c)\n"
        )
        self.assertTrue(
            any("'s.conn' is overwritten without being consumed" in e
                for e in errs),
            errs,
        )

    def test_field_store_after_consume_rearms_ok(self):
        r = check(
            self._NL + "fun main(_s: Stdio)\n    var s = mks()\n"
            "    close(s.conn)\n    s.conn = open()\n    close(s.conn)\n"
            "    let n = s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- WARNING-4/5 borrow facet over paths ----

    def test_read_scalar_field_of_borrowed_carrier_ok(self):
        r = check(
            self._NL + "fun peek(s: S) -> Int\n    return s.conn.id\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_sibling_locals_not_over_rejected_when_param_borrowed(self):
        r = check(
            self._NL + "fun use(s: S) -> Int\n"
            "    let session = mks()\n    close(session.conn)\n"
            "    let s2 = mks()\n    close(s2.conn)\n    return s.tag\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_consume_field_of_borrowed_carrier_rejected(self):
        errs = self._errs(
            self._NL + "fun bad(s: S) -> Unit\n    close(s.conn)\n"
        )
        self.assertTrue(
            any("borrowed value the caller still owns" in e
                or "belongs to a borrowed value" in e for e in errs),
            errs,
        )

    def test_project_field_of_borrowed_then_consume_rejected(self):
        errs = self._errs(
            self._NL + "fun bad(s: S) -> Unit\n    let c = s.conn\n    close(c)\n"
        )
        self.assertTrue(
            any("borrowed" in e for e in errs), errs,
        )

    # ---- retained: no linear value into a container ----

    def test_linear_value_into_container_still_rejected(self):
        # A whole linear value may still not enter a container; the field
        # move-paths do not relax that (containers stay deferred). Embedding
        # it never discharges the obligation, so it leaks at scope exit.
        errs = self._errs(
            self._NL + "fun main(_s: Stdio)\n    let c = open()\n"
            "    let xs = [c]\n"
        )
        self.assertTrue(
            any("dropped without being consumed" in e for e in errs), errs,
        )


class TestLinearConditionalAlias(unittest.TestCase):
    """Finding 1: a linear/typestate value cannot flow through an if/match
    EXPRESSION whose arm selects an existing place.

    The move / consume / return / receiver seams recognise only a bare
    ``Ident`` / ``FieldAccess`` node, so an ``if`` / ``match`` wrapper that
    yields a linear place was invisible to them: binding, consuming, or
    returning the wrapper opened a SECOND obligation on the same runtime
    value, a double-free. ``_check_linear_conditional_alias`` bars it at a
    single ``_check_expr`` site, covering the bind RHS, consume argument,
    ``consume self`` receiver, return value, ``become`` value, and struct-
    literal element uniformly.

    The bar is PRECISE and syntactic: only an ``Ident`` / linear-rooted
    ``FieldAccess`` arm (recursing through nested wrappers) is barred, so the
    legitimate fresh-factory conditional (arms are calls) stays legal, and a
    non-linear conditional (String / Int / Option / plain struct) is untouched.
    Both facets (``linear type`` and ``typestate``) are exercised; the reject
    parity across the three backends is pinned by ``test_ir_wasm_parity``."""

    # A bare linear resource with an indexed factory and a consume sink.
    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open(n: Int) -> Conn\n"
        "    return Conn { id: n }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    # A NON-linear carrier S owning a linear field conn plus a scalar tag.
    _NL = _LIN + (
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(1), tag: 0 }\n"
    )
    # Typestate facet: an authorization that must be settled exactly once.
    _TS = (
        "typestate Auth\n    Pending\n    Settled\n"
        "fun mk() -> Auth[Pending]\n"
        "    return Auth[Pending] {}\n"
        "fun settle(consume a: Auth[Pending]) -> Unit\n"
        "    return ()\n"
    )
    _MSG = "cannot be selected through a conditional / match expression"

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _assert_barred(self, body: str) -> None:
        errs = self._errs(body)
        self.assertTrue(any(self._MSG in e for e in errs), errs)

    # ---- must REJECT: whole value / field / borrowed / all sites ----

    def test_1a_whole_value_via_if_bind(self):
        # ``let t = if true then s else s; close(s); close(t)`` double-frees.
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = if true then s else s\n"
            "    close(s)\n    close(t)\n"
        )

    def test_a3_whole_value_via_match_bind(self):
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = match 0\n        _ -> s\n"
            "    close(s)\n    close(t)\n"
        )

    def test_1b_linear_field_via_if(self):
        # b1: a linear field of a non-linear carrier, selected through if.
        self._assert_barred(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let c = if true then s.conn else s.conn\n"
            "    close(c)\n    close(s.conn)\n"
        )

    def test_1c_borrowed_carrier_field_via_if_return(self):
        # b2: a borrowed carrier's field returned through if bypasses the
        # borrow guard; the wrapper is barred outright.
        self._assert_barred(
            self._NL + "fun bad(s: S) -> Conn\n"
            "    return if true then s.conn else s.conn\n"
        )

    def test_consume_arg_form(self):
        # ``close(if c then s else s)`` -- the wrapper as a consume argument.
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    close(if true then s else s)\n    close(s)\n"
        )

    def test_return_form_on_borrowed_param(self):
        # ``return if c then s else s`` on a borrowed param -- borrow bypass.
        self._assert_barred(
            self._LIN + "fun bad(c: Conn) -> Conn\n"
            "    return if true then c else c\n"
        )

    def test_nested_wrapper_form(self):
        # ``if a then s else (if b then s else s)`` -- a place at depth.
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n    let s = open(1)\n"
            "    let t = if true then s else (if false then s else s)\n"
            "    close(t)\n"
        )

    def test_claimdesk_double_disbursement_typestate(self):
        # The claimdesk shape: one authorization settled twice via an alias
        # laundered through a conditional.
        self._assert_barred(
            self._TS + "fun main(_s: Stdio)\n    let authz = mk()\n"
            "    let dup = if true then authz else authz\n"
            "    settle(authz)\n    settle(dup)\n"
        )

    def test_typestate_whole_value_via_if_bind(self):
        self._assert_barred(
            self._TS + "fun main(_s: Stdio)\n    let a = mk()\n"
            "    let t = if true then a else a\n"
            "    settle(a)\n    settle(t)\n"
        )

    def test_selection_of_distinct_places_rejected(self):
        # Per the design's (2) rule: selecting between two DISTINCT live
        # linear resources is barred (not tracked-through).
        self._assert_barred(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let a = open(1)\n    let b = open(2)\n"
            "    let t = if true then a else b\n"
            "    close(t)\n"
        )

    # ---- must COMPILE: fresh factory + non-linear conditionals ----

    def test_fresh_factory_conditional_ok(self):
        # Arms are CALLS (fresh values), not places, so the bar does not fire.
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let t = if true then open(1) else open(2)\n"
            "    close(t)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_fresh_factory_via_match_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let t = match 0\n        _ -> open(1)\n"
            "    close(t)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_int_conditional_ok(self):
        r = check(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let n = if true then 1 else 2\n    let _ = n\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_string_conditional_ok(self):
        r = check(
            "fun verdict(live: Bool) -> String\n"
            "    return if live then \"yes\" else \"no\"\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_option_match_ok(self):
        r = check(
            "fun pick(o: Option<Int>) -> Int\n"
            "    return match o\n        Some(x) -> x\n        None -> 0\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_non_linear_carrier_field_conditional_ok(self):
        # Selecting a NON-linear field (the scalar tag) through a conditional
        # is untouched: the bar keys on the linear/typestate leaf type only.
        r = check(
            self._NL + "fun main(_s: Stdio)\n    let s = mks()\n"
            "    let n = if true then s.tag else 0\n"
            "    close(s.conn)\n    let _ = n\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


class TestLinearIntoContainerReject(unittest.TestCase):
    """Linearity decision 4b: a linear / typestate value (or a struct that
    OWNS one) cannot enter a container.

    A single-owner value packed into a List / Map / Set escapes name
    threading: a later read hands out an unbounded number of aliases to a
    value that must be consumed exactly once, a double-free / leak. Two
    seams enforce it:

    - the MUTATOR seam (``List.push`` / ``Set.add`` / ``Map.set``), which
      covers an owned, borrowed, fresh, or carrier value in any element /
      value / key position;
    - the LIST-LITERAL seam, which covers a fresh linear packed straight
      into ``[...]`` (it never passes through a mutator).

    Both facets (``linear type`` and ``typestate``) are exercised. This is
    analyzer-only and reject-only; nothing is stored, so no drain / codegen
    changes. The struct-literal factory (``return Session { conn: open()
    }``) stays legitimate and is NOT touched.

    The list-literal facet is now sealed by the container-of-linear use-gate
    (``_container_carries_linear`` in ``_check_expr``) rather than a special-
    case list rule, so its diagnostic is the shared container message; the
    mutator seam keeps its own precise insertion-site message. Both share the
    ``a linear/typestate value cannot ...`` prefix asserted below."""

    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun open() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    # Non-linear struct that OWNS a linear field (a carrier).
    _CARRIER = _LIN + (
        "type S { conn: Conn, tag: Int }\n"
        "fun mks() -> S\n"
        "    return S { conn: open(), tag: 0 }\n"
    )
    # Typestate facet plus a non-linear carrier of a typestate field.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Record { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Record\n"
        "    return Record { claim: become(mk(), Settled), tag: 0 }\n"
    )
    _MSG = "linear/typestate value cannot"

    def _rejects(self, body: str) -> None:
        errs = errors_of(body)
        self.assertTrue(
            any(self._MSG in e for e in errs), errs,
        )

    def _compiles(self, body: str) -> None:
        errs = [e for e in errors_of(body) if "never used" not in e]
        self.assertEqual(errs, [], errs)

    # ---- mutator seam, linear facet, every provenance ----

    def test_push_owned_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var xs: List<Conn> = []\n    xs.push(c)\n"
        )

    def test_push_borrowed_param_rejected(self):
        self._rejects(
            self._LIN + "fun stash(c: Conn, _s: Stdio)\n"
            "    var xs: List<Conn> = []\n    xs.push(c)\n"
        )

    def test_push_fresh_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    var xs: List<Conn> = []\n    xs.push(open())\n"
        )

    def test_push_linear_carrier_struct_rejected(self):
        self._rejects(
            self._CARRIER + "fun main(_s: Stdio)\n    let sess = mks()\n"
            "    var xs: List<S> = []\n    xs.push(sess)\n"
        )

    def test_add_linear_into_set_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var st = new_set()\n    st.add(c)\n"
        )

    def test_set_linear_value_into_map_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var m = new_map()\n    m.set(\"k\", c)\n"
        )

    def test_set_linear_key_into_map_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = open()\n"
            "    var m = new_map()\n    m.set(c, \"v\")\n"
        )

    # ---- list-literal seam (Part B, fresh path) ----

    def test_list_literal_fresh_linear_unannotated_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let xs = [open()]\n"
        )

    def test_list_literal_fresh_linear_annotated_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<Conn> = [open()]\n"
        )

    # ---- typestate facet ----

    def test_push_typestate_value_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    var xs: List<Claim[Settled]> = []\n"
            "    xs.push(become(mk(), Settled))\n"
        )

    def test_push_typestate_carrier_struct_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    var xs: List<Record> = []\n    xs.push(rec)\n"
        )

    def test_list_literal_typestate_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    let xs: List<Claim[Settled]> = [become(mk(), Settled)]\n"
        )

    # ---- must-compile: plain data + the legitimate factory ----

    def test_plain_data_container_ops_compile(self):
        self._compiles(
            "type LedgerEvent { amt: Int }\n"
            "fun main(_s: Stdio)\n"
            "    var xs: List<LedgerEvent> = []\n"
            "    xs.push(LedgerEvent { amt: 1 })\n"
            "    let n = xs.length()\n"
            "    let e = xs.get(0)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", \"s\")\n"
            "    let has = m.contains_key(\"k\")\n"
            "    var st = new_set()\n"
            "    st.add(3)\n"
            "    let flags = [LedgerEvent { amt: 2 }]\n"
        )

    def test_struct_literal_linear_factory_compiles(self):
        # The struct-literal factory is the legitimate way to build a
        # linear-carrying value; it must stay compiling (list literals only
        # are strengthened, never struct literals).
        self._compiles(
            self._LIN + "type Session { conn: Conn }\n"
            "fun open_session() -> Session\n"
            "    return Session { conn: open() }\n"
        )


class TestContainerOfLinearSeal(unittest.TestCase):
    """Container-of-linear seal (7th commit): a List / Map / Set / tuple type
    may not carry a linear/typestate value (nor a linear-carrying struct) at
    any nesting depth, mirroring the capability discipline's four mechanisms
    with one predicate (``_container_carries_linear``). A BARE linear value at
    top level stays legal (single-owner values flow by name, including through
    generics); only the below-a-container form is barred.

    Every route is rejected on both facets (``linear type`` + ``typestate``):
    the tuple literal (the corrected carve-out), nested containers, a producing
    higher-order ``map`` / ``flat_map``, a generic helper instantiated linear,
    and a direct signature (param / return / field / const / variant payload).
    The over-reject line is load-bearing: the generic non-linear-``T`` control,
    a bare linear through a generic, and every plain-data container must still
    compile."""

    _LIN = (
        "linear type Conn { id: Int }\n"
        "fun mkc() -> Conn\n"
        "    return Conn { id: 1 }\n"
        "fun close(consume c: Conn) -> Unit\n"
        "    return ()\n"
    )
    _CARRIER = _LIN + (
        "type Session { conn: Conn, tag: Int }\n"
        "fun mks() -> Session\n"
        "    return Session { conn: mkc(), tag: 0 }\n"
    )
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
    )
    _MSG = "linear/typestate value cannot"

    def _rejects(self, body: str) -> None:
        errs = errors_of(body)
        self.assertTrue(any(self._MSG in e for e in errs), errs)

    def _compiles(self, body: str) -> None:
        errs = [e for e in errors_of(body) if "never used" not in e]
        self.assertEqual(errs, [], errs)

    # ---- tuple literal (the corrected carve-out) ----

    def test_tuple_literal_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let c = mkc()\n"
            "    let t = (c, 1)\n"
        )

    def test_tuple_literal_typestate_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n"
            "    let t = (become(mk(), Settled), 1)\n"
        )

    def test_tuple_literal_fresh_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n    let t = (mkc(), 1)\n"
        )

    # ---- nested containers ----

    def test_nested_list_of_list_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<List<Conn>> = [[mkc()]]\n"
        )

    def test_list_of_tuple_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs: List<(Conn, Int)> = [(mkc(), 1)]\n"
        )

    # ---- producing higher-order map / flat_map ----

    def test_map_producer_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs = [1, 2, 3].map(fun(x) => mkc())\n"
        )

    def test_flat_map_producer_linear_rejected(self):
        self._rejects(
            self._LIN + "fun main(_s: Stdio)\n"
            "    let xs = [1, 2, 3].flat_map(fun(x) => [mkc()])\n"
        )

    # ---- generic helper instantiated linear ----

    _STASH = (
        "fun stash<T>(xs: List<T>, v: T) -> List<T>\n"
        "    xs.push(v)\n"
        "    return xs\n"
    )

    def test_generic_helper_instantiated_linear_rejected(self):
        self._rejects(
            self._LIN + self._STASH + "fun main(_s: Stdio)\n"
            "    var xs: List<Conn> = []\n"
            "    let ys = stash(xs, mkc())\n"
        )

    def test_generic_helper_instantiated_typestate_rejected(self):
        self._rejects(
            self._TS + self._STASH + "fun main(_s: Stdio)\n"
            "    var xs: List<Claim[Settled]> = []\n"
            "    let ys = stash(xs, become(mk(), Settled))\n"
        )

    # ---- direct signatures (entry-gates) ----

    def test_param_list_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(xs: List<Conn>) -> Unit\n    return ()\n"
        )

    def test_param_map_value_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(m: Map<String, Conn>) -> Unit\n    return ()\n"
        )

    def test_param_map_key_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(m: Map<Conn, String>) -> Unit\n    return ()\n"
        )

    def test_return_list_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f() -> List<Conn>\n    return []\n"
        )

    def test_return_tuple_of_linear_rejected(self):
        self._rejects(
            self._LIN + "fun f(consume c: Conn) -> (Conn, Int)\n"
            "    return (c, 1)\n"
        )

    def test_struct_field_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "type Box { items: List<Conn> }\n"
        )

    def test_struct_field_container_of_carrier_rejected(self):
        self._rejects(
            self._CARRIER + "type Fleet { sessions: List<Session> }\n"
        )

    def test_typestate_field_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "typestate Pool { conns: List<Conn> }\n"
            "    Empty\n    Full\n"
        )

    def test_variant_payload_container_of_linear_rejected(self):
        self._rejects(
            self._LIN + "type Wrap =\n    Present(List<Conn>)\n    Nothing\n"
        )

    def test_typestate_param_list_rejected(self):
        self._rejects(
            self._TS + "fun f(xs: List<Claim[Settled]>) -> Unit\n"
            "    return ()\n"
        )

    # ---- over-reject line: must COMPILE ----

    def test_generic_helper_non_linear_t_compiles(self):
        self._compiles(
            self._STASH + "fun main(_s: Stdio)\n"
            "    var nums: List<Int> = []\n"
            "    let ys = stash(nums, 3)\n"
        )

    def test_bare_linear_through_generic_compiles(self):
        # A bare linear value threaded through a generic (id<T>(v: T) -> T at
        # T = Conn) is legal: single-owner values flow by name, including
        # through generics; only a container-of-linear substitution rejects.
        self._compiles(
            self._LIN + "fun id2<T>(consume v: T) -> T\n    return v\n"
            "fun main(_s: Stdio)\n    let c = id2(mkc())\n    close(c)\n"
        )

    def test_plain_data_containers_everywhere_compile(self):
        self._compiles(
            "type Money { cents: Int }\n"
            "fun sink(xs: List<Money>, m: Map<String, Money>) -> List<Money>\n"
            "    return xs\n"
            "fun main(_s: Stdio)\n"
            "    var xs: List<Money> = []\n"
            "    xs.push(Money { cents: 1 })\n"
            "    let doubled = [1, 2, 3].map(fun(x) => x + 1)\n"
            "    var m = new_map()\n"
            "    m.set(\"k\", Money { cents: 2 })\n"
            "    let ys = sink(xs, m)\n"
        )

    def test_bare_linear_signatures_compile(self):
        # The bare-linear flows: a consume param, a factory return, a linear
        # field of a carrier struct, and the struct-literal factory.
        self._compiles(
            self._CARRIER + "fun take(consume c: Conn) -> Conn\n"
            "    return c\n"
            "fun main(_s: Stdio)\n    let s = mks()\n"
            "    close(s.conn)\n"
        )


class TestLinearCarrierObligation(unittest.TestCase):
    """Carrier obligation: a struct (or nested struct) that TRANSITIVELY
    OWNS a linear/typestate field is itself a must-consume CARRIER. It must
    be consumed / transitioned / returned, OR its linear field(s) must be
    consumed / moved out, else it leaks -- exactly as a bare linear value
    does. Closes the struct-literal move-tracking double-free: a linear
    value packed into a field and then re-used double-frees.

    Discharge is PER-FIELD: consuming or moving out the carrier's linear
    field(s) satisfies it (the whole value need not itself reach a
    consume). A ``consume``-param carrier is DROP-EXEMPT transitively.

    Analyzer-only; accepted shapes lower unchanged. Both facets
    (``linear type`` and ``typestate``) are exercised."""

    _BASE = (
        "linear type Handle { id: Int }\n"
        "fun open() -> Handle\n"
        "    return Handle { id: 1 }\n"
        "fun close(consume h: Handle) -> Unit\n"
        "    return ()\n"
        "type Box { h: Handle }\n"
        "fun make_box() -> Box\n"
        "    return Box { h: open() }\n"
        "fun sink(consume b: Box) -> Unit\n"
        "    return ()\n"
    )
    # A carrier W with a single linear field plus a scalar, for the
    # partial-field-consume-across-branches (Connection C) tests.
    _W = (
        "type W { c: Handle, tag: Int }\n"
        "fun mkw() -> W\n"
        "    return W { c: open(), tag: 0 }\n"
    )
    # Typestate facet: a non-linear carrier of a typestate field.
    _TS = (
        "typestate Claim\n    Draft\n    Settled\n"
        "fun mk() -> Claim[Draft]\n"
        "    return Claim[Draft] {}\n"
        "fun archive(consume c: Claim[Settled]) -> Unit\n"
        "    return ()\n"
        "type Rec { claim: Claim[Settled], tag: Int }\n"
        "fun mkrec() -> Rec\n"
        "    return Rec { claim: become(mk(), Settled), tag: 0 }\n"
    )

    def _errs(self, body: str) -> list[str]:
        return [e for e in errors_of(body) if "never used" not in e]

    def _rejects(self, body: str) -> None:
        self.assertTrue(self._errs(body), "expected a rejection, got none")

    def _compiles(self, body: str) -> None:
        errs = self._errs(body)
        self.assertEqual(errs, [], errs)

    # ---- core struct-pack double-free (both orders) ----

    def test_pack_then_reuse_source_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let h = open()\n"
            "    let b = Box { h: h }\n    close(h)\n    close(b.h)\n"
        )

    def test_pack_then_reuse_field_first_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let h = open()\n"
            "    let b = Box { h: h }\n    close(b.h)\n    close(h)\n"
        )

    # ---- E1 binding-level arming from a factory call ----

    def test_factory_carrier_dropped_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
        )

    def test_factory_carrier_anonymous_drop_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let _ = make_box()\n"
        )

    def test_factory_carrier_bare_stmt_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    make_box()\n"
        )

    def test_nested_carrier_dropped_rejected(self):
        self._rejects(
            self._BASE + "type Inner { h: Handle }\n"
            "type Outer { inner: Inner, tag: Int }\n"
            "fun make_outer() -> Outer\n"
            "    return Outer { inner: Inner { h: open() }, tag: 0 }\n"
            "fun main(_s: Stdio)\n    let o = make_outer()\n"
        )

    # ---- Connection C: partial field-consume across branches ----

    def test_partial_field_consume_across_branches_rejected(self):
        self._rejects(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    if flag\n        close(w.c)\n    else\n        s.println(\"x\")\n"
        )

    def test_field_consume_on_all_paths_ok(self):
        self._compiles(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    if flag\n        close(w.c)\n    else\n        close(w.c)\n"
        )

    def test_partial_field_consume_match_rejected(self):
        self._rejects(
            self._BASE + self._W
            + "fun main(s: Stdio, flag: Bool)\n    let w = mkw()\n"
            "    match flag\n"
            "        true -> close(w.c)\n"
            "        false -> s.println(\"x\")\n"
        )

    # ---- E2: reassign drops the old carrier ----

    def test_reassign_drops_old_carrier_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    var b = make_box()\n"
            "    b = make_box()\n    close(b.h)\n"
        )

    # ---- variant payload BAR (declaration) ----

    def test_variant_bare_linear_payload_rejected(self):
        self._rejects(
            "linear type Handle { id: Int }\n"
            "type Wrap =\n    A(Handle)\n    B(Int)\n"
        )

    def test_variant_bare_typestate_payload_rejected(self):
        self._rejects(
            "typestate Claim\n    Draft\n    Settled\n"
            "type Wrap =\n    A(Claim[Draft])\n    B(Int)\n"
        )

    # ---- STAY ACCEPTED ----

    def test_return_carrier_literal_ok(self):
        self._compiles(
            self._BASE + "fun wrap(consume h: Handle) -> Box\n"
            "    return Box { h: h }\n"
        )

    def test_carrier_consumed_once_ok(self):
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    sink(b)\n"
        )

    def test_carrier_passthrough_ok(self):
        self._compiles(
            self._BASE + "fun passthrough(consume b: Box) -> Box\n"
            "    return b\n"
        )

    def test_borrowed_carrier_forwarded_ok(self):
        self._compiles(
            self._BASE + "fun peek(b: Box) -> Int\n    return b.h.id\n"
            "fun use2(b: Box) -> Int\n    return peek(b)\n"
        )

    def test_consume_carrier_param_dropped_ok(self):
        # Adopting the whole carrier + its contents is legal (drop-exempt
        # transitively), consistent with ``adopt(consume h)``.
        self._compiles(
            self._BASE + "fun adopt_box(consume b: Box) -> Unit\n"
            "    return ()\n"
        )

    def test_field_consumed_then_carrier_dropped_ok(self):
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n"
        )

    def test_typestate_carrier_field_moved_out_ok(self):
        self._compiles(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let n = rec.tag\n"
        )

    def test_arm_local_carrier_field_moved_out_ok(self):
        # A carrier bound AND fully field-moved-out inside a single match arm
        # (the capa_claimdesk ``let result = settle(...); let settled =
        # result.claim; settled.archive()`` shape). Moving out its last
        # linear field discharges the whole carrier, so it must not linger
        # into the arm merge (where the sibling arm would wrongly intersect
        # the field-move away and report a false leak).
        self._compiles(
            self._BASE + "fun main(s: Stdio, flag: Bool)\n"
            "    match flag\n"
            "        true ->\n"
            "            let b = make_box()\n"
            "            let inner = b.h\n"
            "            close(inner)\n"
            "        false ->\n"
            "            s.println(\"x\")\n"
        )

    def test_typestate_carrier_dropped_rejected(self):
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    let rec = mkrec()\n"
        )

    # ---- HUSK re-consume after ALL linear fields moved out ----
    # A carrier whose linear field(s) are all moved out is a spent husk. It
    # may be DROPPED, but consuming / returning / re-packing the WHOLE husk
    # again re-transfers an already-moved field -- a runtime double-free.

    def test_field_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    sink(b)\n"
        )

    def test_field_projected_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    let x = b.h\n    close(x)\n    sink(b)\n"
        )

    def test_field_moved_then_whole_returned_rejected(self):
        self._rejects(
            self._BASE + "fun leak(consume b: Box) -> Box\n"
            "    close(b.h)\n    return b\n"
        )

    def test_field_moved_then_repacked_rejected(self):
        self._rejects(
            self._BASE + "type Outer2 { inner: Box }\n"
            "fun sink_o2(consume o: Outer2) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let o = Outer2 { inner: b }\n    sink_o2(o)\n"
        )

    def test_two_fields_both_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "type W2 { c: Handle, d: Handle }\n"
            "fun mkw2() -> W2\n    return W2 { c: open(), d: open() }\n"
            "fun sink2(consume w: W2) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let w = mkw2()\n"
            "    close(w.c)\n    close(w.d)\n    sink2(w)\n"
        )

    def test_nested_field_moved_then_whole_consumed_rejected(self):
        self._rejects(
            self._BASE + "type Inner2 { h: Handle }\n"
            "type Outer3 { inner: Inner2 }\n"
            "fun mko3() -> Outer3\n"
            "    return Outer3 { inner: Inner2 { h: open() } }\n"
            "fun sink_o3(consume o: Outer3) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let o = mko3()\n"
            "    close(o.inner.h)\n    sink_o3(o)\n"
        )

    # ---- STAY ACCEPTED: husk dropped / husk non-linear field read ----

    def test_husk_dropped_ok(self):
        # Field moved out, husk merely dropped, never re-consumed: legal (the
        # per-field-discharge semantic that keeps claimdesk compiling).
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n"
        )

    def test_husk_nonlinear_field_read_after_move_ok(self):
        # Reading a husk's NON-linear field after moving out its linear field
        # must stay legal (this is why the husk root is not marked
        # wholesale-consumed).
        self._compiles(
            "linear type Handle { id: Int }\n"
            "fun open() -> Handle\n    return Handle { id: 1 }\n"
            "fun close(consume h: Handle) -> Unit\n    return ()\n"
            "type BoxT { h: Handle, tag: Int }\n"
            "fun make_boxt() -> BoxT\n    return BoxT { h: open(), tag: 0 }\n"
            "fun main(_s: Stdio)\n    let b = make_boxt()\n"
            "    let x = b.h\n    close(x)\n    let n = b.tag\n"
        )

    # ---- HUSK re-consume through an ALIAS / reassignment ----
    # The move seam poisons the SOURCE binding, but an alias / reassignment
    # re-arms the TARGET with a fresh FULL obligation, so without carrying the
    # moved-out sub-path across, re-consuming the whole husk through the alias
    # slips past every use-site scan and lowers to a runtime double-free. The
    # moved sub-path must travel across the alias (and along a chain), so the
    # husk-reconsume / discharge / field-use scans fire on the alias too.

    def test_alias_husk_then_consume_alias_rejected(self):
        # Alias the spent husk, then consume the alias whole -> double-free.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    sink(c)\n"
        )

    def test_alias_husk_then_field_moved_again_rejected(self):
        # Alias the husk, then move the SAME (already-freed) field out again
        # through the alias.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    close(c.h)\n"
        )

    def test_alias_husk_then_returned_rejected(self):
        # Alias the husk, then return the alias from a by-consume function ->
        # re-transfers an already-moved field to the caller.
        self._rejects(
            self._BASE + "fun leak2(consume b: Box) -> Box\n"
            "    close(b.h)\n    let c = b\n    return c\n"
        )

    def test_chained_alias_husk_then_consume_tail_rejected(self):
        # Alias the alias (a chain), then consume the tail: the moved-out
        # sub-path must travel the whole chain.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n    let d = c\n    sink(d)\n"
        )

    def test_reassign_husk_into_var_then_consume_rejected(self):
        # Reassign the husk into an existing (cleanly discharged) var, then
        # consume it whole -> double-free through the reassigned binding.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    var c = make_box()\n    sink(c)\n"
            "    c = b\n    sink(c)\n"
        )

    def test_typestate_alias_husk_then_consume_rejected(self):
        # Typestate facet: move out a carrier's typestate field, alias the
        # husk, then consume the alias whole.
        self._rejects(
            self._TS + "fun sink_rec(consume r: Rec) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    let rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    let alias = rec\n    sink_rec(alias)\n"
        )

    # ---- STAY ACCEPTED: alias route must not over-reject ----

    def test_alias_full_carrier_consumed_once_ok(self):
        # A full carrier aliased then consumed exactly once, with NO prior
        # field-move: the obligation just moves onto the alias.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    let c = b\n    sink(c)\n"
        )

    def test_alias_husk_nonlinear_field_read_ok(self):
        # Aliasing a husk then reading the alias's NON-linear field stays
        # legal (only the moved linear sub-path travels, never the root).
        self._compiles(
            "linear type Handle { id: Int }\n"
            "fun open() -> Handle\n    return Handle { id: 1 }\n"
            "fun close(consume h: Handle) -> Unit\n    return ()\n"
            "type BoxT { h: Handle, tag: Int }\n"
            "fun make_boxt() -> BoxT\n    return BoxT { h: open(), tag: 0 }\n"
            "fun main(_s: Stdio)\n    let b = make_boxt()\n"
            "    close(b.h)\n    let c = b\n    let n = c.tag\n"
        )

    def test_alias_husk_dropped_ok(self):
        # Aliasing a husk and merely DROPPING the alias (never re-consumed)
        # stays legal, exactly as dropping the husk itself does.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    let b = make_box()\n"
            "    close(b.h)\n    let c = b\n"
        )

    # ---- husk REASSIGNED to a FRESH value: re-arm must be fully live ----
    # A `var` husk (its linear/typestate field moved out) reassigned to a
    # brand-new value must be tracked as fully live again: the stale moved-out
    # sub-path must NOT survive the fresh re-arm, or a legitimate consume is
    # rejected (false positive) and the fresh value's own leak is masked
    # (soundness). Complement of the alias-carry route.

    def test_reassign_fresh_after_husk_consumed_ok(self):
        # FP face (linear): consuming the reassigned-to-fresh carrier once is
        # legal; the stale `c.h` from the spent husk must not linger.
        self._compiles(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    close(c.h)\n    c = make_box()\n    sink(c)\n"
        )

    def test_reassign_fresh_after_husk_dropped_rejected(self):
        # Soundness face (linear): dropping the reassigned-to-fresh carrier
        # without consuming leaks the fresh resource and must be rejected,
        # exactly as a plain fresh-drop is.
        self._rejects(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    close(c.h)\n    c = make_box()\n"
        )

    def test_typestate_reassign_fresh_after_husk_consumed_ok(self):
        # FP face (typestate): same, with a typestate field moved out by
        # projection before the fresh re-arm.
        self._compiles(
            self._TS + "fun sink_rec(consume r: Rec) -> Unit\n    return ()\n"
            "fun main(_s: Stdio)\n    var rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    rec = mkrec()\n    sink_rec(rec)\n"
        )

    def test_typestate_reassign_fresh_after_husk_dropped_rejected(self):
        # Soundness face (typestate): dropping the reassigned-to-fresh carrier
        # leaks and must be rejected.
        self._rejects(
            self._TS + "fun main(_s: Stdio)\n    var rec = mkrec()\n"
            "    let settled = rec.claim\n    archive(settled)\n"
            "    rec = mkrec()\n"
        )

    def test_reassign_fresh_clears_only_own_subtree(self):
        # Precision: the fresh re-arm of `c` clears only `c.*`, never a sibling
        # husk `cc` (nor the root `c`). Consuming the fresh `c` is accepted,
        # while the untouched sibling husk `cc` still rejects its re-consume, so
        # an over-clear (or a whole-root wipe) cannot pass silently.
        errs = self._errs(
            self._BASE + "fun main(_s: Stdio)\n    var c = make_box()\n"
            "    var cc = make_box()\n    close(c.h)\n    close(cc.h)\n"
            "    c = make_box()\n    sink(c)\n    sink(cc)\n"
        )
        self.assertTrue(any("'cc'" in e for e in errs), errs)
        self.assertFalse(any("consume 'c'" in e for e in errs), errs)


if __name__ == "__main__":
    unittest.main()
