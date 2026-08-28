"""Analyzer tests: capability discipline: forge/container/field discipline, capability
methods, net attenuation, user-defined caps, struct-cap consume, and
cap-leak-via-generic.

Split out of tests/test_analyzer.py; see tests/analyzer/__init__.py for
the growth convention. The shared check/errors_of helpers live in
tests/analyzer/_helpers.py.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


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


if __name__ == "__main__":
    unittest.main()
