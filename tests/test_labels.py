"""Tests for the information-flow security-label foundation
(roadmap S2.1 + S2.2): the lattice algebra and the ``@secret`` /
``@public`` parse-and-attach. Propagation + enforcement are tested
separately once those land."""

import unittest

from capa import Lexer, Parser
from capa import capa_ast as A
from capa import _labels as L


class TestLabelLattice(unittest.TestCase):
    def test_join_takes_more_restricted(self):
        self.assertEqual(L.join(L.PUBLIC, L.SECRET), L.SECRET)
        self.assertEqual(L.join(L.SECRET, L.PUBLIC), L.SECRET)
        self.assertEqual(L.join(L.PUBLIC, L.PUBLIC), L.PUBLIC)
        self.assertEqual(L.join(L.SECRET, L.SECRET), L.SECRET)

    def test_none_normalizes_to_public(self):
        self.assertEqual(L.normalize(None), L.PUBLIC)
        self.assertEqual(L.normalize("bogus"), L.PUBLIC)
        self.assertEqual(L.join(None, L.SECRET), L.SECRET)

    def test_join_all(self):
        self.assertEqual(L.join_all([]), L.PUBLIC)
        self.assertEqual(L.join_all([L.PUBLIC, L.PUBLIC]), L.PUBLIC)
        self.assertEqual(L.join_all([L.PUBLIC, L.SECRET, L.PUBLIC]), L.SECRET)

    def test_flows_to_forbids_only_secret_to_public(self):
        self.assertTrue(L.flows_to(L.PUBLIC, L.SECRET))
        self.assertTrue(L.flows_to(L.PUBLIC, L.PUBLIC))
        self.assertTrue(L.flows_to(L.SECRET, L.SECRET))
        self.assertFalse(L.flows_to(L.SECRET, L.PUBLIC))  # the vector

    def test_flows_to_treats_none_as_public(self):
        self.assertTrue(L.flows_to(None, L.SECRET))
        self.assertFalse(L.flows_to(L.SECRET, None))


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


class TestLabelParsing(unittest.TestCase):
    def test_secret_on_param_type(self):
        m = _parse(
            "fun h(token: @secret String, _net: Net) -> Int\n"
            "    return 0\n"
        )
        fn = m.items[0]
        self.assertEqual(fn.params[0].type_expr.label, "secret")
        self.assertIsNone(fn.params[1].type_expr.label)

    def test_public_on_return_type(self):
        m = _parse("fun f() -> @public Int\n    return 0\n")
        self.assertEqual(m.items[0].return_type.label, "public")

    def test_label_on_generic_type(self):
        m = _parse(
            "fun f(xs: @secret List<Int>) -> Int\n"
            "    return 0\n"
        )
        ty = m.items[0].params[0].type_expr
        self.assertIsInstance(ty, A.TypeName)
        self.assertEqual(ty.name, "List")
        self.assertEqual(ty.label, "secret")

    def test_label_on_let_binding_type(self):
        m = _parse(
            "fun f()\n"
            "    let x: @secret Int = 1\n"
            "    return\n"
        )
        let_stmt = m.items[0].body.stmts[0]
        self.assertEqual(let_stmt.type_expr.label, "secret")

    def test_unlabelled_type_has_none(self):
        m = _parse("fun f(x: Int) -> String\n    return \"a\"\n")
        self.assertIsNone(m.items[0].params[0].type_expr.label)
        self.assertIsNone(m.items[0].return_type.label)

    def test_attribute_syntax_not_confused_with_label(self):
        # ``@security(...)`` on a function is an attribute, not a
        # type label -- the ``(`` after the name disambiguates.
        m = _parse(
            "@security(cve: \"CVE-1\")\n"
            "fun f(_s: Stdio)\n"
            "    return\n"
        )
        self.assertEqual(m.items[0].attributes[0].name, "security")


class TestLabelPropagation(unittest.TestCase):
    """Roadmap S2.3: a value's security label is the join of the
    labels that flow into it. Propagation only -- no flow is rejected
    in this slice (enforcement is S2.4)."""

    def _let_labels(self, src: str) -> dict:
        # Drive the analyzer directly to read the per-expression
        # label map it builds (_expr_labels), keyed by RHS id.
        from capa.analyzer import Analyzer
        m = _parse(src)
        az = Analyzer(source=src)
        az.analyze(m)
        out = {}
        for fn in m.items:
            if not isinstance(fn, A.FunDecl):
                continue
            for st in fn.body.stmts:
                if isinstance(st, A.LetStmt) and isinstance(st.pattern, A.IdentPat):
                    out[st.pattern.name] = az._expr_labels.get(id(st.value))
        return out

    def test_ident_inherits_binding_label(self):
        labels = self._let_labels(
            "fun h(token: @secret String, _s: Stdio) -> Unit\n"
            "    let echoed = token\n"
            "    _s.println(\"x\")\n"
        )
        self.assertEqual(labels["echoed"], "secret")

    def test_binop_joins_operand_labels(self):
        labels = self._let_labels(
            "fun h(token: @secret Int, _s: Stdio) -> Unit\n"
            "    let combined = token + 1\n"
            "    let plain = 1 + 2\n"
            "    _s.println(\"x\")\n"
        )
        self.assertEqual(labels["combined"], "secret")
        self.assertEqual(labels["plain"], "public")

    def test_interpolation_is_a_flow(self):
        # "${secret}" is secret -- the classic logging-leak shape.
        labels = self._let_labels(
            "fun h(token: @secret String, _s: Stdio) -> Unit\n"
            "    let msg = \"value=${token}\"\n"
            "    _s.println(\"x\")\n"
        )
        self.assertEqual(labels["msg"], "secret")

    def test_taint_is_transitive(self):
        labels = self._let_labels(
            "fun h(token: @secret Int, _s: Stdio) -> Unit\n"
            "    let a = token\n"
            "    let b = a + 1\n"
            "    _s.println(\"x\")\n"
        )
        self.assertEqual(labels["a"], "secret")
        self.assertEqual(labels["b"], "secret")

    def test_explicit_annotation_on_let(self):
        labels = self._let_labels(
            "fun h(_s: Stdio) -> Unit\n"
            "    let x: @secret Int = 1\n"
            "    let y = x\n"
            "    _s.println(\"z\")\n"
        )
        self.assertEqual(labels["y"], "secret")

    def test_propagation_does_not_reject_yet(self):
        # S2.3 only observes -- a secret-to-sink flow still analyses
        # cleanly (enforcement is the next slice).
        from capa import analyze
        m = _parse(
            "fun h(token: @secret String, stdio: Stdio) -> Unit\n"
            "    stdio.println(token)\n"
        )
        r = analyze(m, source="x")
        self.assertTrue(r.ok, [e.message for e in r.errors])


class TestSinkEnforcement(unittest.TestCase):
    """Roadmap S2.4: a @secret value reaching a public sink
    (Stdio.println, Net.post, Fs.write, ...) is a flow violation --
    a warning by default (warn-then-enforce), a hard error under
    @strict_ifc."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_secret_to_println_warns_not_errors(self):
        r = self._analyze(
            "fun h(token: @secret String, stdio: Stdio)\n"
            "    stdio.println(token)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)
        self.assertIn("Stdio.println", r.warnings[0].message)

    def test_secret_via_interpolation_warns(self):
        r = self._analyze(
            "fun h(token: @secret String, stdio: Stdio)\n"
            "    stdio.println(\"value=${token}\")\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_public_to_sink_is_clean(self):
        r = self._analyze(
            "fun h(stdio: Stdio)\n"
            "    stdio.println(\"plain\")\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertEqual(len(r.errors), 0)

    def test_secret_not_reaching_sink_is_clean(self):
        r = self._analyze(
            "fun h(token: @secret String, _s: Stdio)\n"
            "    let x = token\n"
            "    _s.println(\"unrelated\")\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_strict_ifc_turns_warning_into_error(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun h(token: @secret String, stdio: Stdio)\n"
            "    stdio.println(token)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(r.errors), 1)
        self.assertIn("information-flow", r.errors[0].message)

    def test_strict_ifc_clean_flow_compiles(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun h(stdio: Stdio)\n"
            "    stdio.println(\"ok\")\n"
        )
        self.assertTrue(r.ok)

    def test_strict_ifc_does_not_leak_to_sibling_function(self):
        # The strict flag is per-function: a non-strict function
        # after a strict one still only warns.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun strict_one(token: @secret String, stdio: Stdio)\n"
            "    let x = token\n"
            "    stdio.println(\"clean\")\n"
            "fun loose(token: @secret String, stdio: Stdio)\n"
            "    stdio.println(token)\n"
        )
        # loose's flow is a warning, not an error -> still ok.
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 1)

    def test_net_post_body_is_a_sink(self):
        r = self._analyze(
            "fun h(token: @secret String, net: Net)\n"
            "    let _ = net.post(\"http://x/y\", token)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("Net.post", r.warnings[0].message)


class TestSecretSources(unittest.TestCase):
    """Roadmap S2 source caps: a read from a built-in secret source
    (``env.get``) yields ``@secret`` data with no annotation, and that
    label flows through a ``match``/``let`` destructure to the bound
    names -- so the read-secret-then-leak headline case is caught."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_env_get_result_is_secret(self):
        # The Option<String> from env.get is labelled secret directly.
        from capa.analyzer import Analyzer
        src = (
            "fun f(env: Env, _s: Stdio)\n"
            "    let opt = env.get(\"API_KEY\")\n"
            "    _s.println(\"x\")\n"
        )
        m = _parse(src)
        az = Analyzer(source=src)
        az.analyze(m)
        let_stmt = m.items[0].body.stmts[0]
        self.assertEqual(az._expr_labels.get(id(let_stmt.value)), "secret")

    def test_match_payload_inherits_secret(self):
        # The headline case: env.get -> match Some(key) -> sink(key).
        r = self._analyze(
            "fun leak(env: Env, stdio: Stdio)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(key) -> stdio.println(key)\n"
            "        None -> stdio.println(\"no key\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("Stdio.println", r.warnings[0].message)

    def test_match_payload_not_leaked_is_clean(self):
        # Reading the secret and matching on it without routing the
        # payload to a sink is fine.
        r = self._analyze(
            "fun safe(env: Env, stdio: Stdio)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(_key) -> stdio.println(\"got one\")\n"
            "        None -> stdio.println(\"none\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_public_match_payload_stays_public(self):
        # A match on a public scrutinee does not taint its binds.
        r = self._analyze(
            "fun f(stdio: Stdio)\n"
            "    match (1, 2)\n"
            "        (a, _b) -> stdio.println(\"x\")\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_strict_ifc_makes_source_leak_an_error(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun leak(env: Env, stdio: Stdio)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(key) -> stdio.println(key)\n"
            "        None -> stdio.println(\"no key\")\n"
        )
        self.assertFalse(r.ok)
        # Under strict, the explicit data leak is an error; the implicit
        # control-flow leaks (S2.implicit) are also errors here.
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )


class TestAggregateLabels(unittest.TestCase):
    """Roadmap S2 (laundering fix): an aggregate literal carries the
    join of the labels of the values it holds, so stashing a @secret in
    a struct field / list / tuple and reading it back no longer launders
    it to @public. A for-loop variable inherits the iterable's label."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_struct_field_does_not_launder(self):
        r = self._analyze(
            "type Box { field: String, tag: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = Box { field: token, tag: \"t\" }\n"
            "    stdio.println(b.field)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    def test_list_element_does_not_launder(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let xs = [token, \"other\"]\n"
            "    stdio.println(xs.get(0).unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_tuple_element_does_not_launder(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let pair = (token, 1)\n"
            "    stdio.println(\"${pair}\")\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_public_aggregate_stays_clean(self):
        r = self._analyze(
            "type Box { a: String }\n"
            "fun f(stdio: Stdio)\n"
            "    let b = Box { a: \"hi\" }\n"
            "    stdio.println(b.a)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_for_loop_var_inherits_iterable_label(self):
        # Iterating a tainted list taints the loop variable, and the
        # sink in the body warns exactly once (not twice from the
        # two-pass loop analysis).
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let xs = [token]\n"
            "    for x in xs\n"
            "        stdio.println(x)\n"
        )
        self.assertEqual(len(r.warnings), 1)


class TestMutableContainerTaint(unittest.TestCase):
    """Roadmap S2: a @secret pushed / added / set into a mutable
    container (built via new_map() / new_set() / []) taints the
    container binding, so a later read does not launder it to public."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_map_set_then_get(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let m = new_map()\n"
            "    m.set(\"k\", token)\n"
            "    stdio.println(m.get(\"k\").unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_secret_key_also_taints_map(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let m = new_map()\n"
            "    m.set(token, \"v\")\n"
            "    stdio.println(m.get(\"x\").unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_list_push_then_get(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let xs = []\n"
            "    xs.push(token)\n"
            "    stdio.println(xs.get(0).unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_set_add_then_iterate(self):
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let s = new_set()\n"
            "    s.add(token)\n"
            "    for x in s.to_list()\n"
            "        stdio.println(x)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_public_container_stays_clean(self):
        r = self._analyze(
            "fun f(stdio: Stdio)\n"
            "    let m = new_map()\n"
            "    m.set(\"k\", \"v\")\n"
            "    stdio.println(m.get(\"k\").unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 0)


class TestImplicitFlow(unittest.TestCase):
    """Roadmap S2.implicit: a sink that fires inside a branch guarded by
    a @secret condition leaks whether the branch was taken (the pc-label
    rises to SECRET in the branch body). Gated to @strict_ifc only: the
    default warn tier stays focused on explicit DATA leaks, while strict
    turns on full noninterference (implicit leaks become errors)."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_implicit_not_flagged_in_default_tier(self):
        # Printing a constant inside a secret-conditioned match arm is
        # an implicit leak, but the default (non-strict) tier ignores
        # it -- no explicit data flow, so no warning.
        r = self._analyze(
            "fun f(env: Env, stdio: Stdio)\n"
            "    match env.get(\"K\")\n"
            "        Some(_k) -> stdio.println(\"present\")\n"
            "        None -> stdio.println(\"absent\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_implicit_match_leak_errors_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(env: Env, stdio: Stdio)\n"
            "    match env.get(\"K\")\n"
            "        Some(_k) -> stdio.println(\"present\")\n"
            "        None -> stdio.println(\"absent\")\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            all("information-flow (strict)" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )
        # One implicit leak per arm.
        self.assertEqual(len(r.errors), 2)

    def test_implicit_if_leak_errors_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    if token\n"
            "        stdio.println(\"yes\")\n"
            "    else\n"
            "        stdio.println(\"no\")\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(r.errors), 2)

    def test_sink_outside_secret_branch_is_clean_under_strict(self):
        # The pc-label is restored after the branch, so a sink after the
        # if does not run under secret control flow.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    if token\n"
            "        let _x = 1\n"
            "    stdio.println(\"always\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_public_condition_does_not_raise_pc(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(flag: Bool, stdio: Stdio)\n"
            "    if flag\n"
            "        stdio.println(\"yes\")\n"
            "    else\n"
            "        stdio.println(\"no\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])


class TestConstantTime(unittest.TestCase):
    """Roadmap S4: a @constant_time function must not let a @secret
    value drive control flow (timing) or memory access (cache timing),
    the CWE-208 side channels."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def _ct_errors(self, r):
        return [e for e in r.errors if "constant-time" in e.message]

    def test_if_on_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun cmp(a: @secret Int, b: @secret Int) -> Bool\n"
            "    if a == b\n"
            "        return true\n"
            "    return false\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_match_on_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(x: @secret Int) -> Int\n"
            "    return match x\n"
            "        0 -> 1\n"
            "        _ -> 2\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_while_on_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(n: @secret Int) -> Int\n"
            "    var i = 0\n"
            "    while i < n\n"
            "        i = i + 1\n"
            "    return i\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_index_with_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun pick(table: List<Int>, idx: @secret Int) -> Int\n"
            "    return table[idx]\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_list_get_with_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun pick(table: List<Int>, idx: @secret Int) -> Int\n"
            "    return table.get(idx).unwrap_or(0)\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_map_get_with_secret_key_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun look(m: Map<Int, Int>, k: @secret Int) -> Int\n"
            "    return m.get(k).unwrap_or(0)\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_arithmetic_on_secret_is_fine(self):
        # Arithmetic does not branch or index, so it is constant-time.
        r = self._analyze(
            "@constant_time()\n"
            "fun add(a: @secret Int, b: @secret Int) -> Int\n"
            "    return a + b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_branch_on_public_is_fine(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun pick(flag: Bool, a: @secret Int, b: @secret Int) -> Int\n"
            "    if flag\n"
            "        return a\n"
            "    return b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_public_index_is_fine(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun pick(table: List<Int>, idx: Int) -> Int\n"
            "    return table.get(idx).unwrap_or(0)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_no_attribute_means_no_ct_rule(self):
        # Without @constant_time, a secret branch is allowed (the IFC
        # data-flow rules still apply, but timing is not checked).
        r = self._analyze(
            "fun cmp(a: @secret Int, b: @secret Int) -> Bool\n"
            "    if a == b\n"
            "        return true\n"
            "    return false\n"
        )
        self.assertEqual(self._ct_errors(r), [])

    def test_sbom_records_constant_time(self):
        from capa.manifest import build_manifest
        src = (
            "@constant_time()\n"
            "fun add(a: @secret Int, b: @secret Int) -> Int\n"
            "    return a + b\n"
            "fun plain(x: Int) -> Int\n"
            "    return x\n"
        )
        m = _parse(src)
        manifest = build_manifest(m, filename="<test>")
        by_name = {f["source_name"]: f for f in manifest["functions"]}
        self.assertTrue(by_name["add"]["constant_time"])
        self.assertFalse(by_name["plain"]["constant_time"])


class TestDeclassify(unittest.TestCase):
    """Roadmap S2.5: ``declassify(value, reason: "...")`` is the single
    auditable @secret -> @public bridge. It clears the sink warning,
    requires a named string-literal reason, warns on a no-op, and is
    recorded in the SBOM."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_declassify_clears_the_leak(self):
        r = self._analyze(
            "fun f(env: Env, stdio: Stdio)\n"
            "    match env.get(\"K\")\n"
            "        Some(key) -> "
            "stdio.println(declassify(key, reason: \"audit ok\"))\n"
            "        None -> stdio.println(\"none\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_reason_must_be_named(self):
        r = self._analyze(
            "fun f(token: @secret String, stdio: Stdio)\n"
            "    stdio.println(declassify(token, \"oops\"))\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("named" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_reason_must_be_a_literal(self):
        r = self._analyze(
            "fun f(token: @secret String, stdio: Stdio, why: String)\n"
            "    stdio.println(declassify(token, reason: why))\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("literal" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_declassify_of_public_warns(self):
        r = self._analyze(
            "fun f(stdio: Stdio)\n"
            "    stdio.println(declassify(\"plain\", reason: \"x\"))\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("no-op", r.warnings[0].message)

    def test_declassified_value_keeps_its_type(self):
        # declassify is identity on the value: an Int stays an Int, so
        # a downstream Int use type-checks.
        r = self._analyze(
            "fun f(token: @secret Int) -> Int\n"
            "    let n = declassify(token, reason: \"ok\")\n"
            "    return n + 1\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_user_function_named_declassify_is_not_special(self):
        # A user-defined declassify is an ordinary function: the IFC
        # special-case is guarded by the built-in binding position, so
        # this must not fire the bespoke shape errors.
        r = self._analyze(
            "fun declassify(x: Int) -> Int\n"
            "    return x\n"
            "fun f() -> Int\n"
            "    return declassify(5)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_sbom_records_declassification_site(self):
        from capa.manifest import build_manifest
        src = (
            "fun f(env: Env, stdio: Stdio)\n"
            "    match env.get(\"K\")\n"
            "        Some(key) -> "
            "stdio.println(declassify(key, reason: \"only last 4\"))\n"
            "        None -> stdio.println(\"none\")\n"
        )
        m = _parse(src)
        manifest = build_manifest(m, filename="<test>")
        self.assertEqual(manifest["summary"]["declassification_sites"], 1)
        sites = manifest["functions"][0]["declassifications"]
        self.assertEqual(len(sites), 1)
        self.assertEqual(sites[0]["reason"], "only last 4")
        self.assertEqual(sites[0]["value"], "key")


if __name__ == "__main__":
    unittest.main()
