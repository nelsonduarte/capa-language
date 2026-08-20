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


class TestPerFieldIfc(unittest.TestCase):
    """Roadmap S2 (per-field precision): a struct-typed value carries a
    per-field label map alongside its collapsed whole-value label. A
    field read on a TRACKED, NON-ESCAPED binding reads the precise field
    label -- so a public field of a struct whose OTHER field is secret no
    longer warns. Soundness is preserved at every boundary: a field
    store raises the field's label monotonically; aliasing / escape /
    destructure fall back to the conservative whole-value label, so a
    real leak is never under-reported (a false negative)."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    # ---- precision (previously over-flagged, now clean) ----------

    def test_public_field_of_mixed_struct_is_clean(self):
        # The headline imprecision fix: reading the PUBLIC field of a
        # struct whose OTHER field is secret no longer warns.
        r = self._analyze(
            "type S { secret_v: String, public_v: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = S { secret_v: token, public_v: \"ok\" }\n"
            "    stdio.println(b.public_v)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_secret_field_of_mixed_struct_still_flagged(self):
        r = self._analyze(
            "type S { secret_v: String, public_v: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = S { secret_v: token, public_v: \"ok\" }\n"
            "    stdio.println(b.secret_v)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    # ---- nested-struct precision --------------------------------

    def test_nested_public_field_is_clean(self):
        r = self._analyze(
            "type Inner { x: String, y: String }\n"
            "type Outer { sec: Inner, plain: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let o = Outer { sec: Inner { x: token, y: \"a\" }, "
            "plain: Inner { x: \"b\", y: \"c\" } }\n"
            "    stdio.println(o.plain.x)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_nested_secret_field_is_flagged(self):
        r = self._analyze(
            "type Inner { x: String, y: String }\n"
            "type Outer { sec: Inner, plain: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let o = Outer { sec: Inner { x: token, y: \"a\" }, "
            "plain: Inner { x: \"b\", y: \"c\" } }\n"
            "    stdio.println(o.sec.x)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- field store / mutation ---------------------------------

    def test_field_store_secret_then_sink_flagged(self):
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var p = S { sv: \"a\", pv: \"ok\" }\n"
            "    p.sv = token\n"
            "    stdio.println(p.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_field_store_secret_other_field_clean(self):
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var p = S { sv: \"a\", pv: \"ok\" }\n"
            "    p.sv = token\n"
            "    stdio.println(p.pv)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_nested_field_store_is_precise(self):
        r = self._analyze(
            "type Inner { x: String, y: String }\n"
            "type Outer { sec: Inner, plain: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var o = Outer { sec: Inner { x: \"a\", y: \"b\" }, "
            "plain: Inner { x: \"c\", y: \"d\" } }\n"
            "    o.sec.x = token\n"
            "    stdio.println(o.plain.x)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    # ---- branch-join (monotone over all paths) ------------------

    def test_field_secret_in_one_branch_then_sunk_is_flagged(self):
        # A field made secret in only one branch of an if must be
        # treated as secret after the if (the join over all paths).
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, flag: Bool, token: @secret String)\n"
            "    var p = S { sv: \"a\", pv: \"ok\" }\n"
            "    if flag\n"
            "        p.sv = token\n"
            "    stdio.println(p.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_other_field_stays_public_across_branch(self):
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, flag: Bool, token: @secret String)\n"
            "    var p = S { sv: \"a\", pv: \"ok\" }\n"
            "    if flag\n"
            "        p.sv = token\n"
            "    stdio.println(p.pv)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    # ---- escape boundaries (fall back to whole-value) -----------

    def test_escape_via_function_then_field_read_conservative(self):
        # Once a struct is passed to a function, intraprocedural
        # per-field tracking can no longer follow it -- a later field
        # read falls back to the conservative whole-value label.
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun sink_it(x: S)\n"
            "    let _ = x\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = S { sv: token, pv: \"ok\" }\n"
            "    sink_it(b)\n"
            "    stdio.println(b.pv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_escape_via_list_then_field_read_conservative(self):
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = S { sv: token, pv: \"ok\" }\n"
            "    let xs = [b]\n"
            "    stdio.println(b.pv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_escape_via_match_destructure_conservative(self):
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = S { sv: token, pv: \"ok\" }\n"
            "    match b\n"
            "        S { sv: a, pv: c } -> stdio.println(c)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- embed-then-mutate (closed false negative) --------------

    def test_embed_then_mutate_source_is_flagged(self):
        # Criterion 6: ``let o = Outer { inner: b }; b.sv = token;
        # sink(o.inner.sv)``. ``o.inner`` aliases ``b`` by reference, so
        # a later mutation of the still-live ``b`` is visible through the
        # embedding -- previously a false negative.
        r = self._analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var b = Inner { sv: \"a\" }\n"
            "    let o = Outer { inner: b }\n"
            "    b.sv = token\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1,
                         [w.message for w in r.warnings])

    def test_embed_then_mutate_read_other_field_conservative(self):
        # Criterion 7: the embedding shares the whole object, so a
        # mutation of the source taints the embedding whole-value -- a
        # read of a sibling field through the embedding is conservatively
        # flagged too (sound over-approximation, never a miss).
        r = self._analyze(
            "type Inner { sv: String, pv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var b = Inner { sv: \"a\", pv: \"p\" }\n"
            "    let o = Outer { inner: b }\n"
            "    b.sv = token\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1,
                         [w.message for w in r.warnings])

    def test_embed_then_mutate_outer_taints_source(self):
        # The link is symmetric (a shared alias group): mutating the
        # OUTER's embedded sub-object also taints the source binding, so
        # reading through the source is flagged.
        r = self._analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var b = Inner { sv: \"a\" }\n"
            "    var o = Outer { inner: b }\n"
            "    o.inner = Inner { sv: token }\n"
            "    stdio.println(b.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1,
                         [w.message for w in r.warnings])

    def test_embed_public_struct_no_false_positive(self):
        # Criterion 8: embed a public ``b``, never taint it, read
        # ``o.inner.sv`` -> not flagged.
        r = self._analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio)\n"
            "    var b = Inner { sv: \"a\" }\n"
            "    let o = Outer { inner: b }\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertEqual(len(r.warnings), 0,
                         [w.message for w in r.warnings])

    def test_embed_field_access_chain_then_mutate_flagged(self):
        # W-1 (closed): a non-identifier struct expression embedded in a
        # struct literal -- a field-access chain rooted at a tracked
        # binding (``Outer { inner: m.inner }``) -- is now linked into the
        # ROOT binding's alias group. ``m.inner`` and ``o.inner`` are the
        # same heap object, so ``m.inner.sv = token`` taints ``o`` too.
        # Previously only bare-Ident embeds were linked, so this leaked.
        r = self._analyze(
            "type Inner { sv: String }\n"
            "type Mid { inner: Inner }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio, token: @secret String, m: Mid)\n"
            "    let o = Outer { inner: m.inner }\n"
            "    m.inner.sv = token\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1,
                         [w.message for w in r.warnings])

    def test_embed_field_access_chain_public_no_false_positive(self):
        # No false positive: embed a field-access chain, never taint it,
        # read through the embedding -> not flagged.
        r = self._analyze(
            "type Inner { sv: String }\n"
            "type Mid { inner: Inner }\n"
            "type Outer { inner: Inner }\n"
            "fun f(stdio: Stdio, m: Mid)\n"
            "    let o = Outer { inner: m.inner }\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertEqual(len(r.warnings), 0,
                         [w.message for w in r.warnings])

    def test_struct_from_call_uses_whole_value(self):
        # A struct produced by a function call has no statically-known
        # field map, so any field read uses the conservative whole-value
        # label (the builder's secret field taints the whole result).
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun build(token: @secret String) -> S\n"
            "    return S { sv: token, pv: \"ok\" }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let b = build(token)\n"
            "    stdio.println(b.pv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- aliasing (reference semantics) -------------------------

    def test_alias_then_mutate_taints_original(self):
        # ``var b2 = b`` aliases the same struct (reference semantics):
        # a field store through b2 is visible through b, so reading b
        # afterwards must stay flagged (conservative).
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var b = S { sv: \"a\", pv: \"ok\" }\n"
            "    var b2 = b\n"
            "    b2.sv = token\n"
            "    stdio.println(b.sv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_alias_then_mutate_public_read_conservative(self):
        # After an aliased mutation, even reading a field that was not
        # touched falls back to whole-value (we cannot prove the alias
        # did not touch it cheaply) -- conservative, never a false neg.
        r = self._analyze(
            "type S { sv: String, pv: String }\n"
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    var b = S { sv: \"a\", pv: \"ok\" }\n"
            "    var b2 = b\n"
            "    b2.sv = token\n"
            "    stdio.println(b.pv)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- whole-aggregate rule for lists/tuples unchanged --------

    def test_list_remains_whole_aggregate(self):
        # Lists stay whole-aggregate (this slice is per-STRUCT-field
        # only): a secret element taints the whole list.
        r = self._analyze(
            "fun f(stdio: Stdio, token: @secret String)\n"
            "    let xs = [token, \"other\"]\n"
            "    stdio.println(xs.get(1).unwrap_or(\"\"))\n"
        )
        self.assertEqual(len(r.warnings), 1)


class TestDeclaredSecretField(unittest.TestCase):
    """Roadmap S2 (soundness fix): a struct field whose TYPE is declared
    ``@secret`` (``type Emp { iban: @secret String }``) produces a
    @secret value when READ -- the struct-type analogue of a @secret
    parameter. Closes the laundering hole where reading a declared-secret
    field dropped its label, so PII stashed in a struct field could reach
    a public sink with no warning. Precision is preserved: a field
    declared PUBLIC (or unlabelled) reading off a struct that ALSO holds
    a declared-secret field stays public (no over-tainting)."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    # ---- negatives (now flagged) --------------------------------

    def test_declared_secret_field_to_sink_warns(self):
        # Facet 1: a declared-@secret field sunk directly in the same
        # function now warns (previously silent).
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    stdio.println(e.iban)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    def test_declared_secret_field_via_local_to_sink_warns(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    let x: @secret String = e.iban\n"
            "    stdio.println(x)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_declared_secret_field_under_strict_is_hard_error(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "@strict_ifc()\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    stdio.println(e.iban)\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors)
        )

    def test_declared_secret_field_sunk_in_callee_warns(self):
        # Cross-function: a callee that reads a declared-@secret field of
        # a struct PARAMETER and sinks it is flagged at the call site.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun show(e: Emp, stdio: Stdio)\n"
            "    stdio.println(e.iban)\n"
            "fun caller(e: Emp, stdio: Stdio)\n"
            "    show(e, stdio)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_declared_secret_field_returned_then_sunk_warns(self):
        # Facet 3: a callee returns a value derived from a declared-secret
        # field; the caller sinks the return. The return-secret effect
        # carries the label across the boundary.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun get_it(e: Emp) -> String\n"
            "    return e.iban\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    stdio.println(get_it(e))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_declared_secret_field_on_self_to_sink_warns(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "impl Emp\n"
            "    fun dump(self, stdio: Stdio)\n"
            "        stdio.println(self.iban)\n"
            "fun caller(e: Emp, stdio: Stdio)\n"
            "    e.dump(stdio)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- positives (stay clean) ---------------------------------

    def test_public_field_of_struct_with_secret_field_is_clean(self):
        # The precision guarantee: reading the PUBLIC field of a struct
        # that ALSO declares a @secret field does NOT over-taint.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    stdio.println(e.id)\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_declassify_of_declared_secret_field_is_clean(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    stdio.println(declassify(e.iban, reason: \"audit\"))\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)

    def test_public_field_returned_then_sunk_is_clean(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun get_id(e: Emp) -> String\n"
            "    return e.id\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    stdio.println(get_id(e))\n"
        )
        self.assertEqual(len(r.warnings), 0)

    def test_same_named_field_in_other_struct_no_false_positive(self):
        # A field named ``iban`` is @secret in one struct and PUBLIC in
        # another. Reading the PUBLIC one (and returning it cross-fn)
        # must NOT be tainted by the unrelated secret declaration.
        r = self._analyze(
            "type A { iban: @secret String }\n"
            "type B { iban: String }\n"
            "fun get_b(b: B) -> String\n"
            "    return b.iban\n"
            "fun ok(b: B, stdio: Stdio)\n"
            "    stdio.println(get_b(b))\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)


class TestDestructuredSecretField(unittest.TestCase):
    """Roadmap S2 (soundness fix): extracting a struct field declared
    ``@secret`` by DESTRUCTURING (``let Emp { iban } = e`` or a ``match``
    arm) preserves the field's @secret label, exactly as a direct
    ``e.iban`` read does. Closes the last field-laundering hole of the
    same class the field-access fix closed: a pattern bind no longer
    drops the declared-field label. Precision is preserved -- a name
    bound to a PUBLIC field (even of a struct that also holds a secret
    field) stays public, and a same-named field of an UNRELATED struct
    is never tainted (resolution is by the pattern's struct type)."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    # ---- negatives (now flagged) --------------------------------

    def test_let_destructure_secret_field_to_sink_warns(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    let Emp { id, iban } = e\n"
            "    stdio.println(iban)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    def test_match_destructure_secret_field_to_sink_warns(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    match e\n"
            "        Emp { id, iban } -> stdio.println(iban)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    def test_let_destructure_under_strict_is_hard_error(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "@strict_ifc()\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    let Emp { id, iban } = e\n"
            "    stdio.println(iban)\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors)
        )

    def test_match_destructure_under_strict_is_hard_error(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "@strict_ifc()\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    match e\n"
            "        Emp { id, iban } -> stdio.println(iban)\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors)
        )

    def test_destructured_secret_field_sunk_in_callee_warns(self):
        # Cross-function: a callee destructures a declared-@secret field
        # of a struct PARAMETER and passes the bound name to a sink.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun sink_it(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun caller(e: Emp, stdio: Stdio)\n"
            "    let Emp { id, iban } = e\n"
            "    sink_it(iban, stdio)\n"
        )
        self.assertEqual(len(r.warnings), 1)
        self.assertIn("information-flow", r.warnings[0].message)

    def test_destructured_secret_field_returned_then_sunk_warns(self):
        # Cross-function: a callee destructures a declared-secret field
        # and RETURNS it; the caller sinks the return.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun extract(e: Emp) -> String\n"
            "    let Emp { id, iban } = e\n"
            "    return iban\n"
            "fun leak(e: Emp, stdio: Stdio)\n"
            "    stdio.println(extract(e))\n"
        )
        self.assertEqual(len(r.warnings), 1)

    def test_nested_destructure_secret_subfield_flagged(self):
        # A struct-pattern nested inside a let field is rejected by the
        # analyzer (neither backend lowers it; see
        # test_analyzer.TestStructPatternBinding). The supported form is
        # the two-step destructure: bind the sub-struct, then destructure
        # it separately. The secret-subfield taint must still flow
        # through that form so sinking ``sec`` warns.
        r = self._analyze(
            "type Inner { tag: String, sec: @secret String }\n"
            "type Outer { inner: Inner, name: String }\n"
            "fun leak(o: Outer, stdio: Stdio)\n"
            "    let Outer { inner, name } = o\n"
            "    let Inner { tag, sec } = inner\n"
            "    stdio.println(sec)\n"
        )
        self.assertEqual(len(r.warnings), 1)

    # ---- positives (stay clean) ---------------------------------

    def test_let_destructure_public_field_is_clean(self):
        # The precision guarantee: destructuring the PUBLIC field of a
        # struct that ALSO declares a @secret field does NOT over-taint.
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    let Emp { id, iban } = e\n"
            "    stdio.println(id)\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)

    def test_match_destructure_public_field_is_clean(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    match e\n"
            "        Emp { id, iban } -> stdio.println(id)\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)

    def test_same_named_field_in_other_struct_no_false_positive(self):
        # ``iban`` is @secret in A and PUBLIC in B. Destructuring the
        # PUBLIC one must NOT be tainted by the unrelated secret
        # declaration (resolution is by the pattern's STRUCT TYPE).
        r = self._analyze(
            "type A { iban: @secret String }\n"
            "type B { iban: String, name: String }\n"
            "fun ok(b: B, stdio: Stdio)\n"
            "    let B { iban, name } = b\n"
            "    stdio.println(iban)\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)

    def test_nested_destructure_public_only_is_clean(self):
        # Two-step destructure (the supported form; a struct-pattern
        # nested inside a let field is rejected by the analyzer).
        # Destructuring only the PUBLIC subfield out of the sub-struct
        # must not over-taint, even though the sub-struct also declares a
        # @secret field.
        r = self._analyze(
            "type Inner { tag: String, sec: @secret String }\n"
            "type Outer { inner: Inner, name: String }\n"
            "fun ok(o: Outer, stdio: Stdio)\n"
            "    let Outer { inner, name } = o\n"
            "    let Inner { tag, sec } = inner\n"
            "    stdio.println(tag)\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)

    def test_declassify_of_destructured_secret_field_is_clean(self):
        r = self._analyze(
            "type Emp { id: String, iban: @secret String }\n"
            "fun ok(e: Emp, stdio: Stdio)\n"
            "    let Emp { id, iban } = e\n"
            "    stdio.println(declassify(iban, reason: \"audit\"))\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertTrue(r.ok)


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


class TestImplicitFlowLoopsAndAssign(unittest.TestCase):
    """Roadmap S2.implicit, loop + assignment gaps: a public sink inside
    a secret-conditioned LOOP body, and a value ASSIGNED under a secret
    pc, are implicit flows just like the if/match cases. Strengthened
    under @strict_ifc only; the default warn tier is deliberately
    unchanged (implicit flows stay out of it)."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    # ---- gap 1: secret-conditioned loops raise the pc -------------

    def test_while_secret_cond_sink_errors_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    while token\n"
            "        stdio.println(\"x\")\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            all("information-flow (strict)" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )
        self.assertEqual(len(r.errors), 1)

    def test_while_secret_cond_not_flagged_in_default_tier(self):
        # No @strict_ifc: the implicit loop flow is invisible to the
        # default tier (no explicit data leak), so no new warning.
        r = self._analyze(
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    while token\n"
            "        stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_for_secret_collection_sink_errors_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(xs: @secret List<Int>, stdio: Stdio)\n"
            "    for _x in xs\n"
            "        stdio.println(\"x\")\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            all("information-flow (strict)" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )
        self.assertEqual(len(r.errors), 1)

    def test_for_secret_collection_not_flagged_in_default_tier(self):
        r = self._analyze(
            "fun f(xs: @secret List<Int>, stdio: Stdio)\n"
            "    for _x in xs\n"
            "        stdio.println(\"x\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    # ---- gap 3: assignment joins the pc into the assigned label ---

    def test_implicit_assign_channel_errors_under_strict(self):
        # The classic implicit channel: leaked is public at decl, made
        # secret by an assignment under a secret pc, then sunk.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    var leaked = \"no\"\n"
            "    if token\n"
            "        leaked = \"yes\"\n"
            "    stdio.println(leaked)\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_implicit_assign_channel_not_flagged_in_default_tier(self):
        # Same program without @strict_ifc: the default tier does not
        # join pc into assigned labels, so leaked stays public -> clean.
        r = self._analyze(
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    var leaked = \"no\"\n"
            "    if token\n"
            "        leaked = \"yes\"\n"
            "    stdio.println(leaked)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    def test_implicit_assign_via_struct_field_errors_under_strict(self):
        r = self._analyze(
            "type Box { f: String }\n"
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    var b = Box { f: \"no\" }\n"
            "    if token\n"
            "        b.f = \"yes\"\n"
            "    stdio.println(b.f)\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_implicit_assign_via_struct_field_not_flagged_in_default(self):
        r = self._analyze(
            "type Box { f: String }\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    var b = Box { f: \"no\" }\n"
            "    if token\n"
            "        b.f = \"yes\"\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(r.warnings), 0)

    # ---- pc-restore: no leak into following statements -----------

    def test_sink_after_secret_while_is_clean_under_strict(self):
        # pc is restored after the loop, so a sink AFTER it does not run
        # under secret control flow.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(token: @secret Bool, stdio: Stdio)\n"
            "    while token\n"
            "        let _x = 1\n"
            "    stdio.println(\"always\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_sink_after_secret_for_is_clean_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(xs: @secret List<Int>, stdio: Stdio)\n"
            "    for _x in xs\n"
            "        let _y = 1\n"
            "    stdio.println(\"always\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    # ---- public-conditioned loops / assigns: no false positive ---

    def test_public_while_with_assign_clean_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(n: Int, stdio: Stdio)\n"
            "    var i = 0\n"
            "    var msg = \"a\"\n"
            "    while i < n\n"
            "        msg = \"b\"\n"
            "        stdio.println(msg)\n"
            "        i = i + 1\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_public_for_with_assign_clean_under_strict(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(xs: List<Int>, stdio: Stdio)\n"
            "    var msg = \"a\"\n"
            "    for _x in xs\n"
            "        msg = \"b\"\n"
            "        stdio.println(msg)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_public_if_assign_then_sink_clean_under_strict(self):
        # A public-conditioned assignment under strict does not taint.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun f(flag: Bool, stdio: Stdio)\n"
            "    var msg = \"a\"\n"
            "    if flag\n"
            "        msg = \"b\"\n"
            "    stdio.println(msg)\n"
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

    def test_div_by_secret_rejected(self):
        # Division runs on the variable-latency divider: a secret
        # divisor leaks through timing (CWE-208).
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: Int, b: @secret Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_mod_by_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: Int, b: @secret Int) -> Int\n"
            "    return a % b\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_div_with_secret_dividend_rejected(self):
        # A secret dividend is just as unsafe: the join of the operand
        # labels is secret, so the variable-latency divide leaks it.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: @secret Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_float_div_by_secret_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: Float, b: @secret Float) -> Float\n"
            "    return a / b\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_arithmetic_on_secret_is_fine(self):
        # Add / subtract / multiply are fixed-latency, so they do not
        # leak a secret through timing.
        r = self._analyze(
            "@constant_time()\n"
            "fun add(a: @secret Int, b: @secret Int) -> Int\n"
            "    return (a + b) * (a - b)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_div_by_public_is_fine(self):
        # Division is allowed when no operand is secret.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
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

    def test_secret_string_eq_rejected(self):
        # Audit 2026-06-17 (Finding 4): comparing a @secret String with
        # ``==`` short-circuits byte-by-byte (the Wasm ``$str_eq`` even
        # has a length fast-path + early exit), so the timing reveals the
        # first differing byte -- the MAC / token / password compare
        # oracle. The headline case must be rejected with a constant-time
        # error that points at the comparison.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret String, g: String) -> Bool\n"
            "    return s == g\n"
        )
        self.assertFalse(r.ok)
        errs = self._ct_errors(r)
        self.assertTrue(errs)
        self.assertIn("==", errs[0].message)

    def test_secret_string_neq_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret String, g: String) -> Bool\n"
            "    return s != g\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_secret_string_ordering_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret String, g: String) -> Bool\n"
            "    return s < g\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_secret_list_eq_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: @secret List<Int>, b: List<Int>) -> Bool\n"
            "    return a == b\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_secret_starts_with_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret String, g: String) -> Bool\n"
            "    return s.starts_with(g)\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_secret_arg_contains_rejected(self):
        # A @secret ARGUMENT to a short-circuit method is equally unsafe.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: String, secret: @secret String) -> Bool\n"
            "    return s.contains(secret)\n"
        )
        self.assertTrue(self._ct_errors(r))

    def test_secret_int_eq_is_fine(self):
        # Int scalar comparison is single-cycle on the targets we emit,
        # so an Int ``==`` is NOT a short-circuit byte-scan and stays
        # allowed (only String / List comparison is rejected). The
        # branch-on-secret rule still governs an ``if`` using it.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(a: @secret Int, b: @secret Int) -> Bool\n"
            "    return a == b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_public_string_eq_is_fine(self):
        # No secret operand -> the compare is allowed even on Strings.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: String, g: String) -> Bool\n"
            "    return s == g\n"
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


class TestConstantTimeCrossCall(unittest.TestCase):
    """IFC-2: the constant-time checks are no longer intra-procedural. A
    @secret value passed to an un-annotated helper that performs a
    variable-time operation ON THAT VALUE -- division / modulo, a
    data-dependent branch, a variable-time String / List compare, or a
    data-dependent index / lookup -- is now flagged at the call site inside a
    @constant_time function, closing the timing-side-channel twin of the
    IFC-1 cross-call implicit-flow hole. Reuses ``TestConstantTime``'s
    ``_analyze`` / ``_ct_errors``, and shares the parameter-indexed
    ``ct_sensitive`` summary + dispatch-target resolution."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def _ct_errors(self, r):
        return [e for e in r.errors if "constant-time" in e.message]

    # ---- RED before / GREEN after (each rejects with one ct error) ----

    def test_free_fn_division_rejected(self):
        # The canonical case: a @secret divisor routed into an un-annotated
        # helper whose body does the variable-time divide.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return divide(100, s)\n"
            "fun divide(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_cross_call_data_dependent_branch_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return choose(s)\n"
            "fun choose(x: Int) -> Int\n"
            "    if x > 0\n"
            "        return 1\n"
            "    return 2\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_cross_call_variable_time_compare_rejected(self):
        # ``a == b`` on String short-circuits byte-by-byte (the compare
        # oracle), so a helper doing it is ct-sensitive in both params.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret String) -> Bool\n"
            "    return eq(s, \"x\")\n"
            "fun eq(a: String, b: String) -> Bool\n"
            "    return a == b\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_cross_call_index_by_value_rejected(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f(table: List<Int>, s: @secret Int) -> Int\n"
            "    return pick(table, s)\n"
            "fun pick(xs: List<Int>, i: Int) -> Int\n"
            "    return xs[i]\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_method_form_rejected(self):
        r = self._analyze(
            "type Box { n: Int }\n"
            "impl Box\n"
            "    fun div(self, d: Int) -> Int\n"
            "        return self.n / d\n"
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    let b = Box { n: 100 }\n"
            "    return b.div(s)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_depth_2_transitive_rejected(self):
        # ``outer`` merely forwards its param to ``inner``, which divides:
        # the ct-sensitive fact propagates transitively on the fixpoint.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return outer(s)\n"
            "fun outer(x: Int) -> Int\n"
            "    return inner(x)\n"
            "fun inner(y: Int) -> Int\n"
            "    return 100 / y\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_dynamic_dispatch_rejected(self):
        # A trait-typed receiver dispatches dynamically; the check ORs the
        # ct-sensitive set over the receiver's real dispatch targets
        # (``FastDiv.apply`` divides), so it still bites.
        r = self._analyze(
            "trait Divider\n"
            "    fun apply(self, d: Int) -> Int\n"
            "type FastDiv { k: Int }\n"
            "impl Divider for FastDiv\n"
            "    fun apply(self, d: Int) -> Int\n"
            "        return 100 / d\n"
            "@constant_time()\n"
            "fun f(dv: Divider, s: @secret Int) -> Int\n"
            "    return dv.apply(s)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    def test_constant_time_callee_unannotated_param_rejected(self):
        # Pins the ANNOTATION-BLIND rule: a @constant_time callee whose
        # param is UN-annotated (public inside, ``x / 2`` compiles at its own
        # definition) is exactly the leaking case when called with a secret.
        r = self._analyze(
            "@constant_time()\n"
            "fun g(x: Int) -> Int\n"
            "    return x / 2\n"
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return g(s)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._ct_errors(r)), 1)

    # ---- must-COMPILE controls (the over-reject guards) ----

    def test_secret_into_non_ct_helper_compiles(self):
        # ``add`` does only fixed-latency arithmetic, so no param is
        # ct-sensitive and routing a secret in is clean.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return add(s, 1)\n"
            "fun add(a: Int, b: Int) -> Int\n"
            "    return a + b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._ct_errors(r), [])

    def test_public_value_into_ct_helper_compiles(self):
        r = self._analyze(
            "@constant_time()\n"
            "fun f() -> Int\n"
            "    return divide(100, 7)\n"
            "fun divide(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._ct_errors(r), [])

    def test_declassified_secret_into_ct_helper_compiles(self):
        # declassify lowers the argument to PUBLIC, so the boundary check
        # (which reads the label declassify-aware) does not fire.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return divide(100, declassify(s, reason: \"ok\"))\n"
            "fun divide(a: Int, b: Int) -> Int\n"
            "    return a / b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._ct_errors(r), [])

    def test_ct_callee_secret_param_branchless_compiles(self):
        # Trusted-where-safe: a @constant_time callee whose @secret param
        # provably reaches NO variable-time op (branchless ``x + 1``) has an
        # EMPTY ct-sensitive set, so calling it with a secret is clean.
        r = self._analyze(
            "@constant_time()\n"
            "fun g(x: @secret Int) -> Int\n"
            "    return x + 1\n"
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Int\n"
            "    return g(s)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._ct_errors(r), [])

    def test_int_compare_not_type_scoped_compiles(self):
        # The disclosed-residual boundary: an Int ``==`` compare is
        # fixed-latency and NOT type-scoped to String / List, so the helper
        # has no ct-sensitive param and calling it with a secret compiles. A
        # later widening to non-String compares is then a conscious choice.
        r = self._analyze(
            "@constant_time()\n"
            "fun f(s: @secret Int) -> Bool\n"
            "    return cmp(s, 3)\n"
            "fun cmp(a: Int, b: Int) -> Bool\n"
            "    return a == b\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._ct_errors(r), [])


class TestVarReassignTaint(unittest.TestCase):
    """Audit 2026-06-17 (Finding 3): a reassignment ``x = secret`` is an
    EXPLICIT data flow, so the RHS label must join onto the target's
    label in the DEFAULT tier too (like ``let x = secret``). Previously
    only ``@strict_ifc`` did so, silently laundering PII in the default
    warn tier."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_reassign_from_secret_warns_in_default_tier(self):
        r = self._analyze(
            "fun h(s: @secret String, stdio: Stdio)\n"
            "    var x = \"pub\"\n"
            "    x = s\n"
            "    stdio.println(x)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertTrue(
            any("information-flow" in w.message for w in r.warnings),
            [w.message for w in r.warnings],
        )

    def test_reassign_initializer_already_warned(self):
        # The control case the bug report names: ``var x = s`` (an
        # initializer) already warned; reassignment must now match it.
        r = self._analyze(
            "fun h(s: @secret String, stdio: Stdio)\n"
            "    var x = s\n"
            "    stdio.println(x)\n"
        )
        self.assertTrue(
            any("information-flow" in w.message for w in r.warnings)
        )

    def test_reassign_to_public_stays_clean(self):
        # Reassigning a public value never raises a label (monotonic
        # join from public is a no-op), so no false positive.
        r = self._analyze(
            "fun h(stdio: Stdio)\n"
            "    var x = \"a\"\n"
            "    x = \"b\"\n"
            "    stdio.println(x)\n"
        )
        self.assertEqual(len(r.warnings), 0)
        self.assertEqual(len(r.errors), 0)

    def test_reassign_leak_via_env_get_end_to_end(self):
        # End-to-end via the Env.get secret source, matching the bug
        # report's ``--manifest ... declassification_sites:0`` framing:
        # the leak is now flagged rather than silently laundered.
        r = self._analyze(
            "fun h(env: Env, stdio: Stdio)\n"
            "    var x = \"pub\"\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> x = k\n"
            "        None -> x = \"\"\n"
            "    stdio.println(x)\n"
        )
        self.assertTrue(
            any("information-flow" in w.message for w in r.warnings),
            [w.message for w in r.warnings],
        )


class TestStrictEarlyReturnImplicitFlow(unittest.TestCase):
    """Audit 2026-06-17 (Finding 5): under ``@strict_ifc``, a divergence
    (return / break / continue / panic) inside a secret-conditioned
    branch makes the rest of the enclosing block control-dependent on the
    secret. A sink on the post-branch line leaks the predicate bit and
    must be flagged. Strict-only, monotonic."""

    def _analyze(self, src: str):
        from capa import analyze
        m = _parse(src)
        return analyze(m, source=src)

    def test_early_return_then_sink_is_flagged(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun probe(secret: @secret Int, stdio: Stdio)\n"
            "    if secret > 0\n"
            "        return\n"
            "    stdio.println(\"leak\")\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_return_inside_while_then_sink_is_flagged(self):
        r = self._analyze(
            "@strict_ifc()\n"
            "fun probe(secret: @secret Int, stdio: Stdio)\n"
            "    var i = 0\n"
            "    while secret > i\n"
            "        return\n"
            "    stdio.println(\"leak\")\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors)
        )

    def test_public_early_return_then_sink_is_clean(self):
        # A PUBLIC-conditioned early return reveals nothing secret, so no
        # false positive even under strict.
        r = self._analyze(
            "@strict_ifc()\n"
            "fun probe(flag: Bool, stdio: Stdio)\n"
            "    if flag\n"
            "        return\n"
            "    stdio.println(\"fine\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_no_strict_means_no_implicit_flag(self):
        # The default tier does not report implicit flows, so the early
        # return + post-branch sink analyses cleanly there.
        r = self._analyze(
            "fun probe(secret: @secret Int, stdio: Stdio)\n"
            "    if secret > 0\n"
            "        return\n"
            "    stdio.println(\"leak\")\n"
        )
        self.assertEqual(
            [e for e in r.errors if "information-flow" in e.message], []
        )


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
