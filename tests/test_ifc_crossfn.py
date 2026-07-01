"""Cross-function information-flow inference (roadmap S2.6).

The intra-procedural IFC pass catches a @secret value reaching a
public sink *within one function body*. These tests cover the
additive cross-function slice: a secret passed to a user function /
method parameter that is NOT annotated @secret and that reaches a
sink INSIDE that callee is now caught at the call site -- a warning
by default, a hard error under @strict_ifc, mirroring the
intra-procedural tier.

Acceptance criteria 1-8 from the slice brief are each exercised.
"""

import unittest

from capa import Lexer, Parser


def _parse(src: str):
    return Parser(Lexer(src).lex(), source=src).parse_module()


def _analyze(src: str):
    from capa import analyze
    return analyze(_parse(src), source=src)


def _crossfn_warnings(r):
    """IFC warnings whose wording is the cross-function (boundary)
    leak, distinguishing them from intra-procedural sink warnings."""
    return [
        w for w in r.warnings
        if "reaches a public sink inside" in w.message
    ]


def _crossfn_errors(r):
    return [
        e for e in r.errors
        if "reaches a public sink inside" in e.message
    ]


class TestCrossFnOneHop(unittest.TestCase):
    """Criterion 1: a secret passed to a function whose parameter is
    sunk inside it is caught at the call site (missed before)."""

    def test_one_hop_leak_warns_at_call_site(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun caller(env: Env, stdio: Stdio)\n"
            "    match env.get(\"API_KEY\")\n"
            "        Some(k) -> log(k, stdio)\n"
            "        None -> log(\"none\", stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("log", w[0].message)
        self.assertIn("declassify", w[0].message)

    def test_explicit_secret_arg_one_hop(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(token, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1)

    def test_public_arg_to_sink_param_is_clean(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun caller(stdio: Stdio)\n"
            "    log(\"plain\", stdio)\n"
        )
        self.assertEqual(len(_crossfn_warnings(r)), 0)


class TestCrossFnTwoHop(unittest.TestCase):
    """Criterion 2: a transitive leak through two function hops."""

    def test_two_hop_transitive_leak(self):
        r = _analyze(
            "fun b(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun a(s: String, stdio: Stdio)\n"
            "    b(s, stdio)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    a(token, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("a", w[0].message)


class TestCrossFnMethod(unittest.TestCase):
    """Criterion 3: a struct method whose parameter reaches a sink is
    caught when the method is called with a secret."""

    def test_method_param_reaches_sink(self):
        r = _analyze(
            "type Logger { tag: String }\n"
            "impl Logger\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.println(s)\n"
            "fun caller(token: @secret String, stdio: Stdio, lg: Logger)\n"
            "    lg.emit(token, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("Logger.emit", w[0].message)

    def test_secret_receiver_reaches_sink(self):
        # self reaches a sink inside the method -> a secret receiver
        # is flagged on parameter index 0.
        r = _analyze(
            "type Holder { v: String }\n"
            "impl Holder\n"
            "    fun leak_self(self, stdio: Stdio)\n"
            "        stdio.println(self.v)\n"
            "fun caller(h: @secret Holder, stdio: Stdio)\n"
            "    h.leak_self(stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("self", w[0].message)


class TestCrossFnTraitDispatch(unittest.TestCase):
    """Trait-typed (dynamic-dispatch) receiver: the concrete impl is
    not known statically, so the call-site checker over-approximates
    across every impl method of the name (sound: never misses a leak).
    Closes the soundness hole where a trait-typed receiver missed the
    exact (impl-keyed) summary and the leak went unreported."""

    _TRAIT = (
        "trait Logger\n"
        "    fun emit(self, s: String, stdio: Stdio)\n"
        "type FileLog { path: String }\n"
        "impl Logger for FileLog\n"
        "    fun emit(self, s: String, stdio: Stdio)\n"
        "        stdio.println(s)\n"
    )

    def test_trait_receiver_leak_warns_at_call_site(self):
        # The receiver is the TRAIT type Logger, so the summary's
        # impl-keyed exact lookup (FileLog.emit) misses; the by-name
        # over-approximation catches it.
        r = _analyze(
            self._TRAIT
            + "fun audit(lg: Logger, secret_v: @secret String, stdio: Stdio)\n"
            "    lg.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("Logger.emit", w[0].message)
        self.assertIn("declassify", w[0].message)

    def test_trait_receiver_leak_hard_error_under_strict(self):
        r = _analyze(
            self._TRAIT
            + "@strict_ifc()\n"
            "fun audit(lg: Logger, secret_v: @secret String, stdio: Stdio)\n"
            "    lg.emit(secret_v, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1)

    def test_trait_method_not_sinking_is_clean(self):
        # No impl of the trait sinks the parameter -> no false positive.
        r = _analyze(
            "trait Logger\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "type FileLog { path: String }\n"
            "impl Logger for FileLog\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.println(\"clean\")\n"
            "fun audit(lg: Logger, secret_v: @secret String, stdio: Stdio)\n"
            "    lg.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_crossfn_warnings(r)), 0,
            [w.message for w in r.warnings],
        )

    def test_multi_impl_one_sinks_via_trait_receiver_flagged(self):
        # Two impls of one trait; only one sinks the bound param. A
        # trait-typed receiver could dispatch to either, so the sound
        # over-approximation flags it (AT LEAST ONE impl sinks).
        r = _analyze(
            "trait Logger\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "type Quiet { tag: String }\n"
            "impl Logger for Quiet\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.println(\"clean\")\n"
            "type Loud { tag: String }\n"
            "impl Logger for Loud\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.println(s)\n"
            "fun caller(lg: Logger, secret_v: @secret String, stdio: Stdio)\n"
            "    lg.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [x.message for x in r.warnings])

    def test_multi_impl_both_sink_via_trait_receiver_flagged(self):
        r = _analyze(
            "trait Logger\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "type A { tag: String }\n"
            "impl Logger for A\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.println(s)\n"
            "type B { tag: String }\n"
            "impl Logger for B\n"
            "    fun emit(self, s: String, stdio: Stdio)\n"
            "        stdio.eprintln(s)\n"
            "fun caller(lg: Logger, secret_v: @secret String, stdio: Stdio)\n"
            "    lg.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1,
                         [x.message for x in r.warnings])


class TestCrossFnConcreteReceiverPrecision(unittest.TestCase):
    """A statically-known CONCRETE receiver keeps full precision: it
    uses its own (impl-keyed) summary, NOT the by-name union. So a
    concrete call to a type whose same-named method does NOT sink is
    clean even when another unrelated type's same-named method sinks."""

    _TWO_IMPLS = (
        "type Quiet { tag: String }\n"
        "impl Quiet\n"
        "    fun emit(self, s: String, stdio: Stdio)\n"
        "        let _ = s\n"
        "        stdio.println(\"clean\")\n"
        "type Loud { tag: String }\n"
        "impl Loud\n"
        "    fun emit(self, s: String, stdio: Stdio)\n"
        "        stdio.println(s)\n"
    )

    def test_concrete_non_sinker_not_flagged(self):
        r = _analyze(
            self._TWO_IMPLS
            + "fun caller(q: Quiet, secret_v: @secret String, stdio: Stdio)\n"
            "    q.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_crossfn_warnings(r)), 0,
            [w.message for w in r.warnings],
        )

    def test_concrete_sinker_is_flagged(self):
        r = _analyze(
            self._TWO_IMPLS
            + "fun caller(l: Loud, secret_v: @secret String, stdio: Stdio)\n"
            "    l.emit(secret_v, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("Loud.emit", w[0].message)


class TestCrossFnDeclassifyBreaksChain(unittest.TestCase):
    """Criterion 4: a callee that declassifies before sinking is NOT a
    sink-reaching parameter, so passing a secret is not flagged."""

    def test_declassify_in_callee_no_false_positive(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(declassify(s, reason: \"audited\"))\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(token, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_crossfn_warnings(r)), 0,
            [w.message for w in r.warnings],
        )


class TestCrossFnNoFalsePositive(unittest.TestCase):
    """Criterion 5: a callee that takes the parameter but does NOT
    sink it (pass-through to a non-sink, or just returns it) is not
    flagged by this check."""

    def test_pure_passthrough_not_flagged(self):
        r = _analyze(
            "fun identity(s: String) -> String\n"
            "    return s\n"
            "fun caller(token: @secret String)\n"
            "    let x = identity(token)\n"
        )
        self.assertEqual(len(_crossfn_warnings(r)), 0)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_passthrough_to_non_sink_not_flagged(self):
        r = _analyze(
            "fun store(s: String, m: Map<String, String>)\n"
            "    m.set(\"k\", s)\n"
            "fun caller(token: @secret String, m: Map<String, String>)\n"
            "    store(token, m)\n"
        )
        self.assertEqual(len(_crossfn_warnings(r)), 0)
        self.assertTrue(r.ok, [e.message for e in r.errors])

    def test_result_label_still_taints_caller(self):
        # The existing conservative result-label join is unchanged: a
        # value derived from a secret-returning call is still secret,
        # so sinking it locally still warns intra-procedurally.
        r = _analyze(
            "fun identity(s: String) -> String\n"
            "    return s\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    let x = identity(token)\n"
            "    stdio.println(x)\n"
        )
        # The intra-procedural sink check fires on the local println.
        self.assertTrue(any(
            "information-flow" in w.message for w in r.warnings
        ))


class TestCrossFnRecursion(unittest.TestCase):
    """Criterion 6: self and mutual recursion reach a fixpoint without
    hanging, and still detect the leak."""

    def test_self_recursion_terminates_and_detects(self):
        r = _analyze(
            "fun rec(s: String, n: Int, stdio: Stdio)\n"
            "    if n <= 0\n"
            "        stdio.println(s)\n"
            "    else\n"
            "        rec(s, n - 1, stdio)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    rec(token, 3, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1)

    def test_mutual_recursion_terminates(self):
        r = _analyze(
            "fun ping(s: String, n: Int, stdio: Stdio)\n"
            "    if n <= 0\n"
            "        stdio.println(s)\n"
            "    else\n"
            "        pong(s, n - 1, stdio)\n"
            "fun pong(s: String, n: Int, stdio: Stdio)\n"
            "    ping(s, n - 1, stdio)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    ping(token, 4, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 1)


class TestCrossFnNamedArgs(unittest.TestCase):
    """Criterion 7: a named argument binds to the right parameter."""

    def test_named_arg_binds_to_sink_param(self):
        r = _analyze(
            "fun log(prefix: String, msg: String, stdio: Stdio)\n"
            "    stdio.println(msg)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(prefix: \"p\", msg: token, stdio: stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("msg", w[0].message)

    def test_named_arg_to_non_sink_param_is_clean(self):
        # The sink param is ``msg``; passing the secret as ``prefix``
        # (a non-sink param) must NOT flag.
        r = _analyze(
            "fun log(prefix: String, msg: String, stdio: Stdio)\n"
            "    stdio.println(msg)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(prefix: token, msg: \"safe\", stdio: stdio)\n"
        )
        self.assertEqual(
            len(_crossfn_warnings(r)), 0,
            [w.message for w in r.warnings],
        )


class TestCrossFnStrictTier(unittest.TestCase):
    """Criterion 8: warn by default, hard error under @strict_ifc."""

    def test_default_is_warning(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(token, stdio)\n"
        )
        self.assertTrue(r.ok)
        self.assertEqual(len(_crossfn_warnings(r)), 1)
        self.assertEqual(len(_crossfn_errors(r)), 0)

    def test_strict_ifc_is_hard_error(self):
        r = _analyze(
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "@strict_ifc()\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    log(token, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1)

    def test_strict_on_caller_only(self):
        # The strict flag is the CALLER's: the leak is reported at the
        # call site, so it is the caller's tier that decides.
        r = _analyze(
            "@strict_ifc()\n"
            "fun log(s: String, stdio: Stdio)\n"
            "    let _ = s\n"
            "    stdio.println(\"clean\")\n"
            "fun caller(token: @secret String, stdio: Stdio)\n"
            "    let _ = token\n"
            "    stdio.println(\"also clean\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 0)


class TestCrossFnFieldWriteEffect(unittest.TestCase):
    """Cross-function self/param field-write effect (closed false
    negative): a callee that stores a secret-derived value into a field
    of one of its parameters (incl ``self``) taints the caller's
    binding whole-value, so a later read of any field of it is caught.
    Default-warn / strict-error, matching the sink-reaching tier."""

    def _flow_warnings(self, r):
        return [w for w in r.warnings if "information-flow" in w.message]

    def _flow_errors(self, r):
        return [e for e in r.errors if "information-flow" in e.message]

    def test_method_self_field_write_then_read_flagged(self):
        # Criterion 1: obj.stash(secret); sink(obj.f) -> flagged.
        r = _analyze(
            "type Box { f: String }\n"
            "impl Box\n"
            "    fun stash(self, v: String)\n"
            "        self.f = v\n"
            "fun caller(stdio: Stdio, token: @secret String, obj: Box)\n"
            "    obj.stash(token)\n"
            "    stdio.println(obj.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_method_self_field_write_hard_error_under_strict(self):
        r = _analyze(
            "type Box { f: String }\n"
            "impl Box\n"
            "    fun stash(self, v: String)\n"
            "        self.f = v\n"
            "@strict_ifc()\n"
            "fun caller(stdio: Stdio, token: @secret String, obj: Box)\n"
            "    obj.stash(token)\n"
            "    stdio.println(obj.f)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._flow_errors(r)), 1)

    def test_free_function_param_field_write_flagged(self):
        # Criterion 2: put(b, secret); sink(b.f) -> flagged.
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f = v\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_internal_secret_source_field_write_flagged(self):
        # Criterion 3: the callee writes a field from an internal
        # env.get secret source -> caller's obj.field leaked.
        r = _analyze(
            "type Box { f: String }\n"
            "fun load(box: Box, env: Env)\n"
            "    match env.get(\"K\")\n"
            "        Some(k) -> box.f = k\n"
            "        None -> box.f = \"x\"\n"
            "fun caller(stdio: Stdio, env: Env, b: Box)\n"
            "    load(b, env)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_public_value_into_field_not_flagged(self):
        # Criterion 4: callee writes a PUBLIC value into the field ->
        # no false positive.
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f = \"public\"\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_public_arg_to_source_param_not_flagged(self):
        # Criterion 5: callee writes the field from param i, caller
        # passes a PUBLIC arg for i -> no false positive.
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f = v\n"
            "fun caller(stdio: Stdio, b: Box)\n"
            "    put(b, \"plain\")\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_transitive_field_write_effect_flagged(self):
        # The effect is transitive: ``outer`` calls ``inner`` which
        # performs the field write; a secret routed through ``outer``
        # still taints the caller's binding.
        r = _analyze(
            "type Box { f: String }\n"
            "fun inner(box: Box, v: String)\n"
            "    box.f = v\n"
            "fun outer(box: Box, v: String)\n"
            "    inner(box, v)\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    outer(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])


class TestCrossFnAugmentedFieldWrite(unittest.TestCase):
    """FN-1 (closed): an AUGMENTED field store in a callee
    (``box.f += v``, ``-=`` ...) records a field-write effect too. An
    augmented store joins the incoming value into the old field, so it
    can only RAISE the field's label -- recording it for every op is
    sound. Previously only ``=`` was recorded, so the cross-function
    check missed the leak (the intra-procedural ``b.f += token`` IS
    flagged, proving ``+=`` carries the secret into the field)."""

    def _flow_warnings(self, r):
        return [w for w in r.warnings if "information-flow" in w.message]

    def _flow_errors(self, r):
        return [e for e in r.errors if "information-flow" in e.message]

    def test_free_fn_augmented_field_write_flagged(self):
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f += v\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_self_method_augmented_field_write_flagged(self):
        r = _analyze(
            "type Box { f: String }\n"
            "impl Box\n"
            "    fun stash(self, v: String)\n"
            "        self.f += v\n"
            "fun caller(stdio: Stdio, token: @secret String, obj: Box)\n"
            "    obj.stash(token)\n"
            "    stdio.println(obj.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_transitive_augmented_field_write_flagged(self):
        # 2-hop transitive chain through an augmented store.
        r = _analyze(
            "type Box { f: String }\n"
            "fun inner(box: Box, v: String)\n"
            "    box.f += v\n"
            "fun outer(box: Box, v: String)\n"
            "    inner(box, v)\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    outer(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_augmented_field_write_hard_error_under_strict(self):
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f += v\n"
            "@strict_ifc()\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._flow_errors(r)), 1)

    def test_subtract_assign_field_write_flagged(self):
        # A different augmented op (``-=``) is also recorded.
        r = _analyze(
            "type Box { f: Int }\n"
            "fun put(box: Box, v: Int)\n"
            "    box.f -= v\n"
            "fun caller(stdio: Stdio, token: @secret Int, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(\"${b.f}\")\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_augmented_public_value_not_flagged(self):
        # No false positive: the augmented store uses a PUBLIC value.
        r = _analyze(
            "type Box { f: String }\n"
            "fun put(box: Box, v: String)\n"
            "    box.f += \"public\"\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Box)\n"
            "    put(b, token)\n"
            "    stdio.println(b.f)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 0,
                         [w.message for w in r.warnings])


class TestCrossFnEmbedThenCrossfnMutate(unittest.TestCase):
    """FN-2 (closed): the cross-function whole-value taint propagates
    through an embed alias group. ``let o = Outer { inner: b }`` links
    ``o`` and ``b`` (same heap object); a later CROSS-FUNCTION mutation
    of ``b`` (``put(b, token)``) must taint ``o`` too. Previously the
    cross-function whole-value taint raised only the single root symbol
    and missed the alias group, so a read through the embedding was
    missed."""

    def _flow_warnings(self, r):
        return [w for w in r.warnings if "information-flow" in w.message]

    def _flow_errors(self, r):
        return [e for e in r.errors if "information-flow" in e.message]

    def test_embed_first_then_crossfn_mutate_free_sinker(self):
        # Embed FIRST, then cross-fn mutate ``b``, then read through the
        # embedding via a free sinker chain.
        r = _analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun put(box: Inner, v: String)\n"
            "    box.sv = v\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Inner)\n"
            "    let o = Outer { inner: b }\n"
            "    put(b, token)\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_embed_first_then_crossfn_mutate_self_method(self):
        # Same, but the mutation is a self-method field write.
        r = _analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "impl Inner\n"
            "    fun stash(self, v: String)\n"
            "        self.sv = v\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Inner)\n"
            "    let o = Outer { inner: b }\n"
            "    b.stash(token)\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_embed_first_then_crossfn_mutate_public_clean(self):
        # No false positive: the cross-fn mutation writes a PUBLIC value.
        r = _analyze(
            "type Inner { sv: String }\n"
            "type Outer { inner: Inner }\n"
            "fun put(box: Inner, v: String)\n"
            "    box.sv = \"public\"\n"
            "fun caller(stdio: Stdio, token: @secret String, b: Inner)\n"
            "    let o = Outer { inner: b }\n"
            "    put(b, token)\n"
            "    stdio.println(o.inner.sv)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(self._flow_warnings(r)), 0,
                         [w.message for w in r.warnings])


class TestCrossFnClosureInvokeSink(unittest.TestCase):
    """Closure passed to a higher-order function that INVOKES it and
    sinks the result (the invoke-sink-reaching parameter). The capture
    label never reaches the callee's sink directly (only ``f()`` does),
    so this was a cross-function false negative until the summary builder
    learned to mark an invoked Fun parameter sink-reaching and the call
    site to consult the closure's RESULT label."""

    _APPLY = (
        "fun apply(f: Fun() -> String, stdio: Stdio)\n"
        "    stdio.println(f())\n"
    )

    def test_inline_secret_closure_warns_by_default(self):
        r = _analyze(
            self._APPLY
            + "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    apply(fun () -> String => s, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("apply", w[0].message)

    def test_inline_secret_closure_hard_error_under_strict(self):
        r = _analyze(
            self._APPLY
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    apply(fun () -> String => s, stdio)\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(_crossfn_errors(r)), 1)

    def test_public_closure_is_clean(self):
        # The closure captures nothing secret -> no false positive.
        r = _analyze(
            self._APPLY
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio)\n"
            "    let s = \"hello\"\n"
            "    apply(fun () -> String => s, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_declassifying_closure_is_clean(self):
        # The closure body declassifies the captured secret, so its
        # RESULT is public -- no false positive even under strict.
        r = _analyze(
            self._APPLY
            + "@strict_ifc()\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    apply(fun () -> String => "
            "declassify(s, reason: \"ok\"), stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_fun_param_not_invoked_is_clean(self):
        # ``store`` receives a Fun but only RETURNS it (never invokes /
        # sinks it) -> the parameter is not invoke-sink-reaching.
        r = _analyze(
            "fun store(f: Fun() -> String) -> Fun() -> String\n"
            "    return f\n"
            "@strict_ifc()\n"
            "fun main(env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    let g = store(fun () -> String => s)\n"
            "    let _ = g\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 0,
                         [w.message for w in r.warnings])
        self.assertEqual(len(_crossfn_errors(r)), 0,
                         [e.message for e in r.errors])

    def test_fun_param_result_returned_not_sunk_is_clean(self):
        # ``apply`` invokes the closure and RETURNS the result without an
        # internal sink -> the parameter is not invoke-sink-reaching. (A
        # caller that then sinks the returned secret is caught by the
        # separate return-secret effect, exercised elsewhere.)
        r = _analyze(
            "fun apply(f: Fun() -> String) -> String\n"
            "    return f()\n"
            "@strict_ifc()\n"
            "fun main(env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    let r = apply(fun () -> String => s)\n"
            "    let _ = r\n"
            "    ()\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(len(_crossfn_warnings(r)), 0,
                         [w.message for w in r.warnings])

    def test_method_invoke_sink_closure_warns(self):
        # The method form: a struct method that invokes a Fun parameter
        # and sinks its result.
        r = _analyze(
            "type Box { v: Int }\n"
            "impl Box\n"
            "    fun take(self, f: Fun() -> String, stdio: Stdio)\n"
            "        stdio.println(f())\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"SECRET\").unwrap_or(\"d\")\n"
            "    let b = Box { v: 1 }\n"
            "    b.take(fun () -> String => s, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        w = _crossfn_warnings(r)
        self.assertEqual(len(w), 1, [x.message for x in r.warnings])
        self.assertIn("Box.take", w[0].message)


class TestStrictPcDoesNotLeakAcrossFunctions(unittest.TestCase):
    """Audit 2026-06-17 (BLOCKER): the implicit-flow pc-label is a
    per-function quantity. ``_check_block`` raises it monotonically
    when a statement diverges (e.g. ``return``) under a @secret guard
    and does NOT lower it before the block ends. ``_check_fun`` must
    reset the pc at the function boundary; otherwise a function that
    EXITS with the pc still raised contaminates whichever @strict_ifc
    function is CHECKED NEXT, turning a clean public sink there into an
    order-dependent false positive.

    The suite had no two-strict-function-in-adversarial-order case, so
    the leak shipped. These tests pin it shut and confirm the genuine
    intra-function elevation still fires."""

    def _strict_errors(self, r):
        return [
            e for e in r.errors
            if "runs under secret control flow" in e.message
        ]

    def test_leaky_first_clean_second_no_false_positive(self):
        # ``leaky`` ends with a @secret-conditioned early return, so its
        # body exits with the pc raised. ``clean`` that follows has no
        # secret anywhere; its sink must NOT be flagged. Pre-fix the
        # raised pc leaked across the function boundary and the error
        # landed on ``clean``'s ``println`` (order-dependent false
        # positive).
        r = _analyze(
            "@strict_ifc()\n"
            "fun leaky(s: @secret Int, stdio: Stdio)\n"
            "    stdio.println(\"start\")\n"
            "    if s > 0\n"
            "        return\n"
            "@strict_ifc()\n"
            "fun clean(stdio: Stdio)\n"
            "    stdio.println(\"clean\")\n"
        )
        self.assertTrue(
            r.ok,
            "pc-label leaked from leaky into clean: "
            f"{[e.message for e in r.errors]}",
        )
        self.assertEqual(self._strict_errors(r), [])

    def test_intra_function_elevation_still_flagged(self):
        # The original Finding 5: an early return under a @secret guard
        # followed by a public sink in the SAME body must still be a
        # hard error. The per-function reset must not weaken this.
        r = _analyze(
            "@strict_ifc()\n"
            "fun leaky(s: @secret Int, stdio: Stdio)\n"
            "    if s > 0\n"
            "        return\n"
            "    stdio.println(\"leak\")\n"
        )
        self.assertFalse(r.ok)
        self.assertEqual(len(self._strict_errors(r)), 1,
                         [e.message for e in r.errors])

    def test_clean_first_leaky_second_symmetric(self):
        # The reverse order is also clean for the first function: a leak
        # in the SECOND function must not retroactively touch the first,
        # and the first's clean sink stays clean regardless of order.
        r = _analyze(
            "@strict_ifc()\n"
            "fun clean(stdio: Stdio)\n"
            "    stdio.println(\"clean\")\n"
            "@strict_ifc()\n"
            "fun leaky(s: @secret Int, stdio: Stdio)\n"
            "    stdio.println(\"start\")\n"
            "    if s > 0\n"
            "        return\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(self._strict_errors(r), [])


def _sink_leak_warnings(r):
    """Intra-procedural / call-result sink warnings: a @secret value
    reaching a public sink (Stdio.eprintln, ...). Distinct from the
    cross-function boundary wording matched by ``_crossfn_warnings``."""
    return [
        w for w in r.warnings
        if "public sink that sends data out" in w.message
    ]


class TestMethodResultFollowsReturnEffect(unittest.TestCase):
    """The result of a method call carries the method's RETURN-EFFECT
    (which sources flow into the returned value), NOT the whole-value
    taint of the receiver.

    Pins, side by side, both directions of the fix:

    * the FALSE-POSITIVE shape (``clean_send``): a method whose return
      derives only from its argument / a response, called on a receiver
      that holds a @secret field, then sunk -- must NOT warn; and
    * the LAUNDERING shape (``leak_via_field``): a method that returns a
      value derived from a @secret field of the receiver, then sunk --
      must still be rejected.

    Both are exercised intra-procedurally (Path B, ``_compute_label``)
    and through a free-function helper (Path A, the cross-function
    summary), since the fix touches both paths symmetrically."""

    def test_clean_send_result_not_tainted_intra(self):
        # FALSE POSITIVE (Path B): send returns its argument; the
        # receiver holds a @secret field but the result does not derive
        # from it, so sinking the result must NOT warn.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun send(self, p: String) -> String\n"
            "        return p\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    let resp = llm.send(\"hi\")\n"
            "    stdio.eprintln(resp)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_leak_warnings(r), [],
                         [w.message for w in r.warnings])

    def test_clean_send_result_not_tainted_via_helper(self):
        # FALSE POSITIVE (Path A): a free-function helper calls send and
        # returns its result; sinking the helper result must NOT warn.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun send(self, p: String) -> String\n"
            "        return p\n"
            "fun helper(llm: Llm, p: String) -> String\n"
            "    return llm.send(p)\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    let resp = helper(llm, \"hi\")\n"
            "    stdio.eprintln(resp)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(_sink_leak_warnings(r), [])
        self.assertEqual(_crossfn_warnings(r), [])

    def test_leak_via_field_result_tainted_intra(self):
        # LAUNDERING (Path B): leak returns the @secret field directly;
        # sinking the result MUST be rejected.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun leak(self) -> String\n"
            "        return self.api_key\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    stdio.eprintln(llm.leak())\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leak_via_field_result_tainted_via_helper(self):
        # LAUNDERING (Path A): a helper returns the secret-field-derived
        # method result; sinking it MUST be rejected.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun leak(self) -> String\n"
            "        return self.api_key\n"
            "fun helper(llm: Llm) -> String\n"
            "    return llm.leak()\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    stdio.eprintln(helper(llm))\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leak_via_aggregate_return_tainted(self):
        # A return that wraps the secret field in an aggregate
        # (``[self.api_key, p]``) still taints the result.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun leak(self, p: String) -> List<String>\n"
            "        return [self.api_key, p]\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    let xs = llm.leak(\"q\")\n"
            "    stdio.eprintln(xs.get(0).unwrap_or(\"x\"))\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leak_via_local_indirect_tainted(self):
        # The secret field copied through a local before return.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun leak(self) -> String\n"
            "        let k = self.api_key\n"
            "        return k\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    stdio.eprintln(llm.leak())\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leak_via_destructure_tainted(self):
        # The secret field reached by destructuring the receiver.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun leak(self) -> String\n"
            "        let Llm { api_key } = self\n"
            "        return api_key\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    stdio.eprintln(llm.leak())\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_leak_via_struct_literal_field_tainted(self):
        # The secret field embedded into a returned struct literal.
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "type Box { v: String }\n"
            "impl Llm\n"
            "    fun leak(self) -> Box\n"
            "        return Box { v: self.api_key }\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    let b = llm.leak()\n"
            "    stdio.eprintln(b.v)\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_whole_value_secret_receiver_nested_method_tainted(self):
        # A receiver whose whole value is secret-bearing: ``outer``
        # returns ``self.inner()`` which returns the @secret field. The
        # result must be tainted (nested method, receiver carries a
        # declared-@secret field).
        r = _analyze(
            "type Llm { api_key: @secret String }\n"
            "impl Llm\n"
            "    fun inner(self) -> String\n"
            "        return self.api_key\n"
            "    fun outer(self) -> String\n"
            "        return self.inner()\n"
            "fun main(stdio: Stdio)\n"
            "    let llm = Llm { api_key: \"k\" }\n"
            "    stdio.eprintln(llm.outer())\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_builtin_method_on_secret_receiver_still_tainted(self):
        # Fallback path: a built-in method (no user summary) on a @secret
        # value keeps the result @secret (the conservative whole-value
        # join), so the return-effect rule never under-taints a real
        # secret read.
        r = _analyze(
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"K\").unwrap_or(\"d\")\n"
            "    stdio.eprintln(s.to_upper())\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_builtin_get_not_narrowed_by_same_named_user_method(self):
        # SOUNDNESS corner: a user struct defines a method named ``get``
        # whose return-effect excludes ``self``. A REAL ``List.get`` on a
        # @secret list -- colliding only BY NAME -- must NOT be narrowed by
        # that user method's effect; the conservative whole-value join
        # keeps it @secret, so the leak is still flagged. (Both the
        # intra-procedural read and, in the helper variant below, the
        # cross-function summary.)
        r = _analyze(
            "type Wrap { v: String }\n"
            "impl Wrap\n"
            "    fun get(self, p: Int) -> String\n"
            "        return p.to_string()\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"K\").unwrap_or(\"d\")\n"
            "    let xs = [s]\n"
            "    stdio.eprintln(xs.get(0).unwrap_or(\"x\"))\n"
        )
        self.assertEqual(len(_sink_leak_warnings(r)), 1,
                         [w.message for w in r.warnings])

    def test_builtin_get_collision_via_helper_summary_still_tainted(self):
        # Path A form of the collision: a helper reads a @secret List
        # param via the built-in ``get`` and returns it; a same-named user
        # ``Wrap.get`` must not narrow the summary's result label.
        r = _analyze(
            "type Wrap { v: String }\n"
            "impl Wrap\n"
            "    fun get(self, p: Int) -> String\n"
            "        return self.v\n"
            "fun helper(xs: List<String>) -> String\n"
            "    return xs.get(0).unwrap_or(\"x\")\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    let s = env.get(\"K\").unwrap_or(\"d\")\n"
            "    let xs = [s]\n"
            "    stdio.eprintln(helper(xs))\n"
        )
        self.assertTrue(
            _sink_leak_warnings(r) or _crossfn_warnings(r),
            [w.message for w in r.warnings],
        )

    def test_trait_dispatch_union_keeps_leak_tainted(self):
        # A trait-typed (dynamic-dispatch) receiver keeps the by-name
        # UNION over impl methods: one impl returns its argument (clean),
        # another returns a @secret field (leak). The union must taint the
        # result so the leak is still flagged -- soundness must not be
        # narrowed to a single impl for a dynamic receiver.
        r = _analyze(
            "trait Sender\n"
            "    fun send(self, p: String) -> String\n"
            "type A { k: @secret String }\n"
            "type B { name: String }\n"
            "impl Sender for A\n"
            "    fun send(self, p: String) -> String\n"
            "        return self.k\n"
            "impl Sender for B\n"
            "    fun send(self, p: String) -> String\n"
            "        return p\n"
            "fun use(s: Sender, p: String) -> String\n"
            "    return s.send(p)\n"
            "fun main(stdio: Stdio)\n"
            "    let a = A { k: \"x\" }\n"
            "    stdio.eprintln(use(a, \"hi\"))\n"
        )
        self.assertTrue(
            _sink_leak_warnings(r) or _crossfn_warnings(r),
            [w.message for w in r.warnings],
        )


class TestFreeFnResultFollowsReturnEffect(unittest.TestCase):
    """The result of a FREE-FUNCTION call carries the callee's
    RETURN-EFFECT, not just the join of the argument taints.

    Closes a soundness hole (return laundering through a free function):
    a free function that reads a declared-@secret field of a struct
    parameter and RETURNS it produces an internal-secret result, but the
    summary's free-function-call path used to join only the argument
    taints, dropping the ``INTERNAL_SECRET`` sentinel. So a caller whose
    own return / sink depended on that call result was silently missed.

    Pins both directions:

    * the LAUNDERING shape: a chain of free functions ending in a
      @secret-field read, whose final result reaches a public sink, is
      now flagged (was a false negative); and
    * the NON-LAUNDERING shape: a free function whose return derives only
      from a public argument -- even though another parameter holds a
      @secret field -- must NOT be flagged (the return-effect narrowing
      does not introduce a false positive)."""

    def test_free_fn_return_field_launder_flagged(self):
        # LAUNDERING: ``launder`` returns ``extract(e)`` and ``extract``
        # returns the declared-@secret field ``e.iban``; ``main`` sinks
        # ``launder``'s result. Before the fix ``launder``'s return-effect
        # dropped INTERNAL_SECRET, so this was missed.
        r = _analyze(
            "type Emp { iban: @secret String }\n"
            "fun extract(e: Emp) -> String\n"
            "    return e.iban\n"
            "fun launder(e: Emp) -> String\n"
            "    return extract(e)\n"
            "fun main(stdio: Stdio)\n"
            "    let emp = Emp { iban: \"DE00\" }\n"
            "    stdio.eprintln(launder(emp))\n"
        )
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_free_fn_return_field_launder_into_sink_param(self):
        # LAUNDERING through the SUMMARY path: the free-function result
        # flows into a sink-reaching PARAMETER of a further free function.
        r = _analyze(
            "type Emp { iban: @secret String }\n"
            "fun extract(e: Emp) -> String\n"
            "    return e.iban\n"
            "fun mid(e: Emp) -> String\n"
            "    return extract(e)\n"
            "fun sink(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun top(e: Emp, stdio: Stdio)\n"
            "    sink(mid(e), stdio)\n"
        )
        self.assertEqual(
            len(_crossfn_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_free_fn_passthrough_public_arg_not_flagged(self):
        # NON-LAUNDERING: ``passthrough`` returns only its public arg
        # ``p``; the ``Emp`` parameter holds a @secret field but the
        # return does not derive from it, so sinking the result is clean.
        r = _analyze(
            "type Emp { iban: @secret String }\n"
            "fun passthrough(e: Emp, p: String) -> String\n"
            "    return p\n"
            "fun main(stdio: Stdio)\n"
            "    let emp = Emp { iban: \"x\" }\n"
            "    stdio.eprintln(passthrough(emp, \"hi\"))\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            _sink_leak_warnings(r), [],
            [w.message for w in r.warnings],
        )
        self.assertEqual(_crossfn_warnings(r), [])

    def test_free_fn_return_secret_arg_flagged(self):
        # LAUNDERING via a returned parameter: ``echo`` returns its
        # argument; passing a @secret and sinking the result is caught
        # (the real-param source of the return-effect fires).
        r = _analyze(
            "fun echo(s: String) -> String\n"
            "    return s\n"
            "fun main(token: @secret String, stdio: Stdio)\n"
            "    stdio.eprintln(echo(token))\n"
        )
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )


class TestSecretConstSource(unittest.TestCase):
    """Soundness: a module-level ``const`` annotated ``@secret`` is an
    IFC source. Before the fix the declared label on a const was
    silently dropped, so a reference to it came out PUBLIC and a leak to
    a public sink was NOT flagged -- an accepted ``@secret`` annotation
    that bought nothing. These lock BOTH directions: a secret const
    reaching a sink (directly and via an intermediary) is flagged, and a
    plain (public) const is not (no false positive)."""

    def test_secret_const_direct_sink_flagged(self):
        r = _analyze(
            "const K: @secret String = \"sk-secret\"\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(K)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_via_local_var_flagged(self):
        # Intermediary local binding: the taint must flow from the const
        # symbol through ``let s = K`` into the sink.
        r = _analyze(
            "const K: @secret String = \"sk-secret\"\n"
            "fun main(stdio: Stdio)\n"
            "    let s = K\n"
            "    stdio.eprintln(s)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_via_callee_flagged(self):
        # Intermediary function: the const is passed to a callee that
        # sinks its parameter -- caught at the call site (cross-fn).
        r = _analyze(
            "const K: @secret String = \"sk-secret\"\n"
            "fun log(s: String, stdio: Stdio)\n"
            "    stdio.println(s)\n"
            "fun main(stdio: Stdio)\n"
            "    log(K, stdio)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_crossfn_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_declassify_closes(self):
        # declassify(K, ...) is the sanctioned exit: no leak warning.
        r = _analyze(
            "const K: @secret String = \"sk-secret\"\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(declassify(K, reason: \"audited\"))\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 0,
            [w.message for w in r.warnings],
        )

    def test_public_const_direct_sink_not_flagged(self):
        # Negative direction: an unannotated (public) const referenced at
        # a public sink must NOT be flagged -- the fix must not trade the
        # dropped-label hole for a false positive.
        r = _analyze(
            "const P: String = \"not-secret\"\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(P)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 0,
            [w.message for w in r.warnings],
        )


class TestSecretConstCrossFunction(unittest.TestCase):
    """Soundness (cross-function): a module-level ``@secret`` const must
    be an internal secret source in the CROSS-FUNCTION summary walk, not
    only the intra-procedural pass. The summary is an independent walk
    that seeds only parameters, so before this a secret const crossing a
    FREE-FUNCTION return (or field-write) to a public sink was missed in
    both default and ``@strict_ifc`` mode (fail-open) -- the same
    return-laundering class already closed for env/param sources. These
    lock the return path, the struct-return path, the field-write path,
    a 2-hop chain, the strict fail-closed verdict, symmetry with the
    env-source equivalent, and the no-false-positive negatives."""

    def test_secret_const_via_free_fn_return_flagged(self):
        # ``get_key`` RETURNS the const (not as an argument): the
        # return-effect must carry INTERNAL_SECRET to the call site.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "fun get_key() -> String\n"
            "    return K\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(get_key())\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_in_returned_struct_field_flagged(self):
        # The const is embedded in a struct returned by a free function;
        # the caller reads the field and sinks it.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "type Box { v: String }\n"
            "fun make() -> Box\n"
            "    return Box { v: K }\n"
            "fun main(stdio: Stdio)\n"
            "    let b = make()\n"
            "    stdio.eprintln(b.v)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_via_callee_field_write_flagged(self):
        # ``fill`` writes ``b.v = K`` (a field-write effect from an
        # internal-secret source); the caller reads ``b.v`` and sinks it.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "type Box { v: String }\n"
            "fun fill(b: Box)\n"
            "    b.v = K\n"
            "fun main(stdio: Stdio)\n"
            "    let b = Box { v: \"public\" }\n"
            "    fill(b)\n"
            "    stdio.eprintln(b.v)\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_two_hop_chain_flagged(self):
        # K -> get() -> passthrough() -> sink: the internal-secret source
        # must survive two free-function return hops.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "fun get() -> String\n"
            "    return K\n"
            "fun passthrough(s: String) -> String\n"
            "    return s\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(passthrough(get()))\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 1,
            [w.message for w in r.warnings],
        )

    def test_secret_const_via_free_fn_return_strict_is_error(self):
        # Under @strict_ifc the cross-function const leak is a HARD ERROR
        # (fail-closed), not a warning.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "fun get_key() -> String\n"
            "    return K\n"
            "@strict_ifc()\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(get_key())\n"
        )
        self.assertFalse(r.ok)
        self.assertTrue(
            any("information-flow" in e.message for e in r.errors),
            [e.message for e in r.errors],
        )

    def test_symmetry_const_matches_env_source_via_return(self):
        # A secret const returned by a free function yields the SAME
        # verdict as the env-source equivalent already did: one sink-leak
        # warning in each. Symmetry with the PR #25 return-laundering fix.
        const_src = (
            "const K: @secret String = \"sk\"\n"
            "fun get_key() -> String\n"
            "    return K\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(get_key())\n"
        )
        env_src = (
            "fun get_key(env: Env) -> String\n"
            "    match env.get(\"K\")\n"
            "        Some(k) -> return k\n"
            "        None -> return \"none\"\n"
            "fun main(stdio: Stdio, env: Env)\n"
            "    stdio.eprintln(get_key(env))\n"
        )
        r_const = _analyze(const_src)
        r_env = _analyze(env_src)
        self.assertEqual(
            len(_sink_leak_warnings(r_const)),
            len(_sink_leak_warnings(r_env)),
        )
        self.assertEqual(len(_sink_leak_warnings(r_const)), 1)

    def test_public_const_via_free_fn_return_not_flagged(self):
        # Negative: a PUBLIC const returned by a free function to a sink
        # must NOT be flagged (no cross-function false positive).
        r = _analyze(
            "const P: String = \"pub\"\n"
            "fun get_pub() -> String\n"
            "    return P\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(get_pub())\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 0,
            [w.message for w in r.warnings],
        )

    def test_secret_const_declassified_in_callee_return_not_flagged(self):
        # Negative: a callee that declassifies the const before returning
        # it breaks the chain -- no leak at the caller's sink.
        r = _analyze(
            "const K: @secret String = \"sk\"\n"
            "fun get_key() -> String\n"
            "    return declassify(K, reason: \"audited\")\n"
            "fun main(stdio: Stdio)\n"
            "    stdio.eprintln(get_key())\n"
        )
        self.assertTrue(r.ok, [e.message for e in r.errors])
        self.assertEqual(
            len(_sink_leak_warnings(r)), 0,
            [w.message for w in r.warnings],
        )


if __name__ == "__main__":
    unittest.main()
