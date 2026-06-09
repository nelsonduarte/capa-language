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


if __name__ == "__main__":
    unittest.main()
