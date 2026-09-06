"""Analyzer tests: E3, generic-return-aliasing double-free.

A generic body is checked with its type parameter ``T`` opaque, so a
non-``consume`` parameter typed as a bare ``T`` is neither owned nor borrowed
and ``return x`` passes (a concrete ``idc(x: Conn) -> Conn { x }`` cannot even
be written -- the borrowed-return guard rejects it). At a call where ``T`` is
a linear / carrier type, the identity return carries the argument's
must-consume obligation, but the call-result binding armed a FRESH obligation
and never moved the argument -- two names, one resource, a silent double-free
on BOTH backends. This module pins the whole class.

The fix is single-source: one per-callable return-origin summary
(:mod:`capa.analyzer._return_origin`) built over the ONE shared callable
enumeration (:mod:`capa.analyzer._callables`), and one origin-resolution seam
(``_call_result_alias_args`` in :mod:`capa.analyzer._e3`) consulted at every
move position, each recursing the EXISTING move seam
(``_move_linear_operand``) on the aliased argument -- no move discipline
reimplemented. Multi-origin (may-return one of several) and an
un-summarisable opaque callee carrying a live linear argument are fail-closed
REJECTED this increment.

The BORROWED variant of the class is closed too: a call whose result aliases
a BORROWED argument (``return id(c)`` / ``close(id(c))`` where ``c`` is a
non-consume linear parameter the caller still owns) routes the origin move
into the SAME borrowed-transfer guard the direct move (``return c`` /
``close(c)``) applies -- the E3 mover reuses ``_linear_discharge`` rather than
swallowing its ``False`` return.

OUT OF SCOPE (named here, NOT closed by E3): C3, a returned CLOSURE that
captured an OWNED linear then double-invoked (``close(f()); close(f())``) -- a
separate closure/affine-capture class; the resolver returns ``[]`` for a
first-class Fun-value call, so E3 neither closes nor worsens it. Also the
precise multi-parameter may-move union (M15 fail-closed rejected), the
arrow-type-carried fact for first-class dispatch, path-sensitive conditional
precision, the pre-existing diamond wall-clock DoS, Index, and borrow-read.
"""

import unittest

from tests.analyzer._helpers import check, errors_of


# Shared declarations. ``Conn`` is a bare linear leaf with a ``consume self``
# method ``eat``; ``gid``/``snd``/``via``/``pick``/``pick2``/``ping``/``pong``/
# ``choose``/``tricky`` are the generic identity/passthrough family; ``Box`` is
# a carrier over one ``Conn``; ``Claim`` a typestate; ``W`` carries a generic
# identity method; ``Factory``/``Xf`` are traits for the dynamic-dispatch
# backstop.
_P = (
    "linear type Conn { id: Int }\n"
    "impl Conn\n"
    "    fun eat(consume self) -> Unit\n"
    "        return ()\n"
    "fun open() -> Conn\n"
    "    return Conn { id: 1 }\n"
    "fun close(consume c: Conn) -> Unit\n"
    "    return ()\n"
    "fun gid<T>(x: T) -> T\n"
    "    return x\n"
    "fun snd<T, U>(x: T, y: U) -> U\n"
    "    return y\n"
    "fun via<T>(x: T) -> T\n"
    "    return gid(x)\n"
    "fun pick<T>(x: T) -> T\n"
    "    return pick(x)\n"
    "fun pick2<T>(x: T) -> T\n"
    "    return gid(pick2(x))\n"
    "fun ping<T>(x: T) -> T\n"
    "    return pong(x)\n"
    "fun pong<T>(x: T) -> T\n"
    "    return ping(x)\n"
    "fun choose<T>(x: T, y: T, b: Bool) -> T\n"
    "    return if b then x else y\n"
    "fun tricky<T>(a: T, b: T) -> T\n"
    "    var z = a\n"
    "    z = b\n"
    "    return z\n"
    "fun localalias<T>(x: T) -> T\n"
    "    let y = x\n"
    "    return y\n"
    "type Box { c: Conn, tag: Int }\n"
    "fun mkbox() -> Box\n"
    "    return Box { c: open(), tag: 0 }\n"
    "fun sinkbox(consume b: Box) -> Unit\n"
    "    return ()\n"
    "type Wrap { item: Conn, tag: Int }\n"
    "fun mkwrap(consume k: Conn) -> Wrap\n"
    "    return Wrap { item: k, tag: 0 }\n"
    "fun sinkwrap(consume w: Wrap) -> Unit\n"
    "    return ()\n"
    "type W { tag: Int }\n"
    "impl W\n"
    "    fun idm<T>(self, x: T) -> T\n"
    "        return x\n"
    "typestate Claim\n"
    "    Draft\n"
    "    Settled\n"
    "fun mkclaim() -> Claim[Draft]\n"
    "    return Claim[Draft] {}\n"
    "fun archive(consume c: Claim[Settled]) -> Unit\n"
    "    return ()\n"
    "trait Factory\n"
    "    fun make(self) -> Conn\n"
    "type F1 { tag: Int }\n"
    "impl Factory for F1\n"
    "    fun make(self) -> Conn\n"
    "        return open()\n"
    "trait Xf\n"
    "    fun transform(self, x: Conn) -> Conn\n"
    "type Fx { tag: Int }\n"
    "impl Xf for Fx\n"
    "    fun transform(self, x: Conn) -> Conn\n"
    "        return open()\n"
)


class _Base(unittest.TestCase):
    def errs(self, body: str) -> list:
        return errors_of(_P + body)

    def assertRejects(self, body: str, needle: str = "consumed"):
        errs = self.errs(body)
        self.assertTrue(
            any(needle in e for e in errs),
            f"expected an error containing {needle!r}, got: {errs}",
        )

    def assertAccepts(self, body: str):
        errs = self.errs(body)
        self.assertEqual(errs, [], f"expected no errors, got: {errs}")


class TestMembers(_Base):
    """M1-M19: every member is a silent double-free on main, REJECTED after."""

    def test_M1_bare_linear_let(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let h2 = gid(h)\n"
            "    close(h2)\n"
            "    close(h)\n"
        )

    def test_M2_carrier_identity_whole(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let b = mkbox()\n"
            "    let b2 = gid(b)\n"
            "    sinkbox(b2)\n"
            "    sinkbox(b)\n"
        )

    def test_M3_carrier_identity_field_proj(self):
        # After ``gid(b)`` moves the whole carrier, re-projecting its linear
        # field re-transfers an already-moved resource (report on ``b`` / ``b.c``).
        errs = self.errs(
            "fun main(_s: Stdio)\n"
            "    let b = mkbox()\n"
            "    let b2 = gid(b)\n"
            "    close(b.c)\n"
            "    sinkbox(b2)\n"
        )
        self.assertTrue(
            any(("'b'" in e or "'b.c'" in e) and "consumed" in e for e in errs),
            errs,
        )

    def test_M4_no_bind_consume(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    close(gid(h))\n"
            "    close(h)\n"
        )

    def test_M5_assign(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    var t = open()\n"
            "    close(t)\n"
            "    let c = open()\n"
            "    t = gid(c)\n"
            "    close(t)\n"
            "    close(c)\n"
        )

    def test_M6_named_arg(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let h2 = gid(x: h)\n"
            "    close(h2)\n"
            "    close(h)\n"
        )

    def test_M7_struct_pack(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let w = Wrap { item: gid(c), tag: 0 }\n"
            "    sinkwrap(w)\n"
            "    close(c)\n"
        )

    def test_M7b_typestate_pack(self):
        # A generic identity applied to a bare linear packed into a
        # (consume-parameter) constructor call is moved once.
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let w = mkwrap(gid(c))\n"
            "    sinkwrap(w)\n"
            "    close(c)\n"
        )

    def test_M8_chained(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let h2 = gid(gid(h))\n"
            "    close(h2)\n"
            "    close(h)\n"
        )

    def test_M9_body_composition(self):
        # ``via<T>`` returns ``gid(x)``; its summary is origin {0}, so a caller
        # binding the result moves its own live argument.
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let r = via(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M10_self_recursion(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let r = pick(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M11_mutual_recursion(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let r = ping(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M12_local_alias(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let r = localalias(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M13_non_zero_index(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let r = snd(0, c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M14_method_call(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let w = W { tag: 0 }\n"
            "    let c = open()\n"
            "    let r = w.idm(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M15_multi_param_may_move_rejects(self):
        # Fail-closed: origin {0, 1}, cannot pick which obligation the result
        # carries. The precise union is a later increment.
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c1 = open()\n"
            "    let c2 = open()\n"
            "    let r = choose(c1, c2, true)\n"
            "    close(r)\n"
            "    close(c1)\n"
            "    close(c2)\n",
            needle="one of several",
        )

    def test_M16_become_operand(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = mkclaim()\n"
            "    let c2 = become(gid(c), Settled)\n"
            "    archive(c2)\n"
            "    archive(become(c, Settled))\n"
        )

    def test_M17_consume_self_receiver(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    gid(c).eat()\n"
            "    c.eat()\n"
        )

    def test_M18_lambda_passthrough(self):
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let idl = fun (x: Conn) -> Conn => x\n"
            "    let c = open()\n"
            "    let r = idl(c)\n"
            "    close(r)\n"
            "    close(c)\n"
        )

    def test_M19_var_reassign_local_union(self):
        # ``tricky`` unions both reassignments -> origin {0, 1} -> multi-origin.
        self.assertRejects(
            "fun main(_s: Stdio)\n"
            "    let c1 = open()\n"
            "    let c2 = open()\n"
            "    let r = tricky(c1, c2)\n"
            "    close(r)\n"
            "    close(c1)\n"
            "    close(c2)\n",
            needle="one of several",
        )


class TestOriginValues(unittest.TestCase):
    """The single-pass summary values (S1), incl. pick2 and the lambdas."""

    def _origins(self, src: str) -> dict:
        from capa import Lexer, Parser
        from capa.analyzer._return_origin import compute_return_origins
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        origins, _callables = compute_return_origins(module)
        return {k: set(v) for k, v in origins.items()}

    def test_named_origin_values(self):
        o = self._origins(_P)
        self.assertEqual(o[("fun", "gid")], {0})
        self.assertEqual(o[("fun", "snd")], {1})
        self.assertEqual(o[("fun", "via")], {0})
        self.assertEqual(o[("fun", "pick")], {0})
        self.assertEqual(o[("fun", "pick2")], {0})
        self.assertEqual(o[("fun", "ping")], {0})
        self.assertEqual(o[("fun", "pong")], {0})
        self.assertEqual(o[("fun", "choose")], {0, 1})
        self.assertEqual(o[("fun", "tricky")], {0, 1})
        self.assertEqual(o[("fun", "localalias")], {0})
        self.assertEqual(o[("fun", "open")], set())
        self.assertEqual(o[("fun", "mkbox")], set())
        self.assertEqual(o[("method", "W", "idm")], {1})

    def test_lambda_origin_values(self):
        src = (
            "linear type Conn { id: Int }\n"
            "fun open() -> Conn\n    return Conn { id: 1 }\n"
            "fun main(_s: Stdio)\n"
            "    let idl = fun (x: Conn) -> Conn => x\n"
            "    let sndl = fun (a: Conn, b: Conn) -> Conn => b\n"
            "    let mkl = fun () -> Conn => open()\n"
        )
        o = self._origins(src)
        lam = {k: v for k, v in o.items() if k[0] == "lambda"}
        # Values by param count: passthrough {0}, second-of-two {1}, factory {}.
        self.assertIn({0}, lam.values())
        self.assertIn({1}, lam.values())
        self.assertIn(set(), lam.values())


class TestCoverageGuard(unittest.TestCase):
    """The origin table's named keys are a SUPERSET of the shared
    enumerator's named keys, and an unresolvable linear-returning call
    carrying a live linear argument rejects fail-closed."""

    def test_origin_keys_superset_of_enumeration(self):
        from capa import Lexer, Parser
        from capa.analyzer._callables import iter_user_callables
        from capa.analyzer._return_origin import compute_return_origins
        module = Parser(Lexer(_P).lex(), source=_P).parse_module()
        enum_keys = {
            uc.key for uc in iter_user_callables(module)
            if uc.key[0] in ("fun", "method")
        }
        origins, _callables = compute_return_origins(module)
        origin_named = {k for k in origins if k[0] in ("fun", "method")}
        self.assertTrue(
            enum_keys <= origin_named,
            f"enumeration keys not covered: {enum_keys - origin_named}",
        )

    def test_absent_trait_dynamic_with_linear_rejects(self):
        # A trait-dynamic call passed a live linear argument it could return:
        # the callee cannot be summarised, so it fails closed.
        errs = errors_of(
            _P
            + "fun use_t(f: Xf, c: Conn) -> Conn\n"
            "    return f.transform(c)\n"
        )
        self.assertTrue(
            any("cannot be summarised" in e for e in errs), errs,
        )


class TestConservativeRejects(_Base):
    """Fun-param passthrough (D3) is a known conservative reject."""

    def test_D3_funparam_passthrough_rejects(self):
        errs = self.errs(
            "fun higher(f: Fun(Conn) -> Conn, c: Conn) -> Conn\n"
            "    return f(c)\n"
        )
        self.assertTrue(
            any("cannot be summarised" in e for e in errs), errs,
        )


class TestBorrowedLaunder(_Base):
    """The BORROWED variant of the class: a call whose result aliases a
    BORROWED (non-consume) linear parameter the caller still owns. The E3
    mover must apply the SAME borrowed-transfer reject the direct move does
    (``return c`` / ``close(c)`` on a borrowed value already reject), not
    swallow ``_move_linear_operand``'s ``False`` and silently launder."""

    _NEEDLE = "borrowed"

    def test_return_generic_identity_of_borrowed_rejects(self):
        # ``launder(c: Conn) -> Conn { return gid(c) }`` returns its borrowed
        # parameter laundered through the generic identity -- the same shape
        # as ``return c``, which already rejects.
        self.assertRejects(
            "fun launder(c: Conn) -> Conn\n"
            "    return gid(c)\n",
            needle=self._NEEDLE,
        )

    def test_consume_arg_generic_identity_of_borrowed_rejects(self):
        self.assertRejects(
            "fun sink(c: Conn) -> Unit\n"
            "    close(gid(c))\n",
            needle=self._NEEDLE,
        )

    def test_consume_self_generic_identity_of_borrowed_rejects(self):
        self.assertRejects(
            "fun useit(c: Conn) -> Unit\n"
            "    gid(c).eat()\n",
            needle=self._NEEDLE,
        )

    def test_consume_parameter_version_accepts(self):
        # Declaring the parameter ``consume`` takes ownership, so laundering
        # the OWNED value through the identity transfers it cleanly.
        self.assertAccepts(
            "fun launder2(consume c: Conn) -> Conn\n"
            "    return gid(c)\n"
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let d = launder2(c)\n"
            "    close(d)\n"
        )

    def test_borrow_read_not_over_rejected(self):
        # A borrowed value that is READ (not returned/consumed) and a
        # non-linear result must not trip the borrowed reject.
        self.assertAccepts(
            "fun peek(c: Conn) -> Int\n"
            "    return c.id\n"
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let n = peek(c)\n"
            "    close(c)\n"
        )


class TestStayAccepted(_Base):
    """Legit forms must NOT be over-rejected (fail-closed backstop refined)."""

    def test_N1_fresh_factory_call(self):
        self.assertAccepts(
            "fun mk() -> Conn\n"
            "    return open()\n"
            "fun main(_s: Stdio)\n"
            "    let r = mk()\n"
            "    close(r)\n"
        )

    def test_N1b_fresh_factory_lambda(self):
        self.assertAccepts(
            "fun main(_s: Stdio)\n"
            "    let mkl = fun () -> Conn => open()\n"
            "    let r = mkl()\n"
            "    close(r)\n"
        )

    def test_D1_factory_applier(self):
        self.assertAccepts(
            "fun applyf(mk: Fun() -> Conn) -> Conn\n"
            "    return mk()\n"
            "fun main(_s: Stdio)\n"
            "    let r = applyf(fun () -> Conn => open())\n"
            "    close(r)\n"
        )

    def test_D2b_trait_factory(self):
        self.assertAccepts(
            "fun use_dyn(f: Factory) -> Conn\n"
            "    return f.make()\n"
            "fun main(_s: Stdio)\n"
            "    let f = F1 { tag: 0 }\n"
            "    let c = use_dyn(f)\n"
            "    close(c)\n"
        )

    def test_N2_non_linear_identity(self):
        self.assertAccepts(
            "fun main(_s: Stdio)\n"
            "    let r = gid(5)\n"
            "    let h = open()\n"
            "    close(h)\n"
        )

    def test_N3_borrow_passthrough(self):
        # ``peek`` reads a borrowed linear and returns a non-linear value; the
        # generic identity is never applied to launder ownership.
        self.assertAccepts(
            "fun peek(c: Conn) -> Int\n"
            "    return c.id\n"
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let n = peek(c)\n"
            "    close(c)\n"
        )

    def test_N4_param_used_not_returned(self):
        self.assertAccepts(
            "fun keep<T>(x: T) -> Int\n"
            "    return 7\n"
            "fun main(_s: Stdio)\n"
            "    let c = open()\n"
            "    let n = keep(c)\n"
            "    close(c)\n"
        )

    def test_N7_ignore_param_return_fresh(self):
        self.assertAccepts(
            "fun ignore<T>(x: T) -> Conn\n"
            "    return open()\n"
            "fun main(_s: Stdio)\n"
            "    let r = ignore(5)\n"
            "    close(r)\n"
        )

    def test_fresh_factory_consumed_arg_stays_fine(self):
        # ``mkwrap(open())`` packs a fresh linear into a carrier; nothing is
        # aliased, so the whole thing is consumed once.
        self.assertAccepts(
            "fun main(_s: Stdio)\n"
            "    let w = mkwrap(open())\n"
            "    sinkwrap(w)\n"
        )


class TestFalsePositiveFlips(_Base):
    """Cases that REJECT on main (a spurious leak) and ACCEPT after: the
    identity call now MOVES the source, so the obligation transfers cleanly."""

    def test_N5_let_alias_then_consume_once(self):
        self.assertAccepts(
            "fun main(_s: Stdio)\n"
            "    let h = open()\n"
            "    let h2 = gid(h)\n"
            "    close(h2)\n"
        )

    def test_N6_return_generic_identity_transfers(self):
        self.assertAccepts(
            "fun f() -> Conn\n"
            "    let c = open()\n"
            "    return gid(c)\n"
            "fun main(_s: Stdio)\n"
            "    let r = f()\n"
            "    close(r)\n"
        )


class TestManifestParity(unittest.TestCase):
    """The generic identity's manifest facts are unchanged: it does not
    ``produces_linear`` and gains no ``consumes`` from E3."""

    def test_generic_identity_not_produces_linear(self):
        from capa import Lexer, Parser, analyze
        from capa.manifest import build_manifest
        src = _P + "fun main(_s: Stdio)\n    let c = open()\n    close(c)\n"
        module = Parser(Lexer(src).lex(), source=src).parse_module()
        result = analyze(module, source=src)
        self.assertTrue(result.ok, result.errors)
        manifest = build_manifest(module)
        funs = {f["name"]: f for f in manifest["functions"]}
        self.assertIn("gid", funs)
        self.assertFalse(funs["gid"]["linear_obligations"]["produces_linear"])
        self.assertEqual(
            list(funs["gid"]["linear_obligations"]["consumes"]), [],
        )


if __name__ == "__main__":
    unittest.main()
